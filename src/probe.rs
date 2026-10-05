//! Tells, CID resolution, loopback canary, posture — the measurement half of
//! `probe`.
//!
//! Everything here is one syscall deep and records the raw answer, because the
//! conclusions in this tool have been wrong before when they were drawn from a
//! tell nobody measured (spec §3.2). Two rules in particular:
//!
//! * `/dev/vsock` presence is **never** device evidence. `vsock.ko` (the core)
//!   registers that misc device; a guest with the core and no transport has it
//!   too — a guest can have `/dev/vsock` and no virtio id `0x0013` anywhere.
//! * The `IOCTL_VM_SOCKETS_GET_LOCAL_CID` answer is recorded verbatim. Some
//!   kernels answer `4294967295` (`VMADDR_CID_ANY`, i.e. "nothing bound") while
//!   others answer `1`; both are real answers and the report shows which.

use std::collections::BTreeMap;
use std::path::Path;

use crate::caps::Caps;
use crate::diag;
use crate::kernconfig::{self, ConfigRead, ModuleState, Sym, WATCHED};

/// The symbols that decide what vsock can do here, in report order.
pub const CONFIG_SYMBOLS: &[&str] = &[
    "VSOCKETS",
    "VSOCKETS_DIAG",
    "VSOCKETS_LOOPBACK",
    "VIRTIO_VSOCKETS",
    "VIRTIO_VSOCKETS_COMMON",
    "VHOST_VSOCK",
    "VSOCKMON",
    "MODULES",
    "IKCONFIG_PROC",
];
use crate::model::{
    CidResolution, DiagStatus, Finding, FlagSet, Header, ModuleVerdict, Outcome, OutcomeKind,
    Posture, ProbeRow, Report, Severity, SysctlValue, Tell, TellState, Verdict,
};
use crate::uapi;

/// What `probe` was asked to do.
#[derive(Debug, Clone, Copy)]
pub struct ProbeOpts {
    pub seqpacket: bool,
    pub to_host: bool,
    pub vsockmon: bool,
    pub config: bool,
    pub mmio: bool,
    pub diag: bool,
}

/// One virtio device from sysfs.
#[derive(Debug, Clone)]
pub struct VirtioDev {
    pub name: String,
    pub device: u32,
    pub vendor: u32,
    pub modalias: String,
}

/// Standard virtio-vsock device id; `vendor` is `0x0000` on MMIO
/// and `0x1af4` on QEMU/PCI.
pub const VIRTIO_ID_VSOCK: u32 = 0x0013;
pub const VIRTIO_VENDOR_REDHAT: u32 = 0x1af4;

/// Raw device/config tells, collected once.
#[derive(Debug, Clone)]
pub struct Tells {
    /// `/sys/bus/virtio/devices/*`; `None` means sysfs could not be read at all.
    pub virtio: Option<Vec<VirtioDev>>,
    pub misc_vsock_minor: Option<u32>,
    pub dev_vsock_present: bool,
    pub dev_vsock_openable: bool,
    pub ioctl_cid: Option<u32>,
    pub ioctl_errno: Option<i32>,
    pub vhost_node_present: bool,
    /// `Some(true)` when `/proc/misc` lists `vhost-vsock`, i.e. the h2g transport is
    /// registered *right now*. That — not the device node — is the host-side tell:
    /// unloading `vhost_vsock` removes the `/proc/misc` entry (and takes the
    /// `GET_LOCAL_CID` answer from 2 to 1) while the node stayed on disk. Opening that
    /// stale node re-loads the module via `char-major-10-241` autoload, so the node is
    /// only opened when the registration already says it is there.
    /// `None`: `/proc/misc` could not be read.
    pub vhost_registered: Option<bool>,
    pub vhost_openable: Option<bool>,
    pub vhost_features: Option<u64>,
    pub vhost_errno: Option<i32>,
}

/// Errno -> outcome, per spec §6.1. The three measured kernel signatures are
/// the test below; nothing here guesses reachability from an errno that means
/// "the kernel refused to try" (`ENODEV`) versus "the peer refused" (ECONNRESET).
pub fn classify(errno: i32) -> OutcomeKind {
    match errno {
        0 => OutcomeKind::Open,
        libc::ECONNRESET | libc::ECONNREFUSED => OutcomeKind::Closed,
        libc::ENODEV | libc::EINVAL | libc::EADDRNOTAVAIL | libc::ENOTCONN => {
            OutcomeKind::RefusedKernel
        }
        libc::ESOCKTNOSUPPORT | libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT => {
            OutcomeKind::Unsupported
        }
        libc::ETIMEDOUT => OutcomeKind::Silent,
        _ => OutcomeKind::Error,
    }
}

/// An outcome that always carries its errno name alongside the verdict (a global
/// constraint: a verdict the reader cannot audit is a claim, not a measurement).
fn errno_out(errno: i32, detail: impl Into<String>) -> Outcome {
    Outcome::new(classify(errno))
        .with_errno(errno)
        .with_detail(detail)
}

/// Last errno, or `0` when the error carried no code (`ErrorOther`): `0` then
/// classifies as `Open` only where the caller already knows the call succeeded.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Read `u32` from a sysfs-style file, tolerating `0x` prefixes.
fn read_u32(path: &Path) -> Option<u32> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    u32::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

impl Tells {
    pub fn collect() -> Tells {
        let virtio = match std::fs::read_dir("/sys/bus/virtio/devices") {
            Ok(rd) => {
                let mut v = Vec::new();
                for ent in rd.flatten() {
                    let p = ent.path();
                    let Some(name) = ent.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    v.push(VirtioDev {
                        device: read_u32(&p.join("device")).unwrap_or(u32::MAX),
                        vendor: read_u32(&p.join("vendor")).unwrap_or(u32::MAX),
                        modalias: std::fs::read_to_string(p.join("modalias"))
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                        name,
                    });
                }
                v.sort_by(|a, b| a.name.cmp(&b.name));
                Some(v)
            }
            Err(_) => None,
        };

        // /proc/misc: `<minor> <name>`. For "vsock" this proves the *core*
        // registered, nothing more. For "vhost-vsock" it is the authoritative
        // statement that the h2g transport exists *right now*: a device node on
        // disk says nothing, because it survives `modprobe -r vhost_vsock`.
        let misc = std::fs::read_to_string("/proc/misc").ok();
        let misc_entry_minor = |want: &str| {
            misc.as_ref().and_then(|t| {
                t.lines().find_map(|l| {
                    let (minor, name) = l.trim().split_once(char::is_whitespace)?;
                    (name.trim() == want)
                        .then(|| minor.parse::<u32>().ok())
                        .flatten()
                })
            })
        };
        let misc_vsock_minor = misc_entry_minor("vsock");
        let vhost_registered = misc
            .as_ref()
            .map(|_| misc_entry_minor("vhost-vsock").is_some());

        let dev_present = Path::new("/dev/vsock").exists();
        let mut dev_openable = false;
        let mut ioctl_cid = None;
        let mut ioctl_errno = None;
        if dev_present {
            match std::fs::File::open("/dev/vsock") {
                Ok(f) => {
                    dev_openable = true;
                    let mut cid: u32 = 0;
                    // SAFETY: `IOCTL_GET_LOCAL_CID` is `_IO(7, 0xb9)` — no
                    // direction, and the kernel writes one u32 into `cid`.
                    let rc = unsafe {
                        libc::ioctl(
                            std::os::fd::AsRawFd::as_raw_fd(&f),
                            uapi::IOCTL_GET_LOCAL_CID as libc::Ioctl,
                            &mut cid as *mut u32,
                        )
                    };
                    if rc == 0 {
                        ioctl_cid = Some(cid);
                    } else {
                        ioctl_errno = Some(errno());
                    }
                }
                Err(e) => ioctl_errno = e.raw_os_error(),
            }
        }

        // /dev/vhost-vsock. Two things this node will not tell you honestly:
        //
        //   1. It survives `modprobe -r vhost_vsock`, so its existence and mode say
        //      nothing about the transport. `/proc/misc` is the registration, and
        //      `h2g_active()` reads that.
        //   2. Opening it while the module is *not* loaded triggers
        //      `request_module("char-major-10-241")`: the kernel auto-loads
        //      `vhost_vsock`, the node starts answering ioctls, and `/proc/misc`
        //      lists the name again. A probe that opens the node therefore manufactures
        //      the very host it was trying to detect, and lies to whoever reads the
        //      next measurement. So: probe the node only when the registration says it
        //      is already there (or when /proc/misc cannot be read, where the node is
        //      all we have). `VHOST_GET_FEATURES` is `_IOR`, no state change; the
        //      ioctls that *do* change state (`SET_OWNER`, `SET_RUNNING`) are never
        //      touched.
        let vhost_node_present = Path::new("/dev/vhost-vsock").exists();
        let mut vhost_openable = None;
        let mut vhost_features = None;
        let mut vhost_errno = None;
        let vhost_probed = vhost_node_present && vhost_registered != Some(false);
        if vhost_probed {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/vhost-vsock")
            {
                Ok(f) => {
                    vhost_openable = Some(true);
                    let mut feats: u64 = 0;
                    // SAFETY: VHOST_GET_FEATURES is `_IOR(0xAF, 0x00, u64)`; the
                    // kernel writes exactly those 8 bytes.
                    let rc = unsafe {
                        libc::ioctl(
                            std::os::fd::AsRawFd::as_raw_fd(&f),
                            uapi::VHOST_GET_FEATURES as libc::Ioctl,
                            &mut feats as *mut u64,
                        )
                    };
                    if rc == 0 {
                        vhost_features = Some(feats);
                    } else {
                        vhost_errno = Some(errno());
                    }
                }
                Err(e) => {
                    vhost_openable = Some(false);
                    vhost_errno = e.raw_os_error();
                }
            }
        }

        Tells {
            virtio,
            misc_vsock_minor,
            dev_vsock_present: dev_present,
            dev_vsock_openable: dev_openable,
            ioctl_cid,
            ioctl_errno,
            vhost_node_present,
            vhost_registered,
            vhost_openable,
            vhost_features,
            vhost_errno,
        }
    }

    /// Device presence, per spec §6.2: virtio id 19 is the *only* positive tell;
    /// `/dev/vsock` deliberately plays no part in this decision.
    pub fn device_verdict(&self, cfg: &ConfigRead) -> Verdict {
        let Some(devs) = &self.virtio else {
            return Verdict::Unknown;
        };
        if devs.iter().any(|d| d.device == VIRTIO_ID_VSOCK) {
            return Verdict::Present;
        }
        if cfg.symbol("VIRTIO_VSOCKETS").on() {
            Verdict::AbsentButDriver
        } else {
            Verdict::Absent
        }
    }

    /// Whether the host-side (h2g) transport exists *now*.
    ///
    /// The `/proc/misc` registration is the fact; the device node is not:
    /// `modprobe -r vhost_vsock` removes the entry while the node stays
    /// behind. The node is not even a passive thing to read: `open()` on it triggers
    /// `request_module("char-major-10-241")`, so `collect()` leaves it closed unless the
    /// registration is true or unknown. Registration outranks `EACCES`: a node whose
    /// mode defeats us is still a host.
    pub fn h2g_active(&self) -> Option<bool> {
        match self.vhost_registered {
            Some(registered) => Some(registered),
            None if !self.vhost_node_present => Some(false),
            None => self.vhost_openable,
        }
    }

    /// The on-disk node claims a host the kernel does not have.
    pub fn vhost_node_stale(&self) -> bool {
        self.vhost_node_present && self.vhost_registered == Some(false)
    }

    /// The `/dev/vsock` note, spelled out wherever the report shows that tell so
    /// nobody reads it as device presence again.
    pub fn dev_vsock_note(&self) -> String {
        let core = match self.misc_vsock_minor {
            Some(m) => format!("/proc/misc minor {m}"),
            None => "not in /proc/misc".to_string(),
        };
        format!(
            "{} (openable: {}); {core} — this is the vsock *core* (vsock.ko), which is \
             registered even with no virtio transport, so it is not device evidence",
            if self.dev_vsock_present {
                "/dev/vsock exists"
            } else {
                "no /dev/vsock"
            },
            self.dev_vsock_openable
        )
    }
}

/// Kernel release, from `uname(2)` (the CI image has no `/proc/version`-adjacent
/// tooling, and `uname -r` is what a reader can reproduce).
pub fn kernel_release() -> String {
    // SAFETY: `libc::utsname` is a POD buffer; `uname(2)` fills it or fails.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let bytes = std::ffi::CStr::from_ptr(u.release.as_ptr()).to_bytes();
            return String::from_utf8_lossy(bytes).into_owned();
        }
    }
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// CID resolution, in the order of spec §6.3: ioctl, then a bound socket's
/// `getsockname`, then kernel messages/cmdline, never a guess.
pub fn resolve_cid(t: &Tells) -> CidResolution {
    match t.ioctl_cid {
        // `VMADDR_CID_ANY` from the ioctl is an answer, just not a usable one:
        // it means the transport has no CID bound (measured 6.1.186). Record it
        // and keep looking.
        Some(cid) if cid != uapi::VMADDR_CID_ANY => {
            // The well-known values say more than the number: 1 is the local
            // (host-internal) transport, 2 means this kernel is acting as the
            // host muxer, 0 is the hypervisor reserve.
            let named = match cid {
                uapi::VMADDR_CID_HYPERVISOR => " VMADDR_CID_HYPERVISOR",
                uapi::VMADDR_CID_LOCAL => " VMADDR_CID_LOCAL",
                uapi::VMADDR_CID_HOST => " VMADDR_CID_HOST (this kernel is a vsock host)",
                _ => "",
            };
            return CidResolution {
                cid: Some(cid),
                source: format!(
                    "ioctl(/dev/vsock, IOCTL_VM_SOCKETS_GET_LOCAL_CID) answered {cid}{named}"
                ),
            };
        }
        _ => {}
    }
    if let Some((cid, note)) = cid_from_bound_socket() {
        return CidResolution {
            cid: Some(cid),
            source: format!("bound socket getsockname ({note})"),
        };
    }
    if let Some(cid) = cid_from_cmdline_or_dmesg() {
        return CidResolution {
            cid: Some(cid),
            source: "kernel cmdline / dmesg (guest_cid|vsock_cid)".to_string(),
        };
    }
    let why = match t.ioctl_cid {
        Some(uapi::VMADDR_CID_ANY) => "ioctl answered VMADDR_CID_ANY (4294967295): the transport \
                                       has no CID bound; bind and dmesg gave nothing either"
            .to_string(),
        Some(_) => unreachable!(),
        None => format!(
            "no ioctl answer ({}); bind and dmesg gave nothing",
            match t.ioctl_errno {
                Some(e) => uapi::errno_label(e),
                None => "/dev/vsock absent".to_string(),
            }
        ),
    };
    CidResolution::unknown(why)
}

/// Bind `CID_ANY`/`PORT_ANY` and ask the kernel what it chose. On a kernel with
/// the local transport this yields the real CID; `4294967295` means "unbound" and
/// is not reported.
fn cid_from_bound_socket() -> Option<(u32, String)> {
    let fd = vsock_socket(libc::SOCK_STREAM).ok()?;
    let any = uapi::SockaddrVm::new(uapi::VMADDR_CID_ANY, uapi::VMADDR_PORT_ANY, false);
    let bound = bind_addr(fd, &any)
        .ok()
        .and_then(|()| sockname(fd).ok())
        .filter(|a| a.svm_cid != uapi::VMADDR_CID_ANY);
    unsafe { libc::close(fd) };
    bound.map(|a| (a.svm_cid, format!("port {}", a.svm_port)))
}

/// Last resort: a bootloader/cmdline or dmesg mention of the guest CID. This is
/// a weak source (a stale console log), so the report says where it came from.
fn cid_from_cmdline_or_dmesg() -> Option<u32> {
    let mut texts = Vec::new();
    if let Ok(s) = std::fs::read_to_string("/proc/cmdline") {
        texts.push(s);
    }
    // `dmesg` needs CAP_SYSLOG on most distros; try and move on.
    if let Ok(s) = std::fs::read_to_string("/dev/kmsg") {
        texts.push(s);
    }
    for t in texts {
        for word in t.split_whitespace() {
            // `vsock_cid=3`, `guest_cid=3` — the shapes QEMU/cloud-hypervisor use.
            let Some((k, v)) = word.split_once('=') else {
                continue;
            };
            if !(k.ends_with("guest_cid") || k.ends_with("vsock_cid") || k.ends_with("vmaddr_cid"))
            {
                continue;
            }
            if let Ok(cid) = v.parse::<u32>() {
                return Some(cid);
            }
        }
    }
    None
}

/// `/proc/sys/net/vsock/*` — present only on kernels with the namespace-aware
/// vsock sysctls (measured: 7.2.0 has them, 6.8.0 and 6.1.186 do not). Their
/// absence is itself a finding: pre-namespace kernels have no per-net namespace
/// transport and no opt-out of the CID-2 fallback.
pub fn sysctls() -> Vec<(String, SysctlValue)> {
    let known = ["ns_mode", "child_ns_mode", "g2h_fallback"];
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc/sys/net/vsock") {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if let Ok(v) = std::fs::read_to_string(ent.path()) {
                found.insert(name, v.trim().to_string());
            }
        }
    }
    let mut out: Vec<(String, SysctlValue)> = found
        .into_iter()
        .map(|(k, v)| (format!("net.vsock.{k}"), SysctlValue::Present(v)))
        .collect();
    for k in known {
        let key = format!("net.vsock.{k}");
        if !out.iter().any(|(n, _)| *n == key) {
            out.push((key, SysctlValue::Absent));
        }
    }
    out
}

/// The loopback guard: does a connect to CID 2 come back to *us*? On a kernel
/// with `CONFIG_VSOCKETS_LOOPBACK` it does, so "open" against
/// CID 2 would be a lie; in a device-less guest the guard cannot fire at all, which
/// is `Inert`, not `No`.
pub fn canary(cfg: &ConfigRead) -> (TellState, String) {
    if cfg.symbol("VSOCKETS_LOOPBACK") == crate::kernconfig::Sym::Disabled {
        return (
            TellState::Inert,
            "CONFIG_VSOCKETS_LOOPBACK is not set: a connect to CID 2 cannot be redirected \
             locally, so this guard has nothing to detect here"
                .to_string(),
        );
    }
    // The listener. The guard's question is whether a connect to CID 2 lands on
    // *this* host, which is only observable from the accepting side.
    let listener = match vsock_socket(libc::SOCK_STREAM) {
        Ok(fd) => fd,
        Err(e) => return (TellState::Unknown, e),
    };
    let any = uapi::SockaddrVm::new(uapi::VMADDR_CID_ANY, uapi::VMADDR_PORT_ANY, false);
    if bind_addr(listener, &any).is_err() || unsafe { libc::listen(listener, 4) } != 0 {
        let e = errno();
        unsafe { libc::close(listener) };
        return (
            TellState::Unknown,
            format!("bind/listen failed: {}", uapi::errno_label(e)),
        );
    }
    let port = match sockname(listener) {
        Ok(a) => a.svm_port,
        Err(()) => {
            unsafe { libc::close(listener) };
            return (TellState::Unknown, "getsockname failed".to_string());
        }
    };

    // A *separate* socket does the connect: connecting from the listening socket
    // is EINVAL, which is exactly what an earlier version of this probe measured
    // on the host (2026-10-05) and would have reported as "no redirect".
    let connector = match vsock_socket(libc::SOCK_STREAM) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { libc::close(listener) };
            return (TellState::Unknown, e);
        }
    };
    let to = uapi::SockaddrVm::new(uapi::VMADDR_CID_HOST, port, false);
    let (state, why) = match nonblocking_connect(connector, &to, 200) {
        Connect::Established => match try_accept(listener) {
            Some((pcid, pport)) => (
                TellState::Yes,
                format!(
                    "connect(CID 2, {port}) established and our own listener accepted it (peer \
                     cid {pcid} port {pport}): CID 2 traffic here is loopback"
                ),
            ),
            None => (
                TellState::Yes,
                format!(
                    "connect(CID 2, {port}) established; nothing was queued to accept within \
                     50 ms, so the redirect is confirmed by connect only"
                ),
            ),
        },
        Connect::Timeout => (
            TellState::No,
            format!("connect(CID 2, {port}) got no answer in 200 ms"),
        ),
        // EINVAL/EBADF means our own call was invalid, not that the peer refused.
        Connect::Failed { errno, stage }
            if matches!(errno, libc::EINVAL | libc::EBADF | libc::ENOPROTOOPT) =>
        {
            (
                TellState::Unknown,
                format!(
                    "connect(CID 2, {port}) failed with {} at {stage}: an invalid request, not a \
                     reachability answer",
                    uapi::errno_label(errno)
                ),
            )
        }
        Connect::Failed { errno, stage } => (
            TellState::No,
            format!(
                "connect(CID 2, {port}) did not establish: {} at {stage}",
                uapi::errno_label(errno)
            ),
        ),
    };
    unsafe {
        libc::close(connector);
        libc::close(listener);
    }
    (state, why)
}

/// What a non-blocking connect told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connect {
    Established,
    Timeout,
    Failed { errno: i32, stage: &'static str },
}

fn vsock_socket(kind: libc::c_int) -> Result<libc::c_int, String> {
    // SAFETY: socket(2) with a constant family/type takes no pointers.
    let fd = unsafe { libc::socket(uapi::AF_VSOCK as libc::c_int, kind | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_VSOCK) failed: {}",
            uapi::errno_label(errno())
        ));
    }
    Ok(fd)
}

fn bind_addr(fd: libc::c_int, addr: &uapi::SockaddrVm) -> Result<(), i32> {
    // SAFETY: `addr` is a live `sockaddr_vm` and `len()` is its exact size.
    let rc = unsafe {
        libc::bind(
            fd,
            addr as *const _ as *const libc::sockaddr,
            uapi::SockaddrVm::len(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn sockname(fd: libc::c_int) -> Result<uapi::SockaddrVm, ()> {
    let mut a = uapi::SockaddrVm::default();
    let mut len = uapi::SockaddrVm::len();
    // SAFETY: the kernel writes at most `len` (the struct's own size) bytes.
    let rc = unsafe { libc::getsockname(fd, &mut a as *mut _ as *mut libc::sockaddr, &mut len) };
    if rc == 0 {
        Ok(a)
    } else {
        Err(())
    }
}

/// The sequence every connect in this tool uses: non-blocking `connect`, `poll`
/// for writability, then `SO_ERROR` to learn what actually happened.
pub fn nonblocking_connect(fd: libc::c_int, addr: &uapi::SockaddrVm, timeout_ms: i32) -> Connect {
    // SAFETY: fcntl(F_SETFL) only touches the descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    let rc = unsafe {
        libc::connect(
            fd,
            addr as *const _ as *const libc::sockaddr,
            uapi::SockaddrVm::len(),
        )
    };
    if rc == 0 {
        return Connect::Established;
    }
    let immediate = errno();
    if immediate != libc::EINPROGRESS {
        return Connect::Failed {
            errno: immediate,
            stage: "connect",
        };
    }
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: poll on one descriptor we own.
    let pr = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    if pr == 0 {
        return Connect::Timeout;
    }
    if pr < 0 {
        return Connect::Failed {
            errno: errno(),
            stage: "poll",
        };
    }
    let soerr = sock_error(fd);
    if soerr == 0 {
        Connect::Established
    } else {
        Connect::Failed {
            errno: soerr,
            stage: "SO_ERROR",
        }
    }
}

/// The port a bound socket actually holds. `getsockname` is the only way to learn
/// what `bind(CID_ANY, PORT_ANY)` was handed, and the selftest fixture needs it.
pub fn sockname_port(fd: libc::c_int) -> Option<u32> {
    sockname(fd).ok().map(|a| a.svm_port)
}

/// Accept with a short deadline and report the peer's `(cid, port)`.
fn try_accept(listener: libc::c_int) -> Option<(u32, u32)> {
    let mut p = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut p, 1, 50) } != 1 {
        return None;
    }
    let mut peer = uapi::SockaddrVm::default();
    let mut len = uapi::SockaddrVm::len();
    let fd = unsafe {
        libc::accept(
            listener,
            &mut peer as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if fd < 0 {
        return None;
    }
    unsafe { libc::close(fd) };
    Some((peer.svm_cid, peer.svm_port))
}

fn sock_error(fd: libc::c_int) -> i32 {
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        err
    } else {
        errno()
    }
}

/// g2h/h2g posture, given the device verdict and the host-side evidence.
///
/// `g2h` requires an actual virtio-vsock device: a kernel that merely *has* the
/// driver (the target shape) has nothing to send through, which is the whole
/// reason the competition shape is called out-of-scope for vsock.
pub fn posture(device: Verdict, h2g: bool) -> Posture {
    use crate::model::Posture::*;
    match device {
        Verdict::Unknown => Unknown,
        Verdict::Present if h2g => Both,
        Verdict::Present => Guest,
        Verdict::AbsentButDriver | Verdict::Absent if h2g => Host,
        Verdict::AbsentButDriver | Verdict::Absent => Neither,
    }
}

/// A tell with its id, exactly as the renderers print it.
fn push(report: &mut Report, id: &str, state: TellState, detail: String) {
    report.tells.push(Tell {
        id: id.to_string(),
        state,
        detail,
    });
}

/// Build the whole `probe` report.
pub fn collect(opts: &ProbeOpts) -> Report {
    let release = kernel_release();
    let caps = Caps::from_proc_self_status();
    let cfg = if opts.config {
        ConfigRead::load(&release)
    } else {
        ConfigRead::unavailable(Some("--config not given".to_string()))
    };
    let tells = Tells::collect();
    let device = tells.device_verdict(&cfg);
    let (canary_state, canary_why) = canary(&cfg);

    let mut report = Report::new(
        "probe",
        Header {
            kernel: release.clone(),
            uid:
                // SAFETY: getuid(2) takes no arguments and cannot fail.
                unsafe { libc::getuid() },
            caps: caps.names(),
            cid: resolve_cid(&tells),
            sysctls: sysctls(),
            posture: posture(device, tells.h2g_active().unwrap_or(false)),
            device,
            config_source: opts.config.then(|| cfg.describe()),
            module_verdicts: Vec::new(),
            diag: DiagStatus::Skipped,
            noise: "classification probes only: a few connects to CIDs 1/2, no sweep".to_string(),
        },
    );

    // ---- tells -------------------------------------------------------------
    match &tells.virtio {
        None => push(
            &mut report,
            "virtio-sysfs",
            TellState::Unknown,
            "cannot read /sys/bus/virtio/devices".to_string(),
        ),
        Some(devs) => {
            let seen: Vec<String> = devs
                .iter()
                .map(|d| {
                    // Vendor says which bus put it there: 0x0000 is virtio-mmio,
                    // 0x1af4 is Red Hat/QEMU PCI.
                    let who = match d.vendor {
                        VIRTIO_VENDOR_REDHAT => "redhat/qemu",
                        0 => "virtio-mmio",
                        _ => "other",
                    };
                    format!(
                        "{}={} vendor={:#06x}({who}){}",
                        d.name,
                        d.device,
                        d.vendor,
                        if d.modalias.is_empty() {
                            String::new()
                        } else {
                            format!(" modalias={}", d.modalias)
                        }
                    )
                })
                .collect();
            let hit = devs.iter().any(|d| d.device == VIRTIO_ID_VSOCK);
            push(
                &mut report,
                "virtio-id-0x0013",
                if hit { TellState::Yes } else { TellState::No },
                format!(
                    "{} virtio device(s): {}",
                    devs.len(),
                    if seen.is_empty() {
                        "none".to_string()
                    } else {
                        seen.join(", ")
                    }
                ),
            );
        }
    }
    push(
        &mut report,
        "dev-vsock",
        if tells.dev_vsock_present {
            TellState::Yes
        } else {
            TellState::No
        },
        tells.dev_vsock_note(),
    );
    push(
        &mut report,
        "ioctl-get-local-cid",
        match tells.ioctl_cid {
            Some(_) => TellState::Yes,
            None => TellState::No,
        },
        match tells.ioctl_cid {
            Some(cid) => format!("_IO(7, 0xb9) answered {cid}"),
            None => format!(
                "no answer: {}",
                match tells.ioctl_errno {
                    Some(e) => uapi::errno_label(e),
                    None => "/dev/vsock absent".to_string(),
                }
            ),
        },
    );

    // ---- classification probes --------------------------------------------
    let mut flags = vec![(false, FlagSet::None)];
    if opts.to_host {
        flags.push((true, FlagSet::ToHost));
    }
    for (to_host, flagset) in &flags {
        for (name, cid, kind) in [
            ("connect-cid1", uapi::VMADDR_CID_LOCAL, libc::SOCK_STREAM),
            ("connect-cid2", uapi::VMADDR_CID_HOST, libc::SOCK_STREAM),
            (
                "connect-cid2-seqpacket",
                uapi::VMADDR_CID_HOST,
                libc::SOCK_SEQPACKET,
            ),
        ] {
            if !opts.seqpacket && kind == libc::SOCK_SEQPACKET {
                continue;
            }
            let (outcome, value) = connect_probe(cid, 1234, *to_host, kind);
            report.probes.push(ProbeRow {
                name: name.to_string(),
                outcome,
                value,
                flags: *flagset,
            });
        }
        let (outcome, value) = socket_probe(libc::SOCK_DGRAM);
        report.probes.push(ProbeRow {
            name: "socket-dgram".to_string(),
            outcome,
            value,
            flags: *flagset,
        });
    }

    if opts.to_host {
        // Measured answer on the target shape and on the host: the flag changes
        // nothing observable. Say so instead of leaving two identical blocks for
        // the reader to diff.
        // Pair them by name, not by position in a flat list: the two sets are
        // emitted in the same order, but `vhost-node` is emitted once.
        let plain: Vec<_> = report
            .probes
            .iter()
            .filter(|p| p.flags == FlagSet::None && p.name != "vhost-node")
            .collect();
        let flagged: Vec<_> = report
            .probes
            .iter()
            .filter(|p| p.flags == FlagSet::ToHost)
            .collect();
        let agree = plain.len() == flagged.len()
            && plain.iter().zip(flagged).all(|(a, b)| {
                a.name == b.name
                    && a.outcome.kind == b.outcome.kind
                    && a.outcome.errno == b.outcome.errno
            });
        if agree {
            report.summary.notes.push(
                "VMADDR_FLAG_TO_HOST had no observable effect here: every probe answers the same with and without it"
                    .to_string(),
            );
        } else {
            report.finding(
                Severity::Warn,
                "VMADDR_FLAG_TO_HOST changed at least one probe answer; compare the paired rows before drawing any conclusion",
            );
        }
    }

    // ---- host-side node ----------------------------------------------------
    report.probes.push(ProbeRow {
        name: "vhost-node".to_string(),
        outcome: if tells.vhost_node_stale() {
            // Registration-only row, with no errno we did not measure: the node was
            // deliberately left closed, because opening it would load the module and
            // change what this report is describing.
            let o = Outcome::new(OutcomeKind::RefusedKernel).with_detail(
                "no `vhost-vsock` misc device is registered: `vhost_vsock` is not loaded and the \
                 node on disk is stale (left closed: opening it would auto-load the module)",
            );
            match tells.vhost_errno {
                Some(e) => o.with_errno(e),
                None => o,
            }
        } else {
            match (
                tells.vhost_node_present,
                tells.vhost_registered,
                tells.vhost_openable,
            ) {
                (true, Some(true), _) => Outcome::new(OutcomeKind::Open)
                    .with_detail("h2g transport registered in /proc/misc"),
                (true, None, Some(true)) => Outcome::new(OutcomeKind::Open)
                    .with_detail("device node openable (/proc/misc unreadable)"),
                (true, _, Some(false)) => errno_out(
                    tells.vhost_errno.unwrap_or(libc::EACCES),
                    "node exists, open failed",
                ),
                _ => {
                    Outcome::new(OutcomeKind::RefusedKernel).with_detail("/dev/vhost-vsock absent")
                }
            }
        },
        value: tells.vhost_features.map(|f| format!("{f:#018x}")),
        flags: FlagSet::None,
    });

    push(
        &mut report,
        "loopback-canary",
        canary_state,
        canary_why.clone(),
    );

    // ---- config / modules --------------------------------------------------
    if opts.vsockmon && !opts.config {
        // The vsockmon verdict *is* a config question (it depends on VHOST_VSOCK),
        // and silence would leave the reader to guess whether the module is absent
        // or was simply never looked at. Those are different answers.
        report.finding(
            Severity::Warn,
            "`--vsockmon` needs `--config`: module availability is read from the kernel              config, and none was read, so nothing is known about vsockmon here",
        );
    }
    if opts.config {
        let state: ModuleState = kernconfig::module_state(&cfg, &release, WATCHED);
        let mut verdicts: Vec<ModuleVerdict> = vec![kernconfig::vhost_verdict(
            &cfg,
            &state,
            &caps,
            Some(tells.vhost_registered.unwrap_or(tells.vhost_node_present)),
        )];
        if opts.vsockmon {
            verdicts.push(kernconfig::vsockmon_verdict(&cfg, &state, &caps));
        }
        for sym in CONFIG_SYMBOLS {
            let v = cfg.symbol(sym);
            push(
                &mut report,
                &format!("config:{sym}"),
                match v {
                    Sym::Yes | Sym::Module => TellState::Yes,
                    Sym::Disabled => TellState::No,
                    Sym::Unknown => TellState::Unknown,
                },
                format!("CONFIG_{sym} = {} ({})", v.as_str(), cfg.describe()),
            );
        }
        report.finding(Severity::Info, format!("module state: {}", state.reason));
        report.header.module_verdicts = verdicts;
        if opts.mmio {
            report.findings.push(Finding {
                severity: Severity::Info,
                message: "--mmio: reading the virtio-mmio window needs CAP_SYS_ADMIN plus \
                          iomem=relaxed; this build reports no conclusion from it"
                    .to_string(),
            });
        }
    }

    // ---- findings that follow from the measurements ------------------------
    if matches!(device, Verdict::AbsentButDriver) {
        report.finding(
            Severity::Alert,
            "virtio-vsock driver is available but no device id 0x0013 is bound: this guest \
             has no vsock device configured, so guest->host vsock is impossible here, not \
             merely blocked by a firewall",
        );
    }
    if canary_state == TellState::Yes {
        report.finding(
            Severity::Warn,
            "loopback canary fired: a connect to CID 2 reached this host's own listener, so \
             'open' against CID 2 must be read as local loopback, never as a host service",
        );
    }
    // Capability notes that change what a *later* command can do here.
    if !caps.net_bind_service() {
        report.finding(
            Severity::Info,
            "no CAP_NET_BIND_SERVICE: `listen --census` on ports below 1024 answers EACCES here (measured: the check is on the supplied port, not the assigned one)",
        );
    }
    if opts.mmio && !caps.sys_admin() {
        report.finding(
            Severity::Warn,
            "--mmio was requested without CAP_SYS_ADMIN: /dev/mem will refuse the read regardless of iomem=relaxed",
        );
    }
    if matches!(device, Verdict::Present) && tells.h2g_active() == Some(true) {
        report.finding(
            Severity::Warn,
            "both a virtio-vsock device and /dev/vhost-vsock are present: this kernel is both \
             a guest transport and a host muxer (namespace-per-netns kernels allow that)",
        );
    }
    if tells.vhost_node_stale() {
        report.finding(
            Severity::Warn,
            "/dev/vhost-vsock exists while nothing is registered under that name in /proc/misc: \
             there is no h2g transport and the node is stale. It was deliberately not opened — \
             `open()` there triggers `request_module(\"char-major-10-241\")`, which would load \
             `vhost_vsock` and create the host this report is trying to describe. Posture is \
             computed from the registration.",
        );
    }
    report.header.diag = if opts.diag {
        match diag::census_with_pids(diag::ALL_STATES) {
            Ok(rows) => {
                report.diag_entries = rows.clone();
                DiagStatus::Available {
                    entries: rows.len(),
                }
            }
            Err(e) => DiagStatus::Unavailable(e.to_string()),
        }
    } else {
        DiagStatus::Skipped
    };
    report.summary.notes.push(format!(
        "posture {} / device {}",
        report.header.posture.as_str(),
        report.header.device.as_str()
    ));
    report
}

/// One non-blocking connect, classified the same way `scan` will classify rows.
fn connect_probe(
    cid: u32,
    port: u32,
    to_host: bool,
    kind: libc::c_int,
) -> (Outcome, Option<String>) {
    let fd = match vsock_socket(kind) {
        Ok(fd) => fd,
        Err(e) => return (Outcome::new(OutcomeKind::Unsupported).with_detail(e), None),
    };
    let addr = uapi::SockaddrVm::new(cid, port, to_host);
    let out = match nonblocking_connect(fd, &addr, 200) {
        Connect::Established => Outcome::new(OutcomeKind::Open).with_detail("connect established"),
        Connect::Timeout => Outcome::new(OutcomeKind::Silent).with_detail("200 ms poll timeout"),
        Connect::Failed { errno, stage } => errno_out(errno, stage),
    };
    unsafe { libc::close(fd) };
    (out, None)
}

/// Does this socket type exist at all? (DGRAM is `ENODEV` in the target shape.)
fn socket_probe(kind: libc::c_int) -> (Outcome, Option<String>) {
    let fd = unsafe { libc::socket(uapi::AF_VSOCK as libc::c_int, kind | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return (errno_out(errno(), "socket() failed"), None);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes the struct through the fd we just created.
    let ino = if unsafe { libc::fstat(fd, &mut st) } == 0 {
        st.st_ino as u64
    } else {
        0
    };
    unsafe { libc::close(fd) };
    (
        Outcome::new(OutcomeKind::Open).with_detail("socket created"),
        Some(format!("ino {ino}")),
    )
}

/// `--vsockmon-up NAME`: the only place this tool ever creates an interface, and
/// only on explicit request (spec §2). It creates the monitor and prints how to
/// capture; it never reads or relays vsock traffic itself.
pub fn vsockmon_up(name: &str, report: &mut Report) {
    if !Caps::from_proc_self_status().net_admin() {
        report.finding(
            Severity::Warn,
            format!(
                "--vsockmon-up {name} refused before running `ip`: CAP_NET_ADMIN is required to create a netlink interface"
            ),
        );
        report.tells.push(Tell {
            id: "vsockmon-up".to_string(),
            state: TellState::No,
            detail: "not attempted: no CAP_NET_ADMIN".to_string(),
        });
        return;
    }
    let run = |args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("ip").args(args).output();
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(format!("cannot run `ip`: {e}")),
        }
    };
    let outcome = run(&["link", "add", name, "type", "vsockmon"])
        .and_then(|_| run(&["link", "set", name, "up"]));
    let (state, detail) = match &outcome {
        Ok(()) => (TellState::Yes, vsockmon_up_detail(name, None)),
        Err(e) => (TellState::No, vsockmon_up_detail(name, Some(e))),
    };
    match &outcome {
        Ok(()) => report.finding(Severity::Warn, vsockmon_created(name)),
        Err(e) => report.finding(Severity::Warn, vsockmon_refused(name, e)),
    }
    report.tells.push(Tell {
        id: "vsockmon-up".to_string(),
        state,
        detail,
    });
}

/// The capture recipe, printed only when the interface actually exists.
/// Hypervisors with userspace vsock implementations do not pass traffic through
/// kernel vhost-vsock, so vsockmon sees kernel vhost-vsock traffic only.
fn vsockmon_created(name: &str) -> String {
    format!(
        "created vsockmon interface {name} (already up); capture with `tcpdump -i {name} -w \
         vsock.pcap`. Note: userspace vsock traffic does not appear here; \
         this captures kernel vhost-vsock traffic only. Remove it with `ip link \
         del {name}`."
    )
}

fn vsockmon_refused(name: &str, e: &str) -> String {
    format!(
        "could not create vsockmon {name}: {e} (needs CAP_NET_ADMIN and a kernel with \
         CONFIG_VSOCKMON)"
    )
}

/// What the tell says after the attempt: the recipe on success, the refusal on
/// failure. Printing the command as the detail either way reads as a plan the
/// reader cannot tell from a result.
fn vsockmon_up_detail(name: &str, error: Option<&str>) -> String {
    match error {
        Some(e) => format!("not created: {e}"),
        None => format!("created and up; tcpdump -i {name} -w vsock.pcap"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernconfig::ConfigRead;

    #[test]
    fn vsockmon_up_reports_the_outcome_not_the_intention() {
        assert_eq!(
            vsockmon_up_detail("vsockmon0", None),
            "created and up; tcpdump -i vsockmon0 -w vsock.pcap"
        );
        let bad = vsockmon_up_detail("vsockmon0", Some("Error: Unknown device type."));
        assert!(bad.starts_with("not created: "), "{bad}");
        assert!(!bad.contains("tcpdump"), "{bad}");
        assert!(vsockmon_refused("vm0", "boom").contains("CONFIG_VSOCKMON"));
        assert!(vsockmon_created("vm0").contains("userspace"));
    }

    fn cfg(text: &str) -> ConfigRead {
        ConfigRead::from_text("t", text)
    }

    fn tells_with(devs: Option<Vec<(u32, u32)>>) -> Tells {
        Tells {
            virtio: devs.map(|d| {
                d.into_iter()
                    .map(|(device, vendor)| VirtioDev {
                        name: format!("virtio{}", device),
                        device,
                        vendor,
                        modalias: String::new(),
                    })
                    .collect()
            }),
            misc_vsock_minor: Some(123),
            dev_vsock_present: true,
            dev_vsock_openable: true,
            ioctl_cid: None,
            ioctl_errno: None,
            vhost_node_present: false,
            vhost_registered: None,
            vhost_openable: None,
            vhost_features: None,
            vhost_errno: None,
        }
    }

    const TARGET: &str =
        "CONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS_COMMON=y\n";

    #[test]
    fn id_19_is_the_only_positive_tell() {
        let c = cfg(TARGET);
        // The target shape: /dev/vsock present and openable, no id 19 anywhere.
        assert_eq!(
            tells_with(Some(vec![(1, 0), (2, 0)])).device_verdict(&c),
            Verdict::AbsentButDriver
        );
        assert_eq!(
            tells_with(Some(vec![(0x13, 0)])).device_verdict(&cfg("CONFIG_VIRTIO_VSOCKETS=n\n")),
            Verdict::Present,
            "a bound device outranks the config file"
        );
        assert_eq!(
            tells_with(Some(vec![(1, 0x1af4), (4, 0x1af4)])).device_verdict(&cfg("")),
            Verdict::Absent
        );
        assert_eq!(
            tells_with(None).device_verdict(&cfg(TARGET)),
            Verdict::Unknown,
            "unreadable sysfs is not 'absent'"
        );
    }

    #[test]
    fn dev_vsock_note_says_it_proves_nothing() {
        let t = tells_with(Some(vec![]));
        let note = t.dev_vsock_note();
        assert!(note.contains("not device evidence"), "{note}");
        assert!(note.contains("minor 123"), "{note}");
    }

    /// `modprobe -r vhost_vsock` removes the `/proc/misc` entry but
    /// leaves `/dev/vhost-vsock` on disk. Reading the node as "we are a host" is the false
    /// positive this guards — and it cannot even be sampled as a probe, because opening it
    /// auto-loads the module back (see `collect()`).
    #[test]
    fn a_stale_vhost_node_does_not_make_us_a_host() {
        use crate::model::Posture::*;
        let mut t = tells_with(Some(vec![]));
        t.vhost_node_present = true;
        t.vhost_openable = Some(true);
        t.vhost_features = Some(0x3_3d00_0002);
        t.vhost_registered = Some(false);
        assert_eq!(t.h2g_active(), Some(false));
        assert!(t.vhost_node_stale());
        assert_eq!(
            posture(Verdict::Absent, t.h2g_active().unwrap_or(false)),
            Neither
        );
    }

    /// A node we cannot open because of its mode is still a registered host:
    /// `EACCES` must not demote the posture.
    #[test]
    fn registration_outranks_an_unopenable_node() {
        let mut t = tells_with(Some(vec![]));
        t.vhost_node_present = true;
        t.vhost_openable = Some(false);
        t.vhost_errno = Some(libc::EACCES);
        t.vhost_registered = Some(true);
        assert_eq!(t.h2g_active(), Some(true));
        assert!(!t.vhost_node_stale());
    }

    #[test]
    fn unknown_registration_falls_back_to_the_node() {
        let mut t = tells_with(Some(vec![]));
        t.vhost_registered = None;
        t.vhost_node_present = true;
        t.vhost_openable = Some(true);
        assert_eq!(t.h2g_active(), Some(true));
        t.vhost_node_present = false;
        t.vhost_openable = None;
        assert_eq!(t.h2g_active(), Some(false));
    }

    #[test]
    fn posture_truth_table() {
        use crate::model::Posture::*;
        assert_eq!(posture(Verdict::Present, true), Both);
        assert_eq!(posture(Verdict::Present, false), Guest);
        assert_eq!(posture(Verdict::AbsentButDriver, true), Host);
        assert_eq!(posture(Verdict::Absent, true), Host);
        assert_eq!(posture(Verdict::AbsentButDriver, false), Neither);
        assert_eq!(posture(Verdict::Absent, false), Neither);
        assert_eq!(posture(Verdict::Unknown, true), Unknown);
        assert_eq!(posture(Verdict::Unknown, false), Unknown);
    }

    #[test]
    fn cid_chain_prefers_ioctl_then_bind_then_cmdline() {
        let mut t = tells_with(Some(vec![]));
        t.ioctl_cid = Some(3);
        let r = resolve_cid(&t);
        assert_eq!(r.cid, Some(3));
        assert!(r.source.contains("ioctl"), "{}", r.source);

        // VMADDR_CID_ANY is an answer we must not report as our CID.
        t.ioctl_cid = Some(uapi::VMADDR_CID_ANY);
        let r = resolve_cid(&t);
        // In a container/CI runner the bind probe may legitimately succeed; then
        // the source says so. Otherwise the reason names the ioctl answer.
        if r.cid.is_none() {
            assert!(r.source.contains("VMADDR_CID_ANY"), "{}", r.source);
        }

        t.ioctl_cid = None;
        t.ioctl_errno = Some(libc::ENOENT);
        let r = resolve_cid(&t);
        assert!(r.cid.is_none() || r.cid == Some(1), "{r:?}");
    }

    #[test]
    fn canary_is_inert_when_loopback_is_not_built() {
        let c = cfg("# CONFIG_VSOCKETS_LOOPBACK is not set\n");
        let (state, why) = canary(&c);
        assert_eq!(state, TellState::Inert);
        assert!(why.contains("cannot be redirected"), "{why}");
    }

    #[test]
    fn sysctls_report_absence_not_null() {
        let s = sysctls();
        // On Linux /proc/sys/net/vsock either exists (7.2.0) or does not
        // (6.1/6.8); either way the three known keys must be accounted for.
        for k in [
            "net.vsock.ns_mode",
            "net.vsock.child_ns_mode",
            "net.vsock.g2h_fallback",
        ] {
            assert!(s.iter().any(|(n, _)| n == k), "missing {k} in {s:?}");
        }
        assert!(
            s.iter().all(|(_, v)| !v.as_str().is_empty()),
            "an empty value would be indistinguishable from absent: {s:?}"
        );
    }

    #[test]
    fn kernel_release_is_not_empty() {
        let r = kernel_release();
        assert!(!r.is_empty() && r != "unknown", "{r}");
        assert!(r.contains('.'), "{r}");
    }

    #[test]
    fn socket_probe_records_inode_or_errno() {
        let (o, v) = socket_probe(libc::SOCK_STREAM);
        assert_eq!(
            o.kind,
            OutcomeKind::Open,
            "AF_VSOCK STREAM always exists here: {o:?}"
        );
        assert!(v.unwrap().starts_with("ino "), "must show the socket inode");
    }
}
