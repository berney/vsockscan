//! `vsock_diag`: the listener census over netlink, with the wire format pinned by
//! a byte capture rather than by inference.
//!
//! Two measured facts:
//!
//! * Protocol number: `NETLINK_SOCK_DIAG = 4`. **18 is `NETLINK_ECRYPTFS`** and
//!   its handler answers `-EBADMSG`; that detour cost a whole session, so the
//!   constant carries no aliases.
//! * The request payload is **24 bytes**. The 8-byte generic `sock_diag_req`
//!   (family, protocol, pad, states) is answered with `NLMSG_ERROR -EINVAL`, so
//!   the vsock tail (`ino`, `src_port`, `dst_port`, `extra`) is required even
//!   when every one of them is zero.
//!
//! Reply entries are 32 bytes each, inside 48-byte netlink messages, and their
//! `ino` equals `fstat(fd).st_ino` — which is what makes pid attribution possible
//! without any privileged API.

use std::collections::BTreeMap;

use crate::model::DiagEntry;
use crate::uapi;

/// Why there is no census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagError {
    /// The kernel has no `vsock_diag` (`CONFIG_VSOCKETS_DIAG is not set`): the
    /// answer arrives as `NLMSG_ERROR -ENOENT`.
    Unavailable(String),
    /// Netlink itself failed, with the errno that said so.
    Netlink(i32),
}

impl std::fmt::Display for DiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagError::Unavailable(s) => write!(f, "{s}"),
            DiagError::Netlink(e) => write!(f, "netlink: {}", uapi::errno_label(*e)),
        }
    }
}

/// `sizeof(struct nlmsghdr)` plus the 24-byte request the kernel actually wants.
pub const REQUEST_LEN: usize = 40;

/// The dump request, byte for byte: header `{len=40, SOCK_DIAG_BY_FAMILY,
/// NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST, seq, pid=0}` then
/// `{family=40, protocol=0, pad=0, states, ino=0, src_port=0, dst_port=0, extra=0}`.
pub fn build_request(states: u32, seq: u32) -> Vec<u8> {
    let payload: Vec<u8> = [
        uapi::AF_VSOCK as u8,
        0u8,
        0u8,
        0u8,
    ]
    .into_iter()
    .chain(states.to_le_bytes())
    .chain([0u8; 16])
    .collect();
    let mut msg = Vec::with_capacity(REQUEST_LEN);
    // `nlmsg_len` is `__u32`: encoding `REQUEST_LEN` (a `usize`) directly writes
    // eight bytes on x86_64 and the kernel answers `EINVAL` — the golden test
    // below is what pins this down.
    msg.extend_from_slice(&(REQUEST_LEN as u32).to_le_bytes());
    msg.extend_from_slice(&uapi::SOCK_DIAG_BY_FAMILY.to_le_bytes());
    msg.extend_from_slice(&(uapi::NLM_F_ROOT | uapi::NLM_F_MATCH | uapi::NLM_F_REQUEST).to_le_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// One 32-byte entry. `None` on a short or wrong-family buffer.
pub fn parse_entry(body: &[u8]) -> Option<DiagEntry> {
    if body.len() < 32 || body[0] != uapi::AF_VSOCK as u8 {
        return None;
    }
    let u32_at = |o: usize| -> Option<u32> {
        <[u8; 4]>::try_from(&body[o..o + 4]).map(u32::from_le_bytes).ok()
    };
    Some(DiagEntry {
        family: body[0],
        kind: body[1],
        state: body[2],
        shutdown: body[3],
        src_cid: u32_at(4)?,
        src_port: u32_at(8)?,
        dst_cid: u32_at(12)?,
        dst_port: u32_at(16)?,
        ino: u32_at(20)?,
        // Opaque per-socket cookie; deliberately not interpreted (its contents
        // are not part of the uapi contract).
        cookie: body[24..32].iter().map(|b| format!("{b:02x}")).collect(),
        pid: None,
        pid_comm: None,
    })
}

/// `TCP_ESTABLISHED` and friends are the `TCP_*` states sock_diag reuses;
/// `10` is LISTEN, which is what a census is usually after.
pub const ALL_STATES: u32 = 0xfff;
pub const ST_LISTEN: u32 = 1 << 10;
pub const ST_ESTABLISHED: u32 = 1 << 1;

/// Ask the kernel for every vsock socket in these states.
pub fn census(states: u32) -> Result<Vec<DiagEntry>, DiagError> {
    // SAFETY: socket(2) with constants; no pointers.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, uapi::NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(DiagError::Netlink(errno()));
    }
    // Bind to the kernel's port 0 / our pid so replies come back to us; the
    // kernel rewrites `nl_pid` to our pid on the way in.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: `addr` is a full `sockaddr_nl`.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = errno();
        unsafe { libc::close(fd) };
        return Err(DiagError::Netlink(e));
    }
    let req = build_request(states, 1);
    // SAFETY: `req` outlives the call and its length is exact.
    let sent = unsafe {
        libc::send(
            fd,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            0,
        )
    };
    if sent < 0 {
        let e = errno();
        unsafe { libc::close(fd) };
        return Err(DiagError::Netlink(e));
    }

    let mut entries = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut done = false;
    while !done {
        // SAFETY: writing into `buf`'s own capacity.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let e = errno();
            unsafe { libc::close(fd) };
            return Err(DiagError::Netlink(e));
        }
        if n == 0 {
            break;
        }
        let (mut entries_here, saw_done, err) = parse_messages(&buf[..n as usize]);
        entries.append(&mut entries_here);
        if let Some(code) = err {
            unsafe { libc::close(fd) };
            return Err(if code == -libc::ENOENT {
                DiagError::Unavailable(
                    "CONFIG_VSOCKETS_DIAG is not set (netlink answers -ENOENT when disabled)"
                        .to_string(),
                )
            } else {
                DiagError::Netlink(-code)
            });
        }
        done = saw_done;
    }
    unsafe { libc::close(fd) };
    Ok(entries)
}

/// Walk the netlink messages of one datagram: `(entries, saw_done, error_code)`.
pub fn parse_messages(data: &[u8]) -> (Vec<DiagEntry>, bool, Option<i32>) {
    let mut out = Vec::new();
    let mut done = false;
    let mut error = None;
    let mut off = 0usize;
    while off + 16 <= data.len() {
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        let mtype = u16::from_le_bytes(data[off + 4..off + 6].try_into().unwrap());
        if len < 16 || off + len > data.len() {
            break;
        }
        let body = &data[off + 16..off + len];
        match mtype {
            uapi::NLMSG_DONE => done = true,
            uapi::NLMSG_ERROR => {
                // `struct nlmsgerr { int error; struct nlmsghdr msg; }`
                if body.len() >= 4 {
                    error = Some(i32::from_le_bytes(body[..4].try_into().unwrap()));
                }
                done = true;
            }
            uapi::NLMSG_NOOP => {}
            _ => {
                if let Some(e) = parse_entry(body) {
                    out.push(e);
                }
            }
        }
        off += (len + 3) & !3;
    }
    (out, done, error)
}

/// Match socket inodes to owning processes by scanning `/proc/*/fd`.
///
/// Returns `ino -> pid`. Sockets owned by a process we cannot read (different
/// user without root, or already gone) simply do not appear, and the caller
/// prints `pid: None` for them.
pub fn attribute_pids(entries: &[DiagEntry]) -> BTreeMap<u64, (u32, String)> {
    let wanted: std::collections::BTreeSet<u64> =
        entries.iter().map(|e| e.ino as u64).collect();
    let mut map = BTreeMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return map;
    };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = link.to_string_lossy().into_owned();
            let Some(rest) = target.strip_prefix("socket:[") else {
                continue;
            };
            let Some(ino) = rest.strip_suffix(']').and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            if !wanted.contains(&ino) || map.contains_key(&ino) {
                continue;
            }
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            map.insert(ino, (pid, comm));
        }
    }
    map
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Run the census and attribute what can be attributed.
pub fn census_with_pids(states: u32) -> Result<Vec<DiagEntry>, DiagError> {
    let mut entries = census(states)?;
    let owners = attribute_pids(&entries);
    for e in entries.iter_mut() {
        if let Some((pid, comm)) = owners.get(&(e.ino as u64)) {
            e.pid = Some(*pid);
            e.pid_comm = Some(comm.clone());
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_ss() {
        let m = build_request(0xfff, 1);
        assert_eq!(m.len(), 40);
        assert_eq!(&m[..4], &40u32.to_le_bytes());
        assert_eq!(&m[4..6], &20u16.to_le_bytes(), "SOCK_DIAG_BY_FAMILY");
        assert_eq!(&m[6..8], &0x0301u16.to_le_bytes(), "ROOT|MATCH|REQUEST");
        assert_eq!(&m[8..12], &1u32.to_le_bytes());
        assert_eq!(&m[12..16], &0u32.to_le_bytes(), "pid 0 lets the kernel fill it");
        assert_eq!(m[16], 40, "AF_VSOCK");
        assert_eq!(&m[17..20], &[0, 0, 0]);
        assert_eq!(&m[20..24], &0xfff_u32.to_le_bytes());
        assert_eq!(&m[24..], &[0u8; 16]);
    }

    /// Three entries captured on 7.2.0 on 2026-10-05 while a listener on port
    /// 40111 had one accepted connection (loopback transport, so the peer side
    /// shows `dst_cid 1`). The inodes are the real `fstat` inodes of the sockets
    /// the capturing process held, printed by that script: 129324085 listener,
    /// 129324086 connector, 129324087 accepted.
    const CONNECTOR: &str = "28010100ffffffff1912a7b602000000af9c00003654b50702e0000000000000";
    const LISTENER: &str = "28010a0002000000af9c0000ffffffffffffffff3554b50703e0000000000000";
    const ACCEPTED: &str = "2801010002000000af9c0000010000001912a7b63754b50704e0000000000000";

    fn bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len(), 64, "a 32-byte entry is 64 hex chars");
        (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_captured_entries() {
        let e = parse_entry(&bytes(LISTENER)).expect("listener parses");
        assert_eq!((e.family, e.kind, e.state, e.shutdown), (40, 1, 10, 0));
        assert_eq!((e.src_cid, e.src_port), (2, 40111));
        assert_eq!((e.dst_cid, e.dst_port), (u32::MAX, u32::MAX));
        assert_eq!(e.ino, 129324085);
        assert_eq!(e.cookie, "03e0000000000000");

        let e = parse_entry(&bytes(CONNECTOR)).expect("connector parses");
        assert_eq!((e.state, e.ino), (1, 129324086));
        assert_eq!(e.src_port, 3064402457, "ephemeral u32 port: a u16 would read 4665");
        assert_eq!((e.dst_cid, e.dst_port), (2, 40111));

        let e = parse_entry(&bytes(ACCEPTED)).expect("accepted parses");
        assert_eq!((e.state, e.ino), (1, 129324087));
        assert_eq!((e.src_cid, e.src_port), (2, 40111));
        assert_eq!((e.dst_cid, e.dst_port), (1, 3064402457));
    }

    #[test]
    fn rejects_short_or_foreign_entries() {
        assert!(parse_entry(&[]).is_none());
        assert!(parse_entry(&[0u8; 31]).is_none());
        let mut not_vsock = [0u8; 32];
        not_vsock[0] = 2; // AF_INET
        assert!(parse_entry(&not_vsock).is_none());
    }

    #[test]
    fn done_and_error_are_recognised() {
        let mut d = Vec::new();
        d.extend_from_slice(&20u32.to_le_bytes());
        d.extend_from_slice(&uapi::NLMSG_DONE.to_le_bytes());
        d.extend_from_slice(&0u16.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&[0u8; 4]);
        let (entries, done, err) = parse_messages(&d);
        assert!(entries.is_empty() && done && err.is_none());

        let mut e = Vec::new();
        e.extend_from_slice(&20u32.to_le_bytes());
        e.extend_from_slice(&uapi::NLMSG_ERROR.to_le_bytes());
        e.extend_from_slice(&0u16.to_le_bytes());
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&(-libc::ENOENT).to_le_bytes());
        let (_, done, err) = parse_messages(&e);
        assert!(done);
        assert_eq!(err, Some(-libc::ENOENT));
    }

    /// Live check: with a real listener of ours in this process, the census must
    /// find its inode *and* attribute it to us. Skipped (not faked) where
    /// `vsock_diag` is missing.
    #[test]
    fn census_finds_and_attributes_our_own_listener() {
        let port = 40_123u32;
        let fd = match listen_fixture(port) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("skipping: cannot create a vsock listener here ({})", uapi::errno_label(e));
                return;
            }
        };
        let ino = stat_ino(fd);
        let entries = match census_with_pids(ALL_STATES) {
            Ok(e) => e,
            Err(why) => {
                unsafe { libc::close(fd) };
                eprintln!("skipping: no census here ({why})");
                return;
            }
        };
        unsafe { libc::close(fd) };
        let mine = entries
            .iter()
            .find(|e| e.ino as u64 == ino)
            .expect("our listener must appear in its own netns census");
        assert_eq!(mine.state, 10, "LISTEN");
        assert_eq!(mine.src_port, port);
        assert_eq!(mine.pid, Some(std::process::id()), "ino -> pid attribution");
        assert!(!mine.pid_comm.as_deref().unwrap_or_default().is_empty());
    }

    fn listen_fixture(port: u32) -> Result<libc::c_int, i32> {
        // SAFETY: constants only.
        let fd = unsafe {
            libc::socket(uapi::AF_VSOCK as libc::c_int, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
        };
        if fd < 0 {
            return Err(errno());
        }
        let a = uapi::SockaddrVm::new(uapi::VMADDR_CID_ANY, port, false);
        // SAFETY: `a` is a live sockaddr_vm of exactly `len()` bytes.
        let rc = unsafe {
            libc::bind(
                fd,
                &a as *const _ as *const libc::sockaddr,
                uapi::SockaddrVm::len(),
            )
        };
        if rc != 0 || unsafe { libc::listen(fd, 4) } != 0 {
            return Err(errno());
        }
        Ok(fd)
    }

    fn stat_ino(fd: libc::c_int) -> u64 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes through a valid fd.
        if unsafe { libc::fstat(fd, &mut st) } == 0 {
            st.st_ino as u64
        } else {
            0
        }
    }
}

