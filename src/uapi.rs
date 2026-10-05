//! AF_VSOCK / vhost / netlink constants owned by this tool.
//!
//! Every value below is copied from a uapi header and confirmed by measurement.
//! Sources of truth, in order of preference:
//! `include/uapi/linux/vm_sockets.h`, `include/uapi/linux/vsock_diag.h` equivalents
//! (`struct vm_sockets_diag_req`/`vm_sockets_diag_msg` are not shipped in standard distro
//! headers, so their layout is pinned from the wire format), and
//! `include/uapi/linux/vhost.h`.


/// `AF_VSOCK` (`include/linux/socket.h`). Not 40 by accident: `PF_VSOCK`.
pub const AF_VSOCK: u16 = 40;

/// `struct sockaddr_vm` — `sizeof == sizeof(struct sockaddr) == 16`, `svm_flags` at
/// offset 12 (measured with `offsetof` on 6.1.186, 6.8.0 and 7.2.0; the field is in
/// the uapi of 6.1.y, 6.6.y and master).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockaddrVm {
    pub svm_family: u16,
    pub svm_reserved1: u16,
    pub svm_port: u32,
    pub svm_cid: u32,
    /// `VMADDR_FLAG_TO_HOST` lives here (bit 0). Zero this field for the default.
    pub svm_flags: u8,
    pub svm_zero: [u8; 3],
}

impl SockaddrVm {
    pub fn new(cid: u32, port: u32, to_host: bool) -> Self {
        Self {
            svm_family: AF_VSOCK,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_flags: if to_host { VMADDR_FLAG_TO_HOST } else { 0 },
            svm_zero: [0; 3],
        }
    }

    /// `bind()`/`connect()` want the *family check* to pass: kernel rejects
    /// `addrlen < sizeof(sa_family_t)` and uses `sizeof(struct sockaddr_vm)` for the
    /// rest. Exposed as a helper so no caller hand-writes the length.
    pub fn len() -> libc::socklen_t {
        core::mem::size_of::<SockaddrVm>() as libc::socklen_t
    }
}

pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_CID_HOST: u32 = 2;
pub const VMADDR_CID_ANY: u32 = u32::MAX;
/// Auto-assign. Note this is *not* `0`: passing port 0 as a non-root caller is
/// treated as a privileged port and fails `EACCES` (measured, uid 1000).
pub const VMADDR_PORT_ANY: u32 = u32::MAX;
/// `include/uapi/linux/vm_sockets.h:151`.
pub const VMADDR_FLAG_TO_HOST: u8 = 1 << 0;

/// `IOCTL_VM_SOCKETS_GET_LOCAL_CID = _IO(7, 0xb9)` — **`_IO`, not `_IOR`**, so no
/// direction or size bits (`include/uapi/linux/vm_sockets.h:196`). Answer is
/// version-dependent: `4294967295` on 6.1.186, `1` on 7.2.0.
pub const IOCTL_GET_LOCAL_CID: libc::c_ulong = (7 << 8) | 0xb9;

// Socket options (`SOL_VSOCK = 287`, `include/uapi/linux/vm_sockets.h:207`) are
// deliberately not declared: this tool never sets a buffer size or a connect
// timeout through them. Timeouts are `poll()` deadlines, so the report and the
// syscall agree about what bounded the wait. Note there is **no**
// `SOL_VM_SOCKETS` — code that names it gets `ENOPROTOOPT` at runtime.

// --- netlink / sock_diag -------------------------------------------------------
//
// `NETLINK_SOCK_DIAG` is **4** (the historical alias `NETLINK_INET_DIAG`). Protocol 18
// is `NETLINK_ECRYPTFS`; sending a diag request there is answered with `-EBADMSG`.
// Do not "modernise" this constant.
pub const NETLINK_SOCK_DIAG: libc::c_int = 4;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_MULTI: u16 = 0x0002;
/// `NLM_F_ROOT = 0x100`, `NLM_F_MATCH = 0x200` (`include/uapi/linux/netlink.h`), so
/// the dump flag pair `ss` sends is `0x300` and the whole flags word is `0x301`
/// (captured byte-for-byte from `ss -f vsock`).
pub const NLM_F_ROOT: u16 = 0x0100;
pub const NLM_F_MATCH: u16 = 0x0200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
/// `sizeof(struct nlmsghdr)`.
pub const NLMSG_HDRLEN: usize = 16;

// --- vhost (`include/uapi/linux/vhost.h`) --------------------------------------
// `VHOST_VIRTIO = 0xAF` is the ioctl type; the write-side requests
// (`VHOST_VSOCK_SET_GUEST_CID = _IOW(0xAF, 0x60, u64)`,
// `VHOST_VSOCK_SET_RUNNING = _IOW(0xAF, 0x61, int)`) exist but are *never*
// declared as constants here, because calling them would claim a guest CID or
// start a muxer — interception, which spec §2 rules out. Only the read-only
// `_IOR` below is used.
const fn ior(size: u32, ty: u8, nr: u8) -> libc::c_ulong {
    // _IOC(_IOC_READ=2, type, nr, size): dir<<30 | size<<16 | type<<8 | nr.
    ((2 as libc::c_ulong) << 30)
        | ((size as libc::c_ulong) << 16)
        | ((ty as libc::c_ulong) << 8)
        | (nr as libc::c_ulong)
}
/// `_IOR(VHOST_VIRTIO, 0x00, __u64)` = 0x8008afaf — read-only, so it is safe to
/// issue against a node we do not own.
pub const VHOST_GET_FEATURES: libc::c_ulong = ior(8, 0xAF, 0x00);
/// Errno name for the codes this tool can observe. Unknown codes render numerically
/// at the call site so nothing is silently mislabelled.
pub fn errno_name(err: i32) -> Option<&'static str> {
    Some(match err {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::EINTR => "EINTR",
        libc::EAGAIN => "EAGAIN",
        libc::EBADF => "EBADF",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::ENODEV => "ENODEV",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::ECONNRESET => "ECONNRESET",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ECONNABORTED => "ECONNABORTED",
        libc::EISCONN => "EISCONN",
        libc::ENOTCONN => "ENOTCONN",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EBUSY => "EBUSY",
        libc::EMSGSIZE => "EMSGSIZE",
        libc::ENOBUFS => "ENOBUFS",
        libc::EBADMSG => "EBADMSG",
        _ => return None,
    })
}

/// Errno name, or `E<number>` — used everywhere a verdict is printed.
pub fn errno_label(err: i32) -> String {
    errno_name(err).map(str::to_owned).unwrap_or_else(|| format!("E{err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI invariants `--flags` and the diag client depend on. If a libc/kernel
    /// ever moves `svm_flags`, `--flags to-host` would silently send garbage.
    #[test]
    fn sockaddr_vm_abi() {
        assert_eq!(core::mem::size_of::<SockaddrVm>(), 16);
        assert_eq!(core::mem::offset_of!(SockaddrVm, svm_flags), 12);
        assert_eq!(core::mem::offset_of!(SockaddrVm, svm_cid), 8);
        assert_eq!(core::mem::offset_of!(SockaddrVm, svm_port), 4);
    }

    #[test]
    fn pinned_numbers() {
        assert_eq!(IOCTL_GET_LOCAL_CID, 0x7b9);
        // All five values re-printed from <linux/vm_sockets.h> + <linux/netlink.h>
        assert_eq!(NETLINK_SOCK_DIAG, 4);
        assert_eq!(SOCK_DIAG_BY_FAMILY, 20);
        assert_eq!(NLM_F_DUMP, 0x300);
        assert_eq!(NLM_F_REQUEST | NLM_F_DUMP, 0x301);
        // VHOST_GET_FEATURES = _IOR(0xAF, 0x00, u64); 0x8008af00 is what
        // <linux/vhost.h> expands to (cross-checked with a C print).
        assert_eq!(VHOST_GET_FEATURES, 0x8008_af00);
        assert_eq!(AF_VSOCK, 40);
        assert_eq!(SOL_VSOCK, 287);
    }

    #[test]
    fn to_host_flag_sets_only_the_flags_byte() {
        let a = SockaddrVm::new(VMADDR_CID_HOST, 7, false);
        let b = SockaddrVm::new(VMADDR_CID_HOST, 7, true);
        assert_eq!(a.svm_flags, 0);
        assert_eq!(b.svm_flags, VMADDR_FLAG_TO_HOST);
        let ra = unsafe {
            core::slice::from_ref(&a).as_ptr().cast::<u8>().add(12).read()
        };
        let rb = unsafe {
            core::slice::from_ref(&b).as_ptr().cast::<u8>().add(12).read()
        };
        assert_eq!((ra, rb), (0, 1));
    }

    #[test]
    fn errno_names_resolve() {
        assert_eq!(errno_name(libc::ENODEV), Some("ENODEV"));
        assert_eq!(errno_name(libc::ESOCKTNOSUPPORT), Some("ESOCKTNOSUPPORT"));
        assert_eq!(errno_label(libc::EACCES), "EACCES");
        assert_eq!(errno_label(9999), "E9999");
    }
}
