//! Capability decoding without `libcap`: `/proc/self/status` is enough.
//!
//! `CapEff` is a hex mask. The `NAMES` table below was **generated** from
//! `/usr/include/linux/capability.h` (41 entries, values 0..=40, verified
//! duplicate-free), not transcribed: the plan guessed `CAP_SYS_MODULE = 22`, and
//! the header says **16** — a wrong bit would silently mis-report whether
//! `modprobe` is available, which is the hinge of the vsockmon verdict.
//! `cat /proc/sys/kernel/cap_last_cap` = 40 on the host, 2026-10-05.

use serde::Serialize;

pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_MODULE: u32 = 16;

/// Names for the bits a recon report can meaningfully print. Bits outside this
/// table are reported as `cap_<n>` rather than dropped, so a container with an
/// unusual grant stays visible.
const NAMES: &[(u32, &str)] = &[
    (0, "CAP_CHOWN"),
    (1, "CAP_DAC_OVERRIDE"),
    (2, "CAP_DAC_READ_SEARCH"),
    (3, "CAP_FOWNER"),
    (4, "CAP_FSETID"),
    (5, "CAP_KILL"),
    (6, "CAP_SETGID"),
    (7, "CAP_SETUID"),
    (8, "CAP_SETPCAP"),
    (9, "CAP_LINUX_IMMUTABLE"),
    (10, "CAP_NET_BIND_SERVICE"),
    (11, "CAP_NET_BROADCAST"),
    (12, "CAP_NET_ADMIN"),
    (13, "CAP_NET_RAW"),
    (14, "CAP_IPC_LOCK"),
    (15, "CAP_IPC_OWNER"),
    (16, "CAP_SYS_MODULE"),
    (17, "CAP_SYS_RAWIO"),
    (18, "CAP_SYS_CHROOT"),
    (19, "CAP_SYS_PTRACE"),
    (20, "CAP_SYS_PACCT"),
    (21, "CAP_SYS_ADMIN"),
    (22, "CAP_SYS_BOOT"),
    (23, "CAP_SYS_NICE"),
    (24, "CAP_SYS_RESOURCE"),
    (25, "CAP_SYS_TIME"),
    (26, "CAP_SYS_TTY_CONFIG"),
    (27, "CAP_MKNOD"),
    (28, "CAP_LEASE"),
    (29, "CAP_AUDIT_WRITE"),
    (30, "CAP_AUDIT_CONTROL"),
    (31, "CAP_SETFCAP"),
    (32, "CAP_MAC_OVERRIDE"),
    (33, "CAP_MAC_ADMIN"),
    (34, "CAP_SYSLOG"),
    (35, "CAP_WAKE_ALARM"),
    (36, "CAP_BLOCK_SUSPEND"),
    (37, "CAP_AUDIT_READ"),
    (38, "CAP_PERFMON"),
    (39, "CAP_BPF"),
    (40, "CAP_CHECKPOINT_RESTORE"),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Caps {
    /// Raw `CapEff` value; `None` when `/proc/self/status` was unreadable.
    pub effective: Option<u64>,
    /// `CapPrm` when present — a container can hold a permitted cap it dropped
    /// from effective, which changes what a root exploit could regain.
    pub permitted: Option<u64>,
    /// Highest capability the running kernel knows about (`CapEL` is not
    /// exposed, so this comes from `/proc/sys/kernel/cap_last_cap` if readable).
    pub last_cap: Option<u32>,
}

impl Caps {
    pub fn from_status(status: &str, last_cap: Option<u32>) -> Caps {
        Caps {
            effective: parse_cap_line(status, "CapEff"),
            permitted: parse_cap_line(status, "CapPrm"),
            last_cap,
        }
    }

    /// Live read; every caller degrades to an empty `Caps` rather than failing.
    pub fn from_proc_self_status() -> Caps {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse().ok());
        Caps::from_status(&status, last_cap)
    }

    pub fn has(&self, bit: u32) -> bool {
        match self.effective {
            Some(m) => m & (1u64 << bit) != 0,
            None => false,
        }
    }

    pub fn sys_module(&self) -> bool {
        self.has(CAP_SYS_MODULE)
    }
    pub fn net_admin(&self) -> bool {
        self.has(CAP_NET_ADMIN)
    }
    pub fn sys_admin(&self) -> bool {
        self.has(CAP_SYS_ADMIN)
    }
    pub fn net_bind_service(&self) -> bool {
        self.has(CAP_NET_BIND_SERVICE)
    }

    /// Named set of the effective mask, in bit order.
    pub fn names(&self) -> Vec<String> {
        let Some(m) = self.effective else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // Unknown `cap_last_cap` must not hide a set bit: fall back to the full
        // width and let the name be `cap_<n>`.
        let top = self.last_cap.unwrap_or(63).min(63);
        for b in 0..=top {
            if m & (1u64 << b) == 0 {
                continue;
            }
            out.push(
                NAMES
                    .iter()
                    .find(|(n, _)| *n == b)
                    .map(|(_, s)| (*s).to_string())
                    .unwrap_or_else(|| format!("cap_{b}")),
            );
        }
        out
    }
}

fn parse_cap_line(status: &str, key: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let hex = rest.trim_start_matches(':').trim();
            return u64::from_str_radix(hex, 16).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full modern root mask: bits 0..=40 (`cap_last_cap` = 40 on the host).
    const ROOT: &str = "Uid:\t0\t0\t0\t0\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
    // A container that kept NET_ADMIN but lost everything else.
    const PARTIAL: &str = "CapEff:\t0000000000001400\nCapPrm:\t0000000000001400\n";

    #[test]
    fn root_mask_decodes() {
        let c = Caps::from_status(ROOT, Some(40));
        assert!(c.sys_module() && c.net_admin() && c.sys_admin());
        let n = c.names();
        assert!(n.contains(&"CAP_SYS_MODULE".to_string()));
        assert!(n.contains(&"CAP_BPF".to_string()));
        assert!(n.contains(&"CAP_CHECKPOINT_RESTORE".to_string()));
        assert_eq!(n.first().map(String::as_str), Some("CAP_CHOWN"));
        assert_eq!(n.len(), 41, "every defined bit");
    }

    #[test]
    fn partial_mask_and_unknown_bits() {
        let c = Caps::from_status(PARTIAL, Some(40));
        // 0x1400 = bits 10 and 12: bind-low-ports and netadmin, nothing else.
        assert!(c.net_admin());
        assert!(c.net_bind_service());
        assert!(!c.sys_module(), "CAP_SYS_MODULE is bit 16, not set here");
        assert_eq!(c.names(), vec!["CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN"]);
    }

    #[test]
    fn unreadable_status_is_empty_not_panic() {
        let c = Caps::from_status("", None);
        assert_eq!(c.effective, None);
        assert!(!c.sys_admin());
        assert!(c.names().is_empty());
    }

    #[test]
    fn unknown_bits_are_reported() {
        // A bit with no name in the table (41, just past CAP_CHECKPOINT_RESTORE)
        // is printed as `cap_41` rather than dropped.
        assert_eq!(
            Caps::from_status("CapEff:\t0000020000000000\n", Some(41)).names(),
            vec!["cap_41"]
        );
        // Bits past `cap_last_cap` are not printed: the kernel cannot have them.
        assert_eq!(
            Caps::from_status("CapEff:\t0200000000000000\n", Some(40)).names(),
            Vec::<String>::new()
        );
        // With no cap_last_cap we fall back to the table's top and still show it.
        assert_eq!(
            Caps::from_status("CapEff:\t0200000000000000\n", None).names(),
            vec!["cap_57"]
        );
    }
}
