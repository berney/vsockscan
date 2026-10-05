//! The data model shared by every renderer (spec §5). Plain data only: no
//! syscalls, no formatting decisions, no colour. Colour and layout live in
//! `render`, which keeps `-o FILE` byte-identical to a `--no-color` run by
//! construction rather than by convention.
//!
//! Serde uses kebab-case field names so the JSON/YAML keys read like the text
//! columns (`elapsed-ms`, `errno-name`, `by-outcome`); `render::tests` pins the
//! serialized key list against `render::json_schema`.

use serde::{Deserialize, Serialize};

/// Output format. Also the CLI's `--format` values: the kebab-case rename gives
/// exactly `text|markdown|json|yaml`, so there is no second enum to keep in step
/// between the parser and the renderers.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Text,
    Markdown,
    Json,
    Yaml,
}
/// Which `VMADDR_FLAG_TO_HOST` setting produced a row. Kept per row on purpose:
/// the same `(cid, port)` can classify differently under the two settings, and
/// that difference is exactly the nested-virt / host-with-vsock case (spec §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlagSet {
    None,
    ToHost,
}

impl FlagSet {
    pub fn label(self) -> &'static str {
        match self {
            FlagSet::None => "none",
            FlagSet::ToHost => "to-host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKind {
    /// `connect()` completed.
    Open,
    /// Peer answered RST (muxer refused a port nobody listens on host-side).
    Closed,
    /// The kernel refused it; nothing left the guest.
    RefusedKernel,
    /// Frame left, nothing answered — unrouted or dropped at peer.
    Silent,
    /// CID 2 resolved to the local transport, so "open" would be a lie.
    LoopbackRedirect,
    /// Socket class refused before routing (`ESOCKTNOSUPPORT`, DGRAM `ENODEV`).
    Unsupported,
    /// Anything we could not classify honestly.
    Error,
}

impl OutcomeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OutcomeKind::Open => "open",
            OutcomeKind::Closed => "closed",
            OutcomeKind::RefusedKernel => "refused-kernel",
            OutcomeKind::Silent => "silent",
            OutcomeKind::LoopbackRedirect => "loopback-redirect",
            OutcomeKind::Unsupported => "unsupported",
            OutcomeKind::Error => "error",
        }
    }
}

/// A verdict always carries the raw errno it came from (spec: never print a
/// verdict the signals cannot support).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Outcome {
    pub kind: OutcomeKind,
    pub errno: Option<i32>,
    pub errno_name: Option<String>,
    /// Free-text qualifier: poll timeout, `socket()` failure stage, etc.
    pub detail: Option<String>,
}

impl Outcome {
    pub fn new(kind: OutcomeKind) -> Self {
        Self {
            kind,
            errno: None,
            errno_name: None,
            detail: None,
        }
    }

    pub fn with_errno(mut self, err: i32) -> Self {
        self.errno = Some(err);
        self.errno_name = Some(crate::uapi::errno_label(err));
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// What a tell can say. `Inert` is not `No`: the loopback canary cannot fire on
/// a kernel built without `vsock_loopback`, and claiming "no redirect" there
/// would be an unearned negative (spec §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TellState {
    Yes,
    No,
    Unknown,
    Inert,
}

impl TellState {
    pub fn as_str(self) -> &'static str {
        match self {
            TellState::Yes => "yes",
            TellState::No => "no",
            TellState::Unknown => "unknown",
            TellState::Inert => "inert",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tell {
    pub id: String,
    pub state: TellState,
    /// What it proves, including "this proves nothing about a device" for
    /// `/dev/vsock`.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// virtio device id 0x0013 seen.
    Present,
    /// Driver available (config says built in or loadable), no device bound.
    /// This is the competition/target shape.
    AbsentButDriver,
    /// No device and no driver.
    Absent,
    /// sysfs unreadable: we cannot say.
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Present => "present",
            Verdict::AbsentButDriver => "absent-but-driver",
            Verdict::Absent => "absent",
            Verdict::Unknown => "unknown",
        }
    }
}

/// Directional posture: are we a guest, a host (h2g available), both (nested),
/// or neither (AF_VSOCK not usable at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    Guest,
    Host,
    Both,
    Neither,
    Unknown,
}

impl Posture {
    pub fn as_str(self) -> &'static str {
        match self {
            Posture::Guest => "guest",
            Posture::Host => "host",
            Posture::Both => "both",
            Posture::Neither => "neither",
            Posture::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CidResolution {
    pub cid: Option<u32>,
    /// `ioctl(/dev/vsock)`, `bound-socket`, `dmesg`, or why it stayed unknown.
    pub source: String,
}

impl CidResolution {
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            cid: None,
            source: reason.into(),
        }
    }
}

/// A sysctl value, or its absence. A missing key/directory is itself a finding
/// (pre-namespace kernel, i.e. an unconditional `g2h` fallback, spec §3.2), so it
/// must not collapse into `null` the way an `Option` would. Serialization is
/// manual because serde's untagged unit variants emit `null`: the JSON/YAML shows
/// the value string or the string `"absent"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysctlValue {
    Present(String),
    Absent,
}

impl serde::Serialize for SysctlValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SysctlValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = String::deserialize(d)?;
        Ok(if v == "absent" {
            SysctlValue::Absent
        } else {
            SysctlValue::Present(v)
        })
    }
}

impl SysctlValue {
    pub fn as_str(&self) -> &str {
        match self {
            SysctlValue::Present(v) => v,
            SysctlValue::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleAvailability {
    Builtin,
    Loadable,
    ModulesDisabled,
    Unavailable,
    Unknown,
}

impl ModuleAvailability {
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleAvailability::Builtin => "builtin",
            ModuleAvailability::Loadable => "loadable",
            ModuleAvailability::ModulesDisabled => "modules-disabled",
            ModuleAvailability::Unavailable => "unavailable",
            ModuleAvailability::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleVerdict {
    pub name: String,
    pub state: ModuleAvailability,
    /// Signals behind the verdict, e.g. `CONFIG_VSOCKMON absent from config;
    /// VHOST_VSOCK is not set`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagStatus {
    /// Census answered; `entries` counted.
    Available { entries: usize },
    /// Typically `CONFIG_VSOCKETS_DIAG is not set` -> `ENOENT`.
    Unavailable(String),
    /// `--no-diag`, or the command does not use it.
    Skipped,
}

impl DiagStatus {
    pub fn as_str(&self) -> String {
        match self {
            DiagStatus::Available { entries } => format!("available ({entries} entries)"),
            DiagStatus::Unavailable(why) => format!("unavailable ({why})"),
            DiagStatus::Skipped => "skipped".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagEntry {
    pub family: u8,
    pub kind: u8,
    pub state: u8,
    pub shutdown: u8,
    pub src_cid: u32,
    pub src_port: u32,
    pub dst_cid: u32,
    pub dst_port: u32,
    pub ino: u32,
    /// Opaque `sock_diag` cookie; contents deliberately not interpreted.
    pub cookie: String,
    pub pid: Option<u32>,
    pub pid_comm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProbeRow {
    /// `seqpacket-connect`, `dgram-socket`, `vhost-node`, `ioctl-get-local-cid`…
    pub name: String,
    pub outcome: Outcome,
    /// Measured value when the probe is not a connect (ioctl answer, features).
    pub value: Option<String>,
    pub flags: FlagSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScanRow {
    pub cid: u32,
    pub port: u32,
    pub flags: FlagSet,
    pub outcome: Outcome,
    pub elapsed_ms: u128,
    /// Hex preview of bytes read after a successful connect, if requested.
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Warn,
    Alert,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Alert => "alert",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Summary {
    pub results: usize,
    /// Outcome kind -> count. Sorted in every renderer for stability.
    pub by_outcome: std::collections::BTreeMap<String, usize>,
    /// `--flags both`: did the two flag sets agree everywhere?
    pub flags_agree: Option<bool>,
    pub elapsed_ms: u128,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Header {
    pub kernel: String,
    pub uid: u32,
    /// `CapEff` decoded to names, not hex: a reader must not have to decode.
    pub caps: Vec<String>,
    pub cid: CidResolution,
    pub sysctls: Vec<(String, SysctlValue)>,
    pub posture: Posture,
    pub device: Verdict,
    /// Which config file the kernel-symbol facts came from (`/proc/config.gz`).
    pub config_source: Option<String>,
    pub module_verdicts: Vec<ModuleVerdict>,
    pub diag: DiagStatus,
    /// Noise statement before any sweep: does a wide sweep touch the host?
    pub noise: String,
}

/// One run, in every format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Report {
    pub tool: String,
    pub version: String,
    /// `probe` | `scan` | `listen` | `selftest`
    pub command: String,
    pub header: Header,
    pub tells: Vec<Tell>,
    pub probes: Vec<ProbeRow>,
    pub rows: Vec<ScanRow>,
    /// Filled only when the diag census ran for this command; the header keeps
    /// the status so a reader can tell `0 entries` from `no census`.
    pub diag_entries: Vec<DiagEntry>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

impl Report {
    pub fn new(command: impl Into<String>, header: Header) -> Self {
        Self {
            tool: "vsockscan".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            command: command.into(),
            header,
            tells: Vec::new(),
            probes: Vec::new(),
            rows: Vec::new(),
            diag_entries: Vec::new(),
            findings: Vec::new(),
            summary: Summary::default(),
        }
    }

    pub fn finding(&mut self, severity: Severity, message: impl Into<String>) {
        self.findings.push(Finding {
            severity,
            message: message.into(),
        });
    }

    /// Recompute `summary` from `rows`. Callers must not hand-count: the summary
    /// and the rows must never disagree in a committed transcript.
    pub fn recompute_summary(&mut self, elapsed_ms: u128) {
        let mut by_outcome = std::collections::BTreeMap::new();
        for r in &self.rows {
            *by_outcome
                .entry(r.outcome.kind.as_str().to_owned())
                .or_insert(0) += 1;
        }
        self.summary = Summary {
            results: self.rows.len(),
            by_outcome,
            flags_agree: Self::flags_agree(&self.rows),
            elapsed_ms,
            notes: std::mem::take(&mut self.summary.notes),
        };
    }

    /// `None` when only one flag set was swept (nothing to compare), otherwise
    /// whether every `(cid, port)` classified the same under both settings.
    fn flags_agree(rows: &[ScanRow]) -> Option<bool> {
        if rows.iter().all(|r| r.flags == FlagSet::None) {
            return None;
        }
        let mut pairs: std::collections::BTreeMap<(u32, u32), Vec<&'static str>> =
            Default::default();
        for r in rows {
            pairs
                .entry((r.cid, r.port))
                .or_default()
                .push(r.outcome.kind.as_str());
        }
        Some(pairs.values().all(|v| v.windows(2).all(|w| w[0] == w[1])))
    }
}

/// Header for the tests and for commands that have nothing better yet, so no
/// module invents its own placeholder.
pub fn placeholder_header() -> Header {
    Header {
        kernel: "unknown".to_owned(),
        uid: unsafe { libc::getuid() },
        caps: Vec::new(),
        cid: CidResolution::unknown("not probed"),
        sysctls: Vec::new(),
        posture: Posture::Unknown,
        device: Verdict::Unknown,
        config_source: None,
        module_verdicts: Vec::new(),
        diag: DiagStatus::Skipped,
        noise: "unknown: run `probe` before drawing noise conclusions".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report::new("scan", placeholder_header());
        r.rows.push(ScanRow {
            cid: 2,
            port: 1234,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::RefusedKernel).with_errno(libc::ENODEV),
            elapsed_ms: 1,
            banner: None,
        });
        r.rows.push(ScanRow {
            cid: 2,
            port: 1234,
            flags: FlagSet::ToHost,
            outcome: Outcome::new(OutcomeKind::Open),
            elapsed_ms: 2,
            banner: Some("68656c6c6f".to_owned()),
        });
        r.finding(Severity::Warn, "flag set changed the verdict on 2:1234");
        r.recompute_summary(3);
        r
    }

    #[test]
    fn summary_counts_and_disagreement() {
        let r = sample();
        assert_eq!(r.summary.results, 2);
        assert_eq!(r.summary.by_outcome.get("open"), Some(&1));
        assert_eq!(r.summary.by_outcome.get("refused-kernel"), Some(&1));
        assert_eq!(r.summary.flags_agree, Some(false));
    }

    #[test]
    fn flags_agree_is_none_when_only_one_flag_set_swept() {
        let mut r = Report::new("scan", placeholder_header());
        r.rows.push(ScanRow {
            cid: 3,
            port: 1,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::Silent),
            elapsed_ms: 0,
            banner: None,
        });
        r.recompute_summary(0);
        assert_eq!(r.summary.flags_agree, None);
    }

    #[test]
    fn flags_agree_true_when_both_settings_classify_identically() {
        let mut r = Report::new("scan", placeholder_header());
        for flags in [FlagSet::None, FlagSet::ToHost] {
            r.rows.push(ScanRow {
                cid: 3,
                port: 1,
                flags,
                outcome: Outcome::new(OutcomeKind::Silent),
                elapsed_ms: 0,
                banner: None,
            });
        }
        r.recompute_summary(0);
        assert_eq!(r.summary.flags_agree, Some(true));
    }

    #[test]
    fn outcome_keeps_errno_name() {
        let o = Outcome::new(OutcomeKind::Unsupported).with_errno(libc::ESOCKTNOSUPPORT);
        assert_eq!(o.errno_name.as_deref(), Some("ESOCKTNOSUPPORT"));
        assert_eq!(o.kind.as_str(), "unsupported");
    }

    #[test]
    fn json_round_trips() {
        let r = sample();
        let s = serde_json::to_string(&r).unwrap();
        let back: Report = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn sysctl_value_serializes_flat() {
        assert_eq!(
            serde_json::to_string(&SysctlValue::Present("1".into())).unwrap(),
            "\"1\""
        );
        assert_eq!(serde_json::to_string(&SysctlValue::Absent).unwrap(), "\"absent\"");
        assert_eq!(
            serde_json::from_str::<SysctlValue>("\"absent\"").unwrap(),
            SysctlValue::Absent
        );
    }
}
