//! The sweep: outcome taxonomy (§6.1), the worker pool, stage-1 pruning and the
//! diag cross-check.
//!
//! Two invariants drive the design:
//!
//! * **Output order is job order, never completion order.** Evidence that moves
//!   between runs is evidence nobody can diff, so workers write into indexed
//!   slots and the report is assembled by index.
//! * **A verdict never outruns its signal.** Every `Outcome` carries the errno
//!   and the stage it came from, and `refused-kernel` is printed beside the
//!   device tells (the header already holds them) because `ENODEV` means both
//!   "no driver" and "driver present, no device bound" (§3.2).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::model::{
    DiagEntry, Finding, FlagSet, Outcome, OutcomeKind, Report, ScanRow, Severity, TellState,
};
use crate::probe::{self, Connect};
use crate::uapi;

/// `--flags` coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagMode {
    None,
    ToHost,
    Both,
}

impl FlagMode {
    pub fn sets(self) -> &'static [FlagSet] {
        match self {
            FlagMode::None => &[FlagSet::None],
            FlagMode::ToHost => &[FlagSet::ToHost],
            FlagMode::Both => &[FlagSet::None, FlagSet::ToHost],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub cid: u32,
    pub port: u32,
    pub flags: FlagSet,
}

/// Canonical job order: CID-major, then ascending port, then flag. Everything
/// about a run's determinism follows from this one function.
pub fn jobs(cids: &[u32], ports: &[u32], mode: FlagMode) -> Vec<Job> {
    let mut out = Vec::with_capacity(cids.len() * ports.len() * mode.sets().len());
    for &cid in cids {
        for &port in ports {
            for &flags in mode.sets() {
                out.push(Job { cid, port, flags });
            }
        }
    }
    out
}

/// Map a connect result onto the taxonomy. Table-driven and total: an errno we
/// did not anticipate becomes `error`, never a plausible-looking `closed`.
pub fn classify(res: &Connect) -> Outcome {
    match res {
        Connect::Established => Outcome::new(OutcomeKind::Open),
        Connect::Timeout => Outcome::new(OutcomeKind::Silent)
            .with_detail("poll(POLLOUT) timed out: a frame left and nothing answered"),
        Connect::Failed { errno, stage } => {
            let kind = match *errno {
                libc::ESOCKTNOSUPPORT
                | libc::EPROTONOSUPPORT
                | libc::EAFNOSUPPORT
                | libc::EOPNOTSUPP
                | libc::EPFNOSUPPORT => OutcomeKind::Unsupported,
                libc::ENODEV | libc::EINVAL | libc::EADDRNOTAVAIL => OutcomeKind::RefusedKernel,
                libc::ECONNRESET | libc::ECONNREFUSED | libc::ECONNABORTED | libc::ENOTCONN => {
                    OutcomeKind::Closed
                }
                // EWOULDBLOCK is EAGAIN on Linux; naming both would be an unreachable arm.
                libc::ETIMEDOUT | libc::EAGAIN | libc::EALREADY => OutcomeKind::Silent,
                _ => OutcomeKind::Error,
            };
            let o = Outcome::new(kind).with_errno(*errno);
            match *stage {
                "connect" => o.with_detail("errno at connect(): nothing left this host"),
                "SO_ERROR" => o,
                other => o.with_detail(format!("errno at {other}()")),
            }
        }
    }
}

/// A connect to `CID 2` that the canary says is loopback is not "the host
/// answered". The redirect verdict replaces the raw one, but keeps the errno and
/// names the underlying signal so the reader can see both.
///
/// Only a signal that came back *from routing* can be a redirect. `ENODEV` says
/// the frame never left, so relabelling it would turn "no transport" into
/// "loopback" — a claim the errno contradicts.
pub fn apply_canary(outcome: Outcome, cid: u32, canary: TellState) -> Outcome {
    let routed = matches!(
        outcome.kind,
        OutcomeKind::Open | OutcomeKind::Closed | OutcomeKind::Silent
    );
    if cid != uapi::VMADDR_CID_HOST || canary != TellState::Yes || !routed {
        return outcome;
    }
    let underlying = outcome.kind.as_str().to_string();
    Outcome {
        kind: OutcomeKind::LoopbackRedirect,
        errno: outcome.errno,
        errno_name: outcome.errno_name,
        detail: Some(format!(
            "underlying {underlying}; the canary proved CID 2 resolves to the local \
             transport here, so this says nothing about the host"
        )),
    }
}

fn monotonic_us() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes through a valid pointer to a timespec we own.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1000
}

/// One connect, timed. `banner > 0` reads up to that many bytes after success so
/// a listener can be identified rather than merely found.
pub fn probe_job(job: Job, timeout_ms: i32, banner: usize) -> ScanRow {
    let start = monotonic_us();
    let (outcome, preview) = match vsock_stream() {
        Ok(fd) => {
            let addr = uapi::SockaddrVm::new(job.cid, job.port, job.flags == FlagSet::ToHost);
            let res = probe::nonblocking_connect(fd, &addr, timeout_ms);
            let out = classify(&res);
            let preview = if out.kind == OutcomeKind::Open && banner > 0 {
                read_preview(fd, banner)
            } else {
                None
            };
            // SAFETY: closing the descriptor we just opened.
            unsafe { libc::close(fd) };
            (out, preview)
        }
        Err(e) => (
            Outcome::new(OutcomeKind::Unsupported)
                .with_errno(e)
                .with_detail("socket(AF_VSOCK, SOCK_STREAM) failed"),
            None,
        ),
    };
    ScanRow {
        cid: job.cid,
        port: job.port,
        flags: job.flags,
        outcome,
        elapsed_ms: u128::from((monotonic_us() - start) / 1000),
        banner: preview,
    }
}

fn vsock_stream() -> Result<libc::c_int, i32> {
    // SAFETY: constant family/type/protocol, no pointers.
    let fd = unsafe {
        libc::socket(
            uapi::AF_VSOCK as libc::c_int,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd >= 0 {
        Ok(fd)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// Wait briefly for bytes, then read what is there without blocking further.
fn read_preview(fd: libc::c_int, want: usize) -> Option<String> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll on a descriptor we own.
    if unsafe { libc::poll(&mut p, 1, 100) } != 1 {
        return None;
    }
    let mut buf = vec![0u8; want.min(4096)];
    // SAFETY: read into a buffer of the length passed.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let mut s = buf
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if buf.len() == want {
        s.push_str(" ...");
    }
    Some(s)
}

/// The pool. `std::thread`, no async runtime: the kernel path is cheap and we
/// would rather bound descriptors than maximise syscalls per second.
/// Run the pool. Returns `(completed rows, jobs planned)`: a Ctrl-C stops the
/// workers between jobs, so the caller must expect fewer rows than it asked for
/// and say so in the report rather than pretend the grid is whole.
pub fn sweep(
    job_list: &[Job],
    parallel: usize,
    timeout_ms: i32,
    banner: usize,
    stop: &AtomicBool,
) -> (Vec<ScanRow>, usize) {
    // Work is claimed with an atomic counter and each worker *returns* its
    // `(index, row)` pairs, so there is no lock to poison or unwrap; ordering is
    // restored by assembling from the indices.
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let workers = parallel.clamp(1, job_list.len().max(1));
    let chunks: Vec<Vec<(usize, ScanRow)>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= job_list.len() {
                            break;
                        }
                        local.push((i, probe_job(job_list[i], timeout_ms, banner)));
                        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                        // A long sweep must be visible in a transcript without spamming it.
                        if n > 1000 && n.is_multiple_of(1000) {
                            eprintln!("vsockscan: {n} connects issued");
                        }
                    }
                    local
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a scan worker panicked"))
            .collect()
    });
    let mut slots: Vec<Option<ScanRow>> = vec![None; job_list.len()];
    for chunk in chunks {
        for (i, row) in chunk {
            slots[i] = Some(row);
        }
    }
    // Job order is kept so a transcript is comparable between runs; the holes left
    // by an interrupt are dropped, and the caller reports how many there were.
    let rows = slots.into_iter().flatten().collect::<Vec<_>>();
    (rows, job_list.len())
}

pub struct Opts<'a> {
    pub cids: &'a [u32],
    pub ports: &'a [u32],
    pub flags: FlagMode,
    pub parallel: usize,
    pub timeout_ms: i32,
    pub banner: usize,
    /// Ports probed per CID before the full sweep decides whether that CID is worth it.
    pub stage1_ports: usize,
    pub spec_notes: Vec<String>,
    /// Keep only rows whose answer was `open`, after the summary has counted
    /// the whole sweep (`--open`, spec §6).
    pub open_only: bool,
}

/// Stage-1 selection: the first `n` ports of the spec, plus the middle and last
/// port when the spec is wider. The design suggested "plus 2 random highs"; that
/// is deliberately made deterministic here — a run whose port selection changes
/// between invocations cannot be diffed against earlier evidence.
pub fn stage1_ports(ports: &[u32], n: usize) -> Vec<u32> {
    if ports.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<u32> = ports.iter().copied().take(n).collect();
    if ports.len() > out.len() {
        out.push(ports[ports.len() / 2]);
        out.push(ports[ports.len() - 1]);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Run the sweep into `report`, which the caller has already filled with the
/// §6.3 classification (header, tells, posture) so every row is reported next to
/// the device evidence that qualifies it.
pub fn run(o: &Opts, report: &mut Report) -> Result<(), String> {
    let stop = &crate::INTERRUPTED;
    let canary = report
        .tells
        .iter()
        .find(|t| t.id == "loopback-canary")
        .map(|t| t.state)
        .unwrap_or(TellState::Unknown);
    let all = jobs(o.cids, o.ports, o.flags);
    if all.is_empty() {
        return Err("the --cid/--ports specs selected nothing to probe".to_string());
    }

    // Stage 1: classify each CID cheaply, then drop the ones that are uniformly
    // refused by the kernel (no transport at all — sweeping them further is noise
    // the report would have to explain anyway). The stage-1 rows of a pruned CID
    // are kept: they are the evidence for the pruning, not a detail to discard.
    let mut pruned: Vec<u32> = Vec::new();
    let mut pruned_rows: Vec<ScanRow> = Vec::new();
    if o.ports.len() > o.stage1_ports && o.cids.len() > 1 {
        let s1 = stage1_ports(o.ports, o.stage1_ports);
        let stage_jobs = jobs(o.cids, &s1, o.flags);
        let (early, _) = sweep(&stage_jobs, o.parallel, o.timeout_ms, 0, stop);
        for &cid in o.cids {
            let mine: Vec<&ScanRow> = early.iter().filter(|r| r.cid == cid).collect();
            if !mine.is_empty()
                && mine
                    .iter()
                    .all(|r| r.outcome.kind == OutcomeKind::RefusedKernel)
            {
                pruned.push(cid);
                pruned_rows.extend(mine.into_iter().cloned());
            }
        }
    }
    let kept_jobs: Vec<Job> = all
        .iter()
        .copied()
        .filter(|j| !pruned.contains(&j.cid))
        .collect();
    let start = monotonic_us();
    let (mut rows, planned) = sweep(&kept_jobs, o.parallel, o.timeout_ms, o.banner, stop);
    let dropped = planned.saturating_sub(rows.len());
    let issued = planned - dropped;
    rows.extend(pruned_rows);
    let mut rows = keep_order_rows(&all, rows);
    for r in rows.iter_mut() {
        r.outcome = apply_canary(r.outcome.clone(), r.cid, canary);
    }
    let elapsed_ms = (monotonic_us() - start) / 1000;

    let mut notes: Vec<String> = o.spec_notes.clone();
    if !pruned.is_empty() {
        notes.push(format!(
            "stage-1 pruning skipped {} CID(s) whose probes were all refused by the kernel \
             ({}); the full port sweep never touched them, and their stage-1 rows \
             are the only lines those CIDs get",
            pruned.len(),
            if pruned.len() <= 8 {
                pruned
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!("{} more not listed", pruned.len())
            }
        ));
    }
    if canary == TellState::Yes {
        notes.push(
            "the loopback canary fired before this sweep, so every CID-2 row is reported as \
             loopback-redirect, not as a host answer"
                .to_string(),
        );
    }
    if dropped > 0 {
        // An interrupted sweep is a partial answer and must read that way: the row
        // count, the note and the suppressed flag comparison all say the same thing.
        notes.push(format!(
            "interrupted after {issued} of {planned} planned connects: {dropped} were never \
             issued, so this is a partial sweep and the endpoints it never reached are unknown, \
             not closed. `flags-agree` is suppressed because the two flag sets are no longer \
             paired everywhere."
        ));
        report.findings.push(crate::model::Finding {
            severity: crate::model::Severity::Warn,
            message: format!("sweep interrupted: {dropped} of {planned} connects did not run"),
        });
    }
    report.rows = rows;
    report
        .findings
        .extend(flag_disagreements(o.flags, &report.rows));
    cross_check_diag(report);
    // The model owns the counting so the summary can never disagree with the rows.
    report.recompute_summary(u128::from(elapsed_ms));
    report.summary.notes.extend(notes);
    if o.open_only {
        let note = apply_open(report);
        report.summary.notes.push(note);
    }
    Ok(())
}

/// `--open` over a finished sweep: keep only rows that answered `open` and
/// return the note saying what was filtered. Runs after `recompute_summary`
/// so the summary keeps the swept count - the filter shrinks the view, never
/// the evidence. Findings are untouched, and the `probe` classification rows
/// live in `report.probes`, which this never reads: `--open` filters this
/// command's sweep and nothing else.
fn apply_open(report: &mut Report) -> String {
    let dropped = crate::model::filter_open_rows(&mut report.rows);
    format!(
        "--open: showing {} open row(s) of {}",
        report.rows.len(),
        report.rows.len() + dropped
    )
}

/// `(cid, port, outcome-none, outcome-to-host)` for every pair present.
fn pairs(rows: &[ScanRow]) -> Vec<(u32, u32, OutcomeKind, OutcomeKind)> {
    // Same story as `keep_order_rows`: pairing by searching the row list per row
    // is quadratic, and this runs on every `--flags both` sweep.
    let mut to_host: std::collections::HashMap<(u32, u32), OutcomeKind> =
        std::collections::HashMap::new();
    for o in rows.iter().filter(|r| r.flags == FlagSet::ToHost) {
        to_host.insert((o.cid, o.port), o.outcome.kind);
    }
    let mut out = Vec::new();
    for r in rows.iter().filter(|r| r.flags == FlagSet::None) {
        if let Some(kind) = to_host.get(&(r.cid, r.port)) {
            out.push((r.cid, r.port, r.outcome.kind, *kind));
        }
    }
    out
}

/// Rows where the flag changed the answer: exactly the nested-virt /
/// host-with-vhost case the flag exists to expose (spec §6.1).
pub fn flag_disagreements(mode: FlagMode, rows: &[ScanRow]) -> Vec<Finding> {
    if mode != FlagMode::Both {
        return Vec::new();
    }
    pairs(rows)
        .into_iter()
        .filter(|(_, _, a, b)| a != b)
        .map(|(cid, port, a, b)| Finding {
            severity: Severity::Warn,
            message: format!(
                "CID {cid} port {port} answers differently per flag: no-flag is {}, \
                 VMADDR_FLAG_TO_HOST is {} — one direction of this pair is not what it looks like",
                a.as_str(),
                b.as_str()
            ),
        })
        .collect()
}

/// Did the connect reach something? A redirect counts — it is still an answer —
/// but a *redirected refusal* does not: the canary relabels `closed` too, and
/// calling that "reached a listener" would contradict the errno on the same row
/// (and invent a finding against a census that has no such port).
fn reached(row: &ScanRow) -> bool {
    match row.outcome.kind {
        OutcomeKind::Open => true,
        OutcomeKind::LoopbackRedirect => row.outcome.errno.is_none(),
        _ => false,
    }
}

/// Canonical order for emitted rows: the order of the full job list, so a pruned
/// run and an unpruned one put the same `(cid, port, flag)` on the same line
/// number of the output.
fn keep_order_rows(all: &[Job], mut rows: Vec<ScanRow>) -> Vec<ScanRow> {
    // A `position()` per row is quadratic: measured on a 500 000-job sweep, the
    // connects took about 2 s and this ordering took the other ~115 s of the run.
    // One pass to index the job list makes it linear, and a wide sweep is the
    // case this tool exists for.
    let mut rank: std::collections::HashMap<(u32, u32, crate::model::FlagSet), usize> =
        std::collections::HashMap::with_capacity(all.len());
    for (i, j) in all.iter().enumerate() {
        rank.insert((j.cid, j.port, j.flags), i);
    }
    // Nothing outside the job list should exist; if it does, it sorts last
    // rather than panicking over a bookkeeping slip mid-sweep.
    rows.sort_by_key(|r| {
        rank.get(&(r.cid, r.port, r.flags))
            .copied()
            .unwrap_or(usize::MAX)
    });
    rows
}

/// Findings are facts, not per-row log lines: `--flags both` probes the same
/// port twice, and two identical warnings teach the reader nothing.
fn already_reported(findings: &[Finding], message: &str) -> bool {
    findings.iter().any(|f| f.message == message)
}

/// Census vs sweep, both directions (spec §6.3.4). Each divergence has a
/// different explanation, so each gets its own finding rather than a merged one.
pub fn cross_check_diag(report: &mut Report) {
    let entries: Vec<DiagEntry> = report.diag_entries.clone();
    if entries.is_empty() {
        return;
    }
    let listen = |cid: u32, port: u32| -> Option<&DiagEntry> {
        entries.iter().find(|e| {
            e.state == crate::diag::STATE_LISTEN
                && (e.src_cid == cid || e.src_cid == u32::MAX)
                && e.src_port == port
        })
    };
    for r in &report.rows {
        match (listen(r.cid, r.port), r.outcome.kind) {
            (Some(e), k) if !reached(r) => {
                let message =
                    format!(
                    "a listener is bound at CID {} port {} (ino {}, pid {}) but connecting to it \
                     reported {} — a full backlog, a transport that does not route to it, or a \
                     namespace the census sees and the connect does not",
                    r.cid,
                    r.port,
                    e.ino,
                    e.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string()),
                    k.as_str()
                );
                // `--flags both` probes one port twice: one fact, one finding.
                if !already_reported(&report.findings, &message) {
                    report.findings.push(Finding {
                        severity: Severity::Warn,
                        message,
                    });
                }
            }
            (None, _) if reached(r) => {
                let message = format!(
                    "CID {} port {} connected with no bound socket for it in this namespace's \
                     census — loopback redirect, or a listener in another namespace",
                    r.cid, r.port
                );
                if !already_reported(&report.findings, &message) {
                    report.findings.push(Finding {
                        severity: Severity::Warn,
                        message,
                    });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_pool_returns_what_completed_and_says_so() {
        // Ctrl-C must degrade to a partial answer with an honest count, never to a
        // panic over the holes or a full-size claim.
        let stop = AtomicBool::new(true);
        let jobs = jobs(&[3], &[1, 2, 3, 4, 5], FlagMode::None);
        let (rows, planned) = sweep(&jobs, 4, 50, 0, &stop);
        assert_eq!(planned, 5);
        assert!(
            rows.is_empty(),
            "a stopped pool issued {} connects",
            rows.len()
        );
    }

    #[test]
    fn ordering_a_partial_sweep_keeps_job_order() {
        let all = jobs(&[3, 4], &[80, 443], FlagMode::None);
        let row = |cid: u32, port: u32| ScanRow {
            cid,
            port,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::Closed),
            elapsed_ms: 0,
            banner: None,
        };
        let mut partial = all
            .iter()
            .map(|j| row(j.cid, j.port))
            .collect::<Vec<ScanRow>>();
        partial.retain(|r| !(r.cid == 3 && r.port == 80));
        let ordered = keep_order_rows(&all, partial);
        assert_eq!(ordered.len(), 3);
        assert_eq!(
            ordered.iter().map(|r| (r.cid, r.port)).collect::<Vec<_>>(),
            vec![(3, 443), (4, 80), (4, 443)],
            "holes must not reshuffle the remaining rows"
        );
    }

    fn row(cid: u32, port: u32, flags: FlagSet, kind: OutcomeKind) -> ScanRow {
        ScanRow {
            cid,
            port,
            flags,
            outcome: Outcome::new(kind),
            elapsed_ms: 1,
            banner: None,
        }
    }

    #[test]
    fn job_order_is_cid_major_then_port_then_flag() {
        let j = jobs(&[2, 3], &[80, 22], FlagMode::Both);
        let got: Vec<(u32, u32, &str)> =
            j.iter().map(|x| (x.cid, x.port, x.flags.label())).collect();
        assert_eq!(
            got,
            vec![
                (2, 80, "none"),
                (2, 80, "to-host"),
                (2, 22, "none"),
                (2, 22, "to-host"),
                (3, 80, "none"),
                (3, 80, "to-host"),
                (3, 22, "none"),
                (3, 22, "to-host"),
            ]
        );
        assert_eq!(jobs(&[2], &[1], FlagMode::Both).len(), 2);
        assert_eq!(jobs(&[2, 3], &[1, 2, 3], FlagMode::None).len(), 6);
    }

    /// The measured signature: the same errno means
    /// different things depending on the stage it arrived at, and the stage is
    /// carried through to the detail line.
    #[test]
    fn classifier_matches_the_measured_rows() {
        let cases: Vec<(Connect, OutcomeKind, &str)> = vec![
            (Connect::Established, OutcomeKind::Open, "connect completed"),
            (
                Connect::Failed {
                    errno: libc::ENODEV,
                    stage: "connect",
                },
                OutcomeKind::RefusedKernel,
                "no transport, or transport with no device",
            ),
            (
                Connect::Failed {
                    errno: libc::EINVAL,
                    stage: "connect",
                },
                OutcomeKind::RefusedKernel,
                "address the kernel will not route",
            ),
            (
                Connect::Failed {
                    errno: libc::EADDRNOTAVAIL,
                    stage: "connect",
                },
                OutcomeKind::RefusedKernel,
                "no route to that CID",
            ),
            (
                Connect::Failed {
                    errno: libc::ECONNRESET,
                    stage: "SO_ERROR",
                },
                OutcomeKind::Closed,
                "muxer RST for a port with no host listener",
            ),
            (
                Connect::Failed {
                    errno: libc::ECONNREFUSED,
                    stage: "SO_ERROR",
                },
                OutcomeKind::Closed,
                "RST from a transport with no peer",
            ),
            (
                Connect::Failed {
                    errno: libc::ESOCKTNOSUPPORT,
                    stage: "connect",
                },
                OutcomeKind::Unsupported,
                "no seqpacket path here",
            ),
            (
                Connect::Failed {
                    errno: libc::EAFNOSUPPORT,
                    stage: "connect",
                },
                OutcomeKind::Unsupported,
                "no AF_VSOCK at all",
            ),
            (
                Connect::Failed {
                    errno: libc::ETIMEDOUT,
                    stage: "SO_ERROR",
                },
                OutcomeKind::Silent,
                "frame left, nothing answered",
            ),
            (
                Connect::Timeout,
                OutcomeKind::Silent,
                "unrouted dst_cid drop",
            ),
            (
                Connect::Failed {
                    errno: libc::EACCES,
                    stage: "connect",
                },
                OutcomeKind::Error,
                "privileged port as non-root is not a reachability answer",
            ),
        ];
        for (res, want, why) in cases {
            let got = classify(&res);
            assert_eq!(
                got.kind, want,
                "{why}: {res:?} classified as {:?}",
                got.kind
            );
            let arrived_somewhere_other_than_so_error =
                matches!(&res, Connect::Failed { stage, .. } if *stage != "SO_ERROR");
            assert!(
                !arrived_somewhere_other_than_so_error || got.detail.is_some(),
                "{why}: an errno that did not come from SO_ERROR must say where it came from"
            );
        }
    }

    #[test]
    fn redirect_only_relabels_cid_2_and_keeps_the_errno() {
        let closed = classify(&Connect::Failed {
            errno: libc::ECONNRESET,
            stage: "SO_ERROR",
        });
        let r = apply_canary(closed.clone(), 2, TellState::Yes);
        assert_eq!(r.kind, OutcomeKind::LoopbackRedirect);
        assert_eq!(r.errno, Some(libc::ECONNRESET));
        assert!(r.detail.unwrap().contains("nothing about the host"));
        // Other CIDs, and a canary that never fired or could not fire, are untouched.
        assert_eq!(
            apply_canary(closed.clone(), 3, TellState::Yes).kind,
            OutcomeKind::Closed
        );
        assert_eq!(
            apply_canary(closed.clone(), 2, TellState::No).kind,
            OutcomeKind::Closed
        );
        assert_eq!(
            apply_canary(closed.clone(), 2, TellState::Inert).kind,
            OutcomeKind::Closed
        );
        // A frame that never left the host cannot have been redirected.
        let refused = classify(&Connect::Failed {
            errno: libc::ENODEV,
            stage: "connect",
        });
        assert_eq!(
            apply_canary(refused.clone(), 2, TellState::Yes).kind,
            OutcomeKind::RefusedKernel
        );
        let unsupported = classify(&Connect::Failed {
            errno: libc::ESOCKTNOSUPPORT,
            stage: "connect",
        });
        assert_eq!(
            apply_canary(unsupported, 2, TellState::Yes).kind,
            OutcomeKind::Unsupported
        );
    }

    #[test]
    fn sweep_output_is_in_job_order_whatever_completes_first() {
        // Loopback on the host: every port answers, the pool is wider than the
        // job list, and completion order is whatever the scheduler feels like.
        let j = jobs(
            &[2],
            &[47001, 47002, 47003, 47004, 47005, 47006],
            FlagMode::None,
        );
        let (rows, planned) = sweep(&j, 8, 200, 0, &AtomicBool::new(false));
        assert_eq!(planned, j.len());
        assert_eq!(rows.len(), 6);
        let ports: Vec<u32> = rows.iter().map(|r| r.port).collect();
        assert_eq!(ports, vec![47001, 47002, 47003, 47004, 47005, 47006]);
        assert!(
            rows.iter().all(|r| matches!(
                r.outcome.kind,
                OutcomeKind::Closed | OutcomeKind::RefusedKernel | OutcomeKind::Silent
            )),
            "unlisted ports must not look open: {:?}",
            rows.iter().map(|r| r.outcome.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn emitted_rows_keep_their_canonical_position_when_pruning_reorders_them() {
        let all = jobs(&[1, 2], &[22, 80], FlagMode::None);
        let rows = vec![
            row(2, 22, FlagSet::None, OutcomeKind::Open),
            row(1, 80, FlagSet::None, OutcomeKind::Silent),
            row(1, 22, FlagSet::None, OutcomeKind::Open),
            row(2, 80, FlagSet::None, OutcomeKind::Closed),
        ];
        let out = keep_order_rows(&all, rows);
        assert_eq!(
            out.iter().map(|r| (r.cid, r.port)).collect::<Vec<_>>(),
            vec![(1, 22), (1, 80), (2, 22), (2, 80)]
        );
        // A row that is not in the job list is a bookkeeping slip, not a panic.
        let stray = row(9, 9, FlagSet::None, OutcomeKind::Error);
        assert_eq!(keep_order_rows(&all, vec![stray])[0].cid, 9);
    }

    #[test]
    fn stage1_selection_is_deterministic_and_widens_to_the_tails() {
        let p: Vec<u32> = (0..20).collect();
        assert_eq!(stage1_ports(&p, 3), vec![0, 1, 2, 10, 19]);
        assert_eq!(stage1_ports(&p, 25), (0..20).collect::<Vec<_>>());
        assert_eq!(stage1_ports(&[], 3), Vec::<u32>::new());
        // Two runs must select the same ports or evidence cannot be compared.
        assert_eq!(stage1_ports(&p, 3), stage1_ports(&p, 3));
    }

    #[test]
    fn flags_both_reports_only_real_disagreements() {
        let rows = vec![
            row(2, 80, FlagSet::None, OutcomeKind::Open),
            row(2, 80, FlagSet::ToHost, OutcomeKind::Open),
        ];
        assert!(flag_disagreements(FlagMode::Both, &rows).is_empty());

        let rows = vec![
            row(2, 80, FlagSet::None, OutcomeKind::Open),
            row(2, 80, FlagSet::ToHost, OutcomeKind::Closed),
            row(2, 22, FlagSet::None, OutcomeKind::Closed),
            row(2, 22, FlagSet::ToHost, OutcomeKind::Closed),
        ];
        let mut report = Report::new("scan", crate::model::placeholder_header());
        report.rows = rows;
        report.recompute_summary(0);
        assert_eq!(
            report.summary.flags_agree,
            Some(false),
            "the model must see the disagreement"
        );
        let f = flag_disagreements(FlagMode::Both, &report.rows);
        assert_eq!(f.len(), 1, "only the port that differs is reported");
        assert!(f[0].message.contains("port 80"));
        assert!(f[0].message.contains("open") && f[0].message.contains("closed"));
    }

    #[test]
    fn census_and_sweep_diverge_in_both_directions() {
        let entry = DiagEntry {
            family: 40,
            kind: 1,
            state: crate::diag::STATE_LISTEN,
            shutdown: 0,
            src_cid: 3,
            src_port: 10809,
            dst_cid: u32::MAX,
            dst_port: u32::MAX,
            ino: 4242,
            cookie: "00".into(),
            pid: Some(999),
            pid_comm: Some("test-listen".into()),
        };
        let mut report = Report::new("scan", crate::model::placeholder_header());
        report.diag_entries.push(entry);
        report
            .rows
            .push(row(3, 10809, FlagSet::None, OutcomeKind::Silent));
        report
            .rows
            .push(row(3, 1234, FlagSet::None, OutcomeKind::Open));
        // `--flags both` probes one port twice: the same fact must not appear twice.
        report
            .rows
            .push(row(3, 10809, FlagSet::ToHost, OutcomeKind::Silent));
        // A redirected *refusal* is not a connection: it must not invent a finding
        // about a port nothing is bound to.
        let mut refused = row(2, 9999, FlagSet::None, OutcomeKind::LoopbackRedirect);
        refused.outcome = refused.outcome.with_errno(libc::ECONNRESET);
        report.rows.push(refused);
        cross_check_diag(&mut report);
        assert_eq!(
            report.findings.len(),
            2,
            "{:?}",
            report
                .findings
                .iter()
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );
        assert!(report.findings[0].message.contains("full backlog"));
        assert!(report.findings[0].message.contains("pid 999"));
        assert!(report.findings[1].message.contains("another namespace"));
    }

    /// The `--open` step over an assembled sweep: the same code path `run`
    /// takes, exercised without an AF_VSOCK environment.
    #[test]
    fn open_only_keeps_answered_rows_and_notes_the_filter() {
        let mut report = Report::new("scan", crate::model::placeholder_header());
        report.rows = vec![
            row(3, 22, FlagSet::None, OutcomeKind::Open),
            row(3, 80, FlagSet::None, OutcomeKind::RefusedKernel),
            row(3, 443, FlagSet::None, OutcomeKind::Closed),
        ];
        report.recompute_summary(0);
        let note = apply_open(&mut report);
        assert_eq!(note, "--open: showing 1 open row(s) of 3", "{note}");
        assert_eq!(report.rows.len(), 1, "{:?}", report.rows);
        assert_eq!(report.rows[0].outcome.kind, OutcomeKind::Open);
        assert_eq!(
            report.summary.results, 3,
            "the summary counts the sweep, not the filtered view"
        );
    }

    #[test]
    fn open_only_notes_zero_open_as_an_answer_not_a_failure() {
        // "swept 1, nothing open" must be distinguishable from "failed to sweep".
        let mut report = Report::new("scan", crate::model::placeholder_header());
        report.rows = vec![row(3, 22, FlagSet::None, OutcomeKind::RefusedKernel)];
        report.recompute_summary(0);
        let note = apply_open(&mut report);
        assert_eq!(note, "--open: showing 0 open row(s) of 1", "{note}");
        assert!(report.rows.is_empty());
        assert_eq!(report.summary.results, 1);
    }
}
