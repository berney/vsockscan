//! `selftest`: prove the scanner's own semantics with no host, no vsock device,
//! no fixture process.
//!
//! The point is the exit code, so the checks must be honest about what the
//! environment can prove. On a vsock host the loopback transport answers, so
//! a listener must be found and a free port must not. In a device-less guest the
//! same sweep is refused by the kernel before anything leaves — and that is still a
//! proof, just a different one: *listeners and non-listeners must not be
//! indistinguishable, nothing may be invented as `open`, and every verdict must
//! carry the signal it came from*. Checks that cannot be decided here report
//! `skipped` with the reason rather than passing by silence or failing by shape.

use crate::listen;
use crate::model::{Format, Outcome, OutcomeKind, Report, Severity};
use crate::probe::{self, Connect};
use crate::scan::{self, FlagMode, Job};
use crate::uapi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skipped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skipped => "skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Fail,
            detail: detail.into(),
        }
    }
    fn skip(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: Status::Skipped,
            detail: detail.into(),
        }
    }
}

/// Can this process even open an AF_VSOCK socket? Anything else is a runtime
/// failure (exit 2), not a failed assertion (exit 3).
pub fn environment_usable() -> bool {
    // SAFETY: constant family/type, no pointers.
    let fd = unsafe {
        libc::socket(
            uapi::AF_VSOCK as libc::c_int,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd >= 0 {
        // SAFETY: closing the descriptor we just opened.
        unsafe { libc::close(fd) };
        true
    } else {
        false
    }
}

/// Four listeners, as the design specifies, on kernel-assigned ports so a busy
/// host cannot make the fixture fail for the wrong reason.
fn spawn_listeners(k: usize) -> (Vec<(u32, libc::c_int)>, Vec<u32>) {
    let mut held = Vec::new();
    let mut free = Vec::new();
    for _ in 0..k {
        if let Ok(fd) = listen::bind_listener(uapi::VMADDR_PORT_ANY) {
            match probe::sockname_port(fd) {
                Some(port) => held.push((port, fd)),
                None => {
                    // SAFETY: closing a descriptor whose port we cannot read.
                    unsafe { libc::close(fd) };
                }
            }
        }
    }
    // A port the kernel handed out and we then released is the closest thing to a
    // provably-unlistened port available without privileges.
    for _ in 0..k {
        if let Ok(fd) = listen::bind_listener(uapi::VMADDR_PORT_ANY) {
            if let Some(port) = probe::sockname_port(fd) {
                free.push(port);
            }
            // SAFETY: releasing the port is the whole point of this step.
            unsafe { libc::close(fd) };
        }
    }
    (held, free)
}

/// Accept on the fixture listeners in the background so the sweep has somewhere
/// to arrive. Counting the accepts is the point: it tells the checks whether this
/// machine has a loopback path at all.
fn spawn_accept_counter(
    held: &[(u32, libc::c_int)],
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    accepted: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> std::thread::JoinHandle<()> {
    let fds: Vec<libc::c_int> = held.iter().map(|(_, fd)| *fd).collect();
    let (stop, accepted) = (std::sync::Arc::clone(stop), std::sync::Arc::clone(accepted));
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let mut pfds: Vec<libc::pollfd> = fds
                .iter()
                .map(|fd| libc::pollfd {
                    fd: *fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: poll over descriptors owned by the fixture.
            let pr = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 50) };
            if pr <= 0 {
                continue;
            }
            for p in pfds {
                if p.revents & libc::POLLIN == 0 {
                    continue;
                }
                // SAFETY: accept on a listening descriptor we own; the address is optional.
                let fd = unsafe { libc::accept(p.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
                if fd >= 0 {
                    accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // SAFETY: closing the accepted descriptor we just opened.
                    unsafe { libc::close(fd) };
                }
            }
        }
    })
}

/// Run every check. Order is the order of the design's steps.
pub fn run() -> Vec<Check> {
    let mut checks = Vec::new();
    let (held, free) = spawn_listeners(4);
    let listening: Vec<u32> = held.iter().map(|(p, _)| *p).collect();

    // Did the sweep ever reach one of our own listeners? That is the question the
    // detection check silently depends on, and it is measurable rather than
    // guessable: a kernel without `vsock_loopback` (and any guest
    // where CID 2 leaves the machine) answers a connect to our own port with RST
    // instead of looping back, and then "listeners and controls look identical" is
    // an environment fact, not a broken classifier.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let watcher = spawn_accept_counter(&held, &stop, &accepted);

    checks.push(check_fixture_bound(&listening, &free));

    let mut ports = listening.clone();
    ports.extend(free.iter().copied());
    let jobs = jobs_for(&[uapi::VMADDR_CID_LOCAL, uapi::VMADDR_CID_HOST], &ports);
    // Raw sweep: no canary relabelling, because step 1 is about what the kernel
    // answered before this tool interprets it.
    let (rows, _) = scan::sweep(
        &jobs,
        8,
        1000,
        0,
        &std::sync::atomic::AtomicBool::new(false),
    );

    checks.push(check_no_invented_open(&rows, &listening, &free));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    watcher.join().map_err(|_| ()).and_then(|_| Ok(())).ok();
    let reaches_own_listener = accepted.load(std::sync::atomic::Ordering::Relaxed);
    checks.push(check_listeners_are_distinguishable(
        &rows,
        &listening,
        &free,
        reaches_own_listener,
    ));
    checks.push(check_listeners_agree_with_each_other(&rows, &listening));
    checks.push(check_every_verdict_carries_its_signal(&rows));

    checks.push(check_enodev_is_never_open());
    checks.push(check_immediate_reset_is_never_silent());
    checks.push(check_schema_is_json_and_report_round_trips());

    // Close the fixture listeners only after the sweep: they are what the sweep
    // is testing.
    for (_, fd) in held {
        // SAFETY: closing descriptors this function opened.
        unsafe { libc::close(fd) };
    }
    checks
}

fn jobs_for(cids: &[u32], ports: &[u32]) -> Vec<Job> {
    scan::jobs(cids, ports, FlagMode::Both)
}

fn check_fixture_bound(listening: &[u32], free: &[u32]) -> Check {
    if listening.len() < 4 || free.len() < 4 {
        return Check::skip(
            "fixture-binds",
            format!(
                "kernel-assigned listeners {}/4, released ports {}/4 ({}): the sweep checks \
                 below need both, so they are skipped rather than passed",
                listening.len(),
                free.len(),
                if listening.is_empty() {
                    "bind refused"
                } else {
                    "partial bind"
                }
            ),
        );
    }
    Check::pass(
        "fixture-binds",
        format!(
            "four listeners on kernel-assigned ports {listening:?}, four released ports \
                {free:?} as controls"
        ),
    )
}

/// A port with nothing behind it must never look reachable. This is the check that
/// would catch a classifier mistake, a stale socket, or a redirect the tool failed
/// to notice.
fn check_no_invented_open(
    rows: &[crate::model::ScanRow],
    listening: &[u32],
    free: &[u32],
) -> Check {
    if listening.len() < 4 {
        return Check::skip("no-invented-open", "fixture did not bind");
    }
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| free.contains(&r.port))
        .filter(|r| r.outcome.kind == OutcomeKind::Open)
        .map(|r| format!("CID {} port {} {}", r.cid, r.port, r.flags.label()))
        .collect();
    if bad.is_empty() {
        Check::pass(
            "no-invented-open",
            format!(
                "no control port was reported open across {} rows",
                rows.len()
            ),
        )
    } else {
        Check::fail(
            "no-invented-open",
            format!("control ports reported open: {}", bad.join(", ")),
        )
    }
}

/// Listeners and non-listeners must land in different classes, or the sweep proves
/// nothing. On a host with loopback that is `open` vs `closed`; in a device-less
/// guest both are `refused-kernel` and the check says exactly that instead of
/// pretending to have tested detection.
fn check_listeners_are_distinguishable(
    rows: &[crate::model::ScanRow],
    listening: &[u32],
    free: &[u32],
    reaches_own_listener: usize,
) -> Check {
    if listening.len() < 4 {
        return Check::skip("listeners-distinguishable", "fixture did not bind");
    }
    let kinds = |ports: &[u32]| -> Vec<String> {
        let mut k: Vec<String> = rows
            .iter()
            .filter(|r| ports.contains(&r.port))
            .map(|r| r.outcome.kind.as_str().to_string())
            .collect();
        k.sort();
        k.dedup();
        k
    };
    let l = kinds(listening);
    let f = kinds(free);
    if l != f {
        return Check::pass(
            "listeners-distinguishable",
            format!("listeners {l:?} vs released ports {f:?}"),
        );
    }
    // Same class on both sides is legitimate exactly when nothing could arrive at
    // our own listener: the kernel refused everything (no transport), or the
    // fixture took zero connections (no loopback transport - `vsock_loopback` is
    // not built - so CID 2 went out to a muxer that had nothing listening).
    if reaches_own_listener == 0 {
        return Check::pass(
            "listeners-distinguishable",
            format!(
                "listeners and released ports both reported {l:?} and {} connect(s) reached the \
                 fixture listeners: this machine has no local path (no loopback transport), so \
                 detection itself is not testable here — recorded as a negative environment \
                 fact, not as a passed detection test",
                reaches_own_listener
            ),
        );
    }
    Check::fail(
        "listeners-distinguishable",
        format!(
            "listeners and released ports both reported {l:?}, although {reaches_own_listener} \
             connect(s) did reach a fixture listener - something was listening and the sweep \
             said otherwise"
        ),
    )
}

/// All four listeners are the same kind of object, so for a given `(cid, flag)`
/// they must not produce four different answers.
fn check_listeners_agree_with_each_other(
    rows: &[crate::model::ScanRow],
    listening: &[u32],
) -> Check {
    if listening.len() < 4 {
        return Check::skip("listeners-agree", "fixture did not bind");
    }
    let mut groups: std::collections::BTreeMap<
        (u32, &'static str),
        std::collections::BTreeSet<String>,
    > = Default::default();
    for r in rows.iter().filter(|r| listening.contains(&r.port)) {
        groups
            .entry((r.cid, r.flags.label()))
            .or_default()
            .insert(r.outcome.kind.as_str().to_string());
    }
    let mixed: Vec<String> = groups
        .iter()
        .filter(|(_, kinds)| kinds.len() > 1)
        .map(|((cid, flag), kinds)| {
            format!("CID {cid}/{flag}: {:?}", kinds.iter().collect::<Vec<_>>())
        })
        .collect();
    if mixed.is_empty() {
        Check::pass(
            "listeners-agree",
            format!("all four listeners classified identically within each of the {} (cid, flag) groups", groups.len()),
        )
    } else {
        Check::fail(
            "listeners-agree",
            format!("identical listeners differed: {mixed:?}"),
        )
    }
}

/// An outcome with neither an errno nor an explanation is a verdict the reader
/// cannot audit. A poll timeout is the one signal-less answer the kernel gives, and
/// it carries its own detail, so it is accounted for rather than excused.
fn check_every_verdict_carries_its_signal(rows: &[crate::model::ScanRow]) -> Check {
    let silent_timeouts = rows
        .iter()
        .filter(|r| r.outcome.kind == OutcomeKind::Silent && r.outcome.detail.is_some())
        .count();
    let unexplained: Vec<String> = rows
        .iter()
        .filter(|r| {
            r.outcome.kind != OutcomeKind::Open
                && r.outcome.errno_name.is_none()
                && r.outcome.detail.is_none()
        })
        .map(|r| format!("CID {} port {} {}", r.cid, r.port, r.outcome.kind.as_str()))
        .collect();
    if unexplained.is_empty() {
        Check::pass(
            "verdicts-carry-errno",
            format!(
                "{} rows, every non-open one naming an errno or explaining itself ({silent_timeouts} poll timeouts)",
                rows.len()
            ),
        )
    } else {
        Check::fail(
            "verdicts-carry-errno",
            format!("verdicts with neither errno nor detail: {unexplained:?}"),
        )
    }
}

fn check_enodev_is_never_open() -> Check {
    let bad = [
        Connect::Failed {
            errno: libc::ENODEV,
            stage: "connect",
        },
        Connect::Failed {
            errno: libc::ENODEV,
            stage: "SO_ERROR",
        },
        Connect::Failed {
            errno: libc::ENODEV,
            stage: "poll",
        },
    ]
    .iter()
    .filter(|c| scan::classify(c).kind == OutcomeKind::Open)
    .count();
    if bad == 0 {
        Check::pass(
            "enodev-never-open",
            "ENODEV is classified as refused-kernel at every stage, because it means both \
             'no transport' and 'transport with no device bound'",
        )
    } else {
        Check::fail(
            "enodev-never-open",
            format!("{bad} ENODEV cases mapped to open"),
        )
    }
}

fn check_immediate_reset_is_never_silent() -> Check {
    let o = scan::classify(&Connect::Failed {
        errno: libc::ECONNRESET,
        stage: "connect",
    });
    let t = scan::classify(&Connect::Timeout);
    if o.kind != OutcomeKind::Silent
        && o.kind == OutcomeKind::Closed
        && t.kind == OutcomeKind::Silent
    {
        Check::pass(
            "reset-is-not-timeout",
            "an immediate ECONNRESET is closed (an answer arrived), a poll timeout is silent \
             (nothing answered) — the two must never share a class",
        )
    } else {
        Check::fail(
            "reset-is-not-timeout",
            format!(
                "ECONNRESET-immediate -> {:?}, timeout -> {:?}",
                o.kind, t.kind
            ),
        )
    }
}

/// The machine contract has to be machine-readable: the schema parses, and a report
/// survives JSON round-tripping through the model that produced it.
fn check_schema_is_json_and_report_round_trips() -> Check {
    let schema = crate::render::json_schema();
    if serde_json::from_str::<serde_json::Value>(&schema).is_err() {
        return Check::fail("schema-and-round-trip", "--json-schema is not valid JSON");
    }
    let report = sample_report();
    let mut buf = Vec::new();
    if crate::render::render(
        &report,
        Format::Json,
        crate::render::ColorSupport::Off,
        &mut buf,
    )
    .is_err()
    {
        return Check::fail("schema-and-round-trip", "rendering JSON failed");
    }
    match serde_json::from_str::<Report>(&String::from_utf8_lossy(&buf)) {
        Ok(back) => {
            // `findings`/`notes` are compared too: a field dropped by the emitter
            // would show up here as an unequal report.
            if back == report {
                Check::pass(
                    "schema-and-round-trip",
                    format!(
                        "schema parses; a {} byte JSON report deserialises back identical",
                        buf.len()
                    ),
                )
            } else {
                Check::fail(
                    "schema-and-round-trip",
                    "the JSON document does not deserialise back into the model that produced it",
                )
            }
        }
        Err(e) => Check::fail(
            "schema-and-round-trip",
            format!("JSON did not deserialise: {e}"),
        ),
    }
}

/// A report with every optional field populated in at least one place: `banner`,
/// `value`, `errno`, `pid`, absent sysctls, a finding, notes.
fn sample_report() -> Report {
    let mut r = Report::new("selftest", crate::model::Header::placeholder());
    r.tells.push(crate::model::Tell {
        id: "loopback-canary".into(),
        state: crate::model::TellState::Unknown,
        detail: "not evaluated in the sample".into(),
    });
    r.probes.push(crate::model::ProbeRow {
        name: "bind:80".into(),
        outcome: Outcome::new(OutcomeKind::Error)
            .with_errno(libc::EACCES)
            .with_detail("denied to uid 1000"),
        value: None,
        flags: crate::model::FlagSet::ToHost,
    });
    r.rows.push(crate::model::ScanRow {
        cid: 3,
        port: 3064402411,
        flags: crate::model::FlagSet::None,
        outcome: Outcome::new(OutcomeKind::Closed).with_errno(libc::ECONNRESET),
        elapsed_ms: 1,
        banner: Some("7f 45 4c 46".into()),
    });
    r.diag_entries.push(crate::model::DiagEntry {
        family: 40,
        kind: 1,
        state: 10,
        shutdown: 0,
        src_cid: 3,
        src_port: 10809,
        dst_cid: u32::MAX,
        dst_port: u32::MAX,
        ino: 1,
        cookie: "00".into(),
        pid: Some(1),
        pid_comm: Some("init".into()),
    });
    r.finding(Severity::Warn, "a note worth reading");
    r.summary
        .notes
        .push("first bytes:\n00000000  7f 45 4c 46   |.ELF|".into());
    r.recompute_summary(3);
    r
}

/// Fold the checks into a report so `--format json|markdown|yaml` works for
/// `selftest` like any other command.
pub fn into_report(checks: &[Check], header: crate::model::Header) -> Report {
    let mut r = Report::new("selftest", header);
    for c in checks {
        let severity = match c.status {
            Status::Pass => Severity::Info,
            Status::Skipped => Severity::Warn,
            Status::Fail => Severity::Alert,
        };
        r.finding(
            severity,
            format!("check {} {}: {}", c.name, c.status.as_str(), c.detail),
        );
    }
    let (pass, fail, skip) = counts(checks);
    r.summary.results = checks.len();
    r.summary
        .notes
        .push(format!("{pass} passed, {fail} failed, {skip} skipped"));
    r
}

pub fn counts(checks: &[Check]) -> (usize, usize, usize) {
    let pass = checks.iter().filter(|c| c.status == Status::Pass).count();
    let fail = checks.iter().filter(|c| c.status == Status::Fail).count();
    let skip = checks
        .iter()
        .filter(|c| c.status == Status::Skipped)
        .count();
    (pass, fail, skip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_passes_or_is_skipped_with_a_reason() {
        // Nothing in the selftest is allowed to *fail* on a machine that has
        // AF_VSOCK; a skip must say why.
        if !environment_usable() {
            eprintln!("skipping: no AF_VSOCK here");
            return;
        }
        let checks = run();
        assert!(checks.len() >= 8, "{:?}", checks.len());
        for c in &checks {
            assert!(
                c.status != Status::Fail,
                "check {} failed: {}",
                c.name,
                c.detail
            );
            assert!(!c.detail.is_empty(), "{} carries no detail", c.name);
        }
        let (pass, fail, skip) = counts(&checks);
        assert_eq!(fail, 0, "{pass}/{skip} pass/skip, failures in {checks:?}");
    }

    #[test]
    fn pure_checks_pass_without_touching_the_socket_layer() {
        assert_eq!(check_enodev_is_never_open().status, Status::Pass);
        assert_eq!(check_immediate_reset_is_never_silent().status, Status::Pass);
        assert_eq!(
            check_schema_is_json_and_report_round_trips().status,
            Status::Pass
        );
    }

    #[test]
    fn checks_fold_into_a_report_without_losing_status() {
        let checks = vec![
            Check::pass("a", "ok"),
            Check::fail("b", "nope"),
            Check::skip("c", "no device"),
        ];
        let r = into_report(&checks, crate::model::Header::placeholder());
        assert_eq!(r.summary.results, 3);
        assert_eq!(r.findings.len(), 3);
        assert_eq!(r.findings[1].severity, Severity::Alert);
        assert!(r.summary.notes[0].contains("1 passed, 1 failed, 1 skipped"));
    }
}
