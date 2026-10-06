//! `h2g`: sweep a guest's listening ports from the Firecracker host.
//!
//! See docs/superpowers/specs/2026-10-07-h2g-open-design.md. The vantage is
//! the muxer's, so the taxonomy is the filesystem's plus a text line:
//! absent / denied / stale / not-muxer / silent join open / closed.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::model::{filter_open, FlagSet, Outcome, OutcomeKind, ProbeRow, Report, Severity};
use crate::muxer::{self, Attempt};

pub struct Opts<'a> {
    pub ports: &'a [u32],
    pub uds: &'a Path,
    pub timeout_ms: i32,
    pub parallel: usize,
    pub banner: usize,
    pub open_only: bool,
}

/// Filesystem and handshake answers mapped onto the h2g taxonomy. The two
/// mid-flight errnos are answers from the other end, not local errors:
/// `socket()` and `connect()` never emit EPIPE, so a write-side EPIPE is the
/// guest hanging up on the handshake - a refusal, i.e. Closed - and an
/// AF_UNIX `connect()` reports a vanished peer as ECONNRESET, exactly what
/// ECONNREFUSED says about a socket file whose listener died.
pub fn kind_for_errno(e: i32) -> OutcomeKind {
    match e {
        libc::ENOENT => OutcomeKind::Absent,
        libc::EACCES => OutcomeKind::Denied,
        libc::ECONNREFUSED | libc::ECONNRESET => OutcomeKind::Stale,
        libc::EPIPE => OutcomeKind::Closed,
        _ => OutcomeKind::Error,
    }
}

#[derive(Debug)]
pub struct Preflight {
    pub alert: Option<String>,
}

/// One canary CONNECT before a sweep commits its port list to this socket:
/// `Err` is a uds_path that cannot answer a handshake at all (report it,
/// connect nothing), `Ok` means sweep - and `alert` says the guest answered
/// the random port, which is a finding about the guest, not an abort.
pub fn preflight(path: &Path, timeout_ms: i32, port: u32) -> Result<Preflight, String> {
    // Validate the path length *here*: `probe` reports an over-long path as
    // NotMuxer, and "that is not a muxer" would blame the guest for what is
    // our argument's fault. `sun_path` holds 107 bytes plus the NUL.
    // SAFETY: an all-zero sockaddr_un is a valid value; only the field length is read.
    let zeroed: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let sun_path_max = zeroed.sun_path.len() - 1;
    if path.as_os_str().as_bytes().len() > sun_path_max {
        return Err(format!(
            "preflight: {}: the path is longer than the {sun_path_max}-byte AF_UNIX sun_path limit",
            path.display()
        ));
    }
    let (attempt, _) = muxer::probe(path, port, timeout_ms, 0);
    match attempt {
        Attempt::Closed => Ok(Preflight { alert: None }),
        Attempt::Open { host_port: _ } => Ok(Preflight {
            alert: Some(format!(
                "the guest answered CONNECT on a random high port ({port}); \
                 a forwarder or proxy agent is listening on more than its services",
            )),
        }),
        other => Err(format!(
            "preflight: {}: {}",
            path.display(),
            describe(&other)
        )),
    }
}

/// Why an attempt is not a sweepable muxer, leading with the taxonomy word
/// so the report reads "absent", never a bare errno.
fn describe(a: &Attempt) -> String {
    match a {
        Attempt::ConnectFail { errno } => {
            let kind = kind_for_errno(*errno);
            format!(
                "{} ({}): {}",
                kind.as_str(),
                crate::uapi::errno_label(*errno),
                match kind {
                    OutcomeKind::Absent =>
                        "no VM with this uds_path; a jailer resolves uds_path inside the jail root",
                    OutcomeKind::Denied =>
                        "the socket file denies this uid; jail roots are usually root-owned",
                    OutcomeKind::Stale =>
                        "a socket file with no listener: a VM that died without cleanup",
                    _ => "the path exists but refused us",
                }
            )
        }
        Attempt::Silent => {
            "connected, but nothing answered the handshake: wedged muxer or a non-vsock daemon"
                .into()
        }
        Attempt::NotMuxer { first_line } => {
            format!("something answered that is not a muxer: {first_line:?}")
        }
        Attempt::Open { host_port } => format!("open unexpectedly (muxer host port {host_port})"),
        Attempt::Closed => "closed".into(),
    }
}

/// One completed job: the port, the handshake answer, and any banner bytes
/// the guest sent after `OK`.
type Job = (u32, Attempt, Vec<u8>);

/// The pool, mirroring `scan::sweep`: an atomic cursor, workers *returning*
/// their `(index, result)` pairs so there is no lock to poison, and job order
/// restored by assembly. Returns `(completed, planned)`: Ctrl-C stops the
/// workers between jobs, so the caller must report the holes it left.
fn sweep(
    ports: &[u32],
    parallel: usize,
    timeout_ms: i32,
    banner: usize,
    uds: &Path,
) -> (Vec<Job>, usize) {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let workers = parallel.clamp(1, ports.len().max(1));
    let chunks: Vec<Vec<(usize, Job)>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        if crate::INTERRUPTED.load(Ordering::Relaxed) {
                            break;
                        }
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= ports.len() {
                            break;
                        }
                        let port = ports[i];
                        let (attempt, bytes) = muxer::probe(uds, port, timeout_ms, banner);
                        local.push((i, (port, attempt, bytes)));
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
            .map(|h| h.join().expect("an h2g worker panicked"))
            .collect()
    });
    let mut slots: Vec<Option<Job>> = (0..ports.len()).map(|_| None).collect();
    for chunk in chunks {
        for (i, outcome) in chunk {
            slots[i] = Some(outcome);
        }
    }
    // Job order is kept so a transcript is comparable between runs; the holes
    // left by an interrupt are dropped, and the caller reports how many there were.
    (slots.into_iter().flatten().collect(), ports.len())
}

pub fn run(o: &Opts, report: &mut Report) -> Result<(), String> {
    if o.ports.is_empty() {
        return Err("h2g needs at least one port (--ports SPEC)".to_string());
    }
    // The canary port: a random high u32. No special range - a real listener
    // there is rare, and the alert is exactly for when it happens.
    let mut seed: u32 = 0;
    // SAFETY: getrandom writes 4 bytes to a live local.
    unsafe { libc::getrandom(&mut seed as *mut _ as *mut libc::c_void, 4, 0) };
    let canary = seed | 0x8000_0000; // high half only keeps it out of the well-known band
    let pre = preflight(o.uds, o.timeout_ms, canary)?;
    if let Some(alert) = pre.alert {
        report.finding(Severity::Warn, alert);
    }
    report.header.noise = format!(
        "planned {} connects through {}; up to {} in parallel, each open channel takes \
         one slot of the muxer's 1023-entry table (shared with the guest's own \
         connections); the handshake is the only traffic unless --banner is set",
        o.ports.len(),
        o.uds.display(),
        o.parallel
    );
    let (results, planned) = sweep(o.ports, o.parallel, o.timeout_ms, o.banner, o.uds);
    let issued = results.len();
    let dropped = planned - issued;

    let mut rows: Vec<ProbeRow> = Vec::with_capacity(results.len());
    for (port, attempt, bytes) in results {
        let (outcome, value) = match attempt {
            Attempt::Open { host_port } => {
                let mut v = format!("muxer host port {host_port}");
                if host_port < (1 << 30) {
                    v.push_str("; below the 2^30 pool: not a stock Firecracker muxer");
                }
                (Outcome::new(OutcomeKind::Open), Some(v))
            }
            Attempt::Closed => (Outcome::new(OutcomeKind::Closed), None),
            Attempt::Silent => (Outcome::new(OutcomeKind::Silent), None),
            Attempt::NotMuxer { first_line } => {
                (Outcome::new(OutcomeKind::NotMuxer), Some(first_line))
            }
            // errno rides the outcome so text/json show the answer, like scan.
            Attempt::ConnectFail { errno } => {
                (Outcome::new(kind_for_errno(errno)).with_errno(errno), None)
            }
        };
        if !bytes.is_empty() {
            // The same note shape `listen` uses for its per-connection preview.
            report.summary.notes.push(format!(
                "first bytes from {port}:\n{}",
                crate::listen::hexdump(&bytes)
            ));
        }
        rows.push(ProbeRow {
            name: format!("connect:{port}"),
            outcome,
            value,
            flags: FlagSet::None,
        });
    }
    if dropped > 0 {
        // An interrupted sweep is a partial answer and must read that way, in
        // scan's words: the row count and the note say the same thing.
        report.summary.notes.push(format!(
            "interrupted after {issued} of {planned} planned connects: {dropped} were never \
             issued, so this is a partial sweep and the endpoints it never reached are unknown, \
             not closed."
        ));
        report.finding(
            Severity::Warn,
            format!("sweep interrupted: {dropped} of {planned} connects did not run"),
        );
    }
    // The summary counts the sweep, never the filtered view: `--open` shrinks
    // the rows, not the evidence of what was probed.
    report.summary.results = rows.len();
    if o.open_only {
        let dropped_open = filter_open(&mut rows);
        report.summary.notes.push(format!(
            "--open: showing {} open row(s) of {}",
            rows.len(),
            rows.len() + dropped_open
        ));
    }
    report.probes.extend(rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Report;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// One test's scratch dir plus socket path, unique per test so parallel
    /// tests never share a file, and short enough for `sun_path`.
    fn sock(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vsockscan-h2g-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("s.sock");
        (dir, path)
    }

    fn opts<'a>(ports: &'a [u32], uds: &'a Path) -> Opts<'a> {
        Opts {
            ports,
            uds,
            timeout_ms: 400,
            parallel: 2,
            banner: 0,
            open_only: false,
        }
    }

    /// A stand-in muxer: reads `CONNECT <port>`, answers `OK 1073741824`
    /// (plus optional banner bytes) for the ports in `open`, and hangs up on
    /// everything else. Bounded at 30 connections and polling for the scratch
    /// dir to disappear, so a finished or panicked test never strands it.
    fn fake_muxer(path: PathBuf, open: Vec<u32>, banner: Option<&'static [u8]>) {
        std::thread::spawn(move || {
            let l = UnixListener::bind(&path).expect("the fake muxer binds");
            l.set_nonblocking(true).expect("nonblocking listener");
            for _ in 0..30 {
                if path.parent().is_none_or(|d| !d.exists()) {
                    break;
                }
                let (mut s, _) = match l.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                // accepted streams inherit the listener's nonblocking mode
                let _ = s.set_nonblocking(false);
                let mut line = String::new();
                let mut b = [0u8; 1];
                while s.read(&mut b).unwrap_or(0) == 1 {
                    if b[0] == b'\n' {
                        break;
                    }
                    line.push(b[0] as char);
                }
                let port = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|p| p.parse::<u32>().ok());
                if port.is_some_and(|p| open.contains(&p)) {
                    let _ = s.write_all(b"OK 1073741824\n");
                    if let Some(bytes) = banner {
                        let _ = s.write_all(bytes);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            let _ = std::fs::remove_file(&path);
        });
    }

    /// Wait for the fake's `bind` to publish the socket file, so the sweep
    /// never races the listener into a spurious `ECONNREFUSED`.
    fn wait_for_bind(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("fake muxer never bound {path:?}");
    }

    #[test]
    fn kind_map() {
        assert_eq!(kind_for_errno(libc::ENOENT), OutcomeKind::Absent);
        assert_eq!(kind_for_errno(libc::EACCES), OutcomeKind::Denied);
        assert_eq!(kind_for_errno(libc::ECONNREFUSED), OutcomeKind::Stale);
        // mid-handshake guest refusal; socket()/connect() never emit EPIPE
        assert_eq!(kind_for_errno(libc::EPIPE), OutcomeKind::Closed);
        // AF_UNIX connect-time peer-gone, same semantics as ECONNREFUSED
        assert_eq!(kind_for_errno(libc::ECONNRESET), OutcomeKind::Stale);
        assert_eq!(kind_for_errno(libc::ENOTSOCK), OutcomeKind::Error);
    }

    #[test]
    fn sweep_classifies_open_and_closed() {
        let (dir, path) = sock("sweep");
        fake_muxer(path.clone(), vec![1235], None);
        wait_for_bind(&path);
        let mut report = Report::new("h2g", crate::model::placeholder_header());
        run(&opts(&[1235, 1236], &path), &mut report).expect("the sweep completes");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(report.probes.len(), 2, "{:?}", report.probes);
        assert!(
            report.probes[0].name.contains("connect:"),
            "{}",
            report.probes[0].name
        );
        assert_eq!(
            report.probes[0].outcome.kind,
            OutcomeKind::Open,
            "{:?}",
            report.probes[0]
        );
        let v = report.probes[0]
            .value
            .clone()
            .expect("the handshake answer");
        assert!(v.contains("muxer host port 1073741824"), "{v}");
        assert_eq!(
            report.probes[1].outcome.kind,
            OutcomeKind::Closed,
            "{:?}",
            report.probes[1]
        );
    }

    #[test]
    fn preflight_aborts_when_the_socket_is_absent() {
        let (dir, path) = sock("absent");
        let mut report = Report::new("h2g", crate::model::placeholder_header());
        let err = run(&opts(&[7], &path), &mut report)
            .expect_err("a missing uds_path aborts before any connect is planned");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.contains("absent"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
    }

    #[test]
    fn preflight_alerts_when_a_random_port_answers() {
        let (dir, path) = sock("canary");
        // `run` picks the canary randomly; the test pins one high value and
        // tells the fake to answer it.
        let canary = 0xA11C_0FFE;
        fake_muxer(path.clone(), vec![canary], None);
        wait_for_bind(&path);
        let pre = preflight(&path, 400, canary).expect("a reachable muxer preflights");
        let alert = pre.alert.expect("a canary answer is an alert");
        assert!(alert.contains("answered CONNECT"), "{alert}");
        let missing = dir.join("gone.sock");
        let err = preflight(&missing, 400, canary).expect_err("absent is not a sweepable target");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.contains("absent"), "{err}");
    }

    #[test]
    fn preflight_aborts_on_a_path_too_long_for_af_unix() {
        // `muxer::probe` would report this as NotMuxer; preflight must blame
        // the argument, not the guest.
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
        let err = preflight(&long, 400, 7).expect_err("108+ bytes cannot reach sun_path");
        assert!(err.contains("AF_UNIX"), "{err}");
        assert!(err.contains("107"), "{err}");
    }

    #[test]
    fn banner_bytes_land_in_notes() {
        let (dir, path) = sock("banner");
        fake_muxer(path.clone(), vec![4242], Some(b"hi there guest"));
        wait_for_bind(&path);
        let mut report = Report::new("h2g", crate::model::placeholder_header());
        let ports = [4242u32];
        let o = Opts {
            banner: 8,
            ..opts(&ports, &path)
        };
        run(&o, &mut report).expect("the sweep completes");
        let _ = std::fs::remove_dir_all(&dir);
        let dumped = report
            .summary
            .notes
            .iter()
            .find(|n| n.contains("first bytes"))
            .expect("the banner is dumped");
        assert!(dumped.contains("68 69 20 74 68 65 72 65"), "{dumped}");
    }

    #[test]
    fn open_only_filters_and_notes() {
        let (dir, path) = sock("open-only");
        fake_muxer(path.clone(), vec![1235], None);
        wait_for_bind(&path);
        let ports = [1235u32, 1236];
        let mut report = Report::new("h2g", crate::model::placeholder_header());
        let o = Opts {
            open_only: true,
            ..opts(&ports, &path)
        };
        run(&o, &mut report).expect("the sweep completes");
        assert_eq!(report.probes.len(), 1, "{:?}", report.probes);
        assert_eq!(report.probes[0].outcome.kind, OutcomeKind::Open);
        assert_eq!(
            report.summary.results, 2,
            "the swept count survives the filter"
        );
        let note = report
            .summary
            .notes
            .iter()
            .find(|n| n.contains("--open"))
            .expect("the filter is noted");
        assert!(
            note.contains("--open: showing 1 open row(s) of 2"),
            "{note}"
        );

        // Without the flag every row is reported and nothing mentions filtering.
        let mut plain = Report::new("h2g", crate::model::placeholder_header());
        run(&opts(&ports, &path), &mut plain).expect("the second sweep completes");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(plain.probes.len(), 2, "{:?}", plain.probes);
        assert!(
            !plain.summary.notes.iter().any(|n| n.contains("--open")),
            "{:?}",
            plain.summary.notes
        );
    }
}
