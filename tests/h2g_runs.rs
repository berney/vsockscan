//! h2g against a fake Firecracker muxer: the handshake contract, the JSON
//! shape, and --open, exercised through the real binary end to end.
//!
//! The command surface - usage codes, the sun_path limit, help - is
//! `tests/h2g_cli.rs`'s contract; this file never re-litigates an argument.
//! What lives here is what a real run *says*: the rows and kinds in the
//! `--format json` document, the `--open` note and its swept counts, and the
//! exact stderr strings a runtime error or a failed preflight leaves behind.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vsockscan"))
}

/// One test's scratch dir plus socket path, unique per test so parallel
/// tests never share a file, and short enough for `sun_path`. Stale debris
/// from a previous run (a SIGKILLed harness leaves the dir behind) is
/// cleared first so the fake's `bind` cannot meet `EADDRINUSE`.
fn sock(name: &str) -> (PathBuf, PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("vsockscan-h2g-runs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("s.sock");
    (dir, path)
}

/// A stand-in daemon: reads `CONNECT <port>` per connection and lets
/// `reply(port)` decide the answer - `Some(bytes)` are written before the
/// channel is held briefly and hung up on, `None` is an immediate hangup
/// with no line, which is the muxer's own word for "the guest refused".
/// Serves at most 30 accepted connections inside a 10 s wall-clock budget
/// and polls for the scratch dir to disappear, mirroring the fake in
/// `src/h2g.rs`'s tests: a panicked or finished test never strands the
/// thread, the socket file, or the suite.
fn serve(path: PathBuf, reply: impl Fn(u32) -> Option<&'static [u8]> + Send + 'static) {
    std::thread::spawn(move || {
        let l = UnixListener::bind(&path).expect("the fake daemon binds");
        l.set_nonblocking(true).expect("nonblocking listener");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut served = 0usize;
        while served < 30 && std::time::Instant::now() < deadline {
            if path.parent().is_none_or(|d| !d.exists()) {
                break;
            }
            let (mut s, _) = match l.accept() {
                Ok(pair) => {
                    served += 1;
                    pair
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            // Linux does not propagate the listener's nonblocking mode to
            // accepted streams; this clear makes the blocking read below safe.
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
                .trim()
                .strip_prefix("CONNECT ")
                .and_then(|p| p.parse::<u32>().ok());
            if let Some(answer) = port.and_then(&reply) {
                let _ = s.write_all(answer);
                let _ = s.flush();
                // Hold the answered channel open for a moment, the way a
                // real guest keeps a vsock channel after `OK`.
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
            drop(s);
        }
        let _ = std::fs::remove_file(&path);
    });
}

/// A stand-in muxer: `OK 1073741824` for the ports in `open` - the stock
/// pool's first value - and a silent hangup on everything else, the canary
/// included.
fn fake_muxer(path: PathBuf, open: Vec<u32>) {
    serve(path, move |p| {
        open.contains(&p).then_some(b"OK 1073741824\n")
    });
}

/// Not a muxer: answers every `CONNECT` - the preflight canary included -
/// with a greeting no handshake has a word for.
fn fake_not_a_muxer(path: PathBuf) {
    serve(path, |_| Some(b"HELLO 1\n"));
}

/// Wait for the fake's `bind` to publish the socket file, so the binary
/// never races the listener into a spurious `absent`.
fn wait_for_bind(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("fake daemon never bound {path:?}");
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn h2g(args: &[&str]) -> Run {
    let out = bin().args(args).output().expect("the binary runs");
    Run {
        code: out.status.code().expect("exits, not signalled"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The JSON document, parsed - a malformed document fails here, loudly.
fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("--format json prints a JSON document")
}

/// The two swept endpoints' rows, in document order. The preflight canary
/// is a random port in the upper half of u32 that the fake never answers,
/// so it never becomes a row; should one ever appear, these tests read only
/// the ports they swept, in the order the jobs were issued.
fn swept_rows(doc: &serde_json::Value) -> Vec<&serde_json::Value> {
    doc["probes"]
        .as_array()
        .expect("probes is an array")
        .iter()
        .filter(|r| {
            let n = r["name"].as_str().unwrap_or_default();
            n == "connect:1235" || n == "connect:1236"
        })
        .collect()
}

#[test]
fn h2g_reports_open_and_closed_through_the_real_binary() {
    let (dir, path) = sock("open-closed");
    fake_muxer(path.clone(), vec![1235]);
    wait_for_bind(&path);
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1235,1236",
        "--format",
        "json",
        "--no-color",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let doc = json(&run.stdout);
    assert_eq!(doc["command"], "h2g", "the document labels its command");
    let rows = swept_rows(&doc);
    let names: Vec<&str> = rows
        .iter()
        .map(|r| r["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["connect:1235", "connect:1236"], "job order");
    let kinds: Vec<&str> = rows
        .iter()
        .map(|r| r["outcome"]["kind"].as_str().expect("a kind"))
        .collect();
    assert_eq!(kinds, ["open", "closed"], "the handshake answers");
    let value = rows[0]["value"].as_str().expect("the handshake answer");
    assert!(value.contains("1073741824"), "{value}");
    assert_eq!(doc["summary"]["results"], 2);
}

#[test]
fn h2g_open_filter_reports_counts_through_json() {
    let (dir, path) = sock("open-filter");
    fake_muxer(path.clone(), vec![1235]);
    wait_for_bind(&path);
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1235,1236",
        "--open",
        "--format",
        "json",
        "--no-color",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let doc = json(&run.stdout);
    let rows = doc["probes"].as_array().expect("probes");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r["outcome"]["kind"] == "open" && r["name"] == "connect:1235"),
        "only answered ports are displayed: {rows:?}"
    );
    // The flag shrinks the rows, never the evidence: the summary still
    // counts the sweep, and the note says exactly what was dropped.
    assert_eq!(doc["summary"]["results"], 2);
    assert!(
        doc["summary"]["notes"]
            .as_array()
            .expect("notes")
            .iter()
            .any(|n| n == "--open: showing 1 open row(s) of 2"),
        "{}",
        doc["summary"]["notes"]
    );
}

#[test]
fn h2g_without_a_socket_is_a_runtime_error() {
    let (dir, path) = sock("absent");
    // The dir exists; the socket inside it does not - ENOENT, `absent`.
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1234",
        "--format",
        "json",
        "--no-color",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(run.code, 2, "stderr:\n{}", run.stderr);
    assert!(run.stderr.contains("absent"), "{}", run.stderr);
    assert!(
        run.stderr.contains(&path.display().to_string()),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "a failed run prints no report");
}

#[test]
fn h2g_denies_a_daemon_that_is_not_a_muxer() {
    let (dir, path) = sock("not-muxer");
    // The impostor answers the canary too, so the preflight - not the
    // sweep - is what walks away: no port list is committed to a socket
    // that cannot speak the handshake.
    fake_not_a_muxer(path.clone());
    wait_for_bind(&path);
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1235,1236",
        "--format",
        "json",
        "--no-color",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(run.code, 2, "stderr:\n{}", run.stderr);
    assert!(
        run.stderr.contains("not a muxer"),
        "the taxonomy word leads the abort: {}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "a failed run prints no report");
}

#[test]
fn the_report_discloses_local_traffic_and_drops_host_verdicts() {
    let (dir, path) = sock("honest");
    fake_muxer(path.clone(), vec![1235]);
    wait_for_bind(&path);
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1235",
        "--format",
        "json",
        "--no-color",
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let doc = json(&run.stdout);
    let noise = doc["header"]["noise"].as_str().unwrap_or_default();
    assert!(
        noise.contains("CID 1") && noise.contains("loopback canary"),
        "the noise line denies the AF_VSOCK traffic collect issues: {noise}"
    );
    let notes = doc["summary"]["notes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for n in &notes {
        let s = n.as_str().unwrap_or_default();
        assert!(
            !s.starts_with("posture "),
            "a verdict built from deleted header rows survived: {s}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_not_muxer_line_reaches_the_terminal_escaped() {
    let (dir, path) = sock("scrub");
    // Answers the swept port with a screen-clear; the canary hangs up, so
    // the sweep runs and this line becomes a row value.
    serve(path.clone(), |p| {
        (p == 1235).then_some(b"\x1b[2J\x07pwned\n")
    });
    wait_for_bind(&path);
    let run = h2g(&[
        "h2g",
        "--uds",
        &path.display().to_string(),
        "--ports",
        "1235",
        "--no-color",
    ]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        !run.stdout.contains('\u{1b}'),
        "a raw escape byte reached the terminal: {:?}",
        run.stdout
    );
    assert!(run.stdout.contains("\\x1b[2J\\x07pwned"), "{}", run.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}
