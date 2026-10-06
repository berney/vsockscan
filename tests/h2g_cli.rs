//! The `h2g` command line and `--open` from the outside: argument acceptance,
//! validation ordering, and exit codes through the real binary.
//!
//! What a sweep *says* against a live muxer is `tests/h2g_runs.rs`'s contract;
//! this file pins the command surface: a bad invocation must fail as a usage
//! error (1) before anything reads the environment or touches the socket, a
//! uds_path that cannot answer a handshake must fail as a runtime error (2)
//! with the taxonomy message, and only a clean sweep prints a report (0).

use std::path::Path;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vsockscan"))
}

/// A path that cannot exist, far from any socket, in a directory that is not
/// ours - so `absent` is the only honest answer.
const ABSENT: &str = "/nonexistent-vsockscan-jail/vm.sock";

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn h2g_help_lists_the_whole_surface() {
    let out = bin().args(["h2g", "--help"]).output().unwrap();
    assert!(out.status.success(), "{}", stderr_of(&out));
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--uds",
        "--ports",
        "--timeout",
        "--parallel",
        "--banner",
        "--open",
    ] {
        assert!(help.contains(flag), "{flag} missing from:\n{help}");
    }
    // The top-level help and the subcommand-required hint both know h2g.
    let top = bin().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&top.stdout).contains("h2g"));
    let bare = bin().output().unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(
        stderr_of(&bare).contains("probe | scan | listen | h2g | selftest"),
        "{}",
        stderr_of(&bare)
    );
}

#[test]
fn h2g_without_uds_is_a_usage_error() {
    let out = bin().args(["h2g", "--ports", "1234"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr_of(&out).contains("--uds"), "{}", stderr_of(&out));
}

#[test]
fn h2g_parallel_outside_the_table_never_reaches_the_socket() {
    for p in ["0", "257", "300"] {
        let out = bin()
            .args(["h2g", "--uds", ABSENT, "--ports", "1234", "--parallel", p])
            .output()
            .unwrap();
        let err = stderr_of(&out);
        assert_eq!(out.status.code(), Some(1), "--parallel {p}: {err}");
        assert!(err.contains("1023"), "{err}");
        // Exit 1, not 2: the argument lost, not the preflight - and the
        // preflight's word must not appear, because it never ran.
        assert!(!err.contains("preflight"), "validation ran late:\n{err}");
    }
}

#[test]
fn h2g_bad_port_spec_and_timeout_are_usage_errors() {
    let out = bin()
        .args(["h2g", "--uds", ABSENT, "--ports", "bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr_of(&out);
    assert!(err.contains("--ports"), "{err}");
    assert!(!err.contains("preflight"), "validation ran late:\n{err}");

    for t in ["0", "-1", "NaN"] {
        let out = bin()
            .args([
                "h2g",
                "--uds",
                ABSENT,
                "--ports",
                "1234",
                &format!("--timeout={t}"),
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "--timeout={t} accepted");
        let err = stderr_of(&out);
        assert!(err.contains("--timeout"), "{err}");
        assert!(!err.contains("preflight"), "validation ran late:\n{err}");
    }
}

#[test]
fn h2g_uds_over_the_sun_path_limit_is_our_fault_not_the_guests() {
    let long = format!("/tmp/{}", "v".repeat(200));
    assert!(Path::new(&long).as_os_str().to_string_lossy().len() > 107);
    let out = bin()
        .args(["h2g", "--uds", &long, "--ports", "1234"])
        .output()
        .unwrap();
    // 1, not 2: a name our own argument could not have written is usage, and
    // it must be decided before the muxer gets to "answer" anything.
    assert_eq!(out.status.code(), Some(1));
    let err = stderr_of(&out);
    assert!(err.contains("AF_UNIX") && err.contains("107"), "{err}");
    assert!(
        !err.contains("not-muxer"),
        "the guest must not be blamed:\n{err}"
    );
}

#[test]
fn h2g_without_a_socket_exits_two_with_the_jail_hint() {
    let out = bin()
        .args(["h2g", "--uds", ABSENT, "--ports", "1234"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = stderr_of(&out);
    assert!(err.contains("absent"), "{err}");
    assert!(err.contains(ABSENT), "{err}");
    assert!(err.contains("jail"), "{err}");
    assert!(out.stdout.is_empty(), "a failed run prints no report");
}

#[test]
fn scan_accepts_open_and_still_requires_a_cid() {
    // The flag must parse for real: an unknown flag dies with clap's own
    // message, while the legitimate complaint here is the required --cid.
    let out = bin()
        .args(["scan", "--ports", "22", "--open"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = stderr_of(&out);
    assert!(err.contains("--cid"), "{err}");
    assert!(!err.contains("unexpected argument"), "scan --open: {err}");
}
