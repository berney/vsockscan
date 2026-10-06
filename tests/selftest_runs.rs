//! The binary's contract from the outside: exit codes and machine-readable output.
//!
//! These run the real executable rather than the modules, because the things they
//! check — which code a failed assertion produces, whether `--format json` emits
//! something a parser accepts — live in `main`, not in any module.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vsockscan"))
}

#[test]
fn version_flag_prints_semver() {
    let out = bin().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("vsockscan {}", env!("CARGO_PKG_VERSION"))));
}

#[test]
fn selftest_passes_with_no_fixture_and_no_device() {
    let out = bin()
        .args(["selftest", "--format", "json", "--no-color"])
        .output()
        .expect("run vsockscan selftest");
    assert!(
        out.status.success(),
        "exit {:?}\nstdout {}\nstderr {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["command"], "selftest");
    let findings = v["findings"].as_array().expect("findings array");
    assert!(
        findings.len() >= 8,
        "expected the design's checks, got {findings:?}"
    );
    let notes = v["summary"]["notes"].as_array().unwrap();
    let tally = notes.last().unwrap().as_str().unwrap();
    assert!(tally.contains(", 0 failed"), "a check failed: {tally}");
    assert!(
        findings.iter().any(|f| f["message"]
            .as_str()
            .unwrap_or("")
            .contains("no-invented-open")),
        "the check that guards against phantom listeners must be present"
    );
}

#[test]
fn scan_without_a_cid_is_a_usage_error_not_a_runtime_failure() {
    // 1 = the operator's argument, 2 = this machine cannot do the work. A script
    // cannot tell those apart if both are 2.
    let missing = bin().args(["scan", "--ports", "22"]).output().unwrap();
    assert_eq!(
        missing.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
    let bad_spec = bin()
        .args(["scan", "--cid", "host", "--ports", "nope"])
        .output()
        .unwrap();
    assert_eq!(bad_spec.status.code(), Some(1));
    let wide = bin()
        .args(["scan", "--cid", "0-5000", "--ports", "22"])
        .output()
        .unwrap();
    assert_eq!(wide.status.code(), Some(1));
}

#[test]
fn the_emitted_schema_is_json_and_names_the_document_fields() {
    let out = bin().args(["--json-schema"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("schema parses");
    for field in ["header", "rows", "summary", "diag-entries"] {
        assert!(
            v["properties"].get(field).is_some(),
            "schema is missing {field}: {v}"
        );
    }
}

#[test]
fn every_format_renders_a_selftest_report() {
    for format in ["text", "markdown", "yaml", "json"] {
        let out = bin()
            .args(["selftest", "--format", format, "--no-color"])
            .output()
            .unwrap();
        let body = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{format}: {body}");
        assert!(body.contains("selftest"), "{format} lost its command label");
        assert!(
            body.contains("listeners-distinguishable"),
            "{format} dropped the checks"
        );
    }
}
