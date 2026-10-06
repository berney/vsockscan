//! Source hygiene for the prose the tool prints.
//!
//! Batch edits that flattened `\`-line-continuations left runs of spaces *inside*
//! message strings ("answers the                  same"), and those runs survive
//! into reports, where they read as a broken column or a truncated line. Rendered
//! output is space-padded on purpose; the interior of a sentence is not.

use std::path::PathBuf;

fn src(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// A run of 4+ spaces between two word-ish characters on a line that carries a
/// string literal and is not a comment. Layout padding is written as `format!`
/// width (`{: <16}`) or sits against a `{`, so it never matches.
fn offenders(text: &str) -> Vec<(usize, String)> {
    let mut bad = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || !line.contains('"') {
            continue;
        }
        let q = line.find('"').unwrap_or(0);
        let tail = &line[q..];
        if let Some(m) = regex_run(tail) {
            bad.push((n + 1, m));
        }
    }
    bad
}

fn regex_run(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'`' | b'(');
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if bytes[i] == b' '
            && bytes[i..].starts_with(b"    ")
            && i > 0
            && word(bytes[i - 1])
            && bytes.get(i + 4).copied().is_some_and(word)
        {
            return Some(s.to_string());
        }
        i += 1;
    }
    None
}

#[test]
fn no_message_carries_a_run_of_spaces() {
    let files = [
        "main.rs",
        "probe.rs",
        "scan.rs",
        "listen.rs",
        "selftest.rs",
        "kernconfig.rs",
        "diag.rs",
        "model.rs",
        "spec.rs",
        "caps.rs",
        "render/mod.rs",
        "render/text.rs",
        "render/markdown.rs",
        "render/yaml.rs",
        "muxer.rs",
        "h2g.rs",
    ];
    let mut all = Vec::new();
    for f in files {
        for (line, text) in offenders(&src(f)) {
            all.push(format!("{f}:{line}: {text}"));
        }
    }
    assert!(
        all.is_empty(),
        "runs of spaces inside message strings:\n{all:?}"
    );
}
