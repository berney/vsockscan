//! YAML output, hand-emitted (`serde_yaml` is unmaintained, and a report must be
//! pasteable into a pipeline without pulling an abandoned crate).
//!
//! Invariants that keep the output correct for arbitrary field content:
//! - keys are emitted in a fixed order, never from a hash map;
//! - every string is double-quoted with JSON-style escapes, so `: `, a leading
//!   `-`, `#`, an embedded newline or the literal `null` cannot change meaning;
//! - numbers and booleans stay bare, so consumers get typed values;
//! - absent optionals are explicit `null`, never omitted: a reader must be able
//!   to tell "no value" from "field forgotten";
//! - an empty list is `[]`, an empty map `{}` — never a dangling `key:`.
//!
//! Colour (only on a TTY; the caller decides): keys electric blue, strings
//! titanium gold, numbers amber, bool/null readout green.

use std::io::{self, Write};

use crate::model::{DiagStatus, Outcome, Report};

use super::style::{self, ColorSupport};

/// A value, classified for emission.
enum Val {
    /// Quoted string.
    Str(String),
    /// Bare literal: number, `true`/`false`.
    Raw(String),
    /// Already painted by the caller (verdict colours); emitted verbatim.
    Painted(String),
    Null,
}

struct E {
    c: ColorSupport,
}

impl E {
    fn val(&self, v: Val) -> String {
        match v {
            Val::Str(s) => self.c.fg(style::TITANIUM_GOLD, &quote(&s)),
            Val::Raw(s) => {
                if s == "true" || s == "false" {
                    self.c.fg(style::READOUT_GREEN, &s)
                } else {
                    self.c.fg(style::WARNING_AMBER, &s)
                }
            }
            Val::Painted(s) => s,
            Val::Null => self.c.fg(style::READOUT_GREEN, "null"),
        }
    }

    fn key(&self, key: &str) -> String {
        self.c.fg(style::ELECTRIC_BLUE, key)
    }

    /// `key: value` at `indent`.
    fn pair(&mut self, out: &mut dyn Write, indent: usize, key: &str, v: Val) -> io::Result<()> {
        let val = self.val(v);
        let key = self.key(key);
        writeln!(out, "{}{key}: {val}", " ".repeat(indent))
    }

    /// First key of a sequence item: `- key: value`.
    fn item(&mut self, out: &mut dyn Write, indent: usize, key: &str, v: Val) -> io::Result<()> {
        let val = self.val(v);
        let key = self.key(key);
        writeln!(out, "{}- {key}: {val}", " ".repeat(indent))
    }

    /// `key:` opening a nested mapping or list body.
    fn open(&mut self, out: &mut dyn Write, indent: usize, key: &str) -> io::Result<()> {
        let key = self.key(key);
        writeln!(out, "{}{key}:", " ".repeat(indent))
    }

    /// `key:` for a list, or `key: []` when it is empty (a dangling `key:` with
    /// nothing under it parses as null, not as an empty list).
    fn open_list(
        &mut self,
        out: &mut dyn Write,
        indent: usize,
        key: &str,
        empty: bool,
    ) -> io::Result<()> {
        let key = self.key(key);
        if empty {
            writeln!(out, "{}{key}: []", " ".repeat(indent))
        } else {
            writeln!(out, "{}{key}:", " ".repeat(indent))
        }
    }

    fn strings(&mut self, out: &mut dyn Write, indent: usize, items: &[String]) -> io::Result<()> {
        for it in items {
            let val = self.val(Val::Str(it.clone()));
            writeln!(out, "{}- {val}", " ".repeat(indent))?;
        }
        Ok(())
    }
}

pub fn render(report: &Report, c: ColorSupport, out: &mut dyn Write) -> io::Result<()> {
    let mut y = E { c };
    let h = &report.header;

    writeln!(
        out,
        "# vsockscan {} report ({})",
        report.command, report.version
    )?;
    y.pair(out, 0, "tool", Val::Str(report.tool.clone()))?;
    y.pair(out, 0, "version", Val::Str(report.version.clone()))?;
    y.pair(out, 0, "command", Val::Str(report.command.clone()))?;

    y.open(out, 0, "header")?;
    y.pair(out, 2, "kernel", Val::Str(h.kernel.clone()))?;
    y.pair(out, 2, "uid", Val::Raw(h.uid.to_string()))?;
    y.open_list(out, 2, "caps", h.caps.is_empty())?;
    y.strings(out, 4, &h.caps)?;
    y.open(out, 2, "cid")?;
    y.pair(
        out,
        4,
        "cid",
        match h.cid.cid {
            Some(v) => Val::Raw(v.to_string()),
            None => Val::Null,
        },
    )?;
    y.pair(out, 4, "source", Val::Str(h.cid.source.clone()))?;

    y.open_list(out, 2, "sysctls", h.sysctls.is_empty())?;
    for (name, v) in &h.sysctls {
        y.item(out, 4, name, Val::Str(v.as_str().to_owned()))?;
    }

    y.pair(out, 2, "posture", Val::Str(h.posture.as_str().to_owned()))?;
    // The device verdict is the one header value worth colour-coding by itself.
    y.pair(
        out,
        2,
        "device",
        Val::Painted(y.c.fg(style::verdict_fg(h.device), &quote(h.device.as_str()))),
    )?;
    y.pair(
        out,
        2,
        "config-source",
        match &h.config_source {
            Some(v) => Val::Str(v.clone()),
            None => Val::Null,
        },
    )?;

    y.open_list(out, 2, "module-verdicts", h.module_verdicts.is_empty())?;
    for m in &h.module_verdicts {
        y.item(out, 4, "name", Val::Str(m.name.clone()))?;
        y.pair(out, 6, "state", Val::Str(m.state.as_str().to_owned()))?;
        y.pair(out, 6, "reason", Val::Str(m.reason.clone()))?;
    }

    y.open(out, 2, "diag")?;
    match &h.diag {
        DiagStatus::Available { entries } => {
            y.open(out, 4, "available")?;
            y.pair(out, 6, "entries", Val::Raw(entries.to_string()))?;
        }
        DiagStatus::Unavailable(why) => {
            y.open(out, 4, "unavailable")?;
            y.pair(out, 6, "reason", Val::Str(why.clone()))?;
        }
        DiagStatus::Skipped => {
            y.pair(out, 4, "skipped", Val::Raw("true".to_owned()))?;
        }
    }
    y.pair(out, 2, "noise", Val::Str(h.noise.clone()))?;

    y.open_list(out, 0, "tells", report.tells.is_empty())?;
    for t in &report.tells {
        y.item(out, 2, "id", Val::Str(t.id.clone()))?;
        y.pair(
            out,
            4,
            "state",
            Val::Painted(y.c.fg(style::tell_fg(t.state), &quote(t.state.as_str()))),
        )?;
        y.pair(out, 4, "detail", Val::Str(t.detail.clone()))?;
    }

    y.open_list(out, 0, "probes", report.probes.is_empty())?;
    for p in &report.probes {
        y.item(out, 2, "name", Val::Str(p.name.clone()))?;
        y.pair(out, 4, "flags", Val::Str(p.flags.label().to_owned()))?;
        y.pair(
            out,
            4,
            "value",
            match &p.value {
                Some(v) => Val::Str(v.clone()),
                None => Val::Null,
            },
        )?;
        outcome(&mut y, out, 4, &p.outcome)?;
    }

    y.open_list(out, 0, "rows", report.rows.is_empty())?;
    for r in &report.rows {
        y.item(out, 2, "cid", Val::Raw(r.cid.to_string()))?;
        y.pair(out, 4, "port", Val::Raw(r.port.to_string()))?;
        y.pair(out, 4, "flags", Val::Str(r.flags.label().to_owned()))?;
        outcome(&mut y, out, 4, &r.outcome)?;
        y.pair(out, 4, "elapsed-ms", Val::Raw(r.elapsed_ms.to_string()))?;
        y.pair(
            out,
            4,
            "banner",
            match &r.banner {
                Some(v) => Val::Str(v.clone()),
                None => Val::Null,
            },
        )?;
    }

    y.open_list(out, 0, "diag-entries", report.diag_entries.is_empty())?;
    for e in &report.diag_entries {
        y.item(out, 2, "family", Val::Raw(e.family.to_string()))?;
        y.pair(out, 4, "kind", Val::Raw(e.kind.to_string()))?;
        y.pair(out, 4, "state", Val::Raw(e.state.to_string()))?;
        y.pair(out, 4, "shutdown", Val::Raw(e.shutdown.to_string()))?;
        y.pair(out, 4, "src-cid", Val::Raw(e.src_cid.to_string()))?;
        y.pair(out, 4, "src-port", Val::Raw(e.src_port.to_string()))?;
        y.pair(out, 4, "dst-cid", Val::Raw(e.dst_cid.to_string()))?;
        y.pair(out, 4, "dst-port", Val::Raw(e.dst_port.to_string()))?;
        y.pair(out, 4, "ino", Val::Raw(e.ino.to_string()))?;
        y.pair(out, 4, "cookie", Val::Str(e.cookie.clone()))?;
        y.pair(
            out,
            4,
            "pid",
            match e.pid {
                Some(p) => Val::Raw(p.to_string()),
                None => Val::Null,
            },
        )?;
        y.pair(
            out,
            4,
            "pid-comm",
            match &e.pid_comm {
                Some(cc) => Val::Str(cc.clone()),
                None => Val::Null,
            },
        )?;
    }

    y.open_list(out, 0, "findings", report.findings.is_empty())?;
    for f in &report.findings {
        y.item(out, 2, "severity", Val::Str(f.severity.as_str().to_owned()))?;
        y.pair(out, 4, "message", Val::Str(f.message.clone()))?;
    }

    y.open(out, 0, "summary")?;
    y.pair(
        out,
        2,
        "results",
        Val::Raw(report.summary.results.to_string()),
    )?;
    if report.summary.by_outcome.is_empty() {
        let key = y.key("by-outcome");
        writeln!(out, "  {key}: {{}}")?;
    } else {
        y.open(out, 2, "by-outcome")?;
        for (k, v) in &report.summary.by_outcome {
            y.pair(out, 4, k, Val::Raw(v.to_string()))?;
        }
    }
    y.pair(
        out,
        2,
        "flags-agree",
        match report.summary.flags_agree {
            Some(b) => Val::Raw(b.to_string()),
            None => Val::Null,
        },
    )?;
    y.pair(
        out,
        2,
        "elapsed-ms",
        Val::Raw(report.summary.elapsed_ms.to_string()),
    )?;
    y.open_list(out, 2, "notes", report.summary.notes.is_empty())?;
    y.strings(out, 4, &report.summary.notes)?;
    Ok(())
}

fn outcome(y: &mut E, out: &mut dyn Write, indent: usize, o: &Outcome) -> io::Result<()> {
    y.open(out, indent, "outcome")?;
    let inner = indent + 2;
    y.pair(
        out,
        inner,
        "kind",
        Val::Painted(y.c.fg(style::outcome_fg(o.kind), &quote(o.kind.as_str()))),
    )?;
    y.pair(
        out,
        inner,
        "errno",
        match o.errno {
            Some(e) => Val::Raw(e.to_string()),
            None => Val::Null,
        },
    )?;
    y.pair(
        out,
        inner,
        "errno-name",
        match &o.errno_name {
            Some(n) => Val::Str(n.clone()),
            None => Val::Null,
        },
    )?;
    y.pair(
        out,
        inner,
        "detail",
        match &o.detail {
            Some(d) => Val::Str(d.clone()),
            None => Val::Null,
        },
    )?;
    Ok(())
}

/// Double-quoted YAML scalar with JSON-style escapes (valid YAML 1.2 double
/// quotes), so no value can escape its own field.
fn quote(v: &str) -> String {
    let mut o = String::with_capacity(v.len() + 2);
    o.push('"');
    for ch in v.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        placeholder_header, DiagEntry, FlagSet, Outcome, OutcomeKind, Report, ScanRow, Severity,
        SysctlValue,
    };

    fn s(report: &Report, c: ColorSupport) -> String {
        let mut b = Vec::new();
        render(report, c, &mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    fn nasty() -> Report {
        let mut h = placeholder_header();
        h.sysctls
            .push(("net.core.somaxconn".into(), SysctlValue::Absent));
        h.noise = "frames with dst_cid 2 leave: yes | no | maybe".into();
        let mut r = Report::new("scan", h);
        r.rows.push(ScanRow {
            cid: 2,
            port: 1234,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::RefusedKernel)
                .with_errno(libc::ENODEV)
                .with_detail("line1\nline2: quoted \"value\""),
            elapsed_ms: 0,
            banner: Some("- # null".into()),
        });
        r.diag_entries.push(DiagEntry {
            family: 40,
            kind: 1,
            state: 1,
            shutdown: 0,
            src_cid: 3,
            src_port: 7,
            dst_cid: 2,
            dst_port: 1234,
            ino: 42,
            cookie: "aabbccdd00112233".into(),
            pid: None,
            pid_comm: None,
        });
        r.finding(Severity::Info, "0xdead:beef");
        r.recompute_summary(1);
        r
    }

    #[test]
    fn dangerous_scalars_stay_in_their_field() {
        let y = s(&nasty(), ColorSupport::Off);
        assert!(y.contains("\"line1\\nline2: quoted \\\"value\\\""), "{y}");
        assert!(y.contains("banner: \"- # null\""), "{y}");
        assert!(
            y.contains("noise: \"frames with dst_cid 2 leave: yes | no | maybe\""),
            "{y}"
        );
        assert!(y.contains("message: \"0xdead:beef\""));
        assert!(y.contains("\"absent\""));
    }

    #[test]
    fn no_key_is_left_dangling() {
        // A `key:` whose next line is not a deeper body parses as `key: null`,
        // silently turning a container into nothing. Structural check, so it
        // does not need a whitelist of legal openers.
        let y = s(
            &Report::new("probe", placeholder_header()),
            ColorSupport::Off,
        );
        let lines: Vec<&str> = y.lines().filter(|l| !l.starts_with('#')).collect();
        for i in 0..lines.len() {
            let t = lines[i].trim_end();
            if !t.ends_with(':') {
                continue;
            }
            let indent = t.len() - t.trim_start().len();
            let next = *lines.get(i + 1).unwrap_or(&"");
            let nindent = next.len() - next.trim_start().len();
            assert!(
                !next.is_empty() && nindent > indent,
                "dangling key {:?} followed by {next:?} in\n{y}",
                lines[i]
            );
        }
        assert!(y.contains("tells: []"));
        assert!(y.contains("rows: []"));
        assert!(y.contains("diag-entries: []"));
        assert!(y.contains("by-outcome: {}"));
        assert!(y.contains("caps: []"));
    }

    #[test]
    fn quoting_is_reversible_for_awkward_strings() {
        for v in [
            "",
            "yes",
            "null",
            "a: b",
            "#c",
            "- item",
            "1.2",
            "tab\there",
            "\u{1}",
        ] {
            let q = quote(v);
            // serde_json implements the same escape subset as YAML double quotes.
            let back: String = serde_json::from_str(&q).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn nulls_are_explicit_not_omitted() {
        let mut r = Report::new("scan", placeholder_header());
        r.rows.push(ScanRow {
            cid: 3,
            port: 7,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::Silent),
            elapsed_ms: 1,
            banner: None,
        });
        r.recompute_summary(1);
        let y = s(&r, ColorSupport::Off);
        assert!(y.contains("banner: null"), "{y}");
        assert!(y.contains("errno: null"));
        assert!(y.contains("errno-name: null"));
        assert!(y.contains("flags-agree: null"));
        assert!(y.contains("cid: null"));
    }

    #[test]
    fn nested_shapes_use_consistent_indent() {
        let y = s(&nasty(), ColorSupport::Off);
        assert!(y.contains("rows:\n  - cid: 2"), "{y}");
        assert!(
            y.contains("    outcome:\n      kind: \"refused-kernel\""),
            "{y}"
        );
        assert!(y.contains("      errno: 19"), "{y}");
    }
}
