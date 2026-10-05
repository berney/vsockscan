//! Markdown renderer: pasteable into a finding writeup or a GitHub issue. Same
//! facts as text, arranged as headings, a key/value list and tables.

use std::io::{self, Write};

use crate::model::{Outcome, Report};

use super::style::{self, ColorSupport};

pub fn render(report: &Report, c: ColorSupport, out: &mut dyn Write) -> io::Result<()> {
    let h = &report.header;
    writeln!(
        out,
        "{}",
        c.fg(
            style::ELECTRIC_BLUE,
            &format!("# vsockscan {} — `{}`", report.version, report.command)
        )
    )?;
    writeln!(out)?;
    let caps = if h.caps.is_empty() {
        "none".to_owned()
    } else {
        h.caps
            .iter()
            .map(|x| format!("`{x}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    writeln!(out, "- **kernel**: `{}`", h.kernel)?;
    writeln!(out, "- **uid**: `{}` · **caps**: {}", h.uid, caps)?;
    writeln!(
        out,
        "- **local CID**: {} — {}",
        h.cid
            .cid
            .map(|v| format!("`{v}`"))
            .unwrap_or_else(|| "`?`".to_owned()),
        h.cid.source
    )?;
    writeln!(out, "- **posture**: `{}`", h.posture.as_str())?;
    writeln!(
        out,
        "- **vsock device**: {}{}",
        c.fg(style::verdict_fg(h.device), &format!("`{}`", h.device.as_str())),
        match &h.config_source {
            Some(s) => format!(" · config `{s}`"),
            None => String::new(),
        }
    )?;
    writeln!(out, "- **sock diag**: {}", h.diag.as_str())?;
    writeln!(out, "- **noise**: {}", escape(h.noise.as_str()))?;

    if !h.module_verdicts.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Modules"))?;
        writeln!(out)?;
        writeln!(out, "| module | state | basis |")?;
        writeln!(out, "| --- | --- | --- |")?;
        for m in &h.module_verdicts {
            writeln!(
                out,
                "| `{}` | `{}` | {} |",
                m.name,
                m.state.as_str(),
                escape(&m.reason)
            )?;
        }
    }

    if !h.sysctls.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Sysctls"))?;
        writeln!(out)?;
        writeln!(out, "| name | value |")?;
        writeln!(out, "| --- | --- |")?;
        for (name, v) in &h.sysctls {
            writeln!(out, "| `{}` | `{}` |", name, v.as_str())?;
        }
    }

    if !report.tells.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Tells"))?;
        writeln!(out)?;
        writeln!(out, "| tell | state | what it proves |")?;
        writeln!(out, "| --- | --- | --- |")?;
        for t in &report.tells {
            writeln!(
                out,
                "| `{}` | {} | {} |",
                t.id,
                c.fg(style::tell_fg(t.state), &format!("`{}`", t.state.as_str())),
                escape(&t.detail)
            )?;
        }
    }

    if !report.probes.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Probes"))?;
        writeln!(out)?;
        writeln!(out, "| probe | outcome | errno | value | flags |")?;
        writeln!(out, "| --- | --- | --- | --- | --- |")?;
        for p in &report.probes {
            writeln!(
                out,
                "| `{}` | {} | {} | {} | `{}` |",
                p.name,
                outcome_cell(c, &p.outcome),
                errno_cell(&p.outcome),
                p.value.as_deref().map(escape).unwrap_or_else(|| "—".into()),
                p.flags.label()
            )?;
        }
    }

    if !report.rows.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Results"))?;
        writeln!(out)?;
        writeln!(out, "| CID | port | flags | outcome | errno | ms |")?;
        writeln!(out, "| --- | --- | --- | --- | --- | --- |")?;
        for r in &report.rows {
            writeln!(
                out,
                "| {} | {} | `{}` | {} | {} | {} |",
                r.cid,
                r.port,
                r.flags.label(),
                outcome_cell(c, &r.outcome),
                errno_cell(&r.outcome),
                r.elapsed_ms
            )?;
            if let Some(b) = &r.banner {
                writeln!(out, "| | | banner | `{b}` | | |")?;
            }
        }
    }

    if !report.diag_entries.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Sock diag"))?;
        writeln!(out)?;
        writeln!(
            out,
            "| src | dst | state | shutdown | ino | pid | cookie |"
        )?;
        writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |")?;
        for e in &report.diag_entries {
            let pid = match (&e.pid, &e.pid_comm) {
                (Some(p), Some(comm)) => format!("{p} `{comm}`"),
                (Some(p), None) => p.to_string(),
                _ => "—".to_owned(),
            };
            writeln!(
                out,
                "| {}:{} | {}:{} | {} | {} | {} | {} | `{}` |",
                e.src_cid,
                e.src_port,
                e.dst_cid,
                e.dst_port,
                e.state,
                e.shutdown,
                e.ino,
                pid,
                e.cookie
            )?;
        }
    }

    if !report.findings.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("## Findings"))?;
        writeln!(out)?;
        for f in &report.findings {
            let label = format!("**{}**", f.severity.as_str());
            let label = if style::severity_bold(f.severity) {
                c.bold(&label)
            } else {
                c.fg(style::severity_fg(f.severity), &label)
            };
            writeln!(out, "- {label} {}", escape(&f.message))?;
        }
    }

    writeln!(out)?;
    writeln!(out, "{}", c.bold("## Summary"))?;
    writeln!(out)?;
    writeln!(out, "- results: `{}`", report.summary.results)?;
    let mut keys: Vec<&String> = report.summary.by_outcome.keys().collect();
    keys.sort();
    for k in keys {
        writeln!(out, "- `{k}`: `{}`", report.summary.by_outcome[k])?;
    }
    if let Some(agree) = report.summary.flags_agree {
        writeln!(
            out,
            "- flags agree: {}",
            if agree {
                "yes".to_owned()
            } else {
                format!("`{}`", "NO")
            }
        )?;
    }
    writeln!(out, "- elapsed: `{} ms`", report.summary.elapsed_ms)?;
    for n in &report.summary.notes {
        writeln!(out, "- note: {}", escape(n))?;
    }
    Ok(())
}

fn outcome_cell(c: ColorSupport, o: &Outcome) -> String {
    let text = format!("`{}`", o.kind.as_str());
    c.fg(style::outcome_fg(o.kind), &text)
}

fn errno_cell(o: &Outcome) -> String {
    match (&o.errno_name, o.errno) {
        (Some(n), Some(e)) => format!("`{n}({e})`"),
        (Some(n), None) => format!("`{n}`"),
        (None, Some(e)) => e.to_string(),
        (None, None) => "—".to_owned(),
    }
}

/// A verdict detail may contain `|` (paths, lists); a raw pipe silently breaks
/// the table row it lands in.
fn escape(s: &str) -> String {
    s.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        placeholder_header, Finding, FlagSet, Outcome, OutcomeKind, Report, ScanRow, Severity,
        Tell, TellState,
    };

    fn report() -> Report {
        let mut r = Report::new("scan", placeholder_header());
        r.tells.push(Tell {
            id: "local-echo".into(),
            state: TellState::No,
            detail: "bind(3:7) ok | connect(3:7) refused".into(),
        });
        r.rows.push(ScanRow {
            cid: 2,
            port: 1234,
            flags: FlagSet::None,
            outcome: Outcome::new(OutcomeKind::Silent).with_detail("2000ms poll timeout"),
            elapsed_ms: 2001,
            banner: None,
        });
        r.findings.push(Finding {
            severity: Severity::Warn,
            message: "pipe | in a message".into(),
        });
        r.recompute_summary(2001);
        r
    }

    fn s(r: &Report, c: ColorSupport) -> String {
        let mut b = Vec::new();
        render(r, c, &mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn table_rows_keep_their_column_count() {
        let md = s(&report(), ColorSupport::Off);
        // Inside one table every row must have the same number of cell
        // separators. Content pipes are escaped, so they must not be counted.
        let mut block: Vec<(usize, usize)> = Vec::new();
        for (i, line) in md.lines().enumerate() {
            if line.starts_with('|') {
                let seps = line.replace(r"\|", "").matches('|').count();
                block.push((i, seps));
                continue;
            }
            check_block(&block);
            block.clear();
        }
        check_block(&block);
        assert!(md.contains(r"bind(3:7) ok \| connect(3:7) refused"));
        assert!(md.contains(r"pipe \| in a message"));
    }

    fn check_block(block: &[(usize, usize)]) {
        if block.is_empty() {
            return;
        }
        let want = block[0].1;
        for (i, got) in block {
            assert_eq!(*got, want, "row {i} has a different column count");
        }
    }

    #[test]
    fn sections_appear_only_when_populated() {
        let empty = Report::new("probe", placeholder_header());
        let md = s(&empty, ColorSupport::Off);
        assert!(md.starts_with("# vsockscan"));
        assert!(!md.contains("## Results"));
        assert!(!md.contains("## Tells"));
        assert!(md.contains("## Summary"));
    }

    #[test]
    fn colour_is_optional() {
        let off = s(&report(), ColorSupport::Off);
        let on = s(&report(), ColorSupport::TrueColor);
        assert!(on.contains("\x1b[38;2;"));
        assert!(!off.contains('\x1b'));
    }
}
