//! Canonical plain-text renderer: one fact per line, stable order, nothing a
//! reader has to decode twice (capabilities as names, errnos as names, dates as
//! ISO 8601 UTC).

use std::io::{self, Write};

use crate::model::{Outcome, Report};

use super::style::{self, ColorSupport};

pub fn render(report: &Report, c: ColorSupport, out: &mut dyn Write) -> io::Result<()> {
    let h = &report.header;
    writeln!(
        out,
        "{}",
        c.bold(&format!("# vsockscan {} ({})", report.version, report.command))
    )?;
    let caps = if h.caps.is_empty() {
        "none".to_owned()
    } else {
        h.caps.join(",")
    };
    writeln!(out, "kernel   {}", h.kernel)?;
    writeln!(out, "uid      {}   caps {}", h.uid, caps)?;
    writeln!(
        out,
        "cid      {}   via {}",
        h.cid.cid.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
        h.cid.source
    )?;
    writeln!(out, "posture  {}", h.posture.as_str())?;
    writeln!(
        out,
        "device   {}{}",
        c.fg(style::verdict_fg(h.device), h.device.as_str()),
        match &h.config_source {
            Some(s) => format!("   config {s}"),
            None => String::new(),
        }
    )?;
    for m in &h.module_verdicts {
        writeln!(out, "module   {:<14} {}   {}", m.name, m.state.as_str(), m.reason)?;
    }
    if h.sysctls.is_empty() {
        writeln!(out, "sysctl   (none read)")?;
    }
    for (name, v) in &h.sysctls {
        writeln!(out, "sysctl   {name} = {}", v.as_str())?;
    }
    writeln!(out, "diag     {}", h.diag.as_str())?;
    writeln!(out, "noise    {}", h.noise)?;

    if !report.tells.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("tells"))?;
        for t in &report.tells {
            // Pad the plain state, then colour it: see `write_outcome`.
            let state = t.state.as_str();
            writeln!(
                out,
                "  {:<22} {}{} {}",
                t.id,
                c.fg(style::tell_fg(t.state), state),
                " ".repeat(8usize.saturating_sub(state.len())),
                t.detail
            )?;
        }
    }

    if !report.probes.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("probes"))?;
        for p in &report.probes {
            write!(out, "  {:<22} ", p.name)?;
            write_outcome(c, &p.outcome, true, out)?;
            if !matches!(p.flags, crate::model::FlagSet::None) {
                write!(out, " flag={}", p.flags.label())?;
            }
            if let Some(v) = &p.value {
                write!(out, " = {v}")?;
            }
            writeln!(out)?;
        }
    }

    if !report.diag_entries.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("sock diag"))?;
        writeln!(
            out,
            "  {: <22}{: <22}{: <6}{: <9}{: <12}{: <18}cookie",
            "src", "dst", "state", "shutdown", "ino", "pid"
        )?;
        for e in &report.diag_entries {
            let pid = match (&e.pid, &e.pid_comm) {
                (Some(p), Some(comm)) => format!("{p} ({comm})"),
                (Some(p), None) => p.to_string(),
                _ => "-".to_owned(),
            };
            writeln!(
                out,
                "  {: <22}{: <22}{: <6}{: <9}{: <12}{: <18}{}",
                format!("{}:{}", e.src_cid, e.src_port),
                format!("{}:{}", e.dst_cid, e.dst_port),
                e.state,
                e.shutdown,
                e.ino,
                pid,
                e.cookie
            )?;
        }
    }

    if !report.rows.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("results"))?;
        writeln!(
            out,
            "{: <8}{: <8}{: <10}{: <20}{: <16}ms",
            "cid", "port", "flag", "outcome", "errno"
        )?;
        for r in &report.rows {
            write!(out, "{: <8}{: <8}{: <10}", r.cid, r.port, r.flags.label())?;
            // `ms` stays a fixed column here and the explanation trails it.
            // Printing the detail before the number, the way the probe table does,
            // shifted every column after it and made the sweep ungreppable.
            write_outcome(c, &r.outcome, false, out)?;
            write!(out, "{: >16}", r.elapsed_ms)?;
            let mut tail = Vec::new();
            if let Some(b) = &r.banner {
                tail.push(format!("banner {b}"));
            }
            if let Some(d) = &r.outcome.detail {
                tail.push(d.clone());
            }
            if !tail.is_empty() {
                write!(out, "  {}", tail.join("  "))?;
            }
            writeln!(out)?;
        }
    }

    if !report.findings.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", c.bold("findings"))?;
        for f in &report.findings {
            let label = format!("[{}]", f.severity.as_str());
            let label = if style::severity_bold(f.severity) {
                c.bold(&label)
            } else {
                c.fg(style::severity_fg(f.severity), &label)
            };
            writeln!(out, "  {label} {}", f.message)?;
        }
    }

    writeln!(out)?;
    let mut parts: Vec<String> = report
        .summary
        .by_outcome
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    parts.sort();
    write!(
        out,
        "summary  results={} {}",
        report.summary.results,
        parts.join(" ")
    )?;
    if let Some(agree) = report.summary.flags_agree {
        write!(out, " flags-agree={}", if agree { "yes" } else { "NO" })?;
    }
    writeln!(out, " elapsed={}ms", report.summary.elapsed_ms)?;
    for n in &report.summary.notes {
        // A note may legitimately carry a hexdump; its continuation lines stay
        // under the note column so `grep note` still shows whole facts.
        let mut lines = n.lines();
        writeln!(out, "  note   {}", lines.next().unwrap_or(""))?;
        for rest in lines {
            writeln!(out, "         {rest}")?;
        }
    }
    Ok(())
}

/// `<kind>` coloured, then the errno it came from — a verdict never appears
/// without the signal that supports it.
/// Outcome + errno columns. `inline_detail` is for the probe table, where the
/// explanation *is* the readout; sweep rows pass `false` and print their detail
/// after the fixed columns instead.
fn write_outcome(
    c: ColorSupport,
    o: &Outcome,
    inline_detail: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    // Pad the *plain* text, then colour it: wrapping first would let the escape
    // sequences eat the column width and shift every downstream column.
    let plain = o.kind.as_str();
    write!(
        out,
        "{}{}",
        c.fg(style::outcome_fg(o.kind), plain),
        " ".repeat(20usize.saturating_sub(plain.len()))
    )?;
    let errno = match &o.errno_name {
        Some(n) => match o.errno {
            Some(e) => format!("{n}({e})"),
            None => n.clone(),
        },
        None => match o.errno {
            Some(e) => e.to_string(),
            None => "-".to_owned(),
        },
    };
    write!(out, "{: <16}", errno)?;
    if inline_detail {
        if let Some(d) = &o.detail {
            write!(out, "{}", d)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        placeholder_header, FlagSet, Outcome, OutcomeKind, Report, ScanRow, Severity, Tell,
        TellState,
    };

    fn report() -> Report {
        let mut r = Report::new("scan", placeholder_header());
        r.tells.push(Tell {
            id: "cid2-loopback-canary".into(),
            state: TellState::Inert,
            detail: "vsock_loopback not built".into(),
        });
        for (flags, kind, errno) in [
            (FlagSet::None, OutcomeKind::RefusedKernel, Some(libc::ENODEV)),
            (FlagSet::ToHost, OutcomeKind::Open, None),
        ] {
            let o = match errno {
                Some(e) => Outcome::new(kind).with_errno(e),
                None => Outcome::new(kind),
            };
            r.rows.push(ScanRow {
                cid: 2,
                port: 1234,
                flags,
                outcome: o,
                elapsed_ms: 7,
                banner: None,
            });
        }
        r.finding(Severity::Alert, "device present: this is not the target shape");
        r.recompute_summary(9);
        r
    }

    /// The sweep table is machine-grepped as well as read: a long explanation
    /// must not displace the numeric column that comes before it.
    #[test]
    fn sweep_row_columns_survive_a_long_explanation() {
        let mut r = report();
        for row in r.rows.iter_mut() {
            row.elapsed_ms = 2000;
            row.banner = Some("7f 45 4c 46".to_string());
        }
        r.rows[0].outcome.detail =
            Some("underlying closed; the canary proved CID 2 is loopback".to_string());
        let t = s(&r, ColorSupport::Off);
        let line = t
            .lines()
            .find(|l| l.starts_with("2  ") && l.contains("underlying closed"))
            .expect("one row line carrying the explanation");
        let ms = line.find("2000").expect("the ms column");
        let banner = line.find("7f 45 4c 46").expect("the banner preview");
        let detail = line.find("underlying closed").expect("the detail");
        assert!(
            ms < banner && banner < detail,
            "fixed columns must come before free text:\n{line}"
        );
    }

    fn s(r: &Report, c: ColorSupport) -> String {
        let mut b = Vec::new();
        render(r, c, &mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    /// Notes hold byte dumps, and a dump whose second line starts at column 0 is
    /// no longer readable as part of the note it belongs to.
    #[test]
    fn multiline_notes_stay_under_their_column() {
        let mut r = report();
        r.summary.notes.push(
            "first bytes from 1234:\n00000000  76 73 6f 63 6b   |vsock|\n00000005  00   |.|"
                .to_string(),
        );
        let t = s(&r, ColorSupport::Off);
        let at = t.find("first bytes from 1234:").expect("the note");
        let line_start = t[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let block: Vec<&str> = t[line_start..].lines().take(3).collect();
        assert!(block[0].starts_with("  note   "), "{}", block[0]);
        assert!(block[1].starts_with("         00000000"), "{}", block[1]);
        assert!(block[2].starts_with("         00000005"), "{}", block[2]);
    }

    #[test]
    fn row_and_header_shape() {
        let t = s(&report(), ColorSupport::Off);
        let rows: Vec<&str> = t.lines().filter(|l| l.starts_with("2  ")).collect();
        assert_eq!(rows.len(), 2, "one line per result row:\n{t}");
        assert!(rows.iter().any(|l| l.contains("refused-kernel") && l.contains("ENODEV(19)")));
        assert!(rows.iter().any(|l| l.contains("to-host") && l.contains("open")));
        assert!(t.contains("device   unknown"));
        assert!(t.contains("cid2-loopback-canary   inert"), "{t}");
        assert!(t.contains("[alert] device present"));
        assert!(t.contains("summary  results=2"));
        assert!(t.contains("flags-agree=NO"));
    }

    #[test]
    fn colour_wraps_values_not_columns() {
        let off = s(&report(), ColorSupport::Off);
        let on = s(&report(), ColorSupport::TrueColor);
        // Same visible layout: padding must not shift when colour is on.
        let plain = crate::render::json::strip_sgr(&on);
        assert_eq!(plain, off);
        assert!(on.contains("\x1b[38;2;0;255;136mopen\x1b[0m"));
        assert!(on.contains("\x1b[1m[alert]\x1b[0m"));
    }
}
