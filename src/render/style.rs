//! Titanium-palette colour detection and SGR helpers, vendored from
//! `amirustrained/src/render/style.rs` (the OMP `titanium` dark theme) so the
//! two tools' output matches when they end up in the same transcript.
//!
//! Detection mirrors `packages/utils/src/chalk.ts` (`detectColorLevel`): an
//! explicit `--no-color` wins, then any `NO_COLOR` *presence* (no-color.org;
//! the bare key counts even when empty), then `TERM=dumb`, then the stdout TTY
//! test. Truecolor (`ESC[38;2;r;g;bm`) is the only emission mode, so off-vs-on
//! is the only support decision a renderer makes.
//!
//! Semantic mapping (adapted to this tool's three-level severity, spec §5):
//!
//! | role                              | colour |
//! |-----------------------------------|--------|
//! | severity `alert`                  | `ALERT_RED` #ff4757, bold |
//! | severity `warn`                   | `WARNING_AMBER` #ffb347 |
//! | severity `info`                   | `DIM_ALUMINUM` #9ca3b0 |
//! | outcome `open`                    | `READOUT_GREEN` #00ff88 |
//! | outcome `closed` / `unsupported`  | `WARNING_AMBER` #ffb347 |
//! | outcome `silent` / `refused-kernel` | `DIM_ALUMINUM` #9ca3b0 |
//! | outcome `loopback-redirect` / `error` | `ALERT_RED` #ff4757 |
//! | tell `yes`                        | `ALERT_RED` #ff4757 |
//! | tell `unknown`                    | `WARNING_AMBER` #ffb347 |
//! | device `present`                  | `READOUT_GREEN`, `absent-but-driver` `ELECTRIC_BLUE` #00b4ff, `absent` dim, `unknown` amber |
//!
//! JSON (post-render tokeniser, [`crate::render::json::highlight`]) and YAML
//! (emit-time) share the palette: keys `ELECTRIC_BLUE`, strings
//! `TITANIUM_GOLD` (quoted) / `WARNING_AMBER` (plain scalars), numbers
//! `WARNING_AMBER`, bool/null `READOUT_GREEN`, punctuation `DIM_ALUMINUM`.

use crate::model::{OutcomeKind, Severity, TellState, Verdict};

// --- Titanium palette (titanium.json, dark variant) -------------------------
// Copied whole from `~/co/berney/amirustrained/src/render/style.rs` so the two
// tools' output is comparable token for token. A few entries are unused here;
// dropping them would break that provenance, which is worth more than a lint.
#[allow(dead_code, reason = "vendored palette, kept whole for provenance")]
pub const ELECTRIC_BLUE: &str = "#00b4ff";
pub const TITANIUM_GOLD: &str = "#d4c090";
#[allow(dead_code, reason = "vendored palette, kept whole for provenance")]
pub const BRIGHT_ALUMINUM: &str = "#e8ecf4";
pub const DIM_ALUMINUM: &str = "#9ca3b0";
pub const WARNING_AMBER: &str = "#ffb347";
pub const READOUT_GREEN: &str = "#00ff88";
pub const ALERT_RED: &str = "#ff4757";

pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorSupport {
    Off,
    TrueColor,
}

/// Every off-switch (flag, env, pipe) collapses to [`ColorSupport::Off`], which
/// makes every helper below the identity and keeps piped/`-o` output
/// byte-identical to the unstyled contract.
pub fn detect(no_color: bool, tty: bool, env: &dyn Fn(&str) -> Option<String>) -> ColorSupport {
    if no_color {
        return ColorSupport::Off;
    }
    if env("NO_COLOR").is_some() {
        return ColorSupport::Off;
    }
    if env("TERM").as_deref() == Some("dumb") {
        return ColorSupport::Off;
    }
    if !tty {
        return ColorSupport::Off;
    }
    ColorSupport::TrueColor
}

impl ColorSupport {
    pub fn wrap(self, prefix: &str, text: &str) -> String {
        if self == Self::Off {
            text.to_owned()
        } else {
            format!("{prefix}{text}{RESET}")
        }
    }

    pub fn fg(self, hex: &str, text: &str) -> String {
        self.wrap(&fg(hex), text)
    }

    pub fn bold(self, text: &str) -> String {
        self.wrap(BOLD, text)
    }
}

/// Truecolor foreground sequence for `#rrggbb`. A malformed literal degrades to
/// black instead of panicking a renderer.
pub fn fg(hex: &str) -> String {
    let h = hex.strip_prefix('#').unwrap_or(hex);
    let v = u32::from_str_radix(h, 16).unwrap_or(0);
    format!(
        "\x1b[38;2;{};{};{}m",
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

pub fn severity_fg(sev: Severity) -> &'static str {
    match sev {
        Severity::Alert => ALERT_RED,
        Severity::Warn => WARNING_AMBER,
        Severity::Info => DIM_ALUMINUM,
    }
}

/// Only `alert` is bolded: the escalation marks the alarm level, the foreground
/// carries the rest of the ladder.
pub fn severity_bold(sev: Severity) -> bool {
    sev == Severity::Alert
}

pub fn outcome_fg(kind: OutcomeKind) -> &'static str {
    match kind {
        OutcomeKind::Open => READOUT_GREEN,
        OutcomeKind::Closed | OutcomeKind::Unsupported => WARNING_AMBER,
        OutcomeKind::Silent | OutcomeKind::RefusedKernel => DIM_ALUMINUM,
        OutcomeKind::LoopbackRedirect | OutcomeKind::Error => ALERT_RED,
    }
}

pub fn tell_fg(state: TellState) -> &'static str {
    match state {
        TellState::Yes => ALERT_RED,
        TellState::Unknown => WARNING_AMBER,
        TellState::No | TellState::Inert => DIM_ALUMINUM,
    }
}

pub fn verdict_fg(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Present => READOUT_GREEN,
        Verdict::AbsentButDriver => ELECTRIC_BLUE,
        Verdict::Absent => DIM_ALUMINUM,
        Verdict::Unknown => WARNING_AMBER,
    }
}

/// `#rrggbb` -> anstyle RGB colour; malformed degrades to black, never panics.
fn rgb_color(hex: &str) -> anstyle::Color {
    let digits = hex.strip_prefix('#').unwrap_or(hex);
    let v = u32::from_str_radix(digits, 16).unwrap_or(0);
    anstyle::Color::Rgb(anstyle::RgbColor(
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ))
}

/// Titanium [`clap::builder::Styles`] for the help/version/error streams, which
/// clap owns end-to-end — the palette is still ours. Emission is gated on
/// `NO_COLOR`/`TERM=dumb`/tty by clap's anstream; `--no-color` needs the argv
/// prescan in `main` because help is rendered before parsing finishes.
pub fn clap_styles() -> clap::builder::Styles {
    use anstyle::Style;
    clap::builder::Styles::styled()
        .header(
            Style::new()
                .bold()
                .underline()
                .fg_color(Some(rgb_color(ELECTRIC_BLUE))),
        )
        .usage(Style::new().bold().fg_color(Some(rgb_color(ELECTRIC_BLUE))))
        .literal(Style::new().fg_color(Some(rgb_color(READOUT_GREEN))))
        .placeholder(Style::new().fg_color(Some(rgb_color(TITANIUM_GOLD))))
        .error(Style::new().bold().fg_color(Some(rgb_color(ALERT_RED))))
        .valid(Style::new().fg_color(Some(rgb_color(READOUT_GREEN))))
        .invalid(Style::new().fg_color(Some(rgb_color(WARNING_AMBER))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| {
            owned
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, ev)| ev.clone())
        }
    }

    #[test]
    fn gating_matrix() {
        // tty, NO_COLOR, TERM, --no-color -> expectation
        // (case, tty, NO_COLOR, TERM, --no-color, expect colour)
        type Gate = (&'static str, bool, Option<&'static str>, Option<&'static str>, bool, bool);
        let cases: &[Gate] = &[
            ("tty clean", true, None, None, false, true),
            ("pipe clean", false, None, None, false, false),
            ("NO_COLOR present", true, Some(""), None, false, false),
            ("NO_COLOR set", true, Some("1"), None, false, false),
            ("TERM=dumb", true, None, Some("dumb"), false, false),
            ("TERM=xterm", true, None, Some("xterm-256color"), false, true),
            ("flag wins over tty", true, None, None, true, false),
            ("flag and env agree", true, Some("1"), Some("dumb"), true, false),
        ];
        for (name, tty, no_color, term, flag, want_color) in cases {
            let mut pairs = Vec::new();
            if let Some(v) = no_color {
                pairs.push(("NO_COLOR", *v));
            }
            if let Some(v) = term {
                pairs.push(("TERM", *v));
            }
            let got = detect(*flag, *tty, &env_with(&pairs));
            assert_eq!(
                got == ColorSupport::TrueColor,
                *want_color,
                "case {name}: got {got:?}"
            );
        }
    }

    #[test]
    fn off_is_the_identity_function() {
        assert_eq!(ColorSupport::Off.fg(ALERT_RED, "open"), "open");
        assert_eq!(ColorSupport::Off.bold("x"), "x");
        assert_eq!(ColorSupport::Off.wrap(BOLD, "x"), "x");
    }

    #[test]
    fn truecolor_wraps_and_resets_once() {
        let s = ColorSupport::TrueColor.fg(READOUT_GREEN, "open");
        assert_eq!(s, "\x1b[38;2;0;255;136mopen\x1b[0m");
        assert_eq!(s.matches("\x1b[0m").count(), 1);
    }

    #[test]
    fn malformed_hex_degrades_instead_of_panicking() {
        assert_eq!(fg("#nope"), "\x1b[38;2;0;0;0m");
        assert_eq!(fg("00ff88"), "\x1b[38;2;0;255;136m");
    }
}
