//! JSON output: serialize first (`serde_json::to_string_pretty`), then add
//! colour with a tokeniser over the finished document. String concatenation of
//! JSON fragments is how a report ends up with an unescaped quote in it, and the
//! contract that coloured and uncoloured runs differ *only* in escape sequences
//! is only checkable when the bytes are produced once.

use std::io::{self, Write};

use crate::model::Report;

use super::style::{self, ColorSupport};

pub fn render(report: &Report, c: ColorSupport, out: &mut dyn Write) -> io::Result<()> {
    let doc = serde_json::to_string_pretty(report)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    match c {
        ColorSupport::Off => out.write_all(doc.as_bytes()),
        ColorSupport::TrueColor => {
            // Paint into a buffer first: the paint step is pure, so a bug there
            // cannot half-write a report.
            let painted = highlight(&doc);
            out.write_all(painted.as_bytes())
        }
    }
}

/// Remove every SGR sequence. Used by the test that pins "colour adds escapes
/// and nothing else", and available to anyone diffing a coloured transcript.
/// Test-side and `--no-color` equivalence check: nothing in the JSON renderer
/// emits SGR, so stripping a highlighted document must return it unchanged.
#[cfg(test)]
pub fn strip_sgr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(ch) = it.next() {
        if ch != '\x1b' {
            out.push(ch);
            continue;
        }
        // ESC [ params m — the whole sequence goes, bracket included.
        if it.peek() == Some(&'[') {
            it.next();
            while let Some(&c2) = it.peek() {
                it.next();
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Tokenise the serialized document and paint tokens with the shared palette:
/// keys electric blue, quoted strings titanium gold, numbers and plain scalars
/// amber, `true`/`false`/`null` readout green, punctuation dim.
pub fn highlight(doc: &str) -> String {
    let b = doc.as_bytes();
    let mut out = String::with_capacity(doc.len() + 64);
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let end = match string_end(b, i) {
                    Some(e) => e,
                    None => {
                        out.push_str(&doc[i..]);
                        break;
                    }
                };
                let raw = &doc[i..=end];
                // A string is a key iff the next non-whitespace byte is ':'.
                let is_key = matches!(
                    b[end + 1..].iter().find(|c| !c.is_ascii_whitespace()),
                    Some(b':')
                );
                let inner = &raw[1..raw.len() - 1];
                let hex = if is_key {
                    style::ELECTRIC_BLUE
                } else if matches!(inner, "true" | "false" | "null") {
                    style::READOUT_GREEN
                } else {
                    style::TITANIUM_GOLD
                };
                // Repaint the inner text, keep the quotes dim.
                out.push_str(&format!(
                    "\x1b[38;2;156;163;176m\"\x1b[0m{}\"\x1b[0m",
                    tint(hex, inner)
                ));
                i = end + 1;
            }
            b'0'..=b'9' | b'-' => {
                let start = i;
                if b[i] == b'-' {
                    i += 1;
                }
                while i < b.len()
                    && (b[i].is_ascii_digit() || matches!(b[i], b'.' | b'e' | b'E' | b'+' | b'-'))
                {
                    i += 1;
                }
                out.push_str(&tint(style::WARNING_AMBER, &doc[start..i]));
            }
            b't' | b'f' | b'n' => {
                // Bare literals only appear as values in valid JSON.
                let start = i;
                while i < b.len() && b[i].is_ascii_alphabetic() {
                    i += 1;
                }
                out.push_str(&tint(style::READOUT_GREEN, &doc[start..i]));
            }
            b',' | b':' | b'{' | b'}' | b'[' | b']' => {
                out.push_str(&format!(
                    "\x1b[38;2;156;163;176m{}\x1b[0m",
                    doc[i..i + 1].to_owned()
                ));
                i += 1;
            }
            _ => {
                out.push(doc[i..].chars().next().unwrap());
                i += doc[i..].chars().next().unwrap().len_utf8();
            }
        }
    }
    out
}

fn tint(hex: &str, text: &str) -> String {
    let h = hex.strip_prefix('#').unwrap_or(hex);
    let v = u32::from_str_radix(h, 16).unwrap_or(0);
    format!(
        "\x1b[38;2;{};{};{}m{}\x1b[0m",
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff,
        text
    )
}

/// Index of the closing quote of the string starting at `start`, honouring `\"`.
fn string_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{placeholder_header, Report};

    fn doc() -> String {
        let mut r = Report::new("probe", placeholder_header());
        r.finding(crate::model::Severity::Warn, "quote \" and colon: value");
        let mut buf = Vec::new();
        render(&r, ColorSupport::Off, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn uncoloured_document_is_valid_json_with_escapes_intact() {
        let d = doc();
        let v: serde_json::Value = serde_json::from_str(&d).unwrap();
        assert_eq!(v["findings"][0]["message"], "quote \" and colon: value");
    }

    #[test]
    fn highlighting_adds_only_escape_sequences() {
        let d = doc();
        assert_eq!(strip_sgr(&highlight(&d)), d);
        assert!(highlight(&d).len() > d.len());
    }

    #[test]
    fn strip_sgr_handles_no_sequences() {
        assert_eq!(strip_sgr("{\"a\": 1}"), "{\"a\": 1}");
    }
}
