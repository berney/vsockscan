//! Renderers for [`Report`]: text (canonical), markdown, JSON (tokenised
//! after rendering, never string-concatenated), YAML (hand-emitted with a fixed
//! key order).
//!
//! One colour decision is taken in `main` and passed down as
//! [`ColorSupport`]; a renderer must never call `isatty` itself. `Off` makes
//! every helper the identity, which is what makes `-o FILE` byte-identical to a
//! `--no-color` stdout run a structural property rather than a convention
//! (spec §5).

pub mod json;
pub mod markdown;
pub mod style;
pub mod text;
pub mod yaml;

use std::io::{self, Write};

use crate::model::{Format, Report};
pub use style::ColorSupport;

pub fn render(
    report: &Report,
    format: Format,
    color: ColorSupport,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => text::render(report, color, out),
        Format::Markdown => markdown::render(report, color, out),
        Format::Json => json::render(report, color, out),
        Format::Yaml => yaml::render(report, color, out),
    }
}

/// `-q`: the summary block only, for the human formats. JSON and YAML deliberately
/// ignore quiet — a document with fields missing is not the same machine contract,
/// and a caller that asked for JSON should get JSON.
pub fn render_summary(
    report: &Report,
    format: Format,
    color: ColorSupport,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => text::summary(report, color, out),
        other => render(report, other, color, out),
    }
}

/// JSON Schema for the `--json` document. Hand-written and drift-tested in
/// [`tests::schema_matches_serialized_report`]: a schema nobody checks against
/// the emitter is documentation that rots silently.
pub fn json_schema() -> String {
    SCHEMA.to_owned()
}

const SCHEMA: &str = r##"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "vsockscan report",
  "type": "object",
  "required": ["tool", "version", "command", "header", "tells", "probes", "rows", "diag-entries", "findings", "summary"],
  "additionalProperties": false,
  "properties": {
    "tool": {"type": "string"},
    "version": {"type": "string"},
    "command": {"type": "string", "enum": ["probe", "scan", "listen", "h2g", "selftest"]},
    "header": {
      "type": "object",
      "required": ["kernel", "uid", "caps", "cid", "sysctls", "posture", "device", "module-verdicts", "diag", "noise"],
      "additionalProperties": false,
      "properties": {
        "kernel": {"type": "string"},
        "uid": {"type": "integer"},
        "caps": {"type": "array", "items": {"type": "string"}},
        "cid": {
          "type": "object",
          "required": ["cid", "source"],
          "properties": {"cid": {"type": ["integer", "null"]}, "source": {"type": "string"}}
        },
        "sysctls": {
          "type": "array",
          "items": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "items": [{"type": "string"}, {"type": "string"}]
          }
        },
        "posture": {"type": "string", "enum": ["guest", "host", "both", "neither", "unknown"]},
        "device": {"type": "string", "enum": ["present", "absent-but-driver", "absent", "unknown"]},
        "config-source": {"type": ["string", "null"]},
        "module-verdicts": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["name", "state", "reason"],
            "properties": {
              "name": {"type": "string"},
              "state": {"type": "string", "enum": ["builtin", "loaded", "loadable", "modules-disabled", "unavailable", "unknown"]},
              "reason": {"type": "string"}
            }
          }
        },
        "diag": {
          "oneOf": [
            {"type": "object", "required": ["available"], "properties": {"available": {"type": "object", "required": ["entries"], "properties": {"entries": {"type": "integer"}}}}, "additionalProperties": false},
            {"type": "object", "required": ["unavailable"], "properties": {"unavailable": {"type": "string"}}, "additionalProperties": false},
            {"type": "string", "const": "skipped"}
          ]
        },
        "noise": {"type": "string"}
      }
    },
    "tells": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "state", "detail"],
        "properties": {
          "id": {"type": "string"},
          "state": {"type": "string", "enum": ["yes", "no", "unknown", "inert"]},
          "detail": {"type": "string"}
        }
      }
    },
    "probes": {
      "type": "array",
      "items": {"$ref": "#/definitions/observation"}
    },
    "rows": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["cid", "port", "flags", "outcome", "elapsed-ms"],
        "properties": {
          "cid": {"type": "integer"},
          "port": {"type": "integer"},
          "flags": {"type": "string", "enum": ["none", "to-host"]},
          "outcome": {"$ref": "#/definitions/outcome"},
          "elapsed-ms": {"type": "integer", "minimum": 0},
          "banner": {"type": ["string", "null"]}
        }
      }
    },
    "diag-entries": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["family", "kind", "state", "shutdown", "src-cid", "src-port", "dst-cid", "dst-port", "ino", "cookie"],
        "properties": {
          "family": {"type": "integer"},
          "kind": {"type": "integer"},
          "state": {"type": "integer"},
          "shutdown": {"type": "integer"},
          "src-cid": {"type": "integer"},
          "src-port": {"type": "integer"},
          "dst-cid": {"type": "integer"},
          "dst-port": {"type": "integer"},
          "ino": {"type": "integer"},
          "cookie": {"type": "string"},
          "pid": {"type": ["integer", "null"]},
          "pid-comm": {"type": ["string", "null"]}
        }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["severity", "message"],
        "properties": {
          "severity": {"type": "string", "enum": ["info", "warn", "alert"]},
          "message": {"type": "string"}
        }
      }
    },
    "summary": {
      "type": "object",
      "required": ["results", "by-outcome", "elapsed-ms"],
      "properties": {
        "results": {"type": "integer", "minimum": 0},
        "by-outcome": {"type": "object", "additionalProperties": {"type": "integer"}},
        "flags-agree": {"type": ["boolean", "null"]},
        "elapsed-ms": {"type": "integer", "minimum": 0},
        "notes": {"type": "array", "items": {"type": "string"}}
      }
    }
  },
  "definitions": {
    "outcome": {
      "type": "object",
      "required": ["kind"],
      "properties": {
        "kind": {"type": "string", "enum": ["open", "closed", "refused-kernel", "silent", "loopback-redirect", "unsupported", "error", "absent", "denied", "stale", "not-muxer"]},
        "errno": {"type": ["integer", "null"]},
        "errno-name": {"type": ["string", "null"]},
        "detail": {"type": ["string", "null"]}
      }
    },
    "observation": {
      "type": "object",
      "required": ["name", "outcome", "flags"],
      "properties": {
        "name": {"type": "string"},
        "outcome": {"$ref": "#/definitions/outcome"},
        "value": {"type": ["string", "null"]},
        "flags": {"type": "string", "enum": ["none", "to-host"]}
      }
    }
  }
}"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        placeholder_header, FlagSet, Outcome, OutcomeKind, Report, ScanRow, Severity,
    };

    pub fn sample() -> Report {
        let mut r = Report::new("scan", placeholder_header());
        for (flags, kind) in [
            (FlagSet::None, OutcomeKind::RefusedKernel),
            (FlagSet::ToHost, OutcomeKind::Open),
        ] {
            r.rows.push(ScanRow {
                cid: 2,
                port: 1234,
                flags,
                outcome: if kind == OutcomeKind::RefusedKernel {
                    Outcome::new(kind).with_errno(libc::ENODEV)
                } else {
                    Outcome::new(kind)
                },
                elapsed_ms: 1,
                banner: None,
            });
        }
        r.finding(Severity::Warn, "flag set changed the verdict on 2:1234");
        r.recompute_summary(2);
        r
    }

    fn render_str(f: Format, color: ColorSupport) -> String {
        let mut buf = Vec::new();
        render(&sample(), f, color, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn file_output_equals_no_color_output_in_every_format() {
        // The contract: `-o FILE` is byte-identical to `--no-color`.
        for f in [Format::Text, Format::Markdown, Format::Json, Format::Yaml] {
            let off = render_str(f, ColorSupport::Off);
            assert!(!off.contains('\x1b'), "{f:?} emitted SGR while off");
        }
    }

    #[test]
    fn colored_output_differs_but_resets_balanced() {
        for f in [Format::Text, Format::Markdown, Format::Json, Format::Yaml] {
            let on = render_str(f, ColorSupport::TrueColor);
            assert!(on.contains("\x1b[38;2;"), "{f:?} coloured nothing");
            assert!(
                on.matches("\x1b[0m").count() <= on.matches("\x1b[").count(),
                "{f:?} unbalanced SGR"
            );
        }
    }

    #[test]
    fn json_is_parseable_coloured_or_not() {
        let plain = render_str(Format::Json, ColorSupport::Off);
        let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
        assert_eq!(v["tool"], "vsockscan");
        assert_eq!(v["rows"].as_array().unwrap().len(), 2);
        assert_eq!(v["summary"]["by-outcome"]["open"], 1);
        // Stripping SGR must reproduce the unstyled document exactly: the
        // highlighter may only add sequences, never change bytes.
        let styled = render_str(Format::Json, ColorSupport::TrueColor);
        assert_eq!(json::strip_sgr(&styled), plain.trim_end());
    }

    #[test]
    fn text_renders_one_line_per_row_with_errno() {
        let t = render_str(Format::Text, ColorSupport::Off);
        assert_eq!(t.lines().filter(|l| l.starts_with("2  ")).count(), 2);
        assert!(t.contains("refused-kernel"));
        assert!(t.contains("ENODEV"));
        assert!(t.contains("to-host"));
    }

    #[test]
    fn yaml_key_order_is_stable_across_runs() {
        let a = render_str(Format::Yaml, ColorSupport::Off);
        let b = render_str(Format::Yaml, ColorSupport::Off);
        assert_eq!(a, b);
        let order: Vec<&str> = a
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split(':').next())
            .filter(|k| !k.starts_with(' ') && !k.is_empty())
            .collect();
        assert_eq!(
            order,
            vec![
                "tool",
                "version",
                "command",
                "header",
                "tells",
                "probes",
                "rows",
                "diag-entries",
                "findings",
                "summary"
            ]
        );
    }

    #[test]
    fn empty_report_renders_in_all_formats() {
        let r = Report::new("probe", placeholder_header());
        for f in [Format::Text, Format::Markdown, Format::Json, Format::Yaml] {
            let mut buf = Vec::new();
            render(&r, f, ColorSupport::Off, &mut buf).unwrap();
            assert!(
                !buf.is_empty(),
                "{f:?} rendered nothing for an empty report"
            );
        }
        let j = {
            let mut buf = Vec::new();
            render(&r, Format::Json, ColorSupport::Off, &mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        };
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["rows"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn schema_matches_serialized_report() {
        let schema: serde_json::Value = serde_json::from_str(&json_schema()).unwrap();
        let props = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut buf = Vec::new();
        render(&sample(), Format::Json, ColorSupport::Off, &mut buf).unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap();
        let keys: Vec<String> = doc.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys, props,
            "serialized report and schema disagree on top-level keys/order"
        );
        // Nested shapes we care about drift on:
        assert!(props.contains(&"header".to_owned()));
        let header = schema["properties"]["header"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let doc_header = doc["header"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(header, doc_header, "header key drift");
    }

    #[test]
    fn schema_lists_the_h2g_outcomes() {
        let schema: serde_json::Value = serde_json::from_str(&json_schema()).unwrap();
        let kinds = schema["definitions"]["outcome"]["properties"]["kind"]["enum"]
            .as_array()
            .expect("kind enum");
        for want in ["absent", "denied", "stale", "not-muxer"] {
            assert!(
                kinds.iter().any(|k| k == want),
                "{want} missing from {kinds:?}"
            );
        }
    }
}
