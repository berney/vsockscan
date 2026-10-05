//! CID and port selection, over the domain the kernel actually uses.
//!
//! Both specs are `u32` end to end. That is not pedantry: ephemeral vsock ports
//! on Linux live in the 32-bit range (e.g. `3064402411..3064435423`), so anything that
//! clamps to 16 bits would silently scan a keyspace that contains nothing while
//! reporting success. `4294967295` is a legal port *and* the legal CID `ANY`.
//!
//! The CID spec keeps its keywords symbolic until `resolve`, because `local`
//! cannot be answered until the local CID has been resolved from the ioctl /
//! bound socket (spec §6.3.2) — and if it cannot be resolved, saying so beats
//! guessing a number.

use crate::uapi;

/// The curated `top` port set: 64 entries, the ones worth a first look from
/// inside a microVM. Provenance, in order:
///
/// * common service ports — ssh/http/https, VM agent services, and container-runtime/agent ports;
/// * classic `nmap top`-style service ports that show up in container images;
/// * database/broker/infra ports that are commonly sidecar'd next to a workload;
/// * a tail of high ports where ad-hoc agents and debug listeners land.
///
/// It is a starting point, not a claim about what *should* be open; `--ports`
/// takes an explicit spec for everything else.
pub const TOP_PORTS: [u32; 64] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631, 873, 990, 993, 995,
    1024, 1025, 1026, 1433, 1521, 2049, 2181, 2375, 2376, 2379, 3000, 3306, 3389, 4243, 4369, 5432,
    5555, 5900, 5984, 6379, 6443, 7946, 8000, 8021, 8025, 8080, 8443, 9000, 9090, 9200, 10000,
    10809, 11211, 11434, 15672, 19999, 20000, 25565, 27017, 31337, 45000, 50000, 50051, 56794,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidToken {
    /// The whole `0..=2^32-1` keyspace, gated by [`CidSpec::resolve`].
    All,
    /// `VMADDR_CID_HYPERVISOR` (0).
    Hyp,
    /// The resolved local CID — only answerable at resolve time.
    Local,
    /// `VMADDR_CID_HOST` (2).
    Host,
    /// `VMADDR_CID_ANY` (u32::MAX), which is what a bound socket keeps reporting.
    Any,
    Range(u32, u32),
    One(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidSpec {
    pub tokens: Vec<CidToken>,
}

/// What `resolve` may consult. `extra` is the union of CIDs seen in the
/// `vsock_diag` census and `--cid-file`; `local` is the resolved local CID.
pub struct CidContext<'a> {
    pub max_cids: usize,
    /// `--i-know-this-is-wide`, or an explicitly raised `--max-cids`.
    pub wide_ok: bool,
    pub extra: &'a [u32],
    pub local: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolved {
    pub cids: Vec<u32>,
    /// Explanations the report must carry: what `all` actually meant, what got
    /// dropped, and why.
    pub notes: Vec<String>,
}

impl CidSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if spec.trim().is_empty() {
            return Err("empty --cid spec".to_string());
        }
        let mut tokens = Vec::new();
        for part in spec.split(',') {
            let p = part.trim();
            if p.is_empty() {
                return Err(format!("empty element in --cid spec {spec:?}"));
            }
            tokens.push(match p.to_ascii_lowercase().as_str() {
                "all" => CidToken::All,
                "hyp" | "hypervisor" => CidToken::Hyp,
                "local" => CidToken::Local,
                "host" => CidToken::Host,
                "any" => CidToken::Any,
                _ => {
                    if let Some((a, b)) = p.split_once('-') {
                        let a = parse_u32(a, "--cid range start")?;
                        let b = parse_u32(b, "--cid range end")?;
                        if a > b {
                            return Err(format!(
                                "--cid range {a}-{b} runs backwards"
                            ));
                        }
                        CidToken::Range(a, b)
                    } else {
                        CidToken::One(parse_u32(p, "--cid value")?)
                    }
                }
            });
        }
        Ok(Self { tokens })
    }

    pub fn wants_all(&self) -> bool {
        self.tokens.contains(&CidToken::All)
    }

    /// Expand everything except `All`, which needs the gate.
    fn expand_keywords(&self, local: Option<u32>) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        for t in &self.tokens {
            match *t {
                CidToken::All => {}
                CidToken::Hyp => out.push(uapi::VMADDR_CID_HYPERVISOR),
                CidToken::Host => out.push(uapi::VMADDR_CID_HOST),
                CidToken::Any => out.push(uapi::VMADDR_CID_ANY),
                CidToken::Local => {
                    let cid = local.ok_or_else(|| {
                        "--cid local was requested but the local CID could not be resolved \
                         (the ioctl did not answer and a bound socket still reports ANY); \
                         pass the number explicitly"
                            .to_string()
                    })?;
                    out.push(cid);
                }
                CidToken::One(n) => out.push(n),
                CidToken::Range(a, b) => {
                    // Inclusive, and `a..=b` on u32 without the +1 overflow.
                    for n in a..=b {
                        out.push(n);
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn resolve(&self, ctx: &CidContext) -> Result<Resolved, String> {
        let mut notes = Vec::new();
        let mut cids = self.expand_keywords(ctx.local)?;
        if self.wants_all() {
            if ctx.wide_ok {
                let n = ctx.max_cids.min(u32::MAX as usize + 1);
                cids.extend(0..n as u32);
                notes.push(format!(
                    "--cid all acknowledged: swept 0..{} because --max-cids is {max} \
                     (the real keyspace is 0..=4294967295, so this is a truncation, \
                     not the whole domain)",
                    n - 1,
                    max = ctx.max_cids
                ));
            } else {
                let mut curated = vec![
                    uapi::VMADDR_CID_HYPERVISOR,
                    uapi::VMADDR_CID_LOCAL,
                    uapi::VMADDR_CID_HOST,
                ];
                curated.extend_from_slice(ctx.extra);
                curated.extend_from_slice(&cids);
                cids = curated;
                notes.push(
                    "--cid all narrowed to the curated set (hyp/local/host, the resolved \
                     local CID, and any CID seen in vsock_diag or --cid-file); pass \
                     --i-know-this-is-wide to sweep 0..--max-cids instead"
                        .to_string(),
                );
            }
        }
        cids.extend_from_slice(ctx.extra);
        cids.sort_unstable();
        cids.dedup();
        if cids.len() > ctx.max_cids {
            return Err(format!(
                "the --cid spec expands to {} CIDs, over --max-cids {}; narrow the spec, \
                 raise --max-cids, or (for `all`) pass --i-know-this-is-wide",
                cids.len(),
                ctx.max_cids
            ));
        }
        Ok(Resolved { cids, notes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec(pub Vec<u32>);

impl PortSpec {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let p = spec.trim();
        if p.eq_ignore_ascii_case("top") {
            return Ok(Self(TOP_PORTS.to_vec()));
        }
        if p.is_empty() {
            return Err("empty --ports spec".to_string());
        }
        let mut out = Vec::new();
        for part in p.split(',') {
            let q = part.trim();
            if q.is_empty() {
                return Err(format!("empty element in --ports spec {spec:?}"));
            }
            if let Some((a, b)) = q.split_once('-') {
                let a = parse_u32(a, "--ports range start")?;
                let b = parse_u32(b, "--ports range end")?;
                if a > b {
                    return Err(format!("--ports range {a}-{b} runs backwards"));
                }
                out.extend(a..=b);
            } else {
                out.push(parse_u32(q, "--ports value")?);
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(Self(out))
    }
}

/// Strict `u32`, with an error that says what went wrong rather than "invalid digit".
fn parse_u32(s: &str, what: &str) -> Result<u32, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(format!("{what}: empty"));
    }
    if t.starts_with('-') {
        return Err(format!("{what}: {t:?} is negative; CIDs and ports are u32"));
    }
    t.parse::<u32>()
        .map_err(|e| format!("{what}: {t:?} is not a u32 ({e})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(max_cids: usize, wide_ok: bool, extra: &'a [u32]) -> CidContext<'a> {
        CidContext { max_cids, wide_ok, extra, local: Some(3) }
    }

    #[test]
    fn top_ports_is_sixty_four_unique_entries() {
        assert_eq!(TOP_PORTS.len(), 64);
        let mut v = TOP_PORTS.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), 64, "the curated set must not contain duplicates");
        // The ports the design names must survive any edit of the list.
        for p in [22u32, 80, 443, 1024, 1026, 2375, 2376, 4243, 8080, 10809, 50051, 56794] {
            assert!(TOP_PORTS.contains(&p), "curated set lost {p}");
        }
    }

    #[test]
    fn port_spec_keeps_the_full_u32_domain() {
        // 3064402411 is the first ephemeral port measured on the host; a spec
        // that clamped to u16 would quietly scan nothing.
        let s = PortSpec::parse("3064402411,4294967295").unwrap();
        assert_eq!(s.0, vec![3064402411, 4294967295]);
        assert_eq!(PortSpec::parse("1-3").unwrap().0, vec![1, 2, 3]);
        assert_eq!(PortSpec::parse("3,2,2,1").unwrap().0, vec![1, 2, 3]);
        assert_eq!(PortSpec::parse("top").unwrap().0.len(), 64);
        assert!(PortSpec::parse("-1").is_err());
        assert!(PortSpec::parse("5-3").is_err());
        assert!(PortSpec::parse("4294967296").is_err());
        assert!(PortSpec::parse("").is_err());
    }

    #[test]
    fn cid_keywords_and_ranges() {
        let s = CidSpec::parse("host").unwrap();
        let r = s.resolve(&ctx(256, false, &[])).unwrap();
        assert_eq!(r.cids, vec![2]);
        let r = CidSpec::parse("hyp,local,any").unwrap().resolve(&ctx(256, false, &[])).unwrap();
        assert_eq!(r.cids, vec![0, 3, u32::MAX]);
        let r = CidSpec::parse("3-6").unwrap().resolve(&ctx(256, false, &[])).unwrap();
        assert_eq!(r.cids, vec![3, 4, 5, 6]);
        // Ranges over the u32 tail must not overflow.
        let r = CidSpec::parse("4294967294-4294967295")
            .unwrap()
            .resolve(&ctx(256, false, &[]))
            .unwrap();
        assert_eq!(r.cids, vec![4294967294, 4294967295]);
    }

    #[test]
    fn local_needs_a_resolved_cid() {
        let s = CidSpec::parse("local").unwrap();
        let e = s
            .resolve(&CidContext { max_cids: 256, wide_ok: false, extra: &[], local: None })
            .unwrap_err();
        assert!(e.contains("could not be resolved"), "{e}");
    }

    #[test]
    fn all_is_gated_to_the_curated_set_by_default() {
        let s = CidSpec::parse("all").unwrap();
        let r = s.resolve(&ctx(256, false, &[7, 2])).unwrap();
        assert_eq!(r.cids, vec![0, 1, 2, 7], "curated = hyp/local/host + diag CIDs");
        assert!(r.notes[0].contains("narrowed"));
        assert!(r.notes[0].contains("--i-know-this-is-wide"));
    }

    #[test]
    fn all_with_acknowledgement_sweeps_from_zero_and_says_it_truncated() {
        let s = CidSpec::parse("all").unwrap();
        let r = s.resolve(&ctx(4, true, &[])).unwrap();
        assert_eq!(r.cids, vec![0, 1, 2, 3]);
        assert!(r.notes[0].contains("truncation"), "{}", r.notes[0]);
    }

    #[test]
    fn wide_specs_are_capped() {
        let s = CidSpec::parse("0-1000").unwrap();
        let e = s.resolve(&ctx(256, false, &[])).unwrap_err();
        assert!(e.contains("1001 CIDs"), "{e}");
        assert!(e.contains("--max-cids"), "{e}");
        assert_eq!(s.resolve(&ctx(1001, false, &[])).unwrap().cids.len(), 1001);
    }
}
