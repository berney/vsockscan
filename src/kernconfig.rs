//! Kernel config + module state: the "could this kernel even do vsock?" half.
//!
//! Two facts drive everything here, both measured 2026-10-04/05:
//!
//! 1. Minimal microVM guests may have **no** `/boot`, **no** `/lib/modules`, and
//!    **no** `/proc/modules` — their only config is `/proc/config.gz`
//!    (`CONFIG_IKCONFIG_PROC=y`). So this module must inflate gzip from bytes
//!    with no filesystem scaffolding around it (`crate::gunzip`).
//! 2. A symbol **absent** from the file is `Unknown`, never `Disabled`: a minimal
//!    config may contain no `CONFIG_VSOCKMON` line at all, and reporting "not set"
//!    would be a claim about a file we did not read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::caps::Caps;
use crate::model::{ModuleAvailability, ModuleVerdict};

/// One symbol's state, as the config file states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sym {
    /// `CONFIG_X=y`
    Yes,
    /// `CONFIG_X=m`
    Module,
    /// `# CONFIG_X is not set`, or `CONFIG_X=n`
    Disabled,
    /// Not in the file, or the file itself was unreadable.
    Unknown,
}

impl Sym {
    pub fn as_str(self) -> &'static str {
        match self {
            Sym::Yes => "y",
            Sym::Module => "m",
            Sym::Disabled => "not set",
            Sym::Unknown => "unknown",
        }
    }

    /// Built in or loadable: the driver exists in this kernel somewhere.
    pub fn on(self) -> bool {
        matches!(self, Sym::Yes | Sym::Module)
    }
}

/// A parsed config plus where it came from (the report must say, spec §4.1).
#[derive(Debug, Clone)]
pub struct ConfigRead {
    /// `/proc/config.gz`, `/boot/config-<release>`, ... or `None` if none read.
    pub source: Option<String>,
    /// Set when a candidate existed but could not be decoded, so the report can
    /// say "unreadable" instead of "no config here".
    pub error: Option<String>,
    syms: BTreeMap<String, Sym>,
}

impl ConfigRead {
    pub fn unavailable(error: Option<String>) -> ConfigRead {
        ConfigRead {
            source: None,
            error,
            syms: Default::default(),
        }
    }

    /// Read the running kernel's config, in the order a distro is likely to have
    /// it: IKCONFIG first (the only option in the target shape), then the
    /// packaged file, then the modules tree.
    pub fn load(release: &str) -> ConfigRead {
        let mut errors = Vec::new();
        match std::fs::read("/proc/config.gz") {
            Ok(raw) => {
                if let Some(text) = crate::gunzip::gunzip(&raw).and_then(|b| String::from_utf8(b).ok()) {
                    return ConfigRead::from_text("/proc/config.gz", &text);
                }
                errors.push("/proc/config.gz exists but is not decodable gzip".to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("/proc/config.gz: {e}")),
        }
        for path in [
            format!("/boot/config-{release}"),
            format!("/lib/modules/{release}/config"),
        ] {
            match std::fs::read_to_string(&path) {
                Ok(text) => return ConfigRead::from_text(&path, &text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => errors.push(format!("{path}: {e}")),
            }
        }
        ConfigRead::unavailable(Some(errors.join("; ")))
    }

    pub fn from_text(source: &str, text: &str) -> ConfigRead {
        ConfigRead {
            source: Some(source.to_string()),
            error: None,
            syms: parse(text),
        }
    }

    /// `name` with or without the `CONFIG_` prefix, any case: module names are
    /// lowercase (`vhost_vsock`) and config symbols are uppercase
    /// (`CONFIG_VHOST_VSOCK`), and every verdict is asked in module-name case.
    pub fn symbol(&self, name: &str) -> Sym {
        let key = name.strip_prefix("CONFIG_").unwrap_or(name).to_ascii_uppercase();
        self.syms.get(&key).copied().unwrap_or(Sym::Unknown)
    }

    pub fn describe(&self) -> String {
        match (&self.source, &self.error) {
            (Some(s), None) => s.clone(),
            (Some(s), Some(e)) => format!("{s} (partial: {e})"),
            (None, Some(e)) => format!("unreadable: {e}"),
            (None, None) => "no config source (IKCONFIG off, no /boot, no /lib/modules)".to_string(),
        }
    }
}

/// Parse only the two forms a `.config` uses; everything else is not a symbol.
fn parse(text: &str) -> BTreeMap<String, Sym> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("CONFIG_") {
            if let Some((name, val)) = rest.split_once('=') {
                let sym = match val.trim() {
                    "y" => Sym::Yes,
                    "m" => Sym::Module,
                    "n" => Sym::Disabled,
                    // A string/number value still means "compiled in".
                    _ => Sym::Yes,
                };
                out.insert(name.trim().to_ascii_uppercase(), sym);
            }
        } else if let Some(rest) = line.strip_prefix("# CONFIG_") {
            // `# CONFIG_X is not set`, and nothing else.
            if let Some(name) = rest.strip_suffix(" is not set") {
                out.insert(name.trim().to_ascii_uppercase(), Sym::Disabled);
            }
        }
    }
    out
}

/// Filesystem facts about modules, collected once by [`ModuleFacts::probe`].
#[derive(Debug, Clone, Default)]
pub struct ModuleFacts {
    /// `/proc/modules` was readable; its contents are in `loaded`.
    pub proc_modules_readable: bool,
    /// Module names listed by `/proc/modules` (or implied by `/sys/module/<n>`).
    pub loaded: BTreeSet<String>,
    /// Names from `/lib/modules/<release>/modules.builtin`.
    pub builtin: BTreeSet<String>,
    /// Names that have a `.ko*` under the scanned directories.
    pub files: BTreeSet<String>,
    /// `/lib/modules/<release>` existed at all.
    pub modules_tree: bool,
}

/// A shallow walk (depth 2) of the three places these modules live; the full
/// tree is enormous and the rest is irrelevant here.
const SCAN_DIRS: &[&str] = &["kernel/net/vmw_vsock", "kernel/drivers/vhost", "kernel/drivers/net"];

impl ModuleFacts {
    pub fn probe(release: &str, names: &[&str]) -> ModuleFacts {
        let mut f = ModuleFacts::default();
        if let Ok(text) = std::fs::read_to_string("/proc/modules") {
            f.proc_modules_readable = true;
            f.loaded = text
                .lines()
                .filter_map(|l| l.split_whitespace().next())
                .map(str::to_string)
                .collect();
        }
        let tree = format!("/lib/modules/{release}");
        f.modules_tree = Path::new(&tree).is_dir();
        if let Ok(text) = std::fs::read_to_string(format!("{tree}/modules.builtin")) {
            for line in text.lines() {
                if let Some(base) = line.rsplit('/').next() {
                    if let Some(n) = base.strip_suffix(".ko") {
                        f.builtin.insert(n.to_string());
                    }
                }
            }
        }
        for dir in SCAN_DIRS {
            let mut frontier = vec![Path::new(&tree).join(dir)];
            for _ in 0..2 {
                let mut next = Vec::new();
                for d in &frontier {
                    let Ok(rd) = std::fs::read_dir(d) else { continue };
                    for ent in rd.flatten() {
                        let p = ent.path();
                        if p.is_dir() {
                            next.push(p);
                            continue;
                        }
                        if let Some(name) = ko_name(&p) {
                            if names.iter().any(|w| *w == name) {
                                f.files.insert(name.to_string());
                            }
                        }
                    }
                }
                frontier = next;
            }
        }
        // A loaded module can be visible under /sys/module while /proc/modules is
        // hidden (some container configs); count that as loaded.
        for n in names {
            if Path::new(&format!("/sys/module/{n}")).exists() {
                f.loaded.insert((*n).to_string());
            }
        }
        f
    }
}

/// `.../vhost_vsock.ko[.gz|.zst|.xz]` -> `Some("vhost_vsock")`.
fn ko_name(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let base = name.split(".ko").next()?;
    if base.is_empty() || base == name {
        None
    } else {
        Some(base)
    }
}

/// Whether this kernel can load modules at all, and what is visible in memory.
#[derive(Debug, Clone)]
pub struct ModuleState {
    /// `None` = undecidable (no config file and no filesystem evidence).
    pub enabled: Option<bool>,
    pub facts: ModuleFacts,
    /// Human-readable basis, printed with the verdict.
    pub reason: String,
}

/// Real-filesystem entry point.
pub fn module_state(cfg: &ConfigRead, release: &str, names: &[&str]) -> ModuleState {
    module_state_from(cfg, ModuleFacts::probe(release, names))
}

/// The pure half, so the tests can hand in any combination of signals.
pub fn module_state_from(cfg: &ConfigRead, facts: ModuleFacts) -> ModuleState {
    let sym = cfg.symbol("MODULES");
    let visible = facts.proc_modules_readable || facts.modules_tree || !facts.files.is_empty();
    let (enabled, reason) = match sym {
        Sym::Disabled => (
            Some(false),
            "CONFIG_MODULES is not set: this kernel cannot load anything".to_string(),
        ),
        // The capability is known from the config; whether a given module is
        // *loaded* is a separate question the verdicts answer per name.
        Sym::Yes | Sym::Module => (
            Some(true),
            format!(
                "CONFIG_MODULES={}; /proc/modules {}",
                sym.as_str(),
                if facts.proc_modules_readable {
                    "readable"
                } else {
                    "unreadable, so what is loaded is unknown"
                }
            ),
        ),
        Sym::Unknown if visible => (
            Some(true),
            format!(
                "CONFIG_MODULES absent from {}, but /proc/modules or a module tree exists",
                cfg.describe()
            ),
        ),
        Sym::Unknown => (
            None,
            format!(
                "CONFIG_MODULES {} and no /proc/modules or module tree to check",
                sym.as_str()
            ),
        ),
    };
    ModuleState {
        enabled,
        facts,
        reason,
    }
}

/// Inputs for one per-module verdict. Grouped because the optional signals are
/// what the verdict's *reason* string is made of.
#[derive(Debug, Clone)]
pub struct VerdictQuery<'a> {
    /// Module/config name without the `CONFIG_` prefix, e.g. `vsockmon`.
    pub name: &'a str,
    /// When given, a missing `CAP_SYS_MODULE` is reported as the blocker.
    pub caps: Option<&'a Caps>,
    /// `/dev/<node>` observation from `probe`: `Some(true)` seen, `Some(false)`
    /// definitely not there, `None` not looked.
    pub node_present: Option<bool>,
    /// Unavailable because a Kconfig dependency is off; precomputed by the
    /// caller that knows the dependency (`vsockmon` -> `VHOST_VSOCK`).
    pub dep_note: Option<String>,
}

fn verdict(cfg: &ConfigRead, st: &ModuleState, q: VerdictQuery<'_>) -> ModuleVerdict {
    let name = q.name;
    let v = |state: ModuleAvailability, reason: String| ModuleVerdict {
        name: name.to_string(),
        state,
        reason,
    };
    let sym = cfg.symbol(name);

    // Observed reality outranks the config file's opinion.
    if q.node_present == Some(true) {
        return v(ModuleAvailability::Builtin, "device node present in /dev".to_string());
    }
    if st.facts.loaded.contains(name) {
        return v(
            ModuleAvailability::Builtin,
            "listed in /proc/modules (or /sys/module)".to_string(),
        );
    }
    if sym == Sym::Yes || st.facts.builtin.contains(name) {
        return v(
            ModuleAvailability::Builtin,
            format!("CONFIG_{name}={}, nothing to load", sym.as_str()),
        );
    }
    if let Some(note) = q.dep_note {
        return v(ModuleAvailability::Unavailable, note);
    }
    match sym {
        Sym::Module => {
            if st.enabled == Some(false) {
                return v(
                    ModuleAvailability::ModulesDisabled,
                    format!("CONFIG_{name}=m but CONFIG_MODULES is not set"),
                );
            }
            if !st.facts.files.contains(name) {
                return v(
                    ModuleAvailability::Unavailable,
                    format!(
                        "CONFIG_{name}=m, no {name}.ko found{}",
                        if st.facts.modules_tree {
                            " under the scanned module directories"
                        } else {
                            " (no /lib/modules tree to scan)"
                        }
                    ),
                );
            }
            if let Some(c) = q.caps {
                if !c.sys_module() {
                    return v(
                        ModuleAvailability::Unavailable,
                        format!("{name}.ko present but no CAP_SYS_MODULE to insert it"),
                    );
                }
            }
            v(
                ModuleAvailability::Loadable,
                format!("{name}.ko present and modules enabled"),
            )
        }
        Sym::Disabled => v(ModuleAvailability::Unavailable, format!("# CONFIG_{name} is not set")),
        Sym::Unknown => v(
            ModuleAvailability::Unknown,
            format!(
                "CONFIG_{name} absent from {} (absent is not the same as disabled)",
                cfg.describe()
            ),
        ),
        Sym::Yes => unreachable!("handled above"),
    }
}

/// `vsockmon` is not an independent choice: `drivers/net/Kconfig` gives it
/// **`depends on VHOST_VSOCK`** (checked in 6.1.y and master), so inside a
/// guest VM without vhost-vsock the honest answer is "unavailable because its dependency is
/// off", not "not installed".
pub fn vsockmon_verdict(cfg: &ConfigRead, st: &ModuleState, caps: &Caps) -> ModuleVerdict {
    if !cfg.symbol("VSOCKETS").on() {
        return ModuleVerdict {
            name: "vsockmon".to_string(),
            state: ModuleAvailability::Unavailable,
            reason: format!(
                "CONFIG_VSOCKETS={} — there is no vsock traffic to mirror",
                cfg.symbol("VSOCKETS").as_str()
            ),
        };
    }
    let dep_note = (!cfg.symbol("VHOST_VSOCK").on()).then(|| {
        format!(
            "VSOCKMON depends on VHOST_VSOCK (drivers/net/Kconfig); CONFIG_VHOST_VSOCK={}",
            cfg.symbol("VHOST_VSOCK").as_str()
        )
    });
    verdict(
        cfg,
        st,
        VerdictQuery {
            name: "vsockmon",
            caps: Some(caps),
            node_present: None,
            dep_note,
        },
    )
}

/// `vhost_verdict` takes the `/dev/vhost-vsock` observation from `probe` (only it
/// opens the node), so `builtin` can mean "measured openable".
pub fn vhost_verdict(
    cfg: &ConfigRead,
    st: &ModuleState,
    caps: &Caps,
    node_present: Option<bool>,
) -> ModuleVerdict {
    verdict(
        cfg,
        st,
        VerdictQuery {
            name: "vhost_vsock",
            caps: Some(caps),
            node_present,
            dep_note: None,
        },
    )
}

/// The modules this tool cares about, for [`module_state`]'s file scan.
pub const WATCHED: &[&str] = &[
    "vsockmon",
    "vhost_vsock",
    "vmw_vsock_virtio_transport",
    "vmw_vsock_virtio_transport_common",
    "vsock",
];

#[cfg(test)]
mod tests {
    use super::*;

    const CI: &str = include_str!("../tests/fixtures/ci-config-excerpt.txt");

    fn ci() -> ConfigRead {
        ConfigRead::from_text("/proc/config.gz", CI)
    }

    #[test]
    fn parses_both_forms() {
        let c = ci();
        assert_eq!(c.symbol("VSOCKETS"), Sym::Yes);
        assert_eq!(c.symbol("CONFIG_VSOCKETS"), Sym::Yes, "prefix tolerated");
        assert_eq!(c.symbol("VSOCKETS_DIAG"), Sym::Disabled);
        assert_eq!(c.symbol("VHOST_VSOCK"), Sym::Disabled);
        assert_eq!(c.symbol("MODULES"), Sym::Disabled);
        // The excerpt fixture has no VSOCKMON line at all.
        assert_eq!(c.symbol("VSOCKMON"), Sym::Unknown);
        assert_eq!(c.source.as_deref(), Some("/proc/config.gz"));
    }

    #[test]
    fn comments_and_values_are_not_symbols() {
        let c = ConfigRead::from_text(
            "t",
            "# comment\nCONFIG_LOCALVERSION=\"-fc\"\nCONFIG_HZ=100\nCONFIG_X=n\n\n",
        );
        assert_eq!(c.symbol("LOCALVERSION"), Sym::Yes);
        assert_eq!(c.symbol("HZ"), Sym::Yes);
        assert_eq!(c.symbol("X"), Sym::Disabled);
        assert_eq!(c.symbol("comment"), Sym::Unknown);
    }

    #[test]
    fn missing_file_is_unknown_not_disabled() {
        let c = ConfigRead::unavailable(None);
        assert_eq!(c.symbol("VSOCKETS"), Sym::Unknown);
        assert!(!c.symbol("VSOCKETS").on());
        assert!(c.describe().contains("no config source"), "{}", c.describe());
    }

    #[test]
    fn target_shape_is_modules_disabled() {
        let st = module_state_from(&ci(), ModuleFacts::default());
        assert_eq!(st.enabled, Some(false));
        assert!(st.reason.contains("cannot load"), "{}", st.reason);
    }

    #[test]
    fn modules_y_without_proc_modules_is_not_modules_disabled() {
        let c = ConfigRead::from_text("t", "CONFIG_MODULES=y\n");
        let st = module_state_from(&c, ModuleFacts::default());
        // The capability is known; what is loaded is not. It must never come out
        // as `ModulesDisabled`, which would claim the kernel cannot load.
        assert_eq!(st.enabled, Some(true));
        assert!(st.reason.contains("unreadable"), "{}", st.reason);
        // And with no config and no filesystem evidence at all: undecidable.
        let empty = module_state_from(&ConfigRead::unavailable(None), ModuleFacts::default());
        assert_eq!(empty.enabled, None);
    }

    #[test]
    fn vsockmon_in_the_guest_is_unavailable_because_of_its_dependency() {
        let c = ci();
        let st = module_state_from(&c, ModuleFacts::default());
        let caps = Caps::from_status("CapEff:\t0000003fffffffff\n", Some(40));
        let v = vsockmon_verdict(&c, &st, &caps);
        assert_eq!(v.state, ModuleAvailability::Unavailable);
        assert!(
            v.reason.contains("VSOCKMON depends on VHOST_VSOCK"),
            "{}",
            v.reason
        );
    }

    #[test]
    fn vsockmon_without_vsock_is_unavailable_first() {
        let c = ConfigRead::from_text("t", "# CONFIG_VSOCKETS is not set\nCONFIG_VHOST_VSOCK=m\n");
        let st = module_state_from(&c, ModuleFacts::default());
        let v = vsockmon_verdict(&c, &st, &Caps::default());
        assert_eq!(v.state, ModuleAvailability::Unavailable);
        assert!(v.reason.contains("no vsock traffic"), "{}", v.reason);
    }

    #[test]
    fn loadable_needs_file_and_caps() {
        let c = ConfigRead::from_text(
            "t",
            "CONFIG_MODULES=y\nCONFIG_VSOCKETS=y\nCONFIG_VHOST_VSOCK=m\nCONFIG_VSOCKMON=m\n",
        );
        let facts = ModuleFacts {
            proc_modules_readable: true,
            loaded: ["vhost_vsock".to_string()].into_iter().collect(),
            files: ["vsockmon".to_string()].into_iter().collect(),
            modules_tree: true,
            builtin: Default::default(),
        };
        let st = module_state_from(&c, facts);
        let root = Caps::from_status("CapEff:\t0000003fffffffff\n", Some(40));
        let none = Caps::from_status("CapEff:\t0000000000000000\n", Some(40));

        // Dependency satisfied (vhost_vsock loaded), file present, caps present.
        let v = vsockmon_verdict(&c, &st, &root);
        assert_eq!(v.state, ModuleAvailability::Loadable, "{}", v.reason);
        // Same signals without the right: the blocker is the right, not the file.
        let v = vsockmon_verdict(&c, &st, &none);
        assert_eq!(v.state, ModuleAvailability::Unavailable);
        assert!(v.reason.contains("CAP_SYS_MODULE"), "{}", v.reason);

        // vhost_vsock is already in memory.
        assert_eq!(
            vhost_verdict(&c, &st, &root, None).state,
            ModuleAvailability::Builtin
        );
        // A device node trumps the config file even for a non-root user.
        assert_eq!(
            vhost_verdict(&c, &module_state_from(&c, ModuleFacts::default()), &none, Some(true)).state,
            ModuleAvailability::Builtin
        );
    }

    #[test]
    fn loadable_needs_the_file_too() {
        let c = ConfigRead::from_text(
            "t",
            "CONFIG_MODULES=y\nCONFIG_VSOCKETS=y\nCONFIG_VHOST_VSOCK=m\nCONFIG_VSOCKMON=m\n",
        );
        let st = module_state_from(
            &c,
            ModuleFacts {
                proc_modules_readable: true,
                modules_tree: true,
                ..Default::default()
            },
        );
        let root = Caps::from_status("CapEff:\t0000003fffffffff\n", Some(40));
        let v = vsockmon_verdict(&c, &st, &root);
        assert_eq!(v.state, ModuleAvailability::Unavailable);
        assert!(v.reason.contains("no vsockmon.ko found"), "{}", v.reason);
    }

    #[test]
    fn modules_disabled_beats_a_loadable_config() {
        let c = ConfigRead::from_text("t", "# CONFIG_MODULES is not set\nCONFIG_VSOCKMON=m\n");
        let st = module_state_from(&c, ModuleFacts::default());
        let v = verdict(
            &c,
            &st,
            VerdictQuery {
                name: "vsockmon",
                caps: None,
                node_present: None,
                dep_note: None,
            },
        );
        assert_eq!(v.state, ModuleAvailability::ModulesDisabled);
    }

    #[test]
    fn absent_symbol_is_unknown_with_source() {
        let c = ConfigRead::from_text("t", "CONFIG_MODULES=y\nCONFIG_VSOCKETS=y\n");
        let st = module_state_from(&c, ModuleFacts::default());
        let v = verdict(
            &c,
            &st,
            VerdictQuery {
                name: "vsockmon",
                caps: None,
                node_present: None,
                dep_note: None,
            },
        );
        assert_eq!(v.state, ModuleAvailability::Unknown);
        assert!(v.reason.contains("absent from t"), "{}", v.reason);
    }

    #[test]
    fn ko_name_handles_compressions() {
        for (p, want) in [
            ("a/vhost_vsock.ko", Some("vhost_vsock")),
            ("a/vsockmon.ko.zst", Some("vsockmon")),
            ("a/vsockmon.ko.gz", Some("vsockmon")),
            ("a/README", None),
            ("a/.ko", None),
        ] {
            assert_eq!(ko_name(Path::new(p)), want, "{p}");
        }
    }
}
