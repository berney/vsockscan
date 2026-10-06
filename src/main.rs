//! vsockscan — guest-side AF_VSOCK recon.
//!
//! Exit codes (spec §4): `0` clean run, `1` usage error, `2` runtime error,
//! `3` selftest assertion failure. SIGINT additionally prints the report for
//! whatever completed and exits `130`: a wide sweep is minutes of connects and
//! the default disposition would throw all of them away.

mod caps;
mod diag;
mod gunzip;
mod kernconfig;
mod listen;
mod model;
mod muxer;
mod probe;
mod render;
mod scan;
mod selftest;
mod spec;
mod uapi;

use std::io::Write;
use std::process::ExitCode;

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};

use render::style;

/// Outcome of anything this binary can be asked to do, mapped onto the exit codes
/// documented above.
pub type RunResult<T> = Result<T, RuntimeError>;

/// Ctrl-C is an expected way to end a long sweep, not a reason to lose it.
///
/// A 500 000-port sweep is minutes of connects; with the default disposition the
/// process dies and the report - the entire point of those connects - is never
/// printed. So SIGINT only raises a flag: the scan pool stops claiming work, the
/// accept loop returns, the report is rendered from whatever completed, and the
/// exit status says 130 (128 + SIGINT), which is what a shell expects to see.
pub static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_sigint(_sig: libc::c_int) {
    // Async-signal-safe: a relaxed store to a static bool is all this may do.
    INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// True once Ctrl-C has been seen. Sweep loops check it between units of work.
pub fn interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
}

fn install_sigint_handler() {
    // The function item goes through a pointer first: casting it straight to an
    // integer is what clippy objects to, and the pointer is the honest form of
    // "this is an address the kernel will call".
    let handler = on_sigint as *const () as libc::sighandler_t;
    // SAFETY: a handler that only stores to a static; SIGINT has no other use here.
    unsafe { libc::signal(libc::SIGINT, handler) };
}

#[derive(Debug)]
pub struct RuntimeError {
    pub message: String,
    /// Spec/argument problems exit 1; only a failure to *do* the work exits 2.
    /// A script that treats "your --cid spec is nonsense" and "no AF_VSOCK here"
    /// as the same code cannot tell a typo from an absent transport.
    pub usage: bool,
    /// A failed selftest assertion is its own code: it means the tool disagrees
    /// with itself, which is neither a bad argument nor an unusable environment.
    pub assert_failure: bool,
}

impl From<std::io::Error> for RuntimeError {
    fn from(e: std::io::Error) -> Self {
        RuntimeError {
            message: e.to_string(),
            usage: false,
            assert_failure: false,
        }
    }
}

impl RuntimeError {
    pub fn msg(msg: impl Into<String>) -> Self {
        RuntimeError {
            message: msg.into(),
            usage: false,
            assert_failure: false,
        }
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        RuntimeError {
            message: msg.into(),
            usage: true,
            assert_failure: false,
        }
    }
}

// `--format` values are the renderer's own `model::Format`: one enum, no
// parallel definition to keep in step.
use model::Format;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum FlagsMode {
    /// No `VMADDR_FLAG_TO_HOST`: normal g2h routing for `cid <= 2`.
    #[default]
    None,
    /// Always set the flag: force the guest→host transport even for `cid > 2`.
    ToHost,
    /// Run every (cid, port) twice and keep both rows.
    Both,
}

#[derive(Debug, Parser)]
#[command(
    name = "vsockscan",
    version,
    about = "AF_VSOCK recon: device presence, CID resolution, two-direction reachability, listener census",
    // clap's own usage exit code is 2, which this tool reserves for runtime
    // errors; parse() maps usage problems to 1 and help/version to 0 (spec §4).
    // `arg_required_else_help` is deliberately NOT used: it fires before we can
    // see `--json-schema`, which is a standalone escape hatch (spec §12) and
    // must work with no subcommand. The missing-subcommand case is handled in
    // `main`, where it is reported as a usage error on stderr.
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    pub format: Format,

    /// Write to a file instead of stdout. Never colourised.
    #[arg(short, long, value_name = "FILE", global = true)]
    pub output: Option<std::path::PathBuf>,

    /// Disable colour even on a TTY.
    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Summary only.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Print the JSON document schema and exit.
    #[arg(long, global = true)]
    pub json_schema: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Capability + device report. No CID-2 traffic beyond the classification probes.
    Probe(ProbeArgs),
    /// Reachability sweep over a CID x port matrix.
    Scan(ScanArgs),
    /// Accept on one or more ports; log peer CID/port and a byte preview.
    Listen(ListenArgs),
    /// Loopback fixture: prove scan semantics with no host, no device, no socat.
    Selftest,
}

#[derive(Debug, clap::Args)]
pub struct ProbeArgs {
    /// Force the netlink SOCK_DIAG census even if it failed during probe.
    #[arg(long)]
    pub diag: bool,
    /// Run the SEQPACKET capability probe (default on).
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub seqpacket: bool,
    /// Also run the classification probes with VMADDR_FLAG_TO_HOST set.
    #[arg(long)]
    pub to_host: bool,
    /// Report vsockmon state (builtin / loaded / loadable / modules-disabled / unavailable).
    /// `loaded` means live now by a signal that does not prove how it got there: from outside the
    /// kernel a loaded `=m` module and a built-in are indistinguishable, so `builtin` needs
    /// `CONFIG_X=y` as well.
    #[arg(long)]
    pub vsockmon: bool,
    /// Opt-in: create `ip link add <NAME> type vsockmon` and print the capture recipe.
    #[arg(long, value_name = "NAME")]
    pub vsockmon_up: Option<String>,
    /// Parse the running kernel config (/proc/config.gz and friends).
    #[arg(long)]
    pub config: bool,
    /// Read the virtio-mmio window through /dev/mem (needs CAP_SYS_ADMIN + iomem=relaxed).
    #[arg(long)]
    pub mmio: bool,
}

#[derive(Debug, clap::Args)]
pub struct ScanArgs {
    /// local | host | hyp | N | N-M | comma-list | all. Required: never default a
    /// sweep onto the hypervisor keyspace.
    #[arg(long, value_name = "SPEC")]
    pub cid: Option<String>,
    /// n | n-m | comma-list | top. u32 domain: real ephemeral vsock ports exceed 2^31.
    #[arg(long, value_name = "SPEC", default_value = "top")]
    pub ports: String,
    /// VMADDR_FLAG_TO_HOST coverage.
    #[arg(long, value_enum, default_value_t = FlagsMode::None)]
    pub flags: FlagsMode,
    /// Concurrent connects.
    #[arg(short = 'P', long, default_value_t = 64)]
    pub parallel: usize,
    #[arg(long, default_value_t = 2.0, value_name = "SEC")]
    pub timeout: f64,
    /// After a successful connect, read up to N bytes.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub banner: usize,
    /// Hard cap for `all` / wide ranges (default 256). Passing it explicitly is
    /// itself taken as an acknowledgement of width, per spec §6.5.
    #[arg(long, value_name = "N")]
    pub max_cids: Option<usize>,
    /// Acknowledge that `all` is wide and run past the curated default anyway.
    #[arg(long)]
    pub i_know_this_is_wide: bool,
    /// Skip the vsock_diag cross-check.
    #[arg(long)]
    pub no_diag: bool,
    /// Ports used to classify a CID before the full sweep.
    #[arg(long, default_value_t = 3)]
    pub stage1_ports: usize,
    /// File with one CID per line, merged into the curated set.
    #[arg(long, value_name = "FILE")]
    pub cid_file: Option<std::path::PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ListenArgs {
    #[arg(long, value_name = "SPEC", default_value = "10809")]
    pub ports: String,
    /// Bind-only occupancy census instead of accepting.
    #[arg(long)]
    pub census: bool,
    #[arg(long, default_value_t = 0)]
    pub max_conns: usize,
    /// How long to hold the ports. `0` means bind, report, exit: a liveness
    /// check rather than a listener.
    #[arg(long, default_value_t = 10.0, value_name = "SEC")]
    pub timeout: f64,
    /// Bytes to hexdump from each accepted connection (`scan --banner`'s
    /// counterpart on the accept side).
    #[arg(long, default_value_t = 64, value_name = "N")]
    pub banner: usize,
    /// Accept Firecracker guest-to-host connections on AF_UNIX paths
    /// `<PATH>_<port>` instead of kernel AF_VSOCK sockets.
    #[arg(long, value_name = "PATH", conflicts_with = "census")]
    pub uds: Option<std::path::PathBuf>,
    /// Hold the ports until Ctrl-C or --max-conns; overrides --timeout.
    #[arg(long)]
    pub forever: bool,
}

/// Colour must be decided before clap renders help/errors, so inspect argv directly.
fn plaintext_styles() -> bool {
    std::env::args().any(|a| a == "--no-color") || std::env::var_os("NO_COLOR").is_some()
}

/// Returns `Ok(cli)`, or `Err(exit_code)` after clap has already printed.
/// Usage problems are 1; `--help`/`--version` are 0; code 2 stays for runtime errors.
fn parse() -> Result<Cli, u8> {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    cmd = if plaintext_styles() {
        cmd.styles(clap::builder::Styles::plain())
    } else {
        cmd.styles(style::clap_styles())
    };
    let matches = cmd.try_get_matches_from(std::env::args_os()).map_err(|e| {
        let _ = e.print();
        if e.use_stderr() {
            1
        } else {
            0
        }
    })?;
    <Cli as clap::FromArgMatches>::from_arg_matches(&matches).map_err(|e| {
        let _ = e.print();
        if e.use_stderr() {
            1
        } else {
            0
        }
    })
}

fn main() -> ExitCode {
    let cli = match parse() {
        Ok(cli) => cli,
        Err(code) => return ExitCode::from(code),
    };
    if cli.json_schema {
        // The schema is the machine-readable half of the contract between this
        // tool and whoever parses its output; it is tested against the emitted
        // document in `render::tests`, so printing it can only fail on I/O.
        let out = std::io::stdout();
        let mut w = out.lock();
        return match w.write_all(render::json_schema().as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => runtime(format!("writing schema: {e}")),
        };
    }
    let Some(command) = &cli.command else {
        // No subcommand: usage error, so help goes to stderr with code 1 —
        // stdout stays clean for anything a pipeline might capture.
        let mut cmd = <Cli as CommandFactory>::command();
        cmd = if plaintext_styles() {
            cmd.styles(clap::builder::Styles::plain())
        } else {
            cmd.styles(style::clap_styles())
        };
        let _ = cmd.write_help(&mut std::io::stderr());
        eprintln!("\nvsockscan: a subcommand is required (probe | scan | listen | selftest)");
        return ExitCode::from(1);
    };
    // Only the commands that can run for a long time need this, and installing it
    // for all of them is cheaper than explaining why one forgot.
    install_sigint_handler();
    let res: RunResult<()> = match command {
        Command::Probe(a) => run_probe(&cli, a),
        Command::Scan(a) => run_scan(&cli, a),
        Command::Listen(a) => run_listen(&cli, a),
        Command::Selftest => run_selftest(&cli),
    };
    match res {
        Ok(()) if interrupted() => ExitCode::from(130),
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => e.into(),
    }
}

/// One place decides colour, format and destination, so `-o FILE` is
/// byte-identical to `--no-color` stdout for every command (spec §5).
fn emit(cli: &Cli, report: &model::Report) -> RunResult<()> {
    let color = if cli.output.is_some() {
        render::ColorSupport::Off
    } else {
        render::style::detect(cli.no_color, crate::tty_stdout(), &|k| {
            std::env::var(k).ok()
        })
    };
    let mut buf: Vec<u8> = Vec::new();
    if cli.quiet {
        render::render_summary(report, cli.format, color, &mut buf)?;
    } else {
        render::render(report, cli.format, color, &mut buf)?;
    }
    match &cli.output {
        Some(path) => std::fs::write(path, &buf)
            .map_err(|e| RuntimeError::msg(format!("writing {}: {e}", path.display()))),
        None => {
            let out = std::io::stdout();
            let mut h = out.lock();
            h.write_all(&buf)?;
            h.flush().ok();
            Ok(())
        }
    }
}

fn run_probe(cli: &Cli, a: &ProbeArgs) -> RunResult<()> {
    let opts = probe::ProbeOpts {
        seqpacket: a.seqpacket,
        to_host: a.to_host,
        vsockmon: a.vsockmon,
        config: a.config,
        mmio: a.mmio,
        diag: a.diag,
    };
    let mut report = probe::collect(&opts);
    if let Some(name) = &a.vsockmon_up {
        probe::vsockmon_up(name, &mut report);
    }
    if cli.quiet {
        // Quiet is the one-line answer, not a truncated report: posture, device,
        // and the count of things worth reading above.
        let h = &report.header;
        let line = format!(
            "{}: posture {} / device {} / cid {} / {} probe(s), {} finding(s)\n",
            report.command,
            h.posture.as_str(),
            h.device.as_str(),
            h.cid
                .cid
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            report.probes.len(),
            report.findings.len()
        );
        return match &cli.output {
            Some(p) => std::fs::write(p, line).map_err(Into::into),
            None => {
                let out = std::io::stdout();
                let mut h = out.lock();
                h.write_all(line.as_bytes())
                    .map_err(Into::into)
                    .and_then(|()| h.flush().map_err(Into::into))
            }
        };
    }
    emit(cli, &report)
}

/// The classification header first, then the sweep: every row is reported next to
/// the device tells that qualify it (spec §6.1), which is why `scan` runs the
/// same `probe::collect` that `probe` does instead of a lighter header.
fn run_scan(cli: &Cli, a: &ScanArgs) -> RunResult<()> {
    let spec_text = a.cid.as_deref().ok_or_else(|| {
        RuntimeError::usage(
            "--cid is required for scan: no implicit default, so a run can never be \
             pointed at the hypervisor keyspace by forgetting an argument",
        )
    })?;
    let cid_spec =
        spec::CidSpec::parse(spec_text).map_err(|e| RuntimeError::usage(e + " (--cid SPEC)"))?;
    let port_spec =
        spec::PortSpec::parse(&a.ports).map_err(|e| RuntimeError::usage(e + " (--ports SPEC)"))?;

    let mut report = probe::collect(&probe::ProbeOpts {
        seqpacket: false,
        to_host: a.flags == crate::FlagsMode::ToHost,
        vsockmon: false,
        config: true,
        mmio: false,
        diag: !a.no_diag,
    });

    let mut extra = read_cid_file(a.cid_file.as_deref())?;
    for e in &report.diag_entries {
        for cid in [e.src_cid, e.dst_cid] {
            if cid != uapi::VMADDR_CID_ANY {
                extra.push(cid);
            }
        }
    }
    let resolved = cid_spec
        .resolve(&spec::CidContext {
            max_cids: a.max_cids.unwrap_or(256),
            wide_ok: a.i_know_this_is_wide || a.max_cids.is_some(),
            extra: &extra,
            local: report.header.cid.cid,
        })
        .map_err(RuntimeError::usage)?;
    report.summary.notes.extend(resolved.notes);

    // `probe::collect` labels the document as its own command; this is a scan
    // that borrowed the classification, and the label is part of the evidence.
    report.command = "scan".to_string();
    // The noise statement has to describe *this* run, not the classification
    // probes: a sweep is the part that puts packets on the wire, and on a
    // `g2h_fallback` kernel it puts them toward the host.
    report.header.noise = sweep_noise(&report, a, &resolved.cids, &port_spec.0);

    let opts = scan::Opts {
        cids: &resolved.cids,
        ports: &port_spec.0,
        flags: match a.flags {
            crate::FlagsMode::None => scan::FlagMode::None,
            crate::FlagsMode::ToHost => scan::FlagMode::ToHost,
            crate::FlagsMode::Both => scan::FlagMode::Both,
        },
        parallel: a.parallel,
        timeout_ms: (a.timeout * 1000.0) as i32,
        banner: a.banner,
        stage1_ports: a.stage1_ports,
        spec_notes: Vec::new(),
    };
    scan::run(&opts, &mut report).map_err(RuntimeError::usage)?;
    emit(cli, &report)
}

/// `selftest` proves the engine against itself, so its exit code is the answer:
/// `3` when a check fails, `2` when AF_VSOCK is not usable at all (nothing to
/// test), `0` when every check passed or was skipped for a stated reason.
fn run_selftest(cli: &Cli) -> RunResult<()> {
    if !selftest::environment_usable() {
        return Err(RuntimeError::msg(
            "AF_VSOCK is not available here, so there is nothing for selftest to check",
        ));
    }
    let checks = selftest::run();
    let mut report = probe::collect(&probe::ProbeOpts {
        seqpacket: false,
        to_host: false,
        vsockmon: false,
        config: false,
        mmio: false,
        diag: false,
    });
    let (pass, fail, skip) = selftest::counts(&checks);
    report.header.noise = format!(
        "selftest: loopback traffic inside this machine only ({} connects), never toward a \
         host service",
        2 * 8 * 2
    );
    report = selftest::into_report(&checks, report.header);
    emit(cli, &report)?;
    if cli.quiet {
        eprintln!("selftest: {pass} passed, {fail} failed, {skip} skipped");
    }
    if fail > 0 {
        return Err(RuntimeError {
            message: format!("{fail} selftest check(s) failed"),
            usage: false,
            assert_failure: true,
        });
    }
    Ok(())
}

fn run_listen(cli: &Cli, a: &ListenArgs) -> RunResult<()> {
    let ports =
        spec::PortSpec::parse(&a.ports).map_err(|e| RuntimeError::usage(e + " (--ports SPEC)"))?;
    let mut report = probe::collect(&probe::ProbeOpts {
        seqpacket: false,
        to_host: false,
        vsockmon: false,
        config: true,
        mmio: false,
        diag: true,
    });
    report.command = "listen".to_string();
    let held = if a.forever {
        "with no deadline (--forever)".to_string()
    } else {
        format!("{} s", a.timeout)
    };
    report.header.noise = if a.census {
        format!(
            "bind-only census of {} port(s): a bind either succeeds or is refused by the \
             kernel's own checks; nothing is sent to anyone",
            ports.0.len()
        )
    } else if let Some(p) = &a.uds {
        format!(
            "holding {} UDS path(s) under {} {held} and accepting; Firecracker's userspace \
             vsock proxy connects to <path>_<port> when its guest opens (CID 2, port) - the \
             host kernel's AF_VSOCK is not involved",
            ports.0.len(),
            p.display()
        )
    } else {
        format!(
            "holding {} port(s) {held} and accepting; bytes are read for identification and \
             never written back, but a peer learns that something answered",
            ports.0.len()
        )
    };
    listen::run(
        &listen::Opts {
            ports: &ports.0,
            census: a.census,
            max_conns: a.max_conns,
            timeout_ms: if a.forever {
                0
            } else {
                (a.timeout * 1000.0) as i32
            },
            preview: a.banner,
            uds: a.uds.as_deref(),
            forever: a.forever,
            // Census returns without ever waiting for anyone, so it has nothing to
            // narrate; and prose cannot be interleaved into a JSON document, so
            // only the human-readable format streams the live accept loop.
            live: if a.census || cli.format != Format::Text {
                listen::Live::off()
            } else {
                listen::Live(true)
            },
        },
        &mut report,
    )
    .map_err(RuntimeError::msg)?;
    emit(cli, &report)
}

/// What this sweep is about to make happen, stated before it happens (spec §11).
fn sweep_noise(report: &model::Report, a: &ScanArgs, cids: &[u32], ports: &[u32]) -> String {
    let flag_sets = match a.flags {
        crate::FlagsMode::Both => 2,
        _ => 1,
    };
    let connects = cids.len() * ports.len() * flag_sets;
    let value = |key: &str| -> String {
        report
            .header
            .sysctls
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str().to_string())
            .unwrap_or_else(|| "absent".to_string())
    };
    let fallback = value("net.vsock.g2h_fallback");
    let regime = if fallback == "absent" {
        "the sysctl is absent, which is the pre-namespace regime where the guest-to-host \
         fallback is unconditional: any CID this kernel cannot route locally may leave"
            .to_string()
    } else {
        format!(
            "net.vsock.g2h_fallback={fallback} and ns_mode={} on this kernel: {} CID 2 \
             traffic toward the host",
            value("net.vsock.ns_mode"),
            if fallback == "1" {
                "a wide sweep genuinely sends"
            } else {
                "the fallback is off, so a sweep stays"
            }
        )
    };
    format!(
        "sweep of {connects} connect(s): {} CID(s) x {} port(s) x {flag_sets} flag set(s), \
         {}s timeout each; {regime}",
        cids.len(),
        ports.len(),
        a.timeout
    )
}

/// `--cid-file`: one CID per line, `#` comments tolerated. A line that is not a
/// number is an error rather than a silently skipped entry, because a typo in a
/// file nobody re-reads would otherwise drop a target from the sweep.
fn read_cid_file(path: Option<&std::path::Path>) -> RunResult<Vec<u32>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| RuntimeError::usage(format!("reading {}: {e}", path.display())))?;
    let mut out = Vec::new();
    for (no, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        out.push(l.parse::<u32>().map_err(|e| {
            RuntimeError::usage(format!(
                "{}:{}: {l:?} is not a CID ({e})",
                path.display(),
                no + 1
            ))
        })?);
    }
    Ok(out)
}

/// `isatty(1)` without a crate.
fn tty_stdout() -> bool {
    // SAFETY: isatty only reads the fd's status.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

impl From<RuntimeError> for ExitCode {
    fn from(e: RuntimeError) -> Self {
        eprintln!("vsockscan: {}", e.message);
        ExitCode::from(if e.assert_failure {
            3
        } else if e.usage {
            1
        } else {
            2
        })
    }
}

fn runtime(msg: impl Into<String>) -> ExitCode {
    eprintln!("vsockscan: {}", msg.into());
    ExitCode::from(2)
}
