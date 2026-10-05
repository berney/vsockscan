//! vsockscan — guest-side AF_VSOCK recon.
//!
//! Exit codes (spec §4): `0` clean run, `1` usage error, `2` runtime error,
//! `3` selftest assertion failure.

mod caps;
mod gunzip;
mod kernconfig;
mod model;
mod probe;
mod render;
mod uapi;

use std::io::Write;
use std::process::ExitCode;

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};

use render::style;

/// Outcome of anything this binary can be asked to do, mapped onto the exit codes
/// documented above.
pub type RunResult<T> = Result<T, RuntimeError>;

#[derive(Debug)]
pub struct RuntimeError(pub String);

impl From<std::io::Error> for RuntimeError {
    fn from(e: std::io::Error) -> Self {
        RuntimeError(e.to_string())
    }
}

impl RuntimeError {
    pub fn msg(msg: impl Into<String>) -> Self {
        RuntimeError(msg.into())
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
    /// Report vsockmon state (builtin / loadable / modules-disabled / unavailable).
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
    /// Hard cap for `all` / wide ranges.
    #[arg(long, default_value_t = 256)]
    pub max_cids: usize,
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
    #[arg(long, default_value_t = 0.0)]
    pub timeout: f64,
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
    let res: RunResult<()> = match command {
        Command::Probe(a) => run_probe(&cli, a),
        Command::Scan(_) | Command::Listen(_) | Command::Selftest => Err(RuntimeError::msg(
            "not implemented yet: scan/listen/selftest land in plan Tasks 6-8",
        )),
    };
    res.map_or_else(From::from, |_| ExitCode::SUCCESS)
}

/// One place decides colour, format and destination, so `-o FILE` is
/// byte-identical to `--no-color` stdout for every command (spec §5).
fn emit(cli: &Cli, report: &model::Report) -> RunResult<()> {
    let color = if cli.output.is_some() {
        render::ColorSupport::Off
    } else {
        render::style::detect(cli.no_color, crate::tty_stdout(), &|k| std::env::var(k).ok())
    };
    let mut buf: Vec<u8> = Vec::new();
    render::render(report, cli.format, color, &mut buf)?;
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
            h.cid.cid.map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string()),
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

/// `isatty(1)` without a crate.
fn tty_stdout() -> bool {
    // SAFETY: isatty only reads the fd's status.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

impl From<RuntimeError> for ExitCode {
    fn from(e: RuntimeError) -> Self {
        eprintln!("vsockscan: {}", e.0);
        ExitCode::from(2)
    }
}

fn runtime(msg: impl Into<String>) -> ExitCode {
    eprintln!("vsockscan: {}", msg.into());
    ExitCode::from(2)
}
