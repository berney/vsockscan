//! `listen`: hold ports, take what arrives, and the bind-only occupancy census.
//!
//! The census mode exists because binding is itself an experiment worth running
//! in a guest VM: the privileged-port check is done against the *supplied*
//! port (a bind to port 80 as uid 1000 is `EACCES`, measured), and one binder per
//! port means a second bind reports `EADDRINUSE` — which is how you learn a port
//! is occupied by something you cannot see in a census when `CONFIG_VSOCKETS_DIAG`
//! is off.
//!
//! Nothing here ever sends bytes back. The preview is read so a listener can be
//! identified, not harvested.

use crate::model::{Outcome, OutcomeKind, ProbeRow, Report, Severity};
use crate::uapi;

pub struct Opts<'a> {
    pub ports: &'a [u32],
    /// Bind-and-close instead of accepting.
    pub census: bool,
    /// Stop after this many accepted connections; `0` = no limit.
    pub max_conns: usize,
    /// Overall deadline for the accept loop, and the per-connection read wait.
    pub timeout_ms: i32,
    /// Bytes to preview from each connection, as a hexdump.
    pub preview: usize,
    /// Stream each frame as it arrives (text format only).
    pub live: Live,
}

/// Live progress for `listen`, printed the moment it happens.
///
/// A listener that prints nothing until its timeout expires looks exactly like a
/// listener that bound nothing, so the accept loop narrates itself. It goes to
/// stdout under a process-wide lock: two connections arriving together must not
/// interleave their hexdump blocks. Machine formats pass `Live::off()` and get
/// every fact in the document at the end instead.
#[derive(Clone, Copy)]
pub struct Live(pub bool);

impl Live {
    pub fn off() -> Self {
        Self(false)
    }

    fn line(&self, text: &str) {
        if !self.0 {
            return;
        }
        use std::io::Write as _;
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let stdout = std::io::stdout();
        let mut w = stdout.lock();
        // A dead pipe must not end a listener that is holding ports for someone else.
        let _ = writeln!(w, "{text}");
        let _ = w.flush();
    }
}

/// Wall clock as `HH:MM:SS.mmm`, so a live block can be lined up with a guest
/// `dmesg` or a host capture. UTC-free on purpose: this is read by a human who is
/// standing in front of one machine.
fn clock() -> String {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: gettimeofday writes through a pointer to a live struct.
    if unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) } != 0 {
        return "?".to_string();
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r writes the struct we pass it.
    if unsafe { libc::localtime_r(&tv.tv_sec, &mut tm) }.is_null() {
        return "?".to_string();
    }
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tv.tv_usec / 1000
    )
}

/// One streamed connection block: attribution first, then the bytes under it.
fn conn_block(port: u32, cid: u32, peer_port: u32, bytes: &[u8], closed: bool, ts: &str) -> String {
    let mut out = format!(
        "{ts}  port {port}  peer CID {cid} port {peer_port}  {} byte(s)",
        bytes.len()
    );
    if !closed {
        out.push_str("  (read window ended, connection still open)");
    }
    if bytes.is_empty() {
        out.push_str("\n  peer sent nothing before closing");
    } else {
        for line in hexdump(bytes).lines() {
            out.push_str(&format!("\n  {line}"));
        }
    }
    out
}

/// The result of one `bind(CID_ANY, port)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    Bound { ino: u64 },
    Denied,
    InUse,
    Failed { errno: i32 },
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Try exactly one bind, and say what the kernel answered. No `SO_REUSEADDR`: an
/// occupied port is the fact being measured, not an inconvenience.
pub fn try_bind(port: u32) -> Bind {
    // SAFETY: constant family/type, no pointers.
    let fd = unsafe {
        libc::socket(
            uapi::AF_VSOCK as libc::c_int,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Bind::Failed { errno: errno() };
    }
    let addr = uapi::SockaddrVm::new(uapi::VMADDR_CID_ANY, port, false);
    // SAFETY: `addr` is a live SockaddrVm and its own size is passed as the length.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            uapi::SockaddrVm::len(),
        )
    };
    if rc != 0 {
        let e = errno();
        // SAFETY: closing the descriptor we just opened.
        unsafe { libc::close(fd) };
        return match e {
            libc::EACCES => Bind::Denied,
            libc::EADDRINUSE => Bind::InUse,
            _ => Bind::Failed { errno: e },
        };
    }
    let ino = inode(fd);
    // SAFETY: closing the descriptor we just opened.
    unsafe { libc::close(fd) };
    Bind::Bound { ino }
}

fn inode(fd: libc::c_int) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes through a valid fd.
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        st.st_ino as u64
    } else {
        0
    }
}

/// One census row per port.
pub fn census_rows(ports: &[u32]) -> Vec<ProbeRow> {
    ports
        .iter()
        .map(|&port| {
            // The readout column stays short — an inode, a peer — and the
            // explanation rides on the outcome, the same way the capability probes
            // do it, so both tables read as one shape.
            let (outcome, value) = match try_bind(port) {
                Bind::Bound { ino } => {
                    (Outcome::new(OutcomeKind::Open), Some(format!("ino {ino}")))
                }
                Bind::Denied => (
                    Outcome::new(OutcomeKind::Error)
                        .with_errno(libc::EACCES)
                        .with_detail(format!(
                            "uid {} cannot bind this port; the check is on the supplied port, so \
                             a low port tells you nothing about whether something is listening",
                            // SAFETY: getuid takes no arguments.
                            unsafe { libc::getuid() }
                        )),
                    None,
                ),
                Bind::InUse => (
                    Outcome::new(OutcomeKind::Closed)
                        .with_errno(libc::EADDRINUSE)
                        .with_detail(
                            "occupied by another binder — invisible here if the diag census is \
                             unavailable"
                                .to_string(),
                        ),
                    None,
                ),
                Bind::Failed { errno: e } => (Outcome::new(OutcomeKind::Error).with_errno(e), None),
            };
            ProbeRow {
                name: format!("bind:{}", port),
                outcome,
                value,
                flags: crate::model::FlagSet::None,
            }
        })
        .collect()
}

/// Classic `hexdump -C` layout, because transcripts of byte-level work get
/// copy-pasted and the offset column is what makes them align.
pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (n, chunk) in data.chunks(16).enumerate() {
        let off = n * 16;
        let bytes = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{off:08x}  {bytes:<47}  |{ascii}|\n"));
    }
    out
}

/// Run `listen` into `report`. Census mode returns immediately; the accept loop
/// runs until `--max-conns` or `--timeout`, then reports what it saw.
pub fn run(o: &Opts, report: &mut Report) -> Result<(), String> {
    if o.ports.is_empty() {
        return Err("listen needs at least one port (--ports SPEC)".to_string());
    }
    let base = report.probes.len();
    if o.census {
        report.probes.extend(census_rows(o.ports));
        report.summary.results = report.probes.len() - base;
        report.summary.notes.push(format!(
            "bind-only census of {} port(s): bound/binding-refused is a fact about the \
             kernel's checks and this uid, not about reachability",
            o.ports.len()
        ));
        return Ok(());
    }
    accept_loop(o, report)
}

/// Accept until the deadline or the connection budget. Each connection is read on
/// its own thread and *returns* its row, so there is no shared mutable state.
fn accept_loop(o: &Opts, report: &mut Report) -> Result<(), String> {
    // Only the connections this command made count as its results; the header's
    // classification probes were already in the report.
    let base = report.probes.len();
    let mut listeners = Vec::new();
    for &port in o.ports {
        match bind_listener(port) {
            Ok(fd) => listeners.push((port, fd)),
            Err(e) => report.finding(
                Severity::Warn,
                format!(
                    "could not hold port {port}: {} — nothing will be logged for it",
                    uapi::errno_label(e)
                ),
            ),
        }
    }
    if listeners.is_empty() {
        return Err("no port could be bound; nothing to listen on".to_string());
    }
    let banner = format!(
        "listening on {} port(s) for up to {} ms{}",
        listeners.len(),
        o.timeout_ms,
        if o.max_conns == 0 {
            " (no connection limit)".to_string()
        } else {
            format!(", stopping after {} connection(s)", o.max_conns)
        }
    );
    report.summary.notes.push(banner.clone());
    o.live.line(&banner);

    let deadline_ms = o.timeout_ms.max(0);
    let mut waited = 0i32;
    let mut taken = 0usize;
    let mut handles = Vec::new();
    let tick = 100i32;
    while waited < deadline_ms && (o.max_conns == 0 || taken < o.max_conns) {
        let mut pfds: Vec<libc::pollfd> = listeners
            .iter()
            .map(|(_, fd)| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let slice = deadline_ms - waited;
        let slice = if o.max_conns == 0 {
            slice.min(tick)
        } else {
            tick
        };
        // SAFETY: poll over descriptors we own, length passed explicitly.
        let pr = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, slice) };
        waited += slice;
        if pr <= 0 {
            continue;
        }
        for (i, (port, _)) in listeners.iter().enumerate() {
            if pfds[i].revents & libc::POLLIN == 0 {
                continue;
            }
            // SAFETY: accept writes the peer address through valid pointers.
            let mut peer = uapi::SockaddrVm::default();
            let mut len = uapi::SockaddrVm::len();
            let fd = unsafe {
                libc::accept(
                    listeners[i].1,
                    &mut peer as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            if fd < 0 {
                report.finding(
                    Severity::Warn,
                    format!(
                        "accept on port {port} failed: {}",
                        uapi::errno_label(errno())
                    ),
                );
                continue;
            }
            taken += 1;
            let want = o.preview;
            let local_port = *port;
            let live = o.live;
            handles.push(std::thread::spawn(move || {
                let (bytes, closed) = drain(fd, want);
                // The block is printed as soon as this connection's read window
                // closes, not when the whole loop finishes: waiting for the
                // deadline to find out that anyone called would be useless.
                live.line(&conn_block(
                    local_port,
                    peer.svm_cid,
                    peer.svm_port,
                    &bytes,
                    closed,
                    &clock(),
                ));
                // SAFETY: closing the accepted descriptor.
                unsafe { libc::close(fd) };
                (local_port, peer.svm_cid, peer.svm_port, bytes, closed)
            }));
        }
    }
    let mut rows = Vec::new();
    for h in handles {
        let (port, cid, peer_port, bytes, closed) = h
            .join()
            .map_err(|_| "a connection worker panicked".to_string())?;
        let mut value = format!("peer CID {cid} port {peer_port}, {} byte(s)", bytes.len());
        if !closed {
            value.push_str(" (read timed out, connection still open)");
        }
        let dump = hexdump(&bytes);
        rows.push((port, value, dump, bytes.len()));
    }
    for (port, value, dump, len) in rows {
        let mut outcome = Outcome::new(OutcomeKind::Open);
        if len == 0 {
            outcome = outcome.with_detail("peer sent nothing before closing");
        }
        report.probes.push(ProbeRow {
            name: format!("accept:{port}"),
            outcome,
            value: Some(value),
            flags: crate::model::FlagSet::None,
        });
        if !dump.is_empty() && dump != "\n" {
            report
                .summary
                .notes
                .push(format!("first bytes from {port}:\n{dump}"));
        }
    }
    report.summary.results = report.probes.len() - base;
    // The listeners must not outlive the command holding them.
    for (_, fd) in listeners {
        // SAFETY: closing descriptors we own.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

/// Read up to `want` bytes with the loop's deadline; a peer that closes without
/// sending anything is a legitimate observation, not an error.
fn drain(fd: libc::c_int, want: usize) -> (Vec<u8>, bool) {
    if want == 0 {
        return (Vec::new(), true);
    }
    let mut buf = vec![0u8; want];
    let mut got = 0usize;
    let mut waited = 0i32;
    while got < want && waited < 1000 {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on a descriptor we own.
        let pr = unsafe { libc::poll(&mut p, 1, 100) };
        waited += 100;
        if pr <= 0 {
            return (buf[..got].to_vec(), false);
        }
        // SAFETY: read into `buf[..want-got]` with the matching length.
        let n = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), want - got) };
        if n == 0 {
            return (buf[..got].to_vec(), true);
        }
        if n < 0 {
            return (buf[..got].to_vec(), true);
        }
        got += n as usize;
    }
    (buf[..got].to_vec(), true)
}

/// Bind *and keep* a listening socket, so the accept loop can poll it.
pub fn bind_listener(port: u32) -> Result<libc::c_int, i32> {
    // SAFETY: constant family/type, no pointers.
    let fd = unsafe {
        libc::socket(
            uapi::AF_VSOCK as libc::c_int,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    let addr = uapi::SockaddrVm::new(uapi::VMADDR_CID_ANY, port, false);
    // SAFETY: live struct, own length.
    if unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            uapi::SockaddrVm::len(),
        )
    } != 0
    {
        let e = errno();
        // SAFETY: closing the descriptor we just opened.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: listen on a bound descriptor.
    if unsafe { libc::listen(fd, 8) } != 0 {
        let e = errno();
        // SAFETY: closing the descriptor we just opened.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A golden dump: the offset column, the padded byte column and the ASCII
    /// gutter are what make transcripts comparable, so they are pinned rather than
    /// eyeballed.
    #[test]
    fn hexdump_is_canonical() {
        let d = hexdump(b"vsock probe 0123456789");
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 2, "{d}");
        // The byte column is always 47 characters wide so the ASCII gutters line
        // up between a full line and a short one.
        let full = "76 73 6f 63 6b 20 70 72 6f 62 65 20 30 31 32 33";
        let tail = "34 35 36 37 38 39";
        assert_eq!(full.len(), 47);
        assert_eq!(lines[0], format!("00000000  {full}  |vsock probe 0123|"));
        assert_eq!(lines[1], format!("00000010  {:<47}  |456789|", tail));
        // Non-printable bytes become dots, and the empty input is the empty string.
        assert!(hexdump(&[0, 1, 0x7f])
            .lines()
            .next()
            .unwrap()
            .ends_with("|...|"));
        assert_eq!(hexdump(&[]), "");
    }

    #[test]
    fn census_reports_a_port_another_binder_holds() {
        let port = 47123;
        let held = bind_listener(port).expect("binding the fixture port");
        let rows = census_rows(&[port]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "bind:47123");
        assert_eq!(rows[0].outcome.errno_name.as_deref(), Some("EADDRINUSE"));
        assert_eq!(rows[0].outcome.kind, OutcomeKind::Closed);
        // SAFETY: closing the fixture listener.
        unsafe { libc::close(held) };
        // The same port is bindable once the holder is gone: the census is
        // measuring the kernel, not remembering the previous answer.
        let after = census_rows(&[port]);
        assert_eq!(
            after[0].outcome.kind,
            OutcomeKind::Open,
            "{:?}",
            after[0].value
        );
    }

    #[test]
    fn privileged_port_denies_a_non_root_binder() {
        if unsafe { libc::getuid() } == 0 {
            eprintln!("skipping: running as root, which binds port 80 by definition");
            return;
        }
        let rows = census_rows(&[80]);
        assert_eq!(
            rows[0].outcome.errno_name.as_deref(),
            Some("EACCES"),
            "port 80 as uid {} must be denied, got {:?}",
            unsafe { libc::getuid() },
            rows[0].outcome
        );
    }

    #[test]
    fn a_streamed_block_is_attributed_before_its_bytes() {
        // The whole point of streaming is that a transcript shows *who* sent what
        // without waiting for the run to end, so the attribution line must come
        // first and the dump must hang off it, indented.
        let b = conn_block(10809, 2, 44111, b"hi\n", true, "12:00:01.500");
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 2, "{b}");
        assert_eq!(
            lines[0],
            "12:00:01.500  port 10809  peer CID 2 port 44111  3 byte(s)"
        );
        assert_eq!(
            lines[1], "  00000000  68 69 0a                                         |hi.|",
            "{b}"
        );
    }

    #[test]
    fn a_quiet_peer_and_an_open_peer_say_so() {
        let q = conn_block(7, 3, 1, b"", true, "00:00:00.000");
        assert!(q.contains("peer sent nothing before closing"), "{q}");
        assert!(!q.contains("still open"), "{q}");
        let o = conn_block(7, 3, 1, b"", false, "00:00:00.000");
        assert!(
            o.contains("(read window ended, connection still open)"),
            "{o}"
        );
    }

    #[test]
    fn the_clock_has_a_fixed_shape() {
        let c = clock();
        // HH:MM:SS.mmm - 12 characters plus separators; anything shorter means a
        // failed syscall, which prints `?` rather than a plausible-looking zero.
        assert!(c == "?" || c.len() == 12, "{c}");
        if c != "?" {
            assert_eq!(c.matches(':').count(), 2, "{c}");
            // `HH:MM:SS.mmm`: the dot sits after the eight clock digits.
            assert_eq!(&c[8..9], ".", "{c}");
        }
    }

    #[test]
    fn accept_loop_logs_the_peer_and_previews_bytes() {
        let port = 47124;
        let mut report = Report::new("listen", crate::model::placeholder_header());
        let opts = Opts {
            ports: &[port],
            census: false,
            max_conns: 1,
            timeout_ms: 3000,
            preview: 16,
            live: Live::off(),
        };
        // Connect once from this process; loopback answers on the host and the
        // loop returns as soon as the connection is taken.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let fd = unsafe { libc::socket(uapi::AF_VSOCK as libc::c_int, libc::SOCK_STREAM, 0) };
            let addr = uapi::SockaddrVm::new(uapi::VMADDR_CID_HOST, port, false);
            unsafe {
                libc::connect(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    uapi::SockaddrVm::len(),
                )
            };
            let msg = b"hello from the peer";
            // SAFETY: writing a buffer we own to a connected descriptor.
            unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
            std::thread::sleep(std::time::Duration::from_millis(300));
            // SAFETY: closing the descriptor this thread opened.
            unsafe { libc::close(fd) };
        });
        run(&opts, &mut report).expect("the accept loop finishes on its own");
        assert_eq!(report.probes.len(), 1, "{:?}", report.probes);
        let v = report.probes[0].value.clone().expect("peer identity");
        assert!(v.contains("peer CID"), "{v}");
        assert!(v.contains("port"), "{v}");
        // The preview is a cap, not a target: 19 bytes arrived, 16 were read.
        assert!(v.contains("16 byte(s)"), "{v}");
        let dumped = report
            .summary
            .notes
            .iter()
            .find(|n| n.contains("first bytes"))
            .expect("the preview is dumped");
        assert!(dumped.contains("68 65 6c 6c 6f"), "{dumped}");
    }
}
