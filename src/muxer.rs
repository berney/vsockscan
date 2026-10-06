//! The Firecracker vsock muxer's host side, as a client.
//!
//! A Firecracker virtio-vsock device listens on the host at its `uds_path`
//! and speaks a one-line text protocol: the host connects and sends
//! "CONNECT <port>\n"; a guest listener turns that into "OK <host_port>\n"
//! plus a byte channel, and a guest with no listener is a hangup (EOF, no
//! line). `docs/vsock.md` upstream; the muxer allocates `host_port` from
//! 2^30 upward, which is what makes a stock muxer recognizable.
//!
//! This module never invents handshake text: an invalid word or a non-u32
//! port is a muxer parse path against the *guest's* connection state, and a
//! recon tool poking it is how a scanner stops being recon.

use std::path::Path;

// The handshake client is wired into the sweep by `h2g::run`; see `probe`.
pub enum Attempt {
    Open { host_port: u32 },
    Closed,
    Silent,
    NotMuxer { first_line: String },
    ConnectFail { errno: i32 },
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The strict accepted shape: `OK ` + one decimal u32 and nothing else.
pub fn parse_response(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("OK ")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// One connect + handshake against `path`, never holding the channel longer
/// than the handshake plus `banner` bytes. `Err` never escapes: every host
/// outcome (including filesystem answers) is an `Attempt`.
pub fn probe(path: &Path, port: u32, timeout_ms: i32, banner: usize) -> (Attempt, Vec<u8>) {
    use std::os::unix::ffi::OsStrExt;
    let raw = path.as_os_str().as_bytes();
    let probe_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if raw.len() > probe_addr.sun_path.len() - 1 {
        return (
            Attempt::NotMuxer {
                first_line: "path too long for AF_UNIX".into(),
            },
            Vec::new(),
        );
    }
    // SAFETY: constant family/type, no pointers.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return (Attempt::ConnectFail { errno: errno() }, Vec::new());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in addr.sun_path.iter_mut().zip(raw) {
        *d = *s as libc::c_char;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + raw.len();
    // SAFETY: live sockaddr_un, sun_path prefix initialised, exact length.
    if unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            len as libc::socklen_t,
        )
    } != 0
    {
        let e = errno();
        unsafe { libc::close(fd) };
        return (Attempt::ConnectFail { errno: e }, Vec::new());
    }
    let req = format!("CONNECT {port}\n");
    // SAFETY: writing a buffer we own to a connected descriptor.
    let wr = unsafe { libc::write(fd, req.as_ptr().cast(), req.len()) };
    if wr < 0 {
        let e = errno();
        unsafe { libc::close(fd) };
        return (Attempt::ConnectFail { errno: e }, Vec::new());
    }
    let (line, closed_mid, err) = read_line(fd, timeout_ms);
    if let Some(e) = err {
        unsafe { libc::close(fd) };
        return (Attempt::ConnectFail { errno: e }, Vec::new());
    }
    let outcome = match line {
        None => {
            // EOF before any line is the muxer's refusal; a partial line is
            // not a language we recognise.
            if closed_mid {
                Attempt::Closed
            } else {
                Attempt::Silent
            }
        }
        Some(l) => match parse_response(&l) {
            Some(n) => Attempt::Open { host_port: n },
            None => Attempt::NotMuxer { first_line: l },
        },
    };
    let bytes = match &outcome {
        Attempt::Open { .. } if banner > 0 => drain(fd, banner, timeout_ms),
        _ => Vec::new(),
    };
    // SAFETY: closing the descriptor we opened.
    unsafe { libc::close(fd) };
    (outcome, bytes)
}

/// Read one `\n`-terminated line under `timeout_ms`. Returns
/// `(line, saw_eof_midline, errno)`: `None,false,false` is the timeout.
fn read_line(fd: libc::c_int, timeout_ms: i32) -> (Option<String>, bool, Option<i32>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut waited = 0i32;
    loop {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on a descriptor we own.
        let pr = unsafe { libc::poll(&mut p, 1, 50) };
        waited += 50;
        if pr < 0 {
            return (None, false, Some(errno()));
        }
        if pr == 0 {
            if waited >= timeout_ms {
                return (None, false, None);
            }
            continue;
        }
        let mut b = [0u8; 1];
        // SAFETY: one byte into a live buffer.
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
        if n == 0 {
            if buf.is_empty() {
                return (None, true, None);
            }
            return (Some(String::from_utf8_lossy(&buf).into_owned()), true, None);
        }
        if n < 0 {
            return (None, false, Some(errno()));
        }
        if b[0] == b'\n' {
            let s = String::from_utf8_lossy(&buf).into_owned();
            return (Some(s.trim_end_matches('\r').to_string()), false, None);
        }
        buf.push(b[0]);
        if buf.len() > 4096 {
            return (
                Some(String::from_utf8_lossy(&buf).into_owned()),
                false,
                None,
            );
        }
    }
}

/// Read up to `want` bytes under `timeout_ms`, like `listen`'s preview.
fn drain(fd: libc::c_int, want: usize, timeout_ms: i32) -> Vec<u8> {
    let mut buf = vec![0u8; want];
    let mut got = 0usize;
    let mut waited = 0i32;
    while got < want {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on a descriptor we own.
        let pr = unsafe { libc::poll(&mut p, 1, 50) };
        waited += 50;
        if pr < 0 || waited >= timeout_ms {
            break;
        }
        if pr == 0 {
            continue;
        }
        // SAFETY: read into the free tail of a buffer we own.
        let n = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), want - got) };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    buf.truncate(got);
    buf
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// One test's scratch dir plus socket path, unique per test so parallel
    /// tests never share a file, and short enough for `sun_path`.
    fn sock(name: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("vsockscan-muxer-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("s.sock");
        (dir, path)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    fn scripted(
        path: std::path::PathBuf,
        react: &'static (dyn Fn(std::os::unix::net::UnixStream) + Send + Sync),
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let (s, _) = l.accept().unwrap();
            react(s);
            // the listener unlinks on drop so tests can reuse dirs
            let _ = std::fs::remove_file(&path);
        })
    }

    /// Wait for the responder's `bind` to publish the socket file, so the
    /// probe never races the listener into a spurious `ECONNREFUSED`.
    fn wait_for_bind(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("responder never bound {path:?}");
    }

    /// Drain the client's request line up to and including its `\n`.
    fn read_request(s: &mut std::os::unix::net::UnixStream) -> String {
        let mut line = String::new();
        let mut b = [0u8; 1];
        while s.read(&mut b).unwrap_or(0) == 1 {
            if b[0] == b'\n' {
                line.push('\n');
                break;
            }
            line.push(b[0] as char);
        }
        line
    }

    #[test]
    fn parse_response_ok_line_and_strictness() {
        assert_eq!(parse_response("OK 1073741824"), Some(1073741824));
        assert_eq!(parse_response("OK 0"), Some(0));
        assert_eq!(parse_response("ok 12"), None); // muxer answers uppercase
        assert_eq!(parse_response("OK"), None);
        assert_eq!(parse_response("OK abc"), None);
        assert_eq!(parse_response("OK 12 x"), None);
        assert_eq!(parse_response("HELLO"), None);
    }

    #[test]
    fn open_reads_handshake_then_banner() {
        static REQUEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let (dir, path) = sock("open");
        let h = scripted(path.clone(), &|mut s| {
            let line = read_request(&mut s);
            let _ = REQUEST.set(line);
            let _ = s.write_all(b"OK 1073741824\n");
            let _ = s.write_all(b"guest greeting");
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        wait_for_bind(&path);
        let (attempt, bytes) = probe(&path, 5555, 400, 20);
        h.join().expect("responder");
        assert!(
            matches!(
                attempt,
                Attempt::Open {
                    host_port: 1073741824
                }
            ),
            "OK + host_port is the handshake"
        );
        assert_eq!(bytes, b"guest greeting");
        // The handshake is the contract: pin the exact request bytes.
        assert_eq!(REQUEST.get().map(String::as_str), Some("CONNECT 5555\n"));
        cleanup(&dir);
    }

    #[test]
    fn closed_is_hangup_without_a_line() {
        let (dir, path) = sock("closed");
        let h = scripted(path.clone(), &|mut s| {
            let _ = read_request(&mut s);
            drop(s);
        });
        wait_for_bind(&path);
        let (attempt, bytes) = probe(&path, 7, 400, 0);
        h.join().expect("responder");
        assert!(
            matches!(attempt, Attempt::Closed),
            "EOF with no line is the guest's refusal"
        );
        assert!(bytes.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn silent_is_no_line_before_timeout() {
        let (dir, path) = sock("silent");
        let h = scripted(path.clone(), &|mut s| {
            let _ = read_request(&mut s);
            // Longer than the probe's 400 ms: a guest that answers late is not
            // a guest that answered.
            std::thread::sleep(std::time::Duration::from_millis(900));
        });
        wait_for_bind(&path);
        let started = std::time::Instant::now();
        let (attempt, bytes) = probe(&path, 7, 400, 0);
        assert!(
            matches!(attempt, Attempt::Silent),
            "no line inside the timeout is silence"
        );
        assert!(bytes.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_millis(1500),
            "the probe must stop at its timeout, not at the responder"
        );
        h.join().expect("responder");
        cleanup(&dir);
    }

    #[test]
    fn not_muxer_carries_the_first_line() {
        let (dir, path) = sock("notmuxer");
        let h = scripted(path.clone(), &|mut s| {
            let _ = s.write_all(b"HELLO 1\n");
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        wait_for_bind(&path);
        let (attempt, bytes) = probe(&path, 7, 400, 0);
        h.join().expect("responder");
        let Attempt::NotMuxer { first_line } = attempt else {
            panic!("an unrecognised word is not the muxer's language");
        };
        assert_eq!(first_line, "HELLO 1");
        assert!(bytes.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn connect_failures_are_distinguished() {
        let (dir, _) = sock("connectfail");

        // Nothing at the path at all.
        let missing = dir.join("nope.sock");
        let (attempt, bytes) = probe(&missing, 1, 400, 0);
        assert!(
            matches!(
                attempt,
                Attempt::ConnectFail {
                    errno: libc::ENOENT
                }
            ),
            "a missing path is ENOENT"
        );
        assert!(bytes.is_empty());

        // A regular file is a different filesystem answer; the exact value is
        // kernel-voice (Linux says ENOTSOCK), so only its difference is pinned.
        let plain = dir.join("plain");
        std::fs::write(&plain, b"not a socket").expect("regular file");
        let (attempt, _) = probe(&plain, 1, 400, 0);
        let Attempt::ConnectFail { errno } = attempt else {
            panic!("a regular file must not look like a muxer");
        };
        assert_ne!(
            errno,
            libc::ENOENT,
            "a file that exists is not a missing one"
        );

        // A live socket nobody may touch; root ignores the mode bits.
        if unsafe { libc::getuid() } != 0 {
            let guarded = dir.join("guarded.sock");
            let l = std::os::unix::net::UnixListener::bind(&guarded).expect("bind");
            std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
            let (attempt, _) = probe(&guarded, 1, 400, 0);
            assert!(
                matches!(
                    attempt,
                    Attempt::ConnectFail {
                        errno: libc::EACCES
                    }
                ),
                "a permission bit is its own answer"
            );
            drop(l);
        }
        cleanup(&dir);
    }

    #[test]
    fn stale_socket_refuses() {
        let (dir, path) = sock("stale");
        let l = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        drop(l); // the file stays behind, which is a crashed listener's corpse
        let (attempt, bytes) = probe(&path, 1, 400, 0);
        assert!(
            matches!(
                attempt,
                Attempt::ConnectFail {
                    errno: libc::ECONNREFUSED
                }
            ),
            "a dead socket refuses, it is not silent"
        );
        assert!(bytes.is_empty());
        // A socket file that outlives the test points the next run at a dead
        // path; every test unlinks.
        std::fs::remove_file(&path).expect("unlink stale socket");
        cleanup(&dir);
    }
}
