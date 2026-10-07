# vsockscan

AF_VSOCK recon from inside a VM — device presence, CID resolution, two-direction
reachability, listener census — and from the Firecracker host through a guest's
muxer socket. Written for the shape where the answer matters most —
**root in a guest VM whose config never enabled a vsock device** — where every
existing tool either assumes a device exists or reports "no route" and stops.

Static musl by default: the binary is meant to be copied into a rootfs that has no
glibc guarantee, no `/lib/modules`, and no package manager.

```
cargo build --release          # -> target/x86_64-unknown-linux-musl/release/vsockscan
./target/x86_64-unknown-linux-musl/release/vsockscan probe --config
./target/x86_64-unknown-linux-musl/release/vsockscan selftest
```

`.cargo/config.toml` pins `x86_64-unknown-linux-musl` with `+crt-static`, so a plain
`cargo build` produces the deployable binary (~1.1 MB, `Type: DYN`, no `INTERP`). For a
host build: `cargo build --target x86_64-unknown-linux-gnu`.

## Commands

| command | what it does | traffic |
|---|---|---|
| `probe` | capabilities, device tells, local CID, kernel config (`--config`), module state, `vsock_diag` census (`--diag`), SEQPACKET support | a few connects to CIDs 1/2 plus a loopback canary |
| `scan --cid <spec> --ports <spec>` | reachability sweep over a CID x port matrix; `--flags both` repeats every connect with `VMADDR_FLAG_TO_HOST` set | real; volume is printed before it starts |
| `listen --ports <spec>` | accept on ports, log peer CID/port and a hexdump preview (`--banner N`); `--forever` holds until Ctrl-C, and every exit names its reason (timeout / `--max-conns` / SIGINT) | binds; accepts |
| `listen --census --ports <spec>` | bind-only occupancy (`--timeout 0`): distinguishes `EACCES` (privilege) from `EADDRINUSE` (occupied) | binds only |
| `listen --uds PATH --ports <spec>` | accept on AF_UNIX path `PATH_<port>` — the socket a Firecracker guest's connect to (CID 2, port) arrives at; its userspace vsock proxy never touches the host kernel's AF_VSOCK, so an `AF_VSOCK` listener on a Firecracker host sees nothing | accepts on Unix sockets |
| `h2g --uds PATH --ports <spec>` | from the **Firecracker host**, sweep a guest's ports through the muxer's `CONNECT`/`OK` handshake; `--open` keeps only answered ports (`scan --open` likewise) | one UDS connect per port, plus local AF_VSOCK classification |
| `selftest` | nine loopback checks that prove the outcome classifier with no device, no host, no `socat` | loopback only |

Output: `--format text|markdown|json|yaml`, `-o FILE`, `--json-schema` for the document
schema. Colour appears only on a colour-capable TTY and never in a file.

Exit codes: `0` success, `1` usage, `2` runtime, `3` a `selftest` assertion failed,
`130` interrupted — and an interrupted sweep still prints the rows it finished.

## Why the answers are shaped like this

Every rule below exists because a measurement broke a reasonable-looking alternative.

- **`--cid` has no default.** Forgetting it would point a sweep at the hypervisor
  keyspace, so a missing `--cid` is an error. Matrix size is guarded too: the CID spec
  expands under `--max-cids` (256) unless you pass `--i-know-this-is-wide`.
- **Posture comes from the transport registration, not the device node.**
  `/dev/vhost-vsock` survives `modprobe -r vhost_vsock`, and `open()` on that stale node
  triggers `request_module("char-major-10-241")` — the kernel loads the module back, so a
  tool that samples the node reports a host it just manufactured. `probe` reads the
  `/proc/misc` registration instead and leaves an unregistered node closed.
- **A refusal by the node is not a success and not a host.** `/dev/vhost-vsock` is
  usually `0660 root:kvm`, so an unprivileged probe gets `EACCES`. That row reports
  `refused-kernel EACCES` with the errno actually measured, while posture stays `host`
  off the registration: the kernel denied *us*, it did not deny the transport exists.
- **`/dev/vsock` is not device evidence.** The AF_VSOCK core registers it even with no
  virtio transport bound, so the device tell is the virtio device id `0x0013`.
- **The loopback canary is run before any CID-2 sweep.** On a vsock host, `connect(CID 2)`
  reaches the local transport: `open` there means "a socket of ours listens there". When
  the canary fires, CID-2 rows are labelled `loopback-redirect`, not `open`.
- **Outcome kinds are disjoint on purpose, and only some commands can emit each**:
  `open`, `closed` (peer answered RST), `silent` (a frame left and nothing answered — for
  `h2g`, a handshake line or a `connect()` the muxer backlog never admitted) and `error`
  (the tool could not classify honestly) are sweep answers from `scan` and `h2g` alike;
  `listen` reuses `open`, `closed` (there it means `EADDRINUSE`) and `error` for its
  bind and accept rows.
  `refused-kernel` (nothing left the guest, e.g. `ENODEV`), `loopback-redirect` and
  `unsupported` are kernel-path answers only `probe` and `scan` emit; `absent` (no socket
  file), `denied` (its mode bits), `stale` (socket file whose listener died) and
  `not-muxer` (something else answered the handshake line) are filesystem/protocol
  answers only `h2g` emits. A registered transport with no attached guest still answers
  `connect(CID 3)` with `ENODEV`, so an errno is never read as "the peer refused a port".
- **`loaded` is not `builtin`.** From outside the kernel a loaded `=m` module and a
  built-in are indistinguishable, so `builtin` requires `CONFIG_X=y` *and* a live
  transport, and a verdict reason only names a signal that actually fired
  (`/proc/misc`, `/proc/modules`, `/sys/module/<name>`, or a node this process opened).
- **`SEQPACKET` absence is a transport tell only next to a device tell.** Without a device the
  same `ESOCKTNOSUPPORT` means merely "no device".

## Limits, stated rather than discovered

- Ring 3 only. `--mmio` (virtio-mmio window via `/dev/mem`) needs `CAP_SYS_ADMIN` and
  `iomem=relaxed`, is off by default, and its failure is never reported as "no device".
- No interception: nothing relays, forwards, rewrites or captures traffic beyond the
  byte preview `listen` shows for connections it accepted. `tests/source_hygiene.rs`
  asserts the absence of that machinery, so the claim cannot rot.
- `vsockmon` is a host-side instrument: `CONFIG_VSOCKMON depends on VHOST_VSOCK`
  (`drivers/net/Kconfig`), and `CONFIG_VHOST_VSOCK` is off in the guest kernels checked
  here, so `probe --vsockmon` answers `unavailable` inside a guest — that is the correct
  answer, not a missing package.
- `probe` cannot tell a vsock-disabled guest from a vsock-absent kernel beyond the config
  and transport signals it lists; it reports each signal and the basis for each verdict.
- **h2g speaks only valid handshake text** — malformed port requests poke the muxer's
  bookkeeping against the guest and are never generated by a scan
  (`docs/superpowers/specs/2026-10-07-h2g-open-design.md` §4).

## Tests

`cargo test --release` — 146 unit, 19 integration, 0 doc (the crate is a binary, so
`cargo test` runs no doc tests); `cargo clippy --release --all-targets -- -D warnings`
clean. Integration coverage includes the `h2g` contract end to end against a fake
muxer (handshake rows, JSON shape, `--open` counts, preflight aborts, escaped
`not-muxer` lines, noise that discloses the local AF_VSOCK traffic), the renderers'
colour contract (stripping SGR from a coloured render yields byte-identical output for
`text` and `yaml`, valid JSON for `json`, colour-optional Markdown), the pinned
`vsock_diag` request bytes, and the module-verdict reason rules.

