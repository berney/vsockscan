# h2g scanner and `--open` filter — design

Status: approved in outline 2026-10-07; this document is the contract.

## 1 Problem

Everything the tool does today stands inside a VM and speaks AF_VSOCK through
the kernel. Firecracker exposes the opposite direction to the machine running
it: the virtio-vsock device is a userspace muxer that listens on a host
AF_UNIX socket (`uds_path`) and speaks a text handshake
(`docs/vsock.md`, upstream `vsock/unix/muxer.rs::read_connect_cmd`):

```
host: connect(uds_path), send "CONNECT <port>\n"
muxer: if a guest listener accepts -> "OK <host_port>\n", channel open
       if nobody listens          -> connection torn down (EOF, no line)
```

`<host_port>` is allocated from `(1 << 30) - 1` upward, so stock muxers answer
`OK 1073741824+` — a built-in fingerprint. `MAX_CONNECTIONS = 1023` is shared
with guest-initiated channels; a host sweep that holds channels starves the
VM's guest-to-host direction.

Operators need: which guest ports accept host-originated connections, and a
verdict on the socket itself (real muxer? alive? stale file? someone else's
daemon?).

## 2 Shape: new subcommand, not `scan --h2g`

The test this repo applies to flags: *a flag changes which socket; a
subcommand changes what a row means.* `--h2g` changes the meaning of every
row:

- transport: AF_UNIX + text handshake, not `connect(2)` errnos on a vsock
  transport; works with AF_VSOCK compiled out of the host kernel;
- taxonomy: `ENOENT`/`EACCES`/`ECONNREFUSED` here are facts about the host
  filesystem (jail-root ownership, crashed VM), states `scan` cannot express;
- contradicted options: `--cid` (required, deliberately no default),
  `--flags both`, stage-1 pruning, and the loopback canary are all
  guest-side-only.

`listen --uds` stayed a flag because it kept every meaning of `listen`;
`h2g` shares only the report plumbing.

## 3 CLI surface

```
vsockscan h2g --uds PATH [--ports SPEC] [--timeout SEC] [--parallel N]
                    [--banner N] [--open]
```

| option | default | contract |
|---|---|---|
| `--uds PATH` | required | the device's `uds_path` **exactly** (no `_port` suffix logic — suffixes belong to the g2h direction). AF_UNIX's 107-byte name limit is checked up front |
| `--ports SPEC` | `top` | same u32 `spec.rs` parser as `scan`; the handshake word is decimal u32 |
| `--timeout SEC` | 2.0 | applied separately to UDS `connect()` and to handshake reads |
| `--parallel N` | 16, hard cap 256 | each open channel takes one slot of the muxer's `MAX_CONNECTIONS = 1023` table, shared with guest-initiated traffic; `N > 256` is a clap usage error (not silently clamped) so the sweep stays at least 4x below the table, and the noise line says so |
| `--banner N` | 0 | after `OK`, read up to N bytes the guest speaks first, bounded wait, hexdump into notes (same convention as `listen`) |
| `--open` | off | §6 |

Globals (`--format`, `-o`, `--quiet`, `--no-color`, SIGINT partial report,
exit codes 0/1/2/130) behave as in the other commands.

## 4 Handshake lifecycle

Preflight, once, before any planned port (the canary pattern: measure the
baseline, then sweep):

1. `connect(uds_path)` + `CONNECT <random high port>\n` (uniform u32; a real
   guest listener is rare this high, and if it answers that is exactly what
   the step-3 alert is for - the port choice needs no property beyond sparsity).
2. `EOF` -> muxer alive, `closed` is observable; proceed.
3. `OK n` -> finding `[alert]` "the guest answered CONNECT on a random port"
   (a guest-side forwarder/proxy agent exists or a listener collided); record
   `n`; proceed; close the channel.
4. `ENOENT` / `EACCES` / `ECONNREFUSED` / garbage / timeout -> abort
   (exit 2) with the §5 message for that state: sweeping every port would
   only repeat one fact N times.

Per port: connect -> `CONNECT <port>\n` -> read one line:

- `OK <n>\n` -> `open`; value `muxer host port <n>`; if `n < 2^30`, add the
detail "host port below the muxer's 2^30 pool: not a stock Firecracker
muxer".
- EOF before a complete line -> `closed`.
- complete line that is not `OK <decimal u32>` -> `not-muxer` (another daemon
  owns the path).
- no line before timeout -> `silent`.
- `ENOENT` / `EACCES` / `ECONNREFUSED` at connect -> `absent` / `denied` /
`stale`.

Every channel is closed immediately after its inspection (`--banner` bytes or
the handshake line). The table is shared; a scanner must not hold it.

Malformed handshake text is never sent: a wrong word or a non-u32 port makes
the muxer treat the line as an invalid port request against the guest's
connection bookkeeping. Probing that parser is out of scope (§8).

## 5 Outcome taxonomy (h2g)

Four new `OutcomeKind` variants join the enum; `Open`, `Closed`, `Silent`,
`Error` keep their current meanings.

| outcome | trigger | meaning and action |
|---|---|---|
| `open` | `OK n` | the guest listens; host-reachable now |
| `closed` | EOF after CONNECT | muxer alive and honest; nobody listens in the guest |
| `silent` | no line before timeout | accepted but silent: wedged muxer or a daemon that does not speak the handshake |
| `not-muxer` | full line is neither `OK <u32>` nor EOF | another daemon owns the path; fingerprint it before trusting any row |
| `absent` | connect `ENOENT` | no VM with that `uds_path`; if a jailer is in play the VMM resolves the path **inside the jail root** — that is the first place to look |
| `denied` | connect `EACCES` | permissions on the socket file (jail roots are usually root-owned); a fact about the host filesystem, invisible to the guest |
| `stale` | connect `ECONNREFUSED` | socket file without a listener: a VM that died without cleanup |

Invariant: `scan` never produces `absent`/`denied`/`stale`/`not-muxer`, and
`h2g` never produces `refused-kernel`/`loopback-redirect`/`unsupported`.
The taxonomy table in the README lists each kind with the command that can
emit it.

## 6 `--open` (scan and h2g)

`nmap --open` semantics, noise-honest:

- applied **after** classification, **before** report assembly: a row is kept
iff `kind == Open`.
- `summary.results` stays the swept count; a note always records
`--open: showing N open row(s) of M` — including `N = 0`, because "swept
  4000, nothing open" must be distinguishable from "failed to sweep".
- findings are never filtered: canary, flags-agree, and permission findings
  still fire; a `loopback-redirect` row disappearing while its warning
  remains is the intended reading.
- `--flags both` agreement is computed over all paired rows before filtering;
  a partial run still suppresses `flags-agree` rather than lying.
- JSON `probes` carry only the kept rows; schema gains no fields.
- exit codes unchanged: a clean sweep with zero open rows is 0.

## 7 Plumbing

- new `src/muxer.rs`: UDS connect with errno classification, the
CONNECT/OK line protocol (response parsing unit-tested against the
  muxer's accepted shapes), and the preflight.
- new `src/h2g.rs`: port matrix over `muxer`, parallel pool mirroring
  `scan.rs`'s blocking-connect pool (channels are short-lived, so one socket
  per in-flight port is fine), noise line, `--open` application.
- `src/model.rs`: `+Absent,+Denied,+Stale,+NotMuxer`; `as_str`, renderer
  width tables, and the JSON-schema test updated in the same change.
- `--open` lives in `main.rs`'s two arg structs and is applied in `scan.rs`
  and `h2g.rs` respectively — not in the renderers, so all four formats and
  `-o FILE` share one filtering point.

## 8 Non-goals

- no malformed-handshake probing (invalid port request behavior is guest
  bookkeeping, not a scan target);
- no raw frame injection, no interception, no relay (existing README limits,
  unchanged);
- one `--uds` per run: multi-VM enumeration is a shell loop, deliberately;
- no guest CID reporting: the muxer gives the host no way to learn it;
  reports record the `uds_path` only;
- discovering which ports a *guest* will dial out to stays the job of
  `listen --uds`.

## 9 Verification

- unit: handshake response parsing (`OK` + pool boundary at 2^30, EOF,
  partial line, garbage, trailing junk after the line);
- fake-muxer end-to-end on a temp UDS covering every §5 outcome: scripted
OK/EOF/garbage/silent responders, `denied` via chmod 000 (non-root),
  `stale` via bind-then-close, `absent` via nonexistent path;
- `--open`: counts and note text incl. zero-open; JSON carries only open
  rows; `flags-agree` computed pre-filter; findings survive filtering;
- `h2g --open` against a fake muxer with two scripted open ports shows
  exactly those rows;
- real-Firecracker verification is manual in the lab (runners have no VMM):
  the spec is only "done" after one run against a live `uds_path` reproduces
  `open` for a guest `listen` port and `closed` for one without.
