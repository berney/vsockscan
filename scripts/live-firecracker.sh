#!/usr/bin/env bash
# Live fixture: the h2g contract against a real Firecracker vsock muxer.
#
# Boots a throwaway microVM (guest CID 3, vsock UDS) whose init runs
# `vsockscan listen --ports 1235`, then asserts from the HOST through the
# muxer's CONNECT/OK handshake: 1235 answers open with a host port from the
# stock 2^30 pool, 1236 answers closed, --open filters to the open row, and
# a path with no socket reports absent without touching a VM. The fake-muxer
# integration tests assert the same taxonomy against our own reading of the
# protocol; this asserts it against Firecracker's.
#
# Assets follow the amirustrained live-leaf pattern: one-time download into
# a user cache, rootless (/dev/kvm read/writable is the only privilege).
# Kernel and rootfs are matched Firecracker CI artifacts; that kernel has
# CONFIG_VIRTIO_VSOCKETS=y, so the guest needs no module loading.
#
#   scripts/live-firecracker.sh check                    available | unavailable: why (exit 3)
#   scripts/live-firecracker.sh setup [--system]         fetch firecracker, kernel, rootfs
#   scripts/live-firecracker.sh run [--skip-unavailable] boot once, run the battery
#
# Environment: BIN (default: build the working tree, release, musl),
# VSOCKSCAN_LIVE_CACHE (default ~/.cache/vsockscan/live-firecracker),
# FC_TIMEOUT (boot budget, default 90 s), KEEP=1 (leave the work dir),
# OUT (console log destination, default target/live-firecracker).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${VSOCKSCAN_LIVE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/vsockscan/live-firecracker}"
FC_VERSION=v1.17.0
FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz"
FC_CI="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260722-38359b8055fc-0/x86_64"
FC_KERNEL_URL="$FC_CI/debug/vmlinux-6.1.176"
FC_ROOTFS_SQUASH="$FC_CI/ubuntu-24.04.squashfs"
FC_TIMEOUT="${FC_TIMEOUT:-90}"
OUT="${OUT:-$ROOT/target/live-firecracker}"

KERNEL="$CACHE/vmlinux"
ROOTFS="$CACHE/ubuntu-24.04.ext4"
OPEN_PORT=1235
CLOSED_PORT=1236

tool() { echo "live-firecracker: $*" >&2; }
die() { tool "$*"; exit 2; }

fc_bin() {
  if command -v firecracker >/dev/null; then command -v firecracker
  elif [[ -x "$CACHE/bin/firecracker" ]]; then echo "$CACHE/bin/firecracker"
  else return 1; fi
}

# Prints a reason when this box cannot run the fixture; prints nothing when
# it can. Callers test the OUTPUT for emptiness, not the exit status: every
# branch here ends in a successful echo, so status says nothing.
unavailable() {
  [[ -e /dev/kvm ]] || { echo "/dev/kvm absent"; return; }
  [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm not read/writable (setup --system)"; return; }
  fc_bin >/dev/null || { echo "firecracker not found (setup)"; return; }
  [[ -s "$KERNEL" ]] || { echo "guest kernel not cached (setup)"; return; }
  [[ -s "$ROOTFS" ]] || { echo "guest rootfs not cached (setup)"; return; }
}

fetch() { # url dest
  [[ -s "$2" ]] && return
  mkdir -p "$(dirname "$2")"
  curl -fsSL -o "$2.part" "$1" && mv "$2.part" "$2"
}

cmd_setup() {
  local system=0
  [[ "${2:-}" == --system ]] && system=1
  if ! fc_bin >/dev/null; then
    tool "fetching firecracker $FC_VERSION"
    mkdir -p "$CACHE/bin"
    curl -fsSL "$FC_URL" | tar -xz -C "$CACHE" "release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64"
    mv "$CACHE/release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64" "$CACHE/bin/firecracker"
    rmdir "$CACHE/release-${FC_VERSION}-x86_64"
  fi
  fetch "$FC_KERNEL_URL" "$KERNEL"
  if [[ ! -s "$ROOTFS" ]]; then
    command -v unsquashfs >/dev/null || die "unsquashfs missing (apt-get install squashfs-tools)"
    command -v mkfs.ext4 >/dev/null || die "mkfs.ext4 missing (apt-get install e2fsprogs)"
    tool "fetching ubuntu-24.04 rootfs (one-time conversion)"
    local dir="$CACHE/rootfs-dir" squash="$CACHE/ubuntu-24.04.squashfs" mb
    fetch "$FC_ROOTFS_SQUASH" "$squash"
    rm -rf "$dir" "$ROOTFS.part"
    unsquashfs -no-xattrs -d "$dir" "$squash" >/dev/null
    # mke2fs -d populates from the directory: no loop device, no root.
    # 20% slack plus 128M for the guest's writes; the file stays sparse.
    mb=$(du -sx --block-size=1M "$dir" | cut -f1)
    truncate -s "$(( mb * 12 / 10 + 128 ))M" "$ROOTFS.part"
    mkfs.ext4 -q -d "$dir" "$ROOTFS.part"
    mv "$ROOTFS.part" "$ROOTFS"
    rm -rf "$dir"
  fi
  if (( system )) && [[ -e /dev/kvm && ! -w /dev/kvm ]]; then
    sudo chmod 666 /dev/kvm
  fi
  tool "ready"
}

# Guest PID 1 (dash, reading /dev/vdb): mount what it needs, pull the scanner
# off the binary drive, hold an AF_VSOCK listener on $OPEN_PORT, idle. The
# markers land on the serial console, which the host tails.
guest_script() { # $1: binary size
  cat <<EOF
mount -t proc proc /proc
mount -t sysfs sys /sys
grep -q vsock /proc/misc && echo VSOCKSCAN_LIVE_VSOCK_REGISTERED || echo VSOCKSCAN_LIVE_VSOCK_MISSING
head -c $1 /dev/vdc > /bin/vsockscan
chmod 755 /bin/vsockscan
/bin/vsockscan listen --ports $OPEN_PORT --forever >/dev/console 2>&1 &
echo VSOCKSCAN_LIVE_LISTENER_PID=\$!
echo VSOCKSCAN_LIVE_READY
while :; do sleep 1; done
EOF
}

report_console_tail() {
  tool "console tail:"
  tail -n 40 "$WORK/console.log" >&2 2>/dev/null || true
}

cmd_run() {
  local skip_unavailable=0
  [[ "${2:-}" == --skip-unavailable ]] && skip_unavailable=1
  local why
  why=$(unavailable)
  if [[ -n "$why" ]]; then
    if (( skip_unavailable )); then
      tool "skipped: $why"
      exit 0
    fi
    echo "unavailable: $why" >&2
    exit 3
  fi

  # Unset BIN => build the working tree, so the fixture always tests the
  # latest code (cargo's no-op rebuild is sub-second).
  if [[ -z "${BIN:-}" ]]; then
    (cd "$ROOT" && cargo build --release --target x86_64-unknown-linux-musl >/dev/null)
    BIN="$ROOT/target/x86_64-unknown-linux-musl/release/vsockscan"
  fi
  [[ -x "$BIN" ]] || die "BIN=$BIN is not executable"

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/vsockscan-fc.XXXXXX")"
  local fc_pid=""
  cleanup() {
    if [[ -n "$fc_pid" ]]; then
      kill "$fc_pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$fc_pid" 2>/dev/null || true
    fi
    if [[ "${KEEP:-0}" == 1 ]]; then tool "work dir kept: $WORK"; else rm -rf "$WORK"; fi
  }
  trap cleanup EXIT

  mkdir -p "$WORK/vsockdir"
  cp --reflink=auto "$ROOTFS" "$WORK/rootfs.ext4"
  local size
  size=$(stat -c %s "$BIN")
  cp "$BIN" "$WORK/bin.img"
  truncate -s $(( (size + 511) / 512 * 512 )) "$WORK/bin.img"
  guest_script "$size" >"$WORK/init.sh"
  # Pad the script drive to a sector with newlines: the guest shell never
  # parses NUL bytes.
  while (( $(stat -c %s "$WORK/init.sh") % 512 )); do echo >>"$WORK/init.sh"; done

  cat >"$WORK/vm.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off rw init=/bin/sh -- /dev/vdb"
  },
  "drives": [
    {"drive_id": "rootfs", "path_on_host": "$WORK/rootfs.ext4", "is_root_device": true, "is_read_only": false},
    {"drive_id": "script", "path_on_host": "$WORK/init.sh", "is_root_device": false, "is_read_only": true},
    {"drive_id": "binary", "path_on_host": "$WORK/bin.img", "is_root_device": false, "is_read_only": true}
  ],
  "machine-config": {"vcpu_count": 1, "mem_size_mib": 512},
  "vsock": {"guest_cid": 3, "uds_path": "$WORK/vsockdir/vsock"}
}
EOF

  tool "booting microVM (kernel $(basename "$KERNEL"), guest CID 3)"
  "$(fc_bin)" --no-api --api-sock "$WORK/fc.sock" --config-file "$WORK/vm.json" \
    >"$WORK/console.log" 2>&1 </dev/null &
  fc_pid=$!

  local waited=0 # half-second ticks
  until grep -aq VSOCKSCAN_LIVE_READY "$WORK/console.log" 2>/dev/null; do
    kill -0 "$fc_pid" 2>/dev/null || { report_console_tail; die "firecracker exited before the listener was ready"; }
    (( waited >= FC_TIMEOUT * 2 )) && { report_console_tail; die "listener not ready within ${FC_TIMEOUT}s"; }
    sleep 0.5
    waited=$(( waited + 1 ))
  done
  [[ -S "$WORK/vsockdir/vsock" ]] || die "ready marker but no muxer socket at $WORK/vsockdir/vsock"
  tool "guest listener up on port $OPEN_PORT; sweeping through the muxer"

  local uds="$WORK/vsockdir/vsock" pass=0 fail=0
  check() { # name, then the command that must succeed
    local name="$1"; shift
    if "$@"; then
      tool "ok   $name"; pass=$(( pass + 1 ))
    else
      tool "FAIL $name"; fail=$(( fail + 1 ))
    fi
  }

  # 1. The handshake taxonomy against the real muxer, in JSON: the open row
  # must carry a host port from the stock 2^30 pool, the closed row must be
  # closed without an errno (the muxer answered, the guest refused), and the
  # summary must count both.
  check "open/closed through the real muxer" env BIN="$BIN" UDS="$uds" OP="$OPEN_PORT" CP="$CLOSED_PORT" python3 - <<'PYEOF'
import json, os, subprocess
b, uds = os.environ["BIN"], os.environ["UDS"]
op, cp = os.environ["OP"], os.environ["CP"]
out = subprocess.run([b, "h2g", "--uds", uds, "--ports", f"{op},{cp}", "--timeout", "5",
                      "--format", "json", "--no-color"], capture_output=True, text=True)
assert out.returncode == 0, f"exit {out.returncode}: {out.stderr}"
d = json.loads(out.stdout)
rows = {r["name"]: r for r in d["probes"]}
row = rows[f"connect:{op}"]
assert row["outcome"]["kind"] == "open", row
port = int(row["value"].split()[-1])
assert port >= 2 ** 30, f"not the stock muxer pool: {row['value']}"
refused = rows[f"connect:{cp}"]
assert refused["outcome"]["kind"] == "closed", refused
assert refused["outcome"]["errno"] is None, "closed with an errno: the muxer never answered"
assert d["summary"]["by-outcome"] == {"closed": 1, "open": 1}, d["summary"]
assert d["summary"]["results"] == 2, d["summary"]
PYEOF

  # 2. --open keeps only the answered port and counts the sweep honestly.
  # shellcheck disable=SC2016  # the body runs in bash after env, not here.
  check "--open keeps one row of two" env BIN="$BIN" UDS="$uds" OP="$OPEN_PORT" CP="$CLOSED_PORT" bash -c '
    out=$("$BIN" h2g --uds "$UDS" --ports "$OP,$CP" --timeout 5 --open --no-color)
    grep -q "connect:$OP" <<<"$out" || { echo "open row missing:"; echo "$out"; exit 1; }
    if grep -q "connect:$CP" <<<"$out"; then echo "closed row survived --open:"; echo "$out"; exit 1; fi
    grep -q "showing 1 open row(s) of 2" <<<"$out" || { echo "--open note missing:"; echo "$out"; exit 1; }
  '

  # 3. A path with no socket is a filesystem answer, not a guest failure:
  # ENOENT (nothing there) and ENOTDIR (a walk through the live socket
  # file, the classic jailer mix-up) both read `absent`, and both abort
  # before any CONNECT reaches the muxer.
  # shellcheck disable=SC2016  # the body runs in bash after env, not here.
  check "missing socket path reports absent with exit 2" env BIN="$BIN" WD="$WORK" bash -c '
    set +e
    err=$("$BIN" h2g --uds "$WD/nope.sock" --ports 1 --timeout 5 --no-color 2>&1 >/dev/null)
    code=$?
    set -e
    [[ $code -eq 2 ]] || { echo "exit $code, want 2"; exit 1; }
    grep -q absent <<<"$err" || { echo "taxonomy word missing: $err"; exit 1; }
  '

  # shellcheck disable=SC2016  # the body runs in bash after env, not here.
  check "path through the socket file reports absent with exit 2" env BIN="$BIN" UDS="$uds" bash -c '
    set +e
    err=$("$BIN" h2g --uds "$UDS/nope.sock" --ports 1 --timeout 5 --no-color 2>&1 >/dev/null)
    code=$?
    set -e
    [[ $code -eq 2 ]] || { echo "exit $code, want 2"; exit 1; }
    grep -q absent <<<"$err" || { echo "taxonomy word missing: $err"; exit 1; }
  '

  mkdir -p "$OUT"
  cp "$WORK/console.log" "$OUT/console.log" 2>/dev/null || true
  if (( fail )); then
    report_console_tail
    die "$fail of $(( pass + fail )) muxer checks failed ($pass passed)"
  fi
  tool "PASS: $pass/$(( pass + fail )) muxer checks (Firecracker $FC_VERSION, guest CID 3, uds handshake)"
}

case "${1:-}" in
  check)
    why=$(unavailable)
    if [[ -n "$why" ]]; then echo "unavailable: $why"; exit 3; fi
    echo available
    ;;
  setup) cmd_setup "$@" ;;
  run)   cmd_run "$@" ;;
  *)     die "usage: $0 check | setup [--system] | run [--skip-unavailable]" ;;
esac
