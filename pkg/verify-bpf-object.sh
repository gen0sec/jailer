#!/bin/sh
#
# Load a compiled BPF object into the running kernel and check it carries every
# LSM program the loaders will try to attach.
#
# Two callers, deliberately:
#
#   - wellness-check.yml, on the object the workspace just built. That is what
#     keeps this script honest: it runs on every pull request, so a mistake here
#     surfaces immediately rather than the first time someone cuts a release.
#   - release.yaml, on the object inside the tarball that is about to ship.
#
# The release one is the reason this exists. The unit and integration jobs
# compile their own object with the *runner's* clang; the release container uses
# clang-18 on focal. Nothing else ever loads the bytecode that is published, so
# a program the verifier refuses would surface first on an operator's host.
#
# Programs are loaded and not attached. Attaching additionally needs `bpf` in
# the active LSM list, which CI runners do not have -- but loading is what
# exercises the verifier, and it is what the root integration tests do too.
#
# Usage: sudo pkg/verify-bpf-object.sh <bpfjailer.bpf.o> [programs.rs]

set -eu

OBJ=${1:?usage: verify-bpf-object.sh <bpfjailer.bpf.o> [programs.rs]}
PROGRAMS_RS=${2:-bpfjailer-common/src/programs.rs}
PIN_DIR=/sys/fs/bpf/bpfjailer-verify

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root"
[ -f "$OBJ" ] || die "no such object: $OBJ"
[ -f "$PROGRAMS_RS" ] || die "no such file: $PROGRAMS_RS"

# Finding a working bpftool is not `command -v bpftool`.
#
# On Ubuntu, /usr/sbin/bpftool is a wrapper from linux-tools-common that execs
# /usr/lib/linux-tools/$(uname -r)/bpftool and, failing that, exits 2 with a
# hint about which package to install. It has no generic fallback -- so on a
# cloud runner, whose kernel flavour never matches what linux-tools-generic
# provides, the wrapper is on PATH and does not work.
#
# The binary itself is userspace talking to the bpf syscall; it is not coupled
# to the running kernel. Any installed build will do.
BPFTOOL=${BPFTOOL:-}
if [ -z "$BPFTOOL" ]; then
  if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
    BPFTOOL=bpftool
  else
    BPFTOOL=$(find /usr/lib/linux-tools -name bpftool -type f 2>/dev/null | head -1)
  fi
fi
if [ -z "$BPFTOOL" ] || ! "$BPFTOOL" version >/dev/null 2>&1; then
  die "no working bpftool (install linux-tools-generic, or set BPFTOOL)"
fi

# The one list both loaders attach from, read from the source rather than
# restated here -- the same reason programs.rs derives its own expectations
# from main.bpf.c instead of hardcoding them.
EXPECTED=$(sed -n '/LSM_PROGRAMS/,/^];/p' "$PROGRAMS_RS" | grep -oE '"[a-z_]+"' | tr -d '"')
[ -n "$EXPECTED" ] || die "could not read LSM_PROGRAMS out of $PROGRAMS_RS"

echo "== kernel =="
uname -r
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "BTF: present"
else
  die "no /sys/kernel/btf/vmlinux; CO-RE relocations cannot resolve"
fi

mountpoint -q /sys/fs/bpf 2>/dev/null || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
rm -rf "$PIN_DIR"
# shellcheck disable=SC2064
trap "rm -rf '$PIN_DIR'" EXIT

echo "== loading $OBJ with $BPFTOOL =="
"$BPFTOOL" prog loadall "$OBJ" "$PIN_DIR"

echo "== checking every LSM program is present =="
missing=""
for p in $EXPECTED; do
  [ -e "${PIN_DIR}/${p}" ] || missing="${missing} ${p}"
done

if [ -n "$missing" ]; then
  echo "pinned:"; find "$PIN_DIR" -maxdepth 1 -mindepth 1 -printf "  %f\\n"
  die "the object loaded but does not carry:${missing} -- whatever those \
programs enforce would be silently unenforced"
fi

count=$(echo "$EXPECTED" | wc -l)
echo "ok: loaded and all ${count} LSM programs present"
