#!/bin/sh
#
# Install BpfJailer from a published release.
#
# The version below is owned by `cargo release` (see release.toml) -- do not
# edit it by hand, or the script will fetch a release that does not match the
# tree it was committed from.

VERSION=0.1.1
REPO=gen0sec/jailer
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

set -eu

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "must run as root"

case "$(uname -m)" in
  x86_64|amd64)   ARCH=x86_64 ;;
  aarch64|arm64)  ARCH=aarch64 ;;
  *) die "unsupported architecture: $(uname -m) (releases are built for x86_64 and aarch64)" ;;
esac

TARBALL="bpfjailer-${VERSION}-${ARCH}-linux-gnu.tar.gz"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "== downloading ${TARBALL} =="
curl -fsSL "${BASE_URL}/${TARBALL}"        -o "${WORK}/${TARBALL}"
curl -fsSL "${BASE_URL}/${TARBALL}.sha256" -o "${WORK}/${TARBALL}.sha256"

echo "== verifying checksum =="
# The published .sha256 carries the path the release job hashed, which is not
# where the file is now; compare the digests rather than the whole line.
want=$(cut -d' ' -f1 < "${WORK}/${TARBALL}.sha256")
got=$(sha256sum "${WORK}/${TARBALL}" | cut -d' ' -f1)
[ "$want" = "$got" ] || die "checksum mismatch: expected $want, got $got"
echo "sha256 ok"

# Signature verification is only meaningful against a key you already trust.
# Fetching the signing key from the same release that carries the artifact
# would prove nothing, so this verifies only if the key is already in your
# keyring, and says plainly when it is not.
if command -v gpg >/dev/null 2>&1 &&
   curl -fsSL "${BASE_URL}/${TARBALL}.asc" -o "${WORK}/${TARBALL}.asc" 2>/dev/null; then
  if gpg --verify "${WORK}/${TARBALL}.asc" "${WORK}/${TARBALL}" 2>/dev/null; then
    echo "gpg signature ok"
  else
    echo "note: the signature could not be verified against your keyring."
    echo "      Import the release key first to check provenance:"
    echo "        curl -fsSL ${BASE_URL}/bpfjailer-signing-key.asc | gpg --import"
  fi
fi

echo "== installing =="
tar xzf "${WORK}/${TARBALL}" -C "${WORK}"
SRC="${WORK}/bpfjailer-${VERSION}-${ARCH}-linux-gnu"

install -Dm0755 "${SRC}/bpfjailer-bootstrap" /usr/sbin/bpfjailer-bootstrap
install -Dm0755 "${SRC}/bpfjailer-daemon"    /usr/sbin/bpfjailer-daemon
install -Dm0644 "${SRC}/bpfjailer.bpf.o"     /usr/lib/bpfjailer/bpfjailer.bpf.o
install -Dm0644 "${SRC}/bpfjailer-bootstrap.service" \
                /etc/systemd/system/bpfjailer-bootstrap.service
install -Dm0644 "${SRC}/bpfjailer-daemon.service" \
                /etc/systemd/system/bpfjailer-daemon.service

# Never overwrite a policy in place: it is the operator's, and replacing it
# would silently change what is enforced.
if [ -f /etc/bpfjailer/policy.json ]; then
  install -Dm0644 "${SRC}/policy.json" /etc/bpfjailer/policy.json.example
  echo "kept your /etc/bpfjailer/policy.json; the shipped example is at policy.json.example"
else
  install -Dm0644 "${SRC}/policy.json" /etc/bpfjailer/policy.json
fi

command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload

echo
echo "installed $(/usr/sbin/bpfjailer-bootstrap --version)"
echo
echo "BpfJailer needs the BPF LSM active. Check with:"
echo "  cat /sys/kernel/security/lsm     # must list 'bpf'"
echo "If it does not, add 'lsm=...,bpf' to the kernel command line and reboot."
echo
echo "Then enable one mode -- not both, they load the same programs:"
echo "  systemctl enable --now bpfjailer-daemon      # daemon mode"
echo "  systemctl enable bpfjailer-bootstrap         # daemonless, runs at boot"
