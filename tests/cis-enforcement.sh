#!/bin/bash
# cis-enforcement.sh -- prove the cis_* roles are ENFORCED, not just encoded.
#
#   ./tests/cis-enforcement.sh --target ssh://root@127.0.0.1:2401 --key ~/.ssh/id_test
#
# The unit tests in bpfjailer-common walk the path rules through a Rust model of
# check_path_state_machine. That proves the rules ENCODE to the decisions
# claimed. It cannot prove the kernel agrees, because the model and the BPF
# program could be wrong in the same direction -- and the CI root job loads the
# object without attaching it, since attaching needs `bpf` in the LSM list.
#
# This is the missing half. It needs a host whose kernel has:
#
#   cat /sys/kernel/security/lsm     # must contain "bpf"
#
# On a Ubuntu cloud image, note that /etc/default/grub.d/50-cloudimg-settings.cfg
# is sourced AFTER /etc/default/grub and overrides GRUB_CMDLINE_LINUX_DEFAULT,
# so an lsm= line added to the latter is silently discarded. Put it in a
# drop-in that sorts later.
#
# Every assertion below has a control. A role that denied everything, or a file
# that was unreadable anyway, would otherwise look exactly like enforcement.
set -uo pipefail

TARGET=""; KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --key)    KEY="$2"; shift 2 ;;
    *) echo "usage: $0 --target ssh://root@HOST:PORT --key PATH" >&2; exit 2 ;;
  esac
done
[ -n "$TARGET" ] && [ -n "$KEY" ] || { echo "usage: $0 --target ssh://root@HOST:PORT --key PATH" >&2; exit 2; }

rest=${TARGET#ssh://}; user=${rest%%@*}; hostport=${rest#*@}
host=${hostport%%:*}; port=${hostport##*:}; [ "$port" = "$host" ] && port=22

SSH="ssh -i $KEY -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes $user@$host"

pass=0; fail=0
ok(){  pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad(){ fail=$((fail+1)); printf '  FAIL %s\n       %s\n' "$1" "${2:-}"; }
phase(){ echo; echo "=================== $1 ==================="; }
q(){ $SSH "$@" 2>/dev/null; }

# Runs a command in the guest and reports "allowed" or "denied" by exit status.
verdict(){ q "$1 >/dev/null 2>&1 && echo allowed || echo denied"; }

phase "preconditions"
q true || { echo "error: cannot reach $TARGET" >&2; exit 1; }
LSM=$(q 'cat /sys/kernel/security/lsm')
case "$LSM" in
  *bpf*) ok "BPF LSM active ($LSM)" ;;
  *) bad "BPF LSM active" "lsm=[$LSM] -- programs cannot attach, nothing below means anything"; exit 1 ;;
esac
[ "$(q 'pgrep -c -f /usr/sbin/bpfjailer-daemon')" -ge 1 ] \
  && ok "a jailer is running" || { bad "a jailer is running" "start the daemon first"; exit 1; }

# The guest must have a binary enrolled in cis_service and one in cis_isolated.
# Enrolment is the deploying system's business, so this asserts rather than
# performs it -- see docs/cis-mapping.md.
for b in /usr/local/bin/jailed-cat /usr/local/bin/isolated-python; do
  q "test -x $b" || { bad "$b present" "enrol it first (exec_enrollments)"; exit 1; }
done
ok "test binaries present and enrolled"

phase "the deny set is enforced"
# Each path is one the mapping document claims these roles deny.
for p in /etc/shadow /etc/gshadow /root/.bashrc /etc/ssh/sshd_config /etc/sudoers; do
  v=$(verdict "/usr/local/bin/jailed-cat $p")
  [ "$v" = denied ] && ok "enrolled: $p denied" || bad "enrolled: $p denied" "got $v"
done

phase "control A -- the denial comes from the role, not the file mode"
# The same files, read by a process that is NOT enrolled, as the same uid.
# Without this, a file that root could not read anyway would look like
# enforcement.
for p in /etc/shadow /root/.bashrc; do
  v=$(verdict "/bin/cat $p")
  [ "$v" = allowed ] && ok "not enrolled: $p allowed" \
    || bad "not enrolled: $p allowed" "got $v -- the deny may be DAC, not the jailer"
done

phase "control B -- the role is not simply denying everything"
for p in /etc/hostname /etc/passwd; do
  v=$(verdict "/usr/local/bin/jailed-cat $p")
  [ "$v" = allowed ] && ok "enrolled: $p allowed" || bad "enrolled: $p allowed" "got $v"
done

phase "documented limits -- these SHOULD hold, and are not defects"
# A path deeper than MAX_COMPONENTS reports no rule, which for a role granting
# allow_file_access reads as allowed. Asserted so the documentation cannot
# quietly stop being true.
q 'mkdir -p /root/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/d12/d13/d14/d15/d16 &&
   echo deep > /root/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/d12/d13/d14/d15/d16/secret'
v=$(verdict "/usr/local/bin/jailed-cat /root/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/d11/d12/d13/d14/d15/d16/secret")
[ "$v" = allowed ] && ok "a path too deep to walk escapes the deny (documented)" \
  || bad "deep-path escape" "got $v -- docs/cis-mapping.md says this escapes"

q 'rm -f /var/tmp/shadow-link; ln /etc/shadow /var/tmp/shadow-link'
v=$(verdict "/usr/local/bin/jailed-cat /var/tmp/shadow-link")
[ "$v" = allowed ] && ok "a hard link defeats a path deny (documented)" \
  || bad "hard-link bypass" "got $v -- docs/cis-mapping.md says this bypasses"

phase "allow_network: false denies AF_UNIX too"
q 'cat > /var/tmp/unixprobe.py <<PY
import socket, os
p = "/var/tmp/u.%d" % os.getpid()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(p); s.close(); os.unlink(p)
PY'
v=$(verdict "/usr/local/bin/isolated-python /var/tmp/unixprobe.py")
[ "$v" = denied ] && ok "cis_isolated: AF_UNIX bind denied" || bad "cis_isolated: AF_UNIX denied" "got $v"
v=$(verdict "python3 /var/tmp/unixprobe.py")
[ "$v" = allowed ] && ok "not enrolled: AF_UNIX bind allowed" || bad "control: AF_UNIX allowed" "got $v"

phase "CIS 3.4.x -- module autoload is denied"
# Must run against a protocol whose module is NOT loaded: if it is already in,
# no autoload is requested and the test proves nothing either way. Checked
# rather than assumed, because rmmod fails silently when the module is in use.
PROTO=""
for m in sctp rds tipc; do
  [ "$(q "lsmod | grep -c '^$m '")" = "0" ] && { PROTO=$m; break; }
done
if [ -z "$PROTO" ]; then
  bad "an unloaded protocol module to test with" "sctp, rds and tipc are all loaded; reboot the target"
else
  ok "testing with $PROTO (not currently loaded)"
  case "$PROTO" in
    sctp) fam="socket.AF_INET, socket.SOCK_STREAM, 132" ;;
    rds)  fam="21, socket.SOCK_SEQPACKET, 0" ;;
    tipc) fam="30, socket.SOCK_STREAM, 0" ;;
  esac
  q "cat > /var/tmp/modprobe.py <<PY
import socket
s = socket.socket($fam)
s.close()
PY"
  # Enrolled FIRST: the control would load the module and destroy the state.
  v=$(verdict "/usr/local/bin/isolated-python /var/tmp/modprobe.py")
  still=$(q "lsmod | grep -c '^$PROTO '")
  if [ "$v" = denied ] && [ "$still" = "0" ]; then
    ok "enrolled: $PROTO autoload denied and the module stayed out"
  else
    bad "enrolled: $PROTO autoload denied" "verdict=$v, loaded=$still"
  fi
  v=$(verdict "python3 /var/tmp/modprobe.py")
  [ "$v" = allowed ] && ok "not enrolled: $PROTO autoload succeeded (control)" \
    || bad "control: $PROTO autoload" "got $v"
fi

echo
if [ "$fail" -eq 0 ]; then echo "passed $pass, failed 0"; exit 0; fi
echo "passed $pass, failed $fail"; exit 1
