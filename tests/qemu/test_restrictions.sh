#!/bin/bash
# Test BpfJailer restriction enforcement in QEMU VM

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="/var/lib/libvirt/images/bpfjailer-test"
VM_NAME="bpfjailer-test"

echo "=== BpfJailer Restriction Enforcement Test ==="

# Check VM
if ! virsh dominfo ${VM_NAME} &>/dev/null; then
    echo "Error: VM not defined. Run ./setup_vm.sh first"
    exit 1
fi

# Copy binaries
echo "[1/5] Copying binaries..."
BOOTSTRAP_BIN="${SCRIPT_DIR}/../../target/release/bpfjailer-bootstrap"
BPF_OBJ="${SCRIPT_DIR}/../../bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"

if [ ! -f "$BOOTSTRAP_BIN" ] || [ ! -f "$BPF_OBJ" ]; then
    echo "Error: Build binaries first"
    exit 1
fi

mkdir -p "${VM_DIR}/share"
cp "$BOOTSTRAP_BIN" "${VM_DIR}/share/"
cp "$BPF_OBJ" "${VM_DIR}/share/"

# Create restrictive test policy
cat > "${VM_DIR}/share/restriction_policy.json" << 'POLICY'
{
  "roles": {
    "unrestricted": {
      "id": 1,
      "name": "unrestricted",
      "flags": {
        "allow_file_access": true,
        "allow_network": true,
        "allow_exec": true,
        "require_signed_binary": false,
        "allow_setuid": true,
        "allow_ptrace": false
      },
      "file_paths": [],
      "network_rules": [],
      "execution_rules": [],
      "require_signed_binary": false
    },
    "no_network": {
      "id": 2,
      "name": "no_network",
      "flags": {
        "allow_file_access": true,
        "allow_network": false,
        "allow_exec": true,
        "require_signed_binary": false,
        "allow_setuid": true,
        "allow_ptrace": false
      },
      "file_paths": [],
      "network_rules": [],
      "execution_rules": [],
      "require_signed_binary": false
    },
    "no_exec": {
      "id": 3,
      "name": "no_exec",
      "flags": {
        "allow_file_access": true,
        "allow_network": true,
        "allow_exec": false,
        "require_signed_binary": false,
        "allow_setuid": true,
        "allow_ptrace": false
      },
      "file_paths": [],
      "network_rules": [],
      "execution_rules": [],
      "require_signed_binary": false
    },
    "sandbox": {
      "id": 4,
      "name": "sandbox",
      "flags": {
        "allow_file_access": true,
        "allow_network": false,
        "allow_exec": false,
        "require_signed_binary": false,
        "allow_setuid": true,
        "allow_ptrace": false
      },
      "file_paths": [
        {"pattern": "/tmp/allowed/", "allow": true},
        {"pattern": "/tmp/blocked/", "allow": false},
        {"pattern": "/etc/passwd", "allow": false}
      ],
      "network_rules": [],
      "execution_rules": [],
      "require_signed_binary": false
    }
  },
  "pods": [],
  "exec_enrollments": [
    {"executable_path": "/usr/bin/curl", "pod_id": 100, "role": "no_network"},
    {"executable_path": "/usr/bin/wget", "pod_id": 101, "role": "no_network"},
    {"executable_path": "/usr/bin/python3", "pod_id": 102, "role": "sandbox"}
  ],
  "cgroup_enrollments": []
}
POLICY

# Create test script to run inside VM
cat > "${VM_DIR}/share/run_restriction_tests.sh" << 'TESTSCRIPT'
#!/bin/bash
echo "=== Restriction Enforcement Tests ==="

# Check BPF LSM
echo ""
echo "[Check] BPF LSM status:"
LSM=$(cat /sys/kernel/security/lsm)
echo "  $LSM"
if ! echo "$LSM" | grep -q bpf; then
    echo "  ERROR: BPF LSM not enabled - restrictions won't be enforced!"
    echo "  Tests will show expected behavior but won't actually block."
    BPF_ENABLED=0
else
    echo "  OK: BPF LSM is active"
    BPF_ENABLED=1
fi

PASS=0
FAIL=0

test_result() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" = "$actual" ]; then
        echo "  PASS: $name"
        ((PASS++))
    else
        echo "  FAIL: $name (expected: $expected, got: $actual)"
        ((FAIL++))
    fi
}

echo ""
echo "=== Test 1: Network Restriction (curl enrolled as no_network) ==="
echo "  curl is enrolled with role_id=2 (no_network)"
echo "  Attempting to connect to localhost..."

# Start a simple HTTP server
python3 -m http.server 8080 &>/dev/null &
HTTP_PID=$!
sleep 1

# Test curl (should be blocked if BPF LSM active)
if timeout 3 curl -s http://127.0.0.1:8080/ &>/dev/null; then
    CURL_RESULT="allowed"
else
    CURL_RESULT="blocked"
fi

kill $HTTP_PID 2>/dev/null || true

if [ "$BPF_ENABLED" = "1" ]; then
    test_result "curl network access" "blocked" "$CURL_RESULT"
else
    echo "  Result: $CURL_RESULT (BPF LSM disabled, can't enforce)"
fi

echo ""
echo "=== Test 2: Exec Restriction (python3 enrolled as sandbox/no_exec) ==="
echo "  python3 is enrolled with role_id=4 (sandbox, no exec)"
echo "  Attempting to spawn subprocess..."

# Test python exec (should be blocked)
EXEC_OUTPUT=$(python3 -c "
import subprocess
import sys
try:
    result = subprocess.run(['echo', 'hello'], capture_output=True, timeout=2)
    print('allowed')
except Exception as e:
    print('blocked')
" 2>/dev/null || echo "blocked")

if [ "$BPF_ENABLED" = "1" ]; then
    test_result "python3 exec" "blocked" "$EXEC_OUTPUT"
else
    echo "  Result: $EXEC_OUTPUT (BPF LSM disabled, can't enforce)"
fi

echo ""
echo "=== Test 3: File Path Restriction (python3 sandbox role) ==="
echo "  sandbox role allows /tmp/allowed/, blocks /tmp/blocked/"

# Setup test directories
mkdir -p /tmp/allowed /tmp/blocked
echo "secret" > /tmp/allowed/test.txt
echo "secret" > /tmp/blocked/test.txt

# Test allowed path
ALLOWED_READ=$(python3 -c "
try:
    with open('/tmp/allowed/test.txt') as f:
        print('allowed')
except:
    print('blocked')
" 2>/dev/null || echo "error")

# Test blocked path
BLOCKED_READ=$(python3 -c "
try:
    with open('/tmp/blocked/test.txt') as f:
        print('allowed')
except:
    print('blocked')
" 2>/dev/null || echo "error")

if [ "$BPF_ENABLED" = "1" ]; then
    test_result "read /tmp/allowed/" "allowed" "$ALLOWED_READ"
    test_result "read /tmp/blocked/" "blocked" "$BLOCKED_READ"
else
    echo "  /tmp/allowed/: $ALLOWED_READ"
    echo "  /tmp/blocked/: $BLOCKED_READ"
    echo "  (BPF LSM disabled, can't enforce path rules)"
fi

echo ""
echo "=== Test 4: Sensitive File Protection ==="
echo "  sandbox role blocks /etc/passwd"

PASSWD_READ=$(python3 -c "
try:
    with open('/etc/passwd') as f:
        f.read(10)
        print('allowed')
except:
    print('blocked')
" 2>/dev/null || echo "error")

if [ "$BPF_ENABLED" = "1" ]; then
    test_result "read /etc/passwd" "blocked" "$PASSWD_READ"
else
    echo "  /etc/passwd: $PASSWD_READ (BPF LSM disabled)"
fi

echo ""
echo "=== Test 5: Non-enrolled process (bash) ==="
echo "  Unenrolled processes should not be restricted"

# bash is not enrolled, should work normally
BASH_CURL=$(timeout 3 bash -c 'curl -s http://127.0.0.1:8080/ &>/dev/null && echo allowed || echo blocked' 2>/dev/null || echo "blocked")
BASH_FILE=$(bash -c 'cat /etc/passwd > /dev/null 2>&1 && echo allowed || echo blocked')

echo "  bash curl: $BASH_CURL (expected: allowed or blocked depending on server)"
echo "  bash file: $BASH_FILE (expected: allowed)"

# Cleanup
rm -rf /tmp/allowed /tmp/blocked

echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ "$BPF_ENABLED" = "0" ]; then
    echo ""
    echo "NOTE: BPF LSM was not enabled."
    echo "To enable, ensure kernel boots with: lsm=...bpf"
    echo "Then reboot the VM."
fi

exit $FAIL
TESTSCRIPT
chmod +x "${VM_DIR}/share/run_restriction_tests.sh"

# Stop if running
virsh destroy ${VM_NAME} 2>/dev/null || true
sleep 2

echo "[2/5] Starting VM..."
virsh start ${VM_NAME}

# Wait for IP
echo "[3/5] Waiting for VM..."
IP=""
for i in {1..90}; do
    IP=$(virsh domifaddr ${VM_NAME} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    [ -n "$IP" ] && break
    sleep 2
done

[ -z "$IP" ] && { echo "Error: No IP"; exit 1; }
echo "  VM IP: $IP"

# Wait for SSH
echo "[4/5] Waiting for SSH..."
for i in {1..30}; do
    sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 ubuntu@${IP} true 2>/dev/null && break
    sleep 2
done

# Run tests
echo "[5/5] Running restriction tests..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@${IP} << 'REMOTE'
# Mount share
sudo mkdir -p /mnt/share
sudo mount -t 9p -o trans=virtio share /mnt/share 2>/dev/null || true

# Install deps
echo "Installing dependencies..."
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq curl python3 2>/dev/null

# Install bpfjailer
sudo mkdir -p /usr/lib/bpfjailer /usr/sbin /etc/bpfjailer
sudo cp /mnt/share/bpfjailer-bootstrap /usr/sbin/
sudo cp /mnt/share/bpfjailer.bpf.o /usr/lib/bpfjailer/
sudo cp /mnt/share/restriction_policy.json /etc/bpfjailer/policy.json
sudo chmod +x /usr/sbin/bpfjailer-bootstrap

# Run bootstrap
echo ""
echo "Running bpfjailer-bootstrap..."
sudo RUST_LOG=info /usr/sbin/bpfjailer-bootstrap 2>&1 | grep -E "INFO|enroll" | head -15

# Run restriction tests
echo ""
sudo /mnt/share/run_restriction_tests.sh
REMOTE

RESULT=$?

echo ""
if [ $RESULT -eq 0 ]; then
    echo "All restriction tests passed!"
else
    echo "Some tests failed (exit code: $RESULT)"
fi

echo ""
echo "VM still running. Commands:"
echo "  sshpass -p ubuntu ssh ubuntu@${IP}"
echo "  virsh destroy ${VM_NAME}"

exit $RESULT
