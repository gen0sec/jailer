#!/bin/bash
# Test Alternative Enrollments with nginx in QEMU VM

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="/var/lib/libvirt/images/bpfjailer-test"
VM_NAME="bpfjailer-test"

echo "=== BpfJailer Alternative Enrollment Test ==="

# Check VM is defined
if ! virsh dominfo ${VM_NAME} &>/dev/null; then
    echo "Error: VM not defined. Run ./setup_vm.sh first"
    exit 1
fi

# Copy binaries
echo "[1/5] Copying binaries..."
BOOTSTRAP_BIN="${SCRIPT_DIR}/../../target/release/bpfjailer-bootstrap"
BPF_OBJ="${SCRIPT_DIR}/../../bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"

if [ ! -f "$BOOTSTRAP_BIN" ] || [ ! -f "$BPF_OBJ" ]; then
    echo "Error: Build binaries first: cargo build -p bpfjailer-bootstrap --release"
    exit 1
fi

mkdir -p "${VM_DIR}/share"
cp "$BOOTSTRAP_BIN" "${VM_DIR}/share/"
cp "$BPF_OBJ" "${VM_DIR}/share/"

# Create test policy with exec enrollment for nginx
cat > "${VM_DIR}/share/enrollment_policy.json" << 'POLICY'
{
  "roles": {
    "restricted": {
      "id": 1,
      "name": "restricted",
      "flags": {
        "allow_file_access": false,
        "allow_network": false,
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
    "webserver": {
      "id": 3,
      "name": "webserver",
      "flags": {
        "allow_file_access": true,
        "allow_network": true,
        "allow_exec": false,
        "require_signed_binary": false,
        "allow_setuid": true,
        "allow_ptrace": false
      },
      "file_paths": [
        {"pattern": "/var/www/", "allow": true},
        {"pattern": "/etc/nginx/", "allow": true},
        {"pattern": "/var/log/nginx/", "allow": true},
        {"pattern": "/run/nginx/", "allow": true}
      ],
      "network_rules": [
        {"protocol": "tcp", "direction": "inbound", "port": 80, "allow": true},
        {"protocol": "tcp", "direction": "inbound", "port": 443, "allow": true}
      ],
      "execution_rules": [],
      "require_signed_binary": false
    }
  },
  "pods": [],
  "exec_enrollments": [
    {
      "executable_path": "/usr/sbin/nginx",
      "pod_id": 100,
      "role": "webserver"
    }
  ],
  "cgroup_enrollments": []
}
POLICY

# Stop if running, then start
virsh destroy ${VM_NAME} 2>/dev/null || true
sleep 2

echo "[2/5] Starting VM..."
virsh start ${VM_NAME}

# Wait for IP
echo "[3/5] Waiting for VM..."
IP=""
for i in {1..90}; do
    IP=$(virsh domifaddr ${VM_NAME} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    if [ -n "$IP" ]; then
        echo "  VM IP: $IP"
        break
    fi
    sleep 2
done

if [ -z "$IP" ]; then
    echo "Error: VM did not get IP"
    exit 1
fi

# Wait for SSH
echo "[4/5] Waiting for SSH..."
for i in {1..30}; do
    if sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 ubuntu@${IP} echo "ready" 2>/dev/null; then
        break
    fi
    sleep 2
done

# Run enrollment test
echo "[5/5] Running enrollment test..."
sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@${IP} << 'REMOTE'
set -e
echo "=== Inside VM: Alternative Enrollment Test ==="

# Mount share
sudo mkdir -p /mnt/share
sudo mount -t 9p -o trans=virtio share /mnt/share 2>/dev/null || true

# Install nginx
echo "[1] Installing nginx..."
sudo apt-get update -qq
sudo apt-get install -y -qq nginx > /dev/null

# Stop nginx for now
sudo systemctl stop nginx

# Install bpfjailer
echo "[2] Installing bpfjailer..."
sudo mkdir -p /usr/lib/bpfjailer /usr/sbin /etc/bpfjailer
sudo cp /mnt/share/bpfjailer-bootstrap /usr/sbin/
sudo cp /mnt/share/bpfjailer.bpf.o /usr/lib/bpfjailer/
sudo cp /mnt/share/enrollment_policy.json /etc/bpfjailer/policy.json
sudo chmod +x /usr/sbin/bpfjailer-bootstrap

# Check nginx inode
NGINX_INODE=$(stat -c %i /usr/sbin/nginx)
echo "  nginx inode: $NGINX_INODE"

# Check BPF LSM status
echo "[3] BPF LSM status:"
cat /sys/kernel/security/lsm
if ! grep -q bpf /sys/kernel/security/lsm; then
    echo "  WARNING: BPF LSM not enabled (enforcement won't work)"
fi

# Run bootstrap
echo "[4] Running bootstrap with exec enrollment..."
sudo RUST_LOG=info /usr/sbin/bpfjailer-bootstrap 2>&1 | grep -E "INFO|enrollment"

# Check if exec_enrollment map was populated
echo "[5] Checking exec_enrollment map..."
sudo bpftool map dump name exec_enrollment 2>/dev/null | head -20 || echo "  (map may be empty or not accessible)"

# Start nginx
echo "[6] Starting nginx..."
sudo systemctl start nginx
sleep 2

# Check nginx is running
if pgrep -x nginx > /dev/null; then
    echo "  nginx is running (PID: $(pgrep -x nginx | head -1))"
else
    echo "  ERROR: nginx failed to start"
    exit 1
fi

# Test nginx responds
echo "[7] Testing nginx..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost/ | grep -q 200; then
    echo "  nginx responds on port 80"
else
    echo "  WARNING: nginx not responding (may be blocked by policy)"
fi

# Check if nginx got enrolled (look in task_storage)
echo "[8] Checking enrollment status..."
NGINX_PID=$(pgrep -x nginx | head -1)
echo "  nginx master PID: $NGINX_PID"

# Show BPF programs
echo "[9] Loaded BPF programs:"
sudo bpftool prog list 2>/dev/null | grep -E "task_alloc|file_open|bprm" | head -5

echo ""
echo "=== Enrollment Test Complete ==="
echo "nginx should be auto-enrolled with role_id=3 (webserver)"
REMOTE

RESULT=$?

echo ""
echo "VM still running for manual inspection:"
echo "  sshpass -p ubuntu ssh ubuntu@${IP}"
echo "  virsh destroy ${VM_NAME}  # to stop"

exit $RESULT
