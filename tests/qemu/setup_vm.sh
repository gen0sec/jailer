#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="/var/lib/libvirt/images/bpfjailer-test"
VM_NAME="bpfjailer-test"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"

echo "=== BpfJailer Libvirt Test Setup ==="

# Check for libvirt
if ! command -v virsh &> /dev/null; then
    echo "Error: libvirt not installed. Run: apt-get install -y libvirt-daemon-system libvirt-clients virtinst"
    exit 1
fi

# Create VM directory
mkdir -p "${VM_DIR}"
cd "${VM_DIR}"

# Download Ubuntu 24.04 cloud image if not exists
if [ ! -f "${IMAGE_NAME}" ]; then
    echo "[1/6] Downloading Ubuntu 24.04 cloud image..."
    wget -q --show-progress "${IMAGE_URL}" -O "${IMAGE_NAME}"
else
    echo "[1/6] Ubuntu 24.04 image already exists, skipping download"
fi

# Create a larger disk for the VM
echo "[2/6] Creating VM disk (20GB)..."
rm -f vm-disk.qcow2
qemu-img create -f qcow2 -F qcow2 -b "${VM_DIR}/${IMAGE_NAME}" vm-disk.qcow2 20G

# Create cloud-init config
echo "[3/6] Creating cloud-init configuration..."
mkdir -p cloud-init

cat > cloud-init/meta-data << 'EOF'
instance-id: bpfjailer-test
local-hostname: bpfjailer-vm
EOF

cat > cloud-init/user-data << 'EOF'
#cloud-config
users:
  - default
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo, adm
    shell: /bin/bash
    lock_passwd: false

chpasswd:
  expire: false
  list:
    - ubuntu:ubuntu

ssh_pwauth: true
disable_root: false

bootcmd:
  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
  - echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu
  - chmod 440 /etc/sudoers.d/ubuntu

package_update: true
package_upgrade: false

packages:
  - build-essential
  - clang
  - llvm
  - libelf-dev
  - linux-headers-generic
  - bpftool
  - python3

write_files:
  - path: /etc/bpfjailer/policy.json
    permissions: '0644'
    content: |
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
          "permissive": {
            "id": 2,
            "name": "permissive",
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
          }
        },
        "pods": [],
        "exec_enrollments": [],
        "cgroup_enrollments": []
      }

  - path: /etc/systemd/system/bpfjailer-bootstrap.service
    permissions: '0644'
    content: |
      [Unit]
      Description=BpfJailer Bootstrap (Daemonless Mode)
      DefaultDependencies=no
      Before=basic.target
      After=local-fs.target
      ConditionPathExists=/etc/bpfjailer/policy.json

      [Service]
      Type=oneshot
      ExecStart=/usr/sbin/bpfjailer-bootstrap
      RemainAfterExit=yes
      StandardOutput=journal
      StandardError=journal

      [Install]
      WantedBy=sysinit.target

  - path: /home/ubuntu/test_bootstrap.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      echo "=== BpfJailer Bootstrap Test ==="
      echo "[1] BPF LSM status:"
      cat /sys/kernel/security/lsm
      echo "[2] Running bootstrap..."
      sudo RUST_LOG=info /usr/sbin/bpfjailer-bootstrap
      echo "[3] Pinned objects:"
      ls -la /sys/fs/bpf/bpfjailer/ 2>/dev/null || echo "None"
      echo "=== Done ==="

runcmd:
  - mkdir -p /etc/bpfjailer /sys/fs/bpf
  - mount -t bpf bpf /sys/fs/bpf || true
  - sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="lsm=lockdown,capability,landlock,yama,apparmor,bpf /' /etc/default/grub.d/50-cloudimg-settings.cfg
  - update-grub
  - reboot
EOF

# Generate cloud-init ISO
echo "[4/6] Generating cloud-init ISO..."
rm -f cloud-init.iso
cloud-localds cloud-init.iso cloud-init/user-data cloud-init/meta-data

# Create share directory for binaries
echo "[5/6] Creating share directory..."
mkdir -p share

# Create libvirt domain XML
echo "[6/6] Creating libvirt domain..."
cat > domain.xml << EOF
<domain type='kvm'>
  <name>${VM_NAME}</name>
  <memory unit='GiB'>4</memory>
  <vcpu>2</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'/>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${VM_DIR}/vm-disk.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${VM_DIR}/cloud-init.iso'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <filesystem type='mount' accessmode='passthrough'>
      <source dir='${VM_DIR}/share'/>
      <target dir='share'/>
    </filesystem>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' port='-1' autoport='yes'/>
  </devices>
</domain>
EOF

# Remove old VM if exists
virsh destroy ${VM_NAME} 2>/dev/null || true
virsh undefine ${VM_NAME} 2>/dev/null || true

# Define the VM
virsh define domain.xml

echo ""
echo "Setup complete!"
echo ""
echo "Usage:"
echo "  ./run_test.sh         # Start VM and run bootstrap test"
echo "  virsh start ${VM_NAME}    # Start VM"
echo "  virsh console ${VM_NAME}  # Connect to console"
echo "  virsh destroy ${VM_NAME}  # Stop VM"
echo ""
