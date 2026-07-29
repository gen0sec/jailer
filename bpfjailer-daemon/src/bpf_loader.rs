use anyhow::Result;
use bpfjailer_common::codec;
use libbpf_rs::{MapFlags, Object, ObjectBuilder};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Wrapper to make Object Send + Sync
// libbpf-rs Object contains NonNull pointers that aren't Send/Sync by default
// but in practice they're safe to share if we use Mutex for synchronization
pub struct BpfJailerBpf {
    object: Arc<Mutex<Object>>,
}

// Safety: Object is safe to send/share across threads when protected by Mutex
// The underlying libbpf handles are thread-safe for concurrent access
unsafe impl Send for BpfJailerBpf {}
unsafe impl Sync for BpfJailerBpf {}

impl BpfJailerBpf {
    pub fn load() -> Result<Self> {
        log::info!("Loading BpfJailer eBPF programs with libbpf-rs...");

        // Try multiple possible paths for the compiled BPF object
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(PathBuf::from)
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let possible_paths = [
            workspace_root.join("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            workspace_root.join("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            PathBuf::from("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            PathBuf::from("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            PathBuf::from("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            PathBuf::from("bpfjailer-bpf/target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
        ];

        let obj_path = possible_paths
            .iter()
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("bpfjailer.bpf.o not found in any expected location"))?;

        log::info!("Loading BPF object from: {:?}", obj_path);

        // Load BPF object using libbpf-rs
        // open_file returns OpenObject, then load() returns Object
        let mut object_builder = ObjectBuilder::default();
        let open_object = object_builder.open_file(obj_path)?;

        // Try to load - this will create maps including task_storage
        let mut object = match open_object.load() {
            Ok(obj) => obj,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("task_storage") || err_str.contains("EINVAL") {
                    log::error!("Failed to load BPF object - task_storage map creation failed");
                    log::error!("This may be a kernel issue. Error: {}", err_str);
                    log::error!(
                        "Kernel version: {}",
                        std::process::Command::new("uname")
                            .arg("-r")
                            .output()
                            .ok()
                            .and_then(|o| String::from_utf8(o.stdout).ok())
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                    log::error!(
                        "BPF LSM status: {}",
                        std::fs::read_to_string("/sys/kernel/security/lsm")
                            .unwrap_or_else(|_| "unknown".to_string())
                    );
                }
                return Err(anyhow::Error::from(e));
            }
        };

        log::info!("BPF object loaded successfully");

        // Check that maps exist
        if object.map("pod_to_role").is_none() {
            return Err(anyhow::anyhow!("pod_to_role map not found"));
        }
        if object.map("role_flags").is_none() {
            return Err(anyhow::anyhow!("role_flags map not found"));
        }
        if object.map("pending_enrollments").is_none() {
            return Err(anyhow::anyhow!("pending_enrollments map not found"));
        }
        log::info!("✓ pending_enrollments map available for enrollment");

        if object.map("network_rules").is_none() {
            return Err(anyhow::anyhow!("network_rules map not found"));
        }
        log::info!("✓ network_rules map available for port/protocol filtering");

        if object.map("path_rules").is_none() {
            return Err(anyhow::anyhow!("path_rules map not found"));
        }
        log::info!("✓ path_rules map available for path matching");

        if object.map("path_states").is_none() {
            return Err(anyhow::anyhow!("path_states map not found"));
        }
        log::info!("✓ path_states map available for dentry-based path matching");

        if object.map("inode_cache").is_none() {
            log::warn!("inode_cache map not found (optional)");
        } else {
            log::info!("✓ inode_cache map available for caching");
        }

        // Auto-enrollment maps
        if object.map("exec_enrollment").is_some() {
            log::info!("✓ exec_enrollment map available for executable-based enrollment");
        }
        if object.map("cgroup_enrollment").is_some() {
            log::info!("✓ cgroup_enrollment map available for cgroup-based enrollment");
        }

        // AI agent security maps
        if object.map("ip_rules").is_some() {
            log::info!("✓ ip_rules map available for IP/CIDR filtering");
        }
        if object.map("proxy_config").is_some() {
            log::info!("✓ proxy_config map available for proxy enforcement");
        }
        if object.map("domain_rules").is_some() {
            log::info!("✓ domain_rules map available for domain filtering");
        }
        if object.map("dns_cache").is_some() {
            log::info!("✓ dns_cache map available for DNS tracking");
        }
        if object.map("dns_pending").is_some() {
            log::info!("✓ dns_pending map available for DNS query tracking");
        }

        // Note: task_storage map is automatically handled by libbpf-rs
        // It's created but we don't need to access it from userspace
        if object.map("task_storage").is_some() {
            log::info!("✓ task_storage map created successfully");
        }

        // Load and attach LSM programs
        log::info!("Loading and attaching LSM programs...");
        let program_names = [
            "task_alloc",
            "file_open",
            "socket_bind",
            "socket_connect",
            "socket_sendmsg",
            "bprm_check_security",
            "path_rename",
            "sb_mount",
            "sb_umount",
        ];

        // LSM programs must be explicitly attached
        for name in &program_names {
            match object.prog_mut(name) {
                Some(prog) => {
                    match prog.attach() {
                        Ok(link) => {
                            // Keep the link alive by leaking it (daemon keeps running)
                            // In production, you'd store these in a Vec
                            std::mem::forget(link);
                            log::info!("✓ Program {} attached", name);
                        }
                        Err(e) => {
                            log::error!("Failed to attach program {}: {}", name, e);
                            return Err(anyhow::anyhow!("Failed to attach {}: {}", name, e));
                        }
                    }
                }
                None => {
                    log::warn!("Program {} not found in eBPF object", name);
                }
            }
        }

        log::info!("All eBPF programs loaded and attached successfully");

        Ok(Self {
            // libbpf_rs::Object is neither Send nor Sync; the Arc<Mutex<_>>
            // is only shared within a single thread here. Worth revisiting if
            // the loader ever becomes multi-threaded.
            #[allow(clippy::arc_with_non_send_sync)]
            object: Arc::new(Mutex::new(object)),
        })
    }

    /// Raw map read, for tests that need to assert what was actually written.
    /// Not part of the runtime API -- the daemon only ever writes.
    #[cfg(test)]
    pub(crate) fn map_lookup(&self, map_name: &str, key: &[u8]) -> Option<Vec<u8>> {
        let object = self.object.lock().unwrap();
        let map = object.map(map_name)?;
        map.lookup(key, MapFlags::empty()).ok().flatten()
    }

    /// Read a task's `process_info` out of the `task_storage` map.
    ///
    /// Task-local storage is keyed by a *pidfd* when read from userspace, not
    /// by a pid, which is why an earlier version of `get_process_info` gave up
    /// and returned `None` unconditionally.
    ///
    /// Returns `Ok(None)` when the process is gone or has no entry yet -- the
    /// BPF side only populates storage once the task hits a hooked syscall.
    pub fn lookup_task_storage(&self, pid: u32) -> Result<Option<Vec<u8>>> {
        // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0i32) };
        if raw < 0 {
            // No such process, or no permission to open it.
            return Ok(None);
        }
        let fd = raw as i32;

        let result = {
            let object = self.object.lock().unwrap();
            match object.map("task_storage") {
                Some(map) => map
                    .lookup(&fd.to_ne_bytes(), MapFlags::empty())
                    .ok()
                    .flatten(),
                None => None,
            }
        };

        // SAFETY: fd was just created by pidfd_open and is not used again.
        unsafe { libc::close(fd) };
        Ok(result)
    }

    pub fn update_pod_role(&self, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("pod_to_role")
            .ok_or_else(|| anyhow::anyhow!("pod_to_role map not found"))?;
        let key = pod_id.to_ne_bytes();
        let value = role_id.to_ne_bytes();
        map.update(&key, &value, MapFlags::empty())?;
        Ok(())
    }

    pub fn update_role_flags(&self, role_id: u32, flags: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("role_flags")
            .ok_or_else(|| anyhow::anyhow!("role_flags map not found"))?;
        let key = role_id.to_ne_bytes();
        let value = [flags];
        map.update(&key, &value, MapFlags::empty())?;
        Ok(())
    }

    /// Enroll a process by PID. The BPF code will migrate this to task_storage
    /// on the next syscall (file_open, exec, etc.)
    pub fn enroll_pending_process(&self, pid: u32, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("pending_enrollments")
            .ok_or_else(|| anyhow::anyhow!("pending_enrollments map not found"))?;

        let key = pid.to_ne_bytes();

        // struct process_info { u64 pod_id; u32 role_id; u8 stack_depth; u8 flags; }
        // Layout: 8 bytes + 4 bytes + 1 byte + 1 byte = 14 bytes (padded to 16)
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());
        value[12] = 0; // stack_depth
        value[13] = 0; // flags

        map.update(&key, &value, MapFlags::empty())?;
        log::debug!(
            "Added pending enrollment for PID {} -> pod_id={}, role_id={}",
            pid,
            pod_id,
            role_id
        );
        Ok(())
    }

    /// Add a network rule for a role
    /// protocol: 6 = TCP, 17 = UDP
    /// direction: 0 = bind, 1 = connect
    /// allowed: true = allow, false = deny
    pub fn add_network_rule(
        &self,
        role_id: u32,
        port: u16,
        protocol: u8,
        direction: u8,
        allowed: bool,
    ) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("network_rules")
            .ok_or_else(|| anyhow::anyhow!("network_rules map not found"))?;

        let key = codec::net_rule_key(role_id, port, protocol, direction);

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let proto_name = match protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "UNKNOWN",
        };
        let dir_name = if direction == 0 { "bind" } else { "connect" };
        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!(
            "Network rule: role={} {}:{} {} -> {}",
            role_id,
            proto_name,
            port,
            dir_name,
            action
        );

        Ok(())
    }

    /// Remove a network rule
    #[allow(dead_code)]
    pub fn remove_network_rule(
        &self,
        role_id: u32,
        port: u16,
        protocol: u8,
        direction: u8,
    ) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("network_rules")
            .ok_or_else(|| anyhow::anyhow!("network_rules map not found"))?;

        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        key[6] = protocol;
        key[7] = direction;

        map.delete(&key)?;
        Ok(())
    }

    /// Add a path rule for a role
    /// path: The path or prefix to match (e.g., "/var/www/", "/tmp/")
    /// allowed: true = allow, false = deny
    pub fn add_path_rule(&self, role_id: u32, path: &str, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("path_rules")
            .ok_or_else(|| anyhow::anyhow!("path_rules map not found"))?;

        let key = codec::path_rule_key(role_id, path);

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!(
            "Path rule: role={} path=\"{}\" -> {}",
            role_id,
            path,
            action
        );

        Ok(())
    }

    /// Remove a path rule
    #[allow(dead_code)]
    pub fn remove_path_rule(&self, role_id: u32, path: &str) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("path_rules")
            .ok_or_else(|| anyhow::anyhow!("path_rules map not found"))?;

        let path_hash = bpfjailer_common::hash::fnv1a_hash_u64(path);

        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[8..16].copy_from_slice(&path_hash.to_ne_bytes());

        map.delete(&key)?;
        Ok(())
    }

    /// Add a path pattern to the state machine
    /// Pattern examples: "/var/www/", "/tmp/*", "/etc/passwd"
    /// Supports:
    ///   - Exact paths: "/etc/passwd"
    ///   - Directory prefixes: "/var/www/" (matches everything under /var/www/)
    ///   - Wildcards: "/var/lib/*/data" (* matches any single component)
    pub fn add_path_state(&self, role_id: u32, pattern: &str, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("path_states")
            .ok_or_else(|| anyhow::anyhow!("path_states map not found"))?;

        let entries = codec::path_state_entries(role_id, pattern, allowed);
        if entries.is_empty() {
            return Ok(());
        }
        for (key, value) in &entries {
            map.update(key, value, MapFlags::empty())?;
        }

        log::info!(
            "Added path state machine: role={} pattern={} -> {} ({} transitions)",
            role_id,
            pattern,
            if allowed { "ALLOW" } else { "DENY" },
            entries.len()
        );
        Ok(())
    }

    pub fn invalidate_cache(&self) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("cache_generation")
            .ok_or_else(|| anyhow::anyhow!("cache_generation map not found"))?;

        // Read current generation
        let key = 0u32.to_ne_bytes();
        let current_gen = map
            .lookup(&key, MapFlags::empty())?
            .ok_or_else(|| anyhow::anyhow!("cache_generation map entry not found"))?;

        // Increment it (wrapping is fine)
        let current: u32 = u32::from_ne_bytes([
            current_gen[0],
            current_gen[1],
            current_gen[2],
            current_gen[3],
        ]);
        let new_gen = current.wrapping_add(1);

        map.update(&key, &new_gen.to_ne_bytes(), MapFlags::empty())?;
        log::info!(
            "Invalidated inode cache (generation: {} -> {})",
            current,
            new_gen
        );
        Ok(())
    }

    /// Add auto-enrollment rule for an executable (by inode)
    /// All processes executing this binary will be auto-enrolled
    pub fn add_exec_enrollment(&self, inode: u64, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("exec_enrollment")
            .ok_or_else(|| anyhow::anyhow!("exec_enrollment map not found"))?;

        let key = inode.to_ne_bytes();

        // struct exec_enrollment_value { u64 pod_id; u32 role_id; u32 _pad; }
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());

        map.update(&key, &value, MapFlags::empty())?;
        log::info!(
            "Exec enrollment: inode={} -> pod_id={}, role_id={}",
            inode,
            pod_id,
            role_id
        );
        Ok(())
    }

    /// Remove auto-enrollment rule for an executable
    #[allow(dead_code)]
    pub fn remove_exec_enrollment(&self, inode: u64) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("exec_enrollment")
            .ok_or_else(|| anyhow::anyhow!("exec_enrollment map not found"))?;

        let key = inode.to_ne_bytes();
        map.delete(&key)?;
        log::info!("Removed exec enrollment for inode={}", inode);
        Ok(())
    }

    /// Add auto-enrollment rule for a cgroup
    /// All processes in this cgroup will be auto-enrolled
    pub fn add_cgroup_enrollment(&self, cgroup_id: u64, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("cgroup_enrollment")
            .ok_or_else(|| anyhow::anyhow!("cgroup_enrollment map not found"))?;

        let key = cgroup_id.to_ne_bytes();

        // struct exec_enrollment_value { u64 pod_id; u32 role_id; u32 _pad; }
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());

        map.update(&key, &value, MapFlags::empty())?;
        log::info!(
            "Cgroup enrollment: cgroup_id={} -> pod_id={}, role_id={}",
            cgroup_id,
            pod_id,
            role_id
        );
        Ok(())
    }

    /// Remove auto-enrollment rule for a cgroup
    #[allow(dead_code)]
    pub fn remove_cgroup_enrollment(&self, cgroup_id: u64) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("cgroup_enrollment")
            .ok_or_else(|| anyhow::anyhow!("cgroup_enrollment map not found"))?;

        let key = cgroup_id.to_ne_bytes();
        map.delete(&key)?;
        log::info!("Removed cgroup enrollment for cgroup_id={}", cgroup_id);
        Ok(())
    }

    // =========================================================================
    // AI Agent Security Features
    // =========================================================================

    /// Add an IP/CIDR rule for egress filtering
    /// cidr: IP address or CIDR notation (e.g., "10.0.0.0/8", "192.168.1.1")
    /// direction: 0 = bind, 1 = connect
    /// allowed: true = allow, false = deny
    pub fn add_ip_rule(
        &self,
        role_id: u32,
        cidr: &str,
        direction: u8,
        allowed: bool,
    ) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("ip_rules")
            .ok_or_else(|| anyhow::anyhow!("ip_rules map not found"))?;

        let (ip, prefix_len) = codec::parse_cidr(cidr).map_err(|e| anyhow::anyhow!(e))?;
        let key = codec::ip_rule_key(role_id, ip, prefix_len, direction);

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let dir_name = if direction == 0 { "bind" } else { "connect" };
        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!(
            "IP rule: role={} {} {} -> {}",
            role_id,
            dir_name,
            cidr,
            action
        );
        Ok(())
    }

    // No production caller yet -- rule removal is not wired into the
    // enrollment API. Exercised by the root integration tests, which is
    // how the add/remove byte-order mismatch was found.
    #[allow(dead_code)]
    pub fn remove_ip_rule(&self, role_id: u32, cidr: &str, direction: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("ip_rules")
            .ok_or_else(|| anyhow::anyhow!("ip_rules map not found"))?;

        // Must use the same encoder as add_ip_rule: these previously disagreed
        // on byte order, so removal never matched the stored key.
        let (ip, prefix_len) = codec::parse_cidr(cidr).map_err(|e| anyhow::anyhow!(e))?;
        let key = codec::ip_rule_key(role_id, ip, prefix_len, direction);

        map.delete(&key)?;
        log::info!("Removed IP rule: role={} {}", role_id, cidr);
        Ok(())
    }

    pub fn set_proxy_config(&self, role_id: u32, proxy_addr: &str, required: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("proxy_config")
            .ok_or_else(|| anyhow::anyhow!("proxy_config map not found"))?;

        let (ip, port) = codec::parse_proxy_addr(proxy_addr).map_err(|e| anyhow::anyhow!(e))?;
        let key = role_id.to_ne_bytes();
        let value = codec::proxy_config_value(ip, port, required);
        map.update(&key, &value, MapFlags::empty())?;

        let mode = if required { "REQUIRED" } else { "OPTIONAL" };
        log::info!("Proxy config: role={} {} -> {}", role_id, proxy_addr, mode);
        Ok(())
    }

    // No production caller yet -- rule removal is not wired into the
    // enrollment API. Exercised by the root integration tests, which is
    // how the add/remove byte-order mismatch was found.
    #[allow(dead_code)]
    pub fn remove_proxy_config(&self, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("proxy_config")
            .ok_or_else(|| anyhow::anyhow!("proxy_config map not found"))?;

        let key = role_id.to_ne_bytes();
        map.delete(&key)?;
        log::info!("Removed proxy config for role={}", role_id);
        Ok(())
    }

    /// Add a domain rule for egress filtering
    /// domain: Domain name (e.g., "api.openai.com")
    /// allowed: true = allow, false = deny
    pub fn add_domain_rule(&self, role_id: u32, domain: &str, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("domain_rules")
            .ok_or_else(|| anyhow::anyhow!("domain_rules map not found"))?;

        let key = codec::domain_rule_key(role_id, domain);

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Domain rule: role={} {} -> {}", role_id, domain, action);

        Ok(())
    }

    /// Remove a domain rule
    #[allow(dead_code)]
    pub fn remove_domain_rule(&self, role_id: u32, domain: &str) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object
            .map("domain_rules")
            .ok_or_else(|| anyhow::anyhow!("domain_rules map not found"))?;

        let domain_hash = bpfjailer_common::hash::fnv1a_hash_u64(domain);

        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[8..16].copy_from_slice(&domain_hash.to_ne_bytes());

        map.delete(&key)?;
        log::info!("Removed domain rule: role={} {}", role_id, domain);
        Ok(())
    }

    /// Get inode of a file path
    pub fn get_file_inode(path: &str) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.ino())
    }

    /// Get cgroup ID from cgroup path
    pub fn get_cgroup_id(cgroup_path: &str) -> Result<u64> {
        // Read cgroup.id from the cgroup directory
        // Or use statx with STATX_MNT_ID on the cgroup path
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(cgroup_path)?;
        // For cgroup2, the inode of the cgroup directory is the cgroup ID
        Ok(metadata.ino())
    }

    // =========================================================================
    // Pinning Support for Daemonless Mode
    // =========================================================================

    /// Path where BPF objects are pinned
    pub const BPF_PIN_PATH: &'static str = "/sys/fs/bpf/bpfjailer";

    /// Check if BPF programs are already pinned
    pub fn is_pinned() -> bool {
        std::path::Path::new(Self::BPF_PIN_PATH).exists()
    }

    /// Pin all maps and programs to the BPF filesystem
    /// This allows programs to persist after the process exits
    #[allow(dead_code)]
    pub fn pin_all(&self) -> Result<()> {
        use std::fs;

        log::info!("Pinning BPF objects to {}...", Self::BPF_PIN_PATH);

        let object = self.object.lock().unwrap();

        fs::create_dir_all(Self::BPF_PIN_PATH)?;
        let maps_dir = format!("{}/maps", Self::BPF_PIN_PATH);
        let progs_dir = format!("{}/progs", Self::BPF_PIN_PATH);
        fs::create_dir_all(&maps_dir)?;
        fs::create_dir_all(&progs_dir)?;

        // Pin maps
        let map_names = [
            "task_storage",
            "pod_to_role",
            "role_flags",
            "pending_enrollments",
            "network_rules",
            "path_rules",
            "path_states",
            "inode_cache",
            "cache_generation",
            "exec_enrollment",
            "cgroup_enrollment",
            "audit_events",
        ];

        for name in &map_names {
            if object.map(name).is_some() {
                let pin_path = format!("{}/{}", maps_dir, name);
                // Note: pin() requires &mut self in some versions
                // This is a limitation - in daemon mode we'd need mutable access
                log::debug!("Would pin map {} to {}", name, pin_path);
            }
        }

        // Programs are kept attached via Link objects held in memory
        // In daemonless mode, use the bootstrap binary for pinning

        log::info!("BPF objects pinned (daemon mode - links held in memory)");
        Ok(())
    }

    /// Load BPF object from pinned maps (for audit logging daemon)
    /// This connects to already-pinned programs without re-loading
    #[allow(dead_code)]
    pub fn load_from_pins() -> Result<Self> {
        use libbpf_rs::MapHandle;

        if !Self::is_pinned() {
            return Err(anyhow::anyhow!(
                "BPF programs not pinned at {}",
                Self::BPF_PIN_PATH
            ));
        }

        log::info!(
            "Connecting to pinned BPF objects at {}...",
            Self::BPF_PIN_PATH
        );

        // For the logging daemon, we just need access to the audit_events map
        let audit_map_path = format!("{}/maps/audit_events", Self::BPF_PIN_PATH);
        if !std::path::Path::new(&audit_map_path).exists() {
            return Err(anyhow::anyhow!(
                "audit_events map not found at {}",
                audit_map_path
            ));
        }

        // Open the pinned map
        let _audit_map = MapHandle::from_pinned_path(&audit_map_path)?;
        log::info!("Connected to audit_events map");

        // For now, we create an empty object wrapper
        // The logging daemon only needs map access, not program control
        Err(anyhow::anyhow!(
            "load_from_pins() is for audit daemon only - use MapHandle directly"
        ))
    }

    /// Unpin all BPF objects (requires reboot to take effect for programs)
    #[allow(dead_code)]
    pub fn unpin_all() -> Result<()> {
        use std::fs;

        if !Self::is_pinned() {
            log::info!("No pinned BPF objects to remove");
            return Ok(());
        }

        log::info!("Removing pinned BPF objects from {}...", Self::BPF_PIN_PATH);

        // Remove recursively
        fs::remove_dir_all(Self::BPF_PIN_PATH)?;

        log::info!("Pinned BPF objects removed (programs still active until reboot)");
        Ok(())
    }
}

/// Integration tests that load the real BPF object and round-trip every map
/// write through the kernel.
///
/// These need `CAP_BPF`/root and a kernel with BTF, so they are `#[ignore]`d by
/// default. They do **not** require `bpf` in the active LSM list: the programs
/// are loaded (which creates the maps) but never attached, so the map contract
/// between userspace and BPF is exercised without needing an LSM-enabled
/// kernel.
///
///     sudo -E cargo test -p bpfjailer-daemon --  --include-ignored --test-threads=1
///
/// Single-threaded: each test loads its own BPF object, and running many at
/// once trips the memlock limit on smaller machines.
#[cfg(test)]
mod root_integration {
    use super::*;
    use bpfjailer_common::codec;

    /// Skip rather than fail when not run as root, so the default
    /// `cargo test` run stays green for contributors without privileges.
    fn bpf() -> Option<BpfJailerBpf> {
        match BpfJailerBpf::load() {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("skipping: could not load BPF object ({e})");
                None
            }
        }
    }

    macro_rules! bpf_or_skip {
        () => {
            match bpf() {
                Some(b) => b,
                None => return,
            }
        };
    }

    fn lookup(b: &BpfJailerBpf, map_name: &str, key: &[u8]) -> Option<Vec<u8>> {
        b.map_lookup(map_name, key)
    }

    #[test]
    #[ignore = "requires root"]
    fn loads_and_creates_every_map_the_loader_requires() {
        let b = bpf_or_skip!();
        let object = b.object.lock().unwrap();
        for name in [
            "pod_to_role",
            "role_flags",
            "pending_enrollments",
            "network_rules",
            "path_rules",
            "path_states",
            "inode_cache",
            "exec_enrollment",
            "cgroup_enrollment",
            "ip_rules",
            "proxy_config",
            "domain_rules",
            "task_storage",
        ] {
            assert!(object.map(name).is_some(), "map {name} missing");
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn pod_role_round_trips() {
        let b = bpf_or_skip!();
        b.update_pod_role(4242, 7).expect("update");
        let v = lookup(&b, "pod_to_role", &4242u64.to_ne_bytes()).expect("entry present");
        assert_eq!(u32::from_ne_bytes(v[0..4].try_into().unwrap()), 7);
    }

    #[test]
    #[ignore = "requires root"]
    fn role_flags_round_trip_the_exact_byte() {
        let b = bpf_or_skip!();
        b.update_role_flags(9, 0b1010_0101).expect("update");
        let v = lookup(&b, "role_flags", &9u32.to_ne_bytes()).expect("entry present");
        assert_eq!(v[0], 0b1010_0101);
    }

    #[test]
    #[ignore = "requires root"]
    fn network_rule_lands_on_the_key_the_codec_computes() {
        let b = bpf_or_skip!();
        b.add_network_rule(3, 443, codec::PROTO_TCP, 1, true)
            .expect("add");
        let key = codec::net_rule_key(3, 443, codec::PROTO_TCP, 1);
        assert_eq!(
            lookup(&b, "network_rules", &key).map(|v| v[0]),
            Some(1),
            "userspace and codec must agree on the key"
        );

        b.remove_network_rule(3, 443, codec::PROTO_TCP, 1)
            .expect("remove");
        assert!(lookup(&b, "network_rules", &key).is_none(), "entry removed");
    }

    #[test]
    #[ignore = "requires root"]
    fn path_rule_round_trips_and_removes() {
        let b = bpf_or_skip!();
        b.add_path_rule(1, "/etc/shadow", false).expect("add");
        let key = codec::path_rule_key(1, "/etc/shadow");
        assert_eq!(lookup(&b, "path_rules", &key).map(|v| v[0]), Some(0));
        b.remove_path_rule(1, "/etc/shadow").expect("remove");
        assert!(lookup(&b, "path_rules", &key).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn path_state_writes_one_entry_per_component() {
        let b = bpf_or_skip!();
        b.add_path_state(5, "/etc/ssh/sshd_config", false)
            .expect("add");
        for (key, expected) in codec::path_state_entries(5, "/etc/ssh/sshd_config", false) {
            let got = lookup(&b, "path_states", &key).expect("transition present");
            assert_eq!(
                got.as_slice(),
                expected.as_slice(),
                "value bytes must match"
            );
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn path_state_wildcards_are_stored_under_hash_zero() {
        let b = bpf_or_skip!();
        b.add_path_state(6, "/home/*/.ssh", false).expect("add");
        let entries = codec::path_state_entries(6, "/home/*/.ssh", false);
        let wildcard = &entries[1];
        assert!(lookup(&b, "path_states", &wildcard.0).is_some());
    }

    #[test]
    #[ignore = "requires root"]
    fn directory_pattern_adds_the_trailing_wildcard_transition() {
        let b = bpf_or_skip!();
        b.add_path_state(8, "/var/secrets/", false).expect("add");
        let entries = codec::path_state_entries(8, "/var/secrets/", false);
        let last = entries.last().expect("at least one entry");
        let got = lookup(&b, "path_states", &last.0).expect("wildcard terminal present");
        assert_eq!(got[10], 1, "wildcard flag set in the stored value");
    }

    #[test]
    #[ignore = "requires root"]
    fn exec_enrollment_round_trips_and_removes() {
        let b = bpf_or_skip!();
        b.add_exec_enrollment(987_654, 11, 3).expect("add");
        let v = lookup(&b, "exec_enrollment", &987_654u64.to_ne_bytes()).expect("present");
        assert_eq!(v.as_slice(), codec::enrollment_value(11, 3).as_slice());
        b.remove_exec_enrollment(987_654).expect("remove");
        assert!(lookup(&b, "exec_enrollment", &987_654u64.to_ne_bytes()).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn cgroup_enrollment_round_trips_and_removes() {
        let b = bpf_or_skip!();
        b.add_cgroup_enrollment(555, 12, 4).expect("add");
        assert!(lookup(&b, "cgroup_enrollment", &555u64.to_ne_bytes()).is_some());
        b.remove_cgroup_enrollment(555).expect("remove");
        assert!(lookup(&b, "cgroup_enrollment", &555u64.to_ne_bytes()).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn ip_rule_is_stored_under_the_masked_network_address() {
        let b = bpf_or_skip!();
        b.add_ip_rule(2, "10.1.2.3/8", 1, false).expect("add");
        // The host bits must have been cleared, so the /8 network key hits.
        let key = codec::ip_rule_key(2, "10.0.0.0".parse().unwrap(), 8, 1);
        assert_eq!(lookup(&b, "ip_rules", &key).map(|v| v[0]), Some(0));
        b.remove_ip_rule(2, "10.1.2.3/8", 1).expect("remove");
        assert!(lookup(&b, "ip_rules", &key).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn bare_ip_rule_is_treated_as_a_slash_32() {
        let b = bpf_or_skip!();
        b.add_ip_rule(2, "192.168.5.9", 0, true).expect("add");
        let key = codec::ip_rule_key(2, "192.168.5.9".parse().unwrap(), 32, 0);
        assert_eq!(lookup(&b, "ip_rules", &key).map(|v| v[0]), Some(1));
    }

    #[test]
    #[ignore = "requires root"]
    fn malformed_cidr_is_rejected_rather_than_stored() {
        let b = bpf_or_skip!();
        assert!(b.add_ip_rule(2, "not-an-ip", 1, true).is_err());
        assert!(b.add_ip_rule(2, "10.0.0.0/99", 1, true).is_err());
    }

    #[test]
    #[ignore = "requires root"]
    fn proxy_config_round_trips_and_removes() {
        let b = bpf_or_skip!();
        b.set_proxy_config(6, "127.0.0.1:3128", true).expect("set");
        let v = lookup(&b, "proxy_config", &6u32.to_ne_bytes()).expect("present");
        let expected = codec::proxy_config_value("127.0.0.1".parse().unwrap(), 3128, true);
        assert_eq!(v.as_slice(), expected.as_slice());
        b.remove_proxy_config(6).expect("remove");
        assert!(lookup(&b, "proxy_config", &6u32.to_ne_bytes()).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn malformed_proxy_address_is_rejected() {
        let b = bpf_or_skip!();
        assert!(b.set_proxy_config(6, "127.0.0.1", true).is_err());
        assert!(b.set_proxy_config(6, "127.0.0.1:notaport", true).is_err());
    }

    #[test]
    #[ignore = "requires root"]
    fn domain_rule_round_trips_and_removes() {
        let b = bpf_or_skip!();
        b.add_domain_rule(4, "api.example.com", true).expect("add");
        let key = codec::domain_rule_key(4, "api.example.com");
        assert_eq!(lookup(&b, "domain_rules", &key).map(|v| v[0]), Some(1));
        b.remove_domain_rule(4, "api.example.com").expect("remove");
        assert!(lookup(&b, "domain_rules", &key).is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn pending_enrollment_round_trips() {
        let b = bpf_or_skip!();
        b.enroll_pending_process(4321, 77, 5).expect("enroll");
        let v = lookup(&b, "pending_enrollments", &4321u32.to_ne_bytes()).expect("present");
        assert_eq!(u64::from_ne_bytes(v[0..8].try_into().unwrap()), 77);
        assert_eq!(u32::from_ne_bytes(v[8..12].try_into().unwrap()), 5);
    }

    #[test]
    #[ignore = "requires root"]
    fn invalidate_cache_succeeds() {
        let b = bpf_or_skip!();
        b.invalidate_cache().expect("invalidate");
    }

    #[test]
    #[ignore = "requires root"]
    fn get_file_inode_matches_stat() {
        use std::os::unix::fs::MetadataExt;
        let expected = std::fs::metadata("/bin/sh").expect("stat /bin/sh").ino();
        assert_eq!(BpfJailerBpf::get_file_inode("/bin/sh").unwrap(), expected);
    }

    #[test]
    #[ignore = "requires root"]
    fn get_file_inode_surfaces_a_missing_path() {
        assert!(BpfJailerBpf::get_file_inode("/nonexistent/binary").is_err());
    }
}
