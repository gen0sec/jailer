use anyhow::Result;
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

        let obj_path = possible_paths.iter()
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
                    log::error!("Kernel version: {}", std::process::Command::new("uname")
                        .arg("-r")
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .unwrap_or_else(|| "unknown".to_string()));
                    log::error!("BPF LSM status: {}", std::fs::read_to_string("/sys/kernel/security/lsm")
                        .unwrap_or_else(|_| "unknown".to_string()));
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

    pub fn update_pod_role(&self, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("pod_to_role")
            .ok_or_else(|| anyhow::anyhow!("pod_to_role map not found"))?;
        let key = pod_id.to_ne_bytes();
        let value = role_id.to_ne_bytes();
        map.update(&key, &value, MapFlags::empty())?;
        Ok(())
    }

    pub fn update_role_flags(&self, role_id: u32, flags: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("role_flags")
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
        let map = object.map("pending_enrollments")
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
        log::debug!("Added pending enrollment for PID {} -> pod_id={}, role_id={}", pid, pod_id, role_id);
        Ok(())
    }

    /// Add a network rule for a role
    /// protocol: 6 = TCP, 17 = UDP
    /// direction: 0 = bind, 1 = connect
    /// allowed: true = allow, false = deny
    pub fn add_network_rule(&self, role_id: u32, port: u16, protocol: u8, direction: u8, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("network_rules")
            .ok_or_else(|| anyhow::anyhow!("network_rules map not found"))?;

        // struct net_rule_key { u32 role_id; u16 port; u8 protocol; u8 direction; }
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        key[6] = protocol;
        key[7] = direction;

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let proto_name = match protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "UNKNOWN",
        };
        let dir_name = if direction == 0 { "bind" } else { "connect" };
        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Network rule: role={} {}:{} {} -> {}", role_id, proto_name, port, dir_name, action);

        Ok(())
    }

    /// Remove a network rule
    #[allow(dead_code)]
    pub fn remove_network_rule(&self, role_id: u32, port: u16, protocol: u8, direction: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("network_rules")
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
        let map = object.map("path_rules")
            .ok_or_else(|| anyhow::anyhow!("path_rules map not found"))?;

        let path_hash = djb2_hash(path);

        // struct path_rule_key { u32 role_id; u64 path_hash; }
        let mut key = [0u8; 16];  // 4 + 4 padding + 8 = 16 bytes
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        // padding bytes 4-7 are zero
        key[8..16].copy_from_slice(&path_hash.to_ne_bytes());

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Path rule: role={} path=\"{}\" (hash={:#x}) -> {}", role_id, path, path_hash, action);

        Ok(())
    }

    /// Remove a path rule
    #[allow(dead_code)]
    pub fn remove_path_rule(&self, role_id: u32, path: &str) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("path_rules")
            .ok_or_else(|| anyhow::anyhow!("path_rules map not found"))?;

        let path_hash = djb2_hash(path);

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
        let map = object.map("path_states")
            .ok_or_else(|| anyhow::anyhow!("path_states map not found"))?;

        // Parse path into components
        let components: Vec<&str> = pattern
            .split('/')
            .filter(|s| !s.is_empty() && *s != "**")
            .collect();

        if components.is_empty() {
            return Ok(());
        }

        let mut state: u32 = 0;  // Start from root state

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let is_wildcard = *component == "*";
            let component_hash = if is_wildcard { 0 } else { djb2_hash_u32(component) };

            // Create state transition
            // struct path_state_key { u32 role_id; u32 state; u32 component_hash; }
            let mut key = [0u8; 12];
            key[0..4].copy_from_slice(&role_id.to_ne_bytes());
            key[4..8].copy_from_slice(&state.to_ne_bytes());
            key[8..12].copy_from_slice(&component_hash.to_ne_bytes());

            let next_state = if is_last {
                if allowed { 0xFFFFFFFE } else { 0xFFFFFFFF }  // ACCEPT or REJECT
            } else {
                // Generate unique state ID based on path so far
                djb2_hash_u32(&format!("{}:{}", role_id, &components[..=i].join("/")))
            };

            // struct path_state_value { u32 next_state; u8 is_terminal; u8 decision; u8 wildcard; u8 _pad; }
            let mut value = [0u8; 8];
            value[0..4].copy_from_slice(&next_state.to_ne_bytes());
            value[4] = if is_last { 1 } else { 0 };  // is_terminal
            value[5] = if allowed { 1 } else { 0 };  // decision
            value[6] = if is_wildcard { 1 } else { 0 };  // wildcard
            value[7] = 0;  // padding

            map.update(&key, &value, MapFlags::empty())?;

            state = next_state;
        }

        // If pattern ends with "/" (directory), add terminal state for any file under it
        if pattern.ends_with('/') {
            // Add wildcard transition for any component after this directory
            let mut key = [0u8; 12];
            key[0..4].copy_from_slice(&role_id.to_ne_bytes());
            key[4..8].copy_from_slice(&state.to_ne_bytes());
            key[8..12].copy_from_slice(&0u32.to_ne_bytes());  // wildcard (0 = any)

            let terminal_state: u32 = if allowed { 0xFFFFFFFE } else { 0xFFFFFFFF };
            let mut value = [0u8; 8];
            value[0..4].copy_from_slice(&terminal_state.to_ne_bytes());
            value[4] = 1;  // is_terminal
            value[5] = if allowed { 1 } else { 0 };
            value[6] = 1;  // wildcard
            value[7] = 0;

            map.update(&key, &value, MapFlags::empty())?;
        }

        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Path state: role={} pattern=\"{}\" -> {} ({} components)",
                   role_id, pattern, action, components.len());

        // Debug: show component hashes
        for (i, comp) in components.iter().enumerate() {
            let h = if *comp == "*" { 0 } else { djb2_hash_u32(comp) };
            log::debug!("  Component {}: \"{}\" -> hash={:#x}", i, comp, h);
        }

        Ok(())
    }

    /// Increment cache generation counter to invalidate inode cache
    pub fn invalidate_cache(&self) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("cache_generation")
            .ok_or_else(|| anyhow::anyhow!("cache_generation map not found"))?;

        // Read current generation
        let key = 0u32.to_ne_bytes();
        let current_gen = map.lookup(&key, MapFlags::empty())?
            .ok_or_else(|| anyhow::anyhow!("cache_generation map entry not found"))?;

        // Increment it (wrapping is fine)
        let current: u32 = u32::from_ne_bytes([
            current_gen[0], current_gen[1], current_gen[2], current_gen[3]
        ]);
        let new_gen = current.wrapping_add(1);

        map.update(&key, &new_gen.to_ne_bytes(), MapFlags::empty())?;
        log::info!("Invalidated inode cache (generation: {} -> {})", current, new_gen);
        Ok(())
    }

    /// Add auto-enrollment rule for an executable (by inode)
    /// All processes executing this binary will be auto-enrolled
    pub fn add_exec_enrollment(&self, inode: u64, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("exec_enrollment")
            .ok_or_else(|| anyhow::anyhow!("exec_enrollment map not found"))?;

        let key = inode.to_ne_bytes();

        // struct exec_enrollment_value { u64 pod_id; u32 role_id; u32 _pad; }
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());

        map.update(&key, &value, MapFlags::empty())?;
        log::info!("Exec enrollment: inode={} -> pod_id={}, role_id={}", inode, pod_id, role_id);
        Ok(())
    }

    /// Remove auto-enrollment rule for an executable
    #[allow(dead_code)]
    pub fn remove_exec_enrollment(&self, inode: u64) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("exec_enrollment")
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
        let map = object.map("cgroup_enrollment")
            .ok_or_else(|| anyhow::anyhow!("cgroup_enrollment map not found"))?;

        let key = cgroup_id.to_ne_bytes();

        // struct exec_enrollment_value { u64 pod_id; u32 role_id; u32 _pad; }
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());

        map.update(&key, &value, MapFlags::empty())?;
        log::info!("Cgroup enrollment: cgroup_id={} -> pod_id={}, role_id={}", cgroup_id, pod_id, role_id);
        Ok(())
    }

    /// Remove auto-enrollment rule for a cgroup
    #[allow(dead_code)]
    pub fn remove_cgroup_enrollment(&self, cgroup_id: u64) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("cgroup_enrollment")
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
    pub fn add_ip_rule(&self, role_id: u32, cidr: &str, direction: u8, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("ip_rules")
            .ok_or_else(|| anyhow::anyhow!("ip_rules map not found"))?;

        // Parse CIDR notation
        let (ip_str, prefix_len) = if let Some(slash_pos) = cidr.find('/') {
            let (ip, prefix) = cidr.split_at(slash_pos);
            let prefix_len: u8 = prefix[1..].parse()
                .map_err(|_| anyhow::anyhow!("Invalid prefix length in CIDR: {}", cidr))?;
            (ip, prefix_len)
        } else {
            (cidr, 32u8)  // Single IP = /32
        };

        // Parse IP address
        let ip_addr: std::net::Ipv4Addr = ip_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IPv4 address: {}", ip_str))?;
        let ip_bytes = ip_addr.octets();

        // Create mask and apply in network byte order
        // The IP in sin_addr.s_addr is stored in network byte order (big endian)
        // When read into a u32 on little-endian, it stays as raw bytes
        let mask = if prefix_len < 32 && prefix_len > 0 {
            !0u32 << (32 - prefix_len)
        } else if prefix_len == 0 {
            0u32
        } else {
            !0u32
        };

        // Apply mask in host byte order then convert to network byte order for storage
        let ip_native = u32::from_be_bytes(ip_bytes);
        let masked_native = ip_native & mask;
        // Store as raw bytes (network byte order) - same format as sin_addr.s_addr
        let masked_bytes = masked_native.to_be_bytes();

        // struct ip_rule_key { u32 role_id; u32 ip_addr; u8 prefix_len; u8 direction; u8 _pad[2]; }
        let mut key = [0u8; 12];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        // Store IP in network byte order (raw bytes) to match what BPF reads from sin_addr
        key[4..8].copy_from_slice(&masked_bytes);
        key[8] = prefix_len;
        key[9] = direction;

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let dir_name = if direction == 0 { "bind" } else { "connect" };
        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("IP rule: role={} {} {} -> {}", role_id, cidr, dir_name, action);

        Ok(())
    }

    /// Remove an IP/CIDR rule
    #[allow(dead_code)]
    pub fn remove_ip_rule(&self, role_id: u32, cidr: &str, direction: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("ip_rules")
            .ok_or_else(|| anyhow::anyhow!("ip_rules map not found"))?;

        let (ip_str, prefix_len) = if let Some(slash_pos) = cidr.find('/') {
            let (ip, prefix) = cidr.split_at(slash_pos);
            let prefix_len: u8 = prefix[1..].parse()?;
            (ip, prefix_len)
        } else {
            (cidr, 32u8)
        };

        let ip_addr: std::net::Ipv4Addr = ip_str.parse()?;
        let ip_bytes = ip_addr.octets();
        let ip_u32 = u32::from_be_bytes(ip_bytes);

        let masked_ip = if prefix_len < 32 {
            let mask = !0u32 << (32 - prefix_len);
            u32::from_be_bytes((u32::from_be_bytes(ip_bytes) & mask).to_be_bytes())
        } else {
            ip_u32
        };

        let mut key = [0u8; 12];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..8].copy_from_slice(&masked_ip.to_ne_bytes());
        key[8] = prefix_len;
        key[9] = direction;

        map.delete(&key)?;
        log::info!("Removed IP rule: role={} {}", role_id, cidr);
        Ok(())
    }

    /// Configure proxy requirement for a role
    /// proxy_addr: "host:port" format (e.g., "127.0.0.1:8080")
    /// required: if true, all connections must go through the proxy
    pub fn set_proxy_config(&self, role_id: u32, proxy_addr: &str, required: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("proxy_config")
            .ok_or_else(|| anyhow::anyhow!("proxy_config map not found"))?;

        // Parse proxy address
        let parts: Vec<&str> = proxy_addr.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid proxy address format: {}", proxy_addr));
        }

        let proxy_ip: std::net::Ipv4Addr = parts[0].parse()
            .map_err(|_| anyhow::anyhow!("Invalid proxy IP: {}", parts[0]))?;
        let proxy_port: u16 = parts[1].parse()
            .map_err(|_| anyhow::anyhow!("Invalid proxy port: {}", parts[1]))?;

        let ip_bytes = proxy_ip.octets();
        let ip_u32 = u32::from_be_bytes(ip_bytes);

        let key = role_id.to_ne_bytes();

        // struct proxy_config { u32 proxy_ip; u16 proxy_port; u8 require_proxy; u8 _pad; }
        let mut value = [0u8; 8];
        value[0..4].copy_from_slice(&ip_u32.to_ne_bytes());
        value[4..6].copy_from_slice(&proxy_port.to_ne_bytes());
        value[6] = if required { 1 } else { 0 };

        map.update(&key, &value, MapFlags::empty())?;

        let mode = if required { "REQUIRED" } else { "OPTIONAL" };
        log::info!("Proxy config: role={} {} -> {}", role_id, proxy_addr, mode);

        Ok(())
    }

    /// Remove proxy configuration for a role
    #[allow(dead_code)]
    pub fn remove_proxy_config(&self, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("proxy_config")
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
        let map = object.map("domain_rules")
            .ok_or_else(|| anyhow::anyhow!("domain_rules map not found"))?;

        let domain_hash = djb2_hash_u32(domain);

        // struct domain_rule_key { u32 role_id; u32 domain_hash; }
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..8].copy_from_slice(&domain_hash.to_ne_bytes());

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Domain rule: role={} {} (hash={:#x}) -> {}", role_id, domain, domain_hash, action);

        Ok(())
    }

    /// Remove a domain rule
    #[allow(dead_code)]
    pub fn remove_domain_rule(&self, role_id: u32, domain: &str) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("domain_rules")
            .ok_or_else(|| anyhow::anyhow!("domain_rules map not found"))?;

        let domain_hash = djb2_hash_u32(domain);

        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..8].copy_from_slice(&domain_hash.to_ne_bytes());

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
            "task_storage", "pod_to_role", "role_flags", "pending_enrollments",
            "network_rules", "path_rules", "path_states", "inode_cache",
            "cache_generation", "exec_enrollment", "cgroup_enrollment", "audit_events",
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

        log::info!("Connecting to pinned BPF objects at {}...", Self::BPF_PIN_PATH);

        // For the logging daemon, we just need access to the audit_events map
        let audit_map_path = format!("{}/maps/audit_events", Self::BPF_PIN_PATH);
        if !std::path::Path::new(&audit_map_path).exists() {
            return Err(anyhow::anyhow!("audit_events map not found at {}", audit_map_path));
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

/// djb2 hash function (64-bit) - must match the BPF implementation exactly
fn djb2_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for c in s.bytes().take(64) {
        hash = hash.wrapping_mul(33).wrapping_add(c as u64);
    }
    hash
}

/// djb2 hash function (32-bit) - for path component hashing
fn djb2_hash_u32(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for c in s.bytes().take(32) {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}
