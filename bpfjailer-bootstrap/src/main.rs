//! BpfJailer Bootstrap - Daemonless Installation
//!
//! Loads and pins BPF programs/maps at early boot.
//! After setup, exits immediately. Programs remain active until reboot.

use anyhow::{Context, Result};
use bpfjailer_common::policy::PolicyConfig;
use libbpf_rs::{Link, MapFlags, Object, ObjectBuilder};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/bpfjailer";
const DEFAULT_POLICY_PATH: &str = "/etc/bpfjailer/policy.json";
const LOCAL_POLICY_PATH: &str = "config/policy.json";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = run() {
        log::error!("Bootstrap failed: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    log::info!("BpfJailer bootstrap starting...");

    // Check if already pinned
    if is_pinned() {
        log::info!("BPF programs already pinned at {}", BPF_PIN_PATH);
        log::info!("To reload, remove {} and rerun", BPF_PIN_PATH);
        return Ok(());
    }

    // Load policy
    let policy = load_policy()?;
    log::info!("Loaded {} roles from policy", policy.roles.len());

    // Load BPF object
    let (mut object, mut links) = load_bpf_object()?;

    // Populate maps from policy
    populate_maps(&mut object, &policy)?;

    // Pin maps and programs
    pin_all(&mut object, &mut links)?;

    log::info!("BpfJailer bootstrap complete - programs pinned and active");
    log::info!("Programs will remain active until reboot");
    Ok(())
}

fn is_pinned() -> bool {
    Path::new(BPF_PIN_PATH).exists()
}

fn load_policy() -> Result<PolicyConfig> {
    let policy_path = std::env::var("BPFJAILER_POLICY").ok().or_else(|| {
        if Path::new(DEFAULT_POLICY_PATH).exists() {
            Some(DEFAULT_POLICY_PATH.to_string())
        } else if Path::new(LOCAL_POLICY_PATH).exists() {
            Some(LOCAL_POLICY_PATH.to_string())
        } else {
            None
        }
    });

    let path = policy_path.ok_or_else(|| {
        anyhow::anyhow!(
            "No policy file found. Set BPFJAILER_POLICY or create {}",
            DEFAULT_POLICY_PATH
        )
    })?;

    log::info!("Loading policy from: {}", path);
    let content = fs::read_to_string(&path).context("Failed to read policy file")?;
    let config: PolicyConfig = serde_json::from_str(&content).context("Failed to parse policy")?;
    Ok(config)
}

fn load_bpf_object() -> Result<(Object, Vec<Link>)> {
    log::info!("Loading BPF programs...");

    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(PathBuf::from)
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let possible_paths = [
        PathBuf::from("/usr/lib/bpfjailer/bpfjailer.bpf.o"),
        PathBuf::from("/usr/share/bpfjailer/bpfjailer.bpf.o"),
        workspace_root.join("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
        workspace_root.join("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
        workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
        workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
        PathBuf::from("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
        PathBuf::from("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
    ];

    let obj_path = possible_paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| anyhow::anyhow!("bpfjailer.bpf.o not found"))?;

    log::info!("Loading BPF object from: {:?}", obj_path);

    let mut object_builder = ObjectBuilder::default();
    let open_object = object_builder.open_file(obj_path)?;
    let mut object = open_object.load().context("Failed to load BPF object")?;

    log::info!("BPF object loaded successfully");

    // Attach LSM programs
    let program_names = [
        "task_alloc",
        "file_open",
        "socket_bind",
        "socket_connect",
        "bprm_check_security",
        "path_rename",
        "sb_mount",
        "sb_umount",
        "ptrace_access_check",
        "kernel_module_request",
        "bpf",
    ];

    let mut links = Vec::new();
    for name in &program_names {
        if let Some(prog) = object.prog_mut(name) {
            let link = prog
                .attach()
                .with_context(|| format!("Failed to attach {}", name))?;
            log::info!("Attached: {}", name);
            links.push(link);
        } else {
            log::warn!("Program {} not found", name);
        }
    }

    Ok((object, links))
}

fn populate_maps(object: &mut Object, policy: &PolicyConfig) -> Result<()> {
    log::info!("Populating BPF maps from policy...");

    // Load roles and their flags
    for (name, role) in &policy.roles {
        let role_id = role.id.0;
        let flags = bpfjailer_common::flags::policy_flags_to_u8(&role.flags);

        // Update role_flags map
        if let Some(map) = object.map("role_flags") {
            let key = role_id.to_ne_bytes();
            let value = [flags];
            map.update(&key, &value, MapFlags::empty())?;
            log::info!("Role '{}' (id={}) flags={:#x}", name, role_id, flags);
        }

        // Load network rules
        if let Some(map) = object.map("network_rules") {
            for rule in &role.network_rules {
                let protocol = match rule.protocol.as_str() {
                    "tcp" | "TCP" => 6u8,
                    "udp" | "UDP" => 17u8,
                    _ => continue,
                };

                let ports: Vec<u16> = if let Some(port) = rule.port {
                    vec![port]
                } else if let (Some(start), Some(end)) = (rule.port_start, rule.port_end) {
                    (start..=end).collect()
                } else {
                    continue;
                };

                for port in ports {
                    // Add both bind and connect rules
                    for direction in [0u8, 1u8] {
                        let mut key = [0u8; 8];
                        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
                        key[4..6].copy_from_slice(&port.to_ne_bytes());
                        key[6] = protocol;
                        key[7] = direction;
                        let value = [if rule.allow { 1u8 } else { 0u8 }];
                        map.update(&key, &value, MapFlags::empty())?;
                    }
                }
            }
        }

        // Load path rules (state machine)
        if let Some(map) = object.map("path_states") {
            for path_rule in &role.file_paths {
                add_path_state(map, role_id, &path_rule.pattern, path_rule.allow)?;
            }
        }
    }

    // Load pod mappings
    if let Some(map) = object.map("pod_to_role") {
        for pod in &policy.pods {
            let key = pod.id.to_ne_bytes();
            let value = pod.role_id.0.to_ne_bytes();
            map.update(&key, &value, MapFlags::empty())?;
            log::info!("Pod {} -> role {}", pod.id, pod.role_id.0);
        }
    }

    // Load exec enrollments
    if let Some(map) = object.map("exec_enrollment") {
        for enrollment in &policy.exec_enrollments {
            if let Ok(metadata) = fs::metadata(&enrollment.executable_path) {
                let inode = metadata.ino();
                if let Some(role) = policy.get_role(&enrollment.role) {
                    let key = inode.to_ne_bytes();
                    let mut value = [0u8; 16];
                    value[0..8].copy_from_slice(&enrollment.pod_id.to_ne_bytes());
                    value[8..12].copy_from_slice(&role.id.0.to_ne_bytes());
                    map.update(&key, &value, MapFlags::empty())?;
                    log::info!(
                        "Exec enrollment: {} (inode={}) -> pod={}, role={}",
                        enrollment.executable_path,
                        inode,
                        enrollment.pod_id,
                        enrollment.role
                    );
                }
            } else {
                log::warn!(
                    "Exec enrollment: {} not found, skipping",
                    enrollment.executable_path
                );
            }
        }
    }

    // Load cgroup enrollments
    if let Some(map) = object.map("cgroup_enrollment") {
        for enrollment in &policy.cgroup_enrollments {
            if let Ok(metadata) = fs::metadata(&enrollment.cgroup_path) {
                let cgroup_id = metadata.ino();
                if let Some(role) = policy.get_role(&enrollment.role) {
                    let key = cgroup_id.to_ne_bytes();
                    let mut value = [0u8; 16];
                    value[0..8].copy_from_slice(&enrollment.pod_id.to_ne_bytes());
                    value[8..12].copy_from_slice(&role.id.0.to_ne_bytes());
                    map.update(&key, &value, MapFlags::empty())?;
                    log::info!(
                        "Cgroup enrollment: {} (id={}) -> pod={}, role={}",
                        enrollment.cgroup_path,
                        cgroup_id,
                        enrollment.pod_id,
                        enrollment.role
                    );
                }
            } else {
                log::warn!(
                    "Cgroup enrollment: {} not found, skipping",
                    enrollment.cgroup_path
                );
            }
        }
    }

    log::info!("BPF maps populated");
    Ok(())
}

fn add_path_state(map: &libbpf_rs::Map, role_id: u32, pattern: &str, allowed: bool) -> Result<()> {
    let components: Vec<&str> = pattern
        .split('/')
        .filter(|s| !s.is_empty() && *s != "**")
        .collect();

    if components.is_empty() {
        return Ok(());
    }

    let mut state: u64 = 0;

    for (i, component) in components.iter().enumerate() {
        let is_last = i == components.len() - 1;
        let is_wildcard = *component == "*";
        let component_hash = if is_wildcard {
            0
        } else {
            bpfjailer_common::hash::fnv1a_hash_u64(component)
        };

        let mut key = [0u8; 24];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[8..16].copy_from_slice(&state.to_ne_bytes());
        key[16..24].copy_from_slice(&component_hash.to_ne_bytes());

        let next_state = if is_last {
            if allowed {
                0xFFFF_FFFF_FFFF_FFFE_u64
            } else {
                0xFFFF_FFFF_FFFF_FFFF_u64
            }
        } else {
            bpfjailer_common::hash::fnv1a_hash_u64(&format!(
                "{}:{}",
                role_id,
                components[..=i].join("/")
            ))
        };

        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&next_state.to_ne_bytes());
        value[8] = if is_last { 1 } else { 0 };
        value[9] = if allowed { 1 } else { 0 };
        value[10] = if is_wildcard { 1 } else { 0 };
        value[11] = 0;

        map.update(&key, &value, MapFlags::empty())?;
        state = next_state;
    }

    // Handle directory patterns (ending with /)
    if pattern.ends_with('/') {
        let mut key = [0u8; 24];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[8..16].copy_from_slice(&state.to_ne_bytes());
        key[16..24].copy_from_slice(&0u64.to_ne_bytes());

        let terminal_state: u64 = if allowed {
            0xFFFF_FFFF_FFFF_FFFE
        } else {
            0xFFFF_FFFF_FFFF_FFFF
        };
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&terminal_state.to_ne_bytes());
        value[8] = 1;
        value[9] = if allowed { 1 } else { 0 };
        value[10] = 1;
        value[11] = 0;

        map.update(&key, &value, MapFlags::empty())?;
    }

    log::debug!(
        "Path state: role={} pattern=\"{}\" -> {}",
        role_id,
        pattern,
        if allowed { "ALLOW" } else { "DENY" }
    );

    Ok(())
}

fn pin_all(object: &mut Object, links: &mut [Link]) -> Result<()> {
    log::info!("Pinning BPF programs and maps to {}...", BPF_PIN_PATH);

    // Create pin directory
    fs::create_dir_all(BPF_PIN_PATH).context("Failed to create BPF pin directory")?;

    let maps_dir = format!("{}/maps", BPF_PIN_PATH);
    let progs_dir = format!("{}/progs", BPF_PIN_PATH);
    let links_dir = format!("{}/links", BPF_PIN_PATH);

    fs::create_dir_all(&maps_dir)?;
    fs::create_dir_all(&progs_dir)?;
    fs::create_dir_all(&links_dir)?;

    // Pin all maps
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
        if let Some(map) = object.map_mut(name) {
            let pin_path = format!("{}/{}", maps_dir, name);
            if let Err(e) = map.pin(&pin_path) {
                log::warn!("Failed to pin map {}: {}", name, e);
            } else {
                log::info!("Pinned map: {}", name);
            }
        }
    }

    // Pin all programs
    let prog_names = [
        "task_alloc",
        "file_open",
        "socket_bind",
        "socket_connect",
        "bprm_check_security",
        "path_rename",
        "sb_mount",
        "sb_umount",
        "ptrace_access_check",
        "kernel_module_request",
        "bpf",
    ];

    for name in &prog_names {
        if let Some(prog) = object.prog_mut(name) {
            let pin_path = format!("{}/{}", progs_dir, name);
            if let Err(e) = prog.pin(&pin_path) {
                log::warn!("Failed to pin program {}: {}", name, e);
            } else {
                log::info!("Pinned program: {}", name);
            }
        }
    }

    // Pin links to keep programs attached
    for (i, link) in links.iter_mut().enumerate() {
        let pin_path = format!("{}/link_{}", links_dir, i);
        if let Err(e) = link.pin(&pin_path) {
            log::warn!("Failed to pin link {}: {}", i, e);
        } else {
            log::info!("Pinned link: {}", i);
        }
    }

    log::info!("All BPF objects pinned successfully");
    Ok(())
}
