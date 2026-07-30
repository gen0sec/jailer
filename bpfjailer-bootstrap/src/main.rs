//! BpfJailer Bootstrap - Daemonless Installation
//!
//! Loads and pins BPF programs/maps at early boot.
//! After setup, exits immediately. Programs remain active until reboot.

use anyhow::{Context, Result};
use bpfjailer_common::apply::{apply_role, PolicySink};
use bpfjailer_common::codec;
use bpfjailer_common::policy::PolicyConfig;
use libbpf_rs::MapCore;
use libbpf_rs::{Link, MapFlags, Object, ObjectBuilder};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/bpfjailer";
const DEFAULT_POLICY_PATH: &str = "/etc/bpfjailer/policy.json";
const LOCAL_POLICY_PATH: &str = "config/policy.json";

/// Find a map by name.
///
/// libbpf-rs 0.26 removed `Object::map(name)`/`map_mut(name)` in favour of
/// iterating. `update` is a `MapCore` method taking `&self`, so the immutable
/// iterator is enough here.
fn map_by_name<'a>(object: &'a Object, name: &str) -> Option<libbpf_rs::Map<'a>> {
    let want = std::ffi::OsStr::new(name);
    object.maps().find(|m| m.name() == want)
}

/// Find a map by name for operations that mutate it, such as pinning.
fn map_mut_by_name<'a>(object: &'a mut Object, name: &str) -> Option<libbpf_rs::MapMut<'a>> {
    let want = std::ffi::OsStr::new(name);
    object.maps_mut().find(|m| m.name() == want)
}

/// Find a program by name. `Object::prog_mut(name)` was removed in 0.26.
fn prog_by_name<'a>(object: &'a Object, name: &str) -> Option<libbpf_rs::ProgramMut<'a>> {
    let want = std::ffi::OsStr::new(name);
    object.progs_mut().find(|p| p.name() == want)
}

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

    // Refuse a policy asking for something this build does not enforce, rather
    // than pinning it and looking protected. Same check as the daemon.
    for (name, role) in &config.roles {
        let unenforced = bpfjailer_common::flags::unenforced_flags(&role.flags);
        if !unenforced.is_empty() {
            anyhow::bail!(
                "role '{}' requests {} which this build does not enforce; \
                 remove the setting or do not rely on it",
                name,
                unenforced.join(", ")
            );
        }
    }
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
    let object = open_object.load().context("Failed to load BPF object")?;

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
        if let Some(prog) = prog_by_name(&object, name) {
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

/// Writes role rules straight into the loaded object's maps.
///
/// The bootstrap has no daemon abstractions, so this is the thinnest possible
/// adapter between [`apply_role`] and the raw maps.
struct ObjectSink<'a> {
    object: &'a Object,
}

impl ObjectSink<'_> {
    fn map(&self, name: &str) -> Result<libbpf_rs::Map<'_>> {
        map_by_name(self.object, name).ok_or_else(|| anyhow::anyhow!("{name} map not found"))
    }
}

impl PolicySink for ObjectSink<'_> {
    type Err = anyhow::Error;

    fn set_role_flags(&mut self, role_id: u32, flags: u8) -> Result<()> {
        self.map("role_flags")?
            .update(&role_id.to_ne_bytes(), &[flags], MapFlags::empty())?;
        Ok(())
    }

    fn add_path_state(&mut self, role_id: u32, pattern: &str, allow: bool) -> Result<()> {
        let map = self.map("path_states")?;
        for (key, value) in codec::path_state_entries(role_id, pattern, allow) {
            map.update(&key, &value, MapFlags::empty())?;
        }
        Ok(())
    }

    fn add_network_rule(
        &mut self,
        role_id: u32,
        port: u16,
        protocol: u8,
        direction: u8,
        allow: bool,
    ) -> Result<()> {
        self.map("network_rules")?.update(
            &codec::net_rule_key(role_id, port, protocol, direction),
            &[allow as u8],
            MapFlags::empty(),
        )?;
        Ok(())
    }

    fn add_ip_rule(&mut self, role_id: u32, cidr: &str, direction: u8, allow: bool) -> Result<()> {
        let (ip, prefix_len) = codec::parse_cidr(cidr).map_err(|e| anyhow::anyhow!(e))?;
        self.map("ip_rules")?.update(
            &codec::ip_rule_key(role_id, ip, prefix_len, direction),
            &[allow as u8],
            MapFlags::empty(),
        )?;
        Ok(())
    }

    fn add_domain_rule(&mut self, role_id: u32, domain: &str, allow: bool) -> Result<()> {
        self.map("domain_rules")?.update(
            &codec::domain_rule_key(role_id, domain),
            &[allow as u8],
            MapFlags::empty(),
        )?;
        Ok(())
    }

    fn set_proxy(&mut self, role_id: u32, address: &str, required: bool) -> Result<()> {
        let (ip, port) = codec::parse_proxy_addr(address).map_err(|e| anyhow::anyhow!(e))?;
        self.map("proxy_config")?.update(
            &role_id.to_ne_bytes(),
            &codec::proxy_config_value(ip, port, required),
            MapFlags::empty(),
        )?;
        Ok(())
    }
}

fn populate_maps(object: &mut Object, policy: &PolicyConfig) -> Result<()> {
    log::info!("Populating BPF maps from policy...");

    // Roles are applied through the shared walk in bpfjailer_common::apply, so
    // the daemon and this bootstrap cannot diverge on which sections they
    // honour. They previously did: this path silently ignored ip_rules,
    // domain_rules and proxy entirely.
    for (name, role) in &policy.roles {
        let mut sink = ObjectSink { object };
        let skipped = apply_role(&mut sink, role)?;
        for s in skipped {
            log::warn!("Role '{}': skipped {}", name, s);
        }
        log::info!("Role '{}' (id={}) applied", name, role.id.0);
    }

    // Load pod mappings
    if let Some(map) = map_by_name(object, "pod_to_role") {
        for pod in &policy.pods {
            let key = pod.id.to_ne_bytes();
            let value = pod.role_id.0.to_ne_bytes();
            map.update(&key, &value, MapFlags::empty())?;
            log::info!("Pod {} -> role {}", pod.id, pod.role_id.0);
        }
    }

    // Load exec enrollments
    if let Some(map) = map_by_name(object, "exec_enrollment") {
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
    if let Some(map) = map_by_name(object, "cgroup_enrollment") {
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
        if let Some(mut map) = map_mut_by_name(object, name) {
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
        if let Some(mut prog) = prog_by_name(object, name) {
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

/// Root-gated tests for the daemonless bootstrap.
///
/// `load_bpf_object` and `pin_all` also *attach* the LSM programs, which needs
/// `bpf` in the kernel's active LSM list; they are exercised on an LSM-enabled
/// host rather than here. `populate_maps` only needs the maps to exist, so it
/// is driven against an object that is loaded but never attached.
#[cfg(test)]
mod root_integration {
    use super::*;

    fn bpf_object_path() -> Option<std::path::PathBuf> {
        let root = std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(PathBuf::from)?
            .parent()?
            .to_path_buf();
        let p = root.join("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o");
        p.exists().then_some(p)
    }

    /// Load (but do not attach) the BPF object, so the maps exist.
    fn loaded_object() -> Option<Object> {
        let path = bpf_object_path()?;
        let mut builder = libbpf_rs::ObjectBuilder::default();
        builder.open_file(path).ok()?.load().ok()
    }

    fn write_policy(tag: &str, body: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("bpfjailer-boot-{tag}-{}.json", std::process::id()));
        fs::write(&p, body).expect("write policy");
        p
    }

    const POLICY: &str = r#"{
      "roles": {
        "web": { "id": 30, "name": "web",
          "flags": {"allow_file_access": true, "allow_network": true, "allow_exec": true,
                    "require_signed_binary": false, "allow_setuid": true, "allow_ptrace": false,
                    "allow_module_load": true, "allow_bpf_load": true},
          "file_paths": [{"pattern": "/var/www/", "allow": true},
                         {"pattern": "/etc/shadow", "allow": false}],
          "network_rules": [{"protocol": "tcp", "port": 443, "allow": true}],
          "execution_rules": [], "require_signed_binary": false }
      },
      "pods": [{"id": 300, "role_id": 30, "stack_depth": 0}],
      "exec_enrollments": [],
      "cgroup_enrollments": []
    }"#;

    #[test]
    #[ignore = "requires root"]
    fn is_pinned_reflects_the_pin_directory() {
        // Whatever the current state, the answer must match the filesystem.
        assert_eq!(is_pinned(), Path::new(BPF_PIN_PATH).exists());
    }

    #[test]
    #[ignore = "requires root"]
    fn load_policy_honours_the_env_override() {
        let path = write_policy("env", POLICY);
        std::env::set_var("BPFJAILER_POLICY", &path);
        let cfg = load_policy().expect("load");
        std::env::remove_var("BPFJAILER_POLICY");
        assert!(cfg.get_role("web").is_some());
        let _ = fs::remove_file(path);
    }

    #[test]
    #[ignore = "requires root"]
    fn load_policy_refuses_an_unenforced_flag() {
        let body = POLICY.replace(
            r#""require_signed_binary": false, "allow_setuid": true"#,
            r#""require_signed_binary": true, "allow_setuid": true"#,
        );
        assert!(
            body.contains(r#""require_signed_binary": true"#),
            "fixture not patched"
        );
        let path = write_policy("unenforced", &body);
        std::env::set_var("BPFJAILER_POLICY", &path);
        let err = load_policy().unwrap_err();
        std::env::remove_var("BPFJAILER_POLICY");
        assert!(
            format!("{err:#}").contains("require_signed_binary"),
            "got: {err:#}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    #[ignore = "requires root"]
    fn load_policy_surfaces_malformed_json() {
        let path = write_policy("bad", "{ not json");
        std::env::set_var("BPFJAILER_POLICY", &path);
        let err = load_policy().unwrap_err();
        std::env::remove_var("BPFJAILER_POLICY");
        assert!(format!("{err:#}").contains("parse"), "got: {err:#}");
        let _ = fs::remove_file(path);
    }

    #[test]
    #[ignore = "requires root"]
    fn load_policy_surfaces_a_missing_file() {
        std::env::set_var("BPFJAILER_POLICY", "/nonexistent/policy.json");
        let err = load_policy().unwrap_err();
        std::env::remove_var("BPFJAILER_POLICY");
        assert!(format!("{err:#}").contains("read"), "got: {err:#}");
    }

    #[test]
    #[ignore = "requires root"]
    fn populate_maps_writes_roles_flags_and_path_states() {
        let Some(mut object) = loaded_object() else {
            eprintln!("skipping: BPF object not built or no permission");
            return;
        };
        let cfg: PolicyConfig = serde_json::from_str(POLICY).expect("parse policy");
        populate_maps(&mut object, &cfg).expect("populate");

        // role_flags: every bit must survive, not just the first three.
        let flags = map_by_name(&object, "role_flags")
            .expect("map")
            .lookup(&30u32.to_ne_bytes(), MapFlags::empty())
            .expect("lookup")
            .expect("role present");
        let expected =
            bpfjailer_common::flags::policy_flags_to_u8(&cfg.get_role("web").unwrap().flags);
        assert_eq!(flags[0], expected);

        // path_states: the deny rule must be present under the codec's key.
        let entries = bpfjailer_common::codec::path_state_entries(30, "/etc/shadow", false);
        let map = map_by_name(&object, "path_states").expect("map");
        for (key, value) in entries {
            let got = map
                .lookup(&key, MapFlags::empty())
                .expect("lookup")
                .expect("transition present");
            assert_eq!(got.as_slice(), value.as_slice());
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn populate_maps_writes_pod_to_role() {
        let Some(mut object) = loaded_object() else {
            return;
        };
        let cfg: PolicyConfig = serde_json::from_str(POLICY).expect("parse");
        populate_maps(&mut object, &cfg).expect("populate");
        let v = map_by_name(&object, "pod_to_role")
            .expect("map")
            .lookup(&300u64.to_ne_bytes(), MapFlags::empty())
            .expect("lookup")
            .expect("pod present");
        assert_eq!(u32::from_ne_bytes(v[0..4].try_into().unwrap()), 30);
    }

    #[test]
    #[ignore = "requires root"]
    fn object_sink_writes_path_states_matching_the_codec() {
        let Some(object) = loaded_object() else {
            return;
        };
        let mut sink = ObjectSink { object: &object };
        sink.add_path_state(31, "/srv/data/", false).expect("add");
        let map = map_by_name(&object, "path_states").expect("map");
        for (key, value) in bpfjailer_common::codec::path_state_entries(31, "/srv/data/", false) {
            let got = map
                .lookup(&key, MapFlags::empty())
                .expect("lookup")
                .expect("present");
            assert_eq!(got.as_slice(), value.as_slice());
        }
    }
}
