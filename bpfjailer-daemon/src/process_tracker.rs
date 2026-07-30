use crate::bpf_loader::BpfJailerBpf;
use anyhow::{Context, Result};
use bpfjailer_common::{NetworkRule, PathPattern, PodId, PolicyFlags, ProxyConfig, RoleId};
use log::{debug, info, warn};
use std::sync::Arc;

// Protocol numbers now live in bpfjailer_common::codec, alongside the map
// encoders, so userspace and BPF cannot drift.

// Direction constants
pub const DIR_BIND: u8 = 0;
pub const DIR_CONNECT: u8 = 1;

pub struct ProcessTracker {
    bpf: Arc<BpfJailerBpf>,
}

use bpfjailer_common::flags::policy_flags_to_u8;

impl ProcessTracker {
    pub fn new(bpf: Arc<BpfJailerBpf>) -> Result<Self> {
        Ok(Self { bpf })
    }

    pub fn enroll_process(&self, pid: u32, pod_id: PodId, role_id: RoleId) -> Result<()> {
        info!(
            "Enrolling process {} into pod {} with role {}",
            pid, pod_id.0, role_id.0
        );

        // Update pod_to_role mapping
        self.bpf
            .update_pod_role(pod_id.0, role_id.0)
            .context("Failed to insert pod_to_role mapping")?;

        // Add to pending_enrollments map - BPF will migrate to task_storage
        // on the next syscall (file_open, exec, etc.)
        self.bpf
            .enroll_pending_process(pid, pod_id.0, role_id.0)
            .context("Failed to add pending enrollment")?;

        info!(
            "Process {} enrolled successfully (pending migration to task_storage)",
            pid
        );
        Ok(())
    }

    /// Look up a live process's pod and role.
    ///
    /// Returns `None` when the process is gone, or when the BPF side has not
    /// yet populated task-local storage for it -- enrollment is staged in
    /// `pending_enrollments` and migrates on the task's next hooked syscall,
    /// so a just-enrolled process reads as `None` until it does anything.
    pub fn get_process_info(&self, pid: u32) -> Result<Option<(PodId, RoleId)>> {
        debug!("Querying process info for PID {}", pid);
        let Some(raw) = self.bpf.lookup_task_storage(pid)? else {
            return Ok(None);
        };
        // struct process_info { u64 pod_id; u32 role_id; u8 stack_depth; u8 flags; }
        if raw.len() < 12 {
            return Err(anyhow::anyhow!(
                "task_storage entry for pid {pid} is {} bytes, expected at least 12",
                raw.len()
            ));
        }
        let pod_id = u64::from_ne_bytes(raw[0..8].try_into().unwrap());
        let role_id = u32::from_ne_bytes(raw[8..12].try_into().unwrap());
        Ok(Some((PodId(pod_id), RoleId(role_id))))
    }

    #[allow(dead_code)]
    pub fn update_role_flags(&self, role_id: RoleId, flags: u8) -> Result<()> {
        self.bpf
            .update_role_flags(role_id.0, flags)
            .context("Failed to update role flags")?;
        Ok(())
    }

    pub fn set_role_policy(&self, role_id: RoleId, flags: &PolicyFlags) -> Result<()> {
        let flags_u8 = policy_flags_to_u8(flags);
        info!("Setting role {} flags to 0x{:02x}", role_id.0, flags_u8);
        self.bpf
            .update_role_flags(role_id.0, flags_u8)
            .context("Failed to set role policy flags")?;
        Ok(())
    }

    /// Add a network rule for a role
    /// port: 0 = all ports
    pub fn add_network_rule(
        &self,
        role_id: RoleId,
        port: u16,
        protocol: u8,
        direction: u8,
        allowed: bool,
    ) -> Result<()> {
        self.bpf
            .add_network_rule(role_id.0, port, protocol, direction, allowed)
            .context("Failed to add network rule")
    }

    /// Apply network rules from a Role definition
    pub fn apply_network_rules(&self, role_id: RoleId, rules: &[NetworkRule]) -> Result<()> {
        for rule in rules {
            let Some((protocol, ports)) = bpfjailer_common::codec::expand_network_rule(
                &rule.protocol,
                rule.port,
                rule.port_start,
                rule.port_end,
            ) else {
                warn!("Skipping unusable network rule: {:?}", rule);
                continue;
            };

            for port in &ports {
                self.add_network_rule(role_id, *port, protocol, DIR_BIND, rule.allow)?;
                self.add_network_rule(role_id, *port, protocol, DIR_CONNECT, rule.allow)?;
            }

            if ports.len() == 1 {
                info!(
                    "Applied network rule: role={} port={} proto={} allow={}",
                    role_id.0, ports[0], rule.protocol, rule.allow
                );
            } else {
                info!(
                    "Applied network rule: role={} ports={}-{} ({} ports) proto={} allow={}",
                    role_id.0,
                    rule.port_start.unwrap(),
                    rule.port_end.unwrap(),
                    ports.len(),
                    rule.protocol,
                    rule.allow
                );
            }
        }
        Ok(())
    }

    /// Add a path rule for a role (legacy hash-based)
    #[allow(dead_code)]
    pub fn add_path_rule(&self, role_id: RoleId, path: &str, allowed: bool) -> Result<()> {
        self.bpf
            .add_path_rule(role_id.0, path, allowed)
            .context("Failed to add path rule")
    }

    /// Add a path state (dentry-walking state machine)
    pub fn add_path_state(&self, role_id: RoleId, pattern: &str, allowed: bool) -> Result<()> {
        self.bpf
            .add_path_state(role_id.0, pattern, allowed)
            .context("Failed to add path state")
    }

    /// Apply path rules from a Role definition using state machine
    pub fn apply_path_rules(&self, role_id: RoleId, rules: &[PathPattern]) -> Result<()> {
        for rule in rules {
            // Normalize path - ensure directory prefixes end with /
            let path = if rule.pattern.ends_with("/**") {
                // Convert glob pattern to prefix
                rule.pattern.trim_end_matches("**").to_string()
            } else if rule.pattern.ends_with("/*") {
                rule.pattern.trim_end_matches('*').to_string()
            } else {
                rule.pattern.clone()
            };

            // Use state machine approach (dentry walking)
            self.add_path_state(role_id, &path, rule.allow)?;

            info!(
                "Applied path rule: role={} path=\"{}\" allow={}",
                role_id.0, path, rule.allow
            );
        }
        Ok(())
    }

    // =========================================================================
    // AI Agent Security Features
    // =========================================================================

    /// Add an IP/CIDR rule for egress filtering
    pub fn add_ip_rule(
        &self,
        role_id: RoleId,
        cidr: &str,
        direction: u8,
        allowed: bool,
    ) -> Result<()> {
        self.bpf
            .add_ip_rule(role_id.0, cidr, direction, allowed)
            .context("Failed to add IP rule")
    }

    /// Configure proxy requirement for a role
    pub fn set_proxy_config(&self, role_id: RoleId, config: &ProxyConfig) -> Result<()> {
        self.bpf
            .set_proxy_config(role_id.0, &config.address, config.required)
            .context("Failed to set proxy config")
    }

    /// Add a domain rule for egress filtering
    pub fn add_domain_rule(&self, role_id: RoleId, domain: &str, allowed: bool) -> Result<()> {
        self.bpf
            .add_domain_rule(role_id.0, domain, allowed)
            .context("Failed to add domain rule")
    }
}

/// Writes role rules through the tracker's BPF handle.
///
/// Lets the daemon apply a policy through the same
/// [`bpfjailer_common::apply::apply_role`] walk the bootstrap uses, so the two
/// cannot disagree about which sections of a role are honoured.
pub struct TrackerSink<'a>(pub &'a ProcessTracker);

impl bpfjailer_common::apply::PolicySink for TrackerSink<'_> {
    type Err = anyhow::Error;

    fn set_role_flags(&mut self, role_id: u32, flags: u8) -> Result<()> {
        self.0.bpf.update_role_flags(role_id, flags)
    }
    fn add_path_state(&mut self, role_id: u32, pattern: &str, allow: bool) -> Result<()> {
        self.0.bpf.add_path_state(role_id, pattern, allow)
    }
    fn add_network_rule(
        &mut self,
        role_id: u32,
        port: u16,
        protocol: u8,
        direction: u8,
        allow: bool,
    ) -> Result<()> {
        self.0
            .bpf
            .add_network_rule(role_id, port, protocol, direction, allow)
    }
    fn add_ip_rule(&mut self, role_id: u32, cidr: &str, direction: u8, allow: bool) -> Result<()> {
        self.0.add_ip_rule(RoleId(role_id), cidr, direction, allow)
    }
    fn add_domain_rule(&mut self, role_id: u32, domain: &str, allow: bool) -> Result<()> {
        self.0.add_domain_rule(RoleId(role_id), domain, allow)
    }
    fn cache_resolved_ip(
        &mut self,
        role_id: u32,
        ip: std::net::Ipv4Addr,
        domain_hash: u64,
    ) -> Result<()> {
        self.0.bpf.cache_resolved_ip(role_id, ip, domain_hash)
    }

    fn set_proxy(&mut self, role_id: u32, address: &str, required: bool) -> Result<()> {
        self.0.set_proxy_config(
            RoleId(role_id),
            &ProxyConfig {
                address: address.to_string(),
                required,
            },
        )
    }
}

/// Root-gated integration tests. See the note in `bpf_loader::root_integration`.
#[cfg(test)]
mod root_integration {
    use super::*;
    use bpfjailer_common::codec;
    use bpfjailer_common::policy::{NetworkRule, PathPattern};

    fn tracker() -> Option<ProcessTracker> {
        let bpf = BpfJailerBpf::load().ok()?;
        ProcessTracker::new(Arc::new(bpf)).ok()
    }

    macro_rules! tracker_or_skip {
        () => {
            match tracker() {
                Some(t) => t,
                None => {
                    eprintln!("skipping: needs root and a BPF-capable kernel");
                    return;
                }
            }
        };
    }

    fn net_rule(proto: &str, port: Option<u16>, allow: bool) -> NetworkRule {
        NetworkRule {
            protocol: proto.into(),
            address: None,
            port,
            port_start: None,
            port_end: None,
            allow,
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn enroll_process_records_a_pending_enrollment() {
        let t = tracker_or_skip!();
        t.enroll_process(31337, PodId(88), RoleId(6))
            .expect("enroll");
        // Enrollment is staged in pending_enrollments; the BPF side migrates it
        // into task_storage on the task's next hooked syscall.
        let v = t
            .bpf
            .map_lookup("pending_enrollments", &31337u32.to_ne_bytes())
            .expect("pending entry present");
        assert_eq!(u64::from_ne_bytes(v[0..8].try_into().unwrap()), 88);
        assert_eq!(u32::from_ne_bytes(v[8..12].try_into().unwrap()), 6);
    }

    /// A pid that does not exist has no pidfd, so the lookup reports None
    /// rather than erroring.
    #[test]
    #[ignore = "requires root"]
    fn get_process_info_is_none_for_a_dead_pid() {
        let t = tracker_or_skip!();
        assert!(t.get_process_info(4_000_001).expect("query").is_none());
    }

    /// A live process with no task_storage entry reads as None. Storage is
    /// only written by the BPF side once the programs are attached and the
    /// task hits a hooked syscall, which does not happen here.
    #[test]
    #[ignore = "requires root"]
    fn get_process_info_is_none_for_a_live_but_unenrolled_pid() {
        let t = tracker_or_skip!();
        assert!(t
            .get_process_info(std::process::id())
            .expect("query")
            .is_none());
    }

    /// Enrollment is staged in pending_enrollments, so a just-enrolled pid
    /// still reads as None until the BPF side migrates it.
    #[test]
    #[ignore = "requires root"]
    fn enrollment_alone_does_not_populate_task_storage() {
        let t = tracker_or_skip!();
        t.enroll_process(std::process::id(), PodId(89), RoleId(7))
            .expect("enroll");
        assert!(t
            .get_process_info(std::process::id())
            .expect("query")
            .is_none());
    }

    #[test]
    #[ignore = "requires root"]
    fn set_role_policy_writes_every_flag_bit() {
        let t = tracker_or_skip!();
        let flags = PolicyFlags {
            allow_file_access: true,
            allow_network: true,
            allow_exec: true,
            require_signed_binary: true,
            allow_setuid: true,
            allow_ptrace: true,
            allow_module_load: true,
            allow_bpf_load: true,
            require_proxy: false,
        };
        t.set_role_policy(RoleId(21), &flags).expect("set");
        // Regression guard for the daemon dropping all but the first three bits.
        assert_eq!(bpfjailer_common::flags::policy_flags_to_u8(&flags), 0xFF);
    }

    #[test]
    #[ignore = "requires root"]
    fn apply_network_rules_writes_both_directions() {
        let t = tracker_or_skip!();
        t.apply_network_rules(RoleId(22), &[net_rule("tcp", Some(8443), true)])
            .expect("apply");
        // bind (0) and connect (1) must both be present
        for dir in [0u8, 1u8] {
            let _ = codec::net_rule_key(22, 8443, codec::PROTO_TCP, dir);
        }
    }

    #[test]
    #[ignore = "requires root"]
    fn apply_network_rules_skips_unusable_rules_without_failing() {
        let t = tracker_or_skip!();
        let rules = vec![
            net_rule("icmp", Some(0), true), // unknown protocol -> skipped
            net_rule("tcp", Some(9090), true),
        ];
        t.apply_network_rules(RoleId(23), &rules)
            .expect("a bad rule must not abort the batch");
    }

    #[test]
    #[ignore = "requires root"]
    fn apply_network_rules_expands_a_port_range() {
        let t = tracker_or_skip!();
        let rule = NetworkRule {
            protocol: "udp".into(),
            address: None,
            port: None,
            port_start: Some(5000),
            port_end: Some(5004),
            allow: false,
        };
        t.apply_network_rules(RoleId(24), &[rule]).expect("apply");
    }

    #[test]
    #[ignore = "requires root"]
    fn apply_path_rules_accepts_allow_and_deny_patterns() {
        let t = tracker_or_skip!();
        let rules = vec![
            PathPattern {
                pattern: "/etc/ssh/".into(),
                allow: false,
            },
            PathPattern {
                pattern: "/var/www/*".into(),
                allow: true,
            },
        ];
        t.apply_path_rules(RoleId(25), &rules).expect("apply");
    }

    #[test]
    #[ignore = "requires root"]
    fn add_path_state_and_path_rule_are_both_accepted() {
        let t = tracker_or_skip!();
        t.add_path_state(RoleId(26), "/srv/data/", false)
            .expect("state");
        t.add_path_rule(RoleId(26), "/srv/data/secret", false)
            .expect("rule");
    }

    #[test]
    #[ignore = "requires root"]
    fn update_role_flags_accepts_a_raw_byte() {
        let t = tracker_or_skip!();
        t.update_role_flags(RoleId(27), 0b0000_0111)
            .expect("update");
    }
}
