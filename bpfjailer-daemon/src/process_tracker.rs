use crate::bpf_loader::BpfJailerBpf;
use anyhow::{Context, Result};
use bpfjailer_common::{
    DomainRule, IpRule, NetworkRule, PathPattern, PodId, PolicyFlags, ProxyConfig, RoleId,
};
use log::{debug, info, warn};
use std::sync::Arc;

// Protocol constants
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// Direction constants
pub const DIR_BIND: u8 = 0;
pub const DIR_CONNECT: u8 = 1;

pub struct ProcessTracker {
    bpf: Arc<BpfJailerBpf>,
}

// Convert PolicyFlags to u8 for BPF map
// bit 0 (0x01) = allow_file_access
// bit 1 (0x02) = allow_network
// bit 2 (0x04) = allow_exec
fn policy_flags_to_u8(flags: &PolicyFlags) -> u8 {
    let mut result = 0u8;
    if flags.allow_file_access {
        result |= 0x01;
    }
    if flags.allow_network {
        result |= 0x02;
    }
    if flags.allow_exec {
        result |= 0x04;
    }
    result
}

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

    pub fn get_process_info(&self, pid: u32) -> Result<Option<(PodId, RoleId)>> {
        // Task storage is managed by kernel, we can't directly query it from userspace
        // This would need to be implemented via a separate eBPF program or map
        debug!("Querying process info for PID {}", pid);
        Ok(None)
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
            let protocol = match rule.protocol.to_lowercase().as_str() {
                "tcp" => PROTO_TCP,
                "udp" => PROTO_UDP,
                other => {
                    warn!("Unknown protocol '{}', skipping rule", other);
                    continue;
                }
            };

            // Handle port range or single port
            let ports: Vec<u16> = if let (Some(start), Some(end)) = (rule.port_start, rule.port_end)
            {
                // Port range specified
                if start > end {
                    warn!("Invalid port range {}-{}, skipping", start, end);
                    continue;
                }
                let range_size = (end - start + 1) as usize;
                if range_size > 1000 {
                    warn!(
                        "Port range {}-{} has {} ports (large ranges use many map entries)",
                        start, end, range_size
                    );
                }
                (start..=end).collect()
            } else if let Some(port) = rule.port {
                // Single port
                vec![port]
            } else {
                // Wildcard (all ports)
                vec![0]
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

    /// Apply IP rules from a Role definition
    pub fn apply_ip_rules(&self, role_id: RoleId, rules: &[IpRule]) -> Result<()> {
        for rule in rules {
            let direction = match rule.direction.to_lowercase().as_str() {
                "bind" => DIR_BIND,
                "connect" => DIR_CONNECT,
                _ => DIR_CONNECT, // Default to connect for egress control
            };

            self.add_ip_rule(role_id, &rule.cidr, direction, rule.allow)?;

            info!(
                "Applied IP rule: role={} cidr={} direction={} allow={}",
                role_id.0, rule.cidr, rule.direction, rule.allow
            );
        }
        Ok(())
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

    /// Apply domain rules from a Role definition
    pub fn apply_domain_rules(&self, role_id: RoleId, rules: &[DomainRule]) -> Result<()> {
        for rule in rules {
            self.add_domain_rule(role_id, &rule.domain, rule.allow)?;

            info!(
                "Applied domain rule: role={} domain={} allow={}",
                role_id.0, rule.domain, rule.allow
            );
        }
        Ok(())
    }
}
