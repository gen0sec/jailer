//! One place that turns a [`Role`] into map writes.
//!
//! The daemon and the daemonless bootstrap previously each walked a `Role` and
//! decided what to apply. They drifted three times: the daemon packed only
//! three of eight flag bits, both carried their own copy of the path-pattern
//! walk, and the bootstrap silently ignored `ip_rules`, `domain_rules` and
//! `proxy` entirely -- a policy asking for them was applied as if those
//! sections were not there.
//!
//! [`apply_role`] is the single walk. Anything that can write BPF maps
//! implements [`PolicySink`], and adding a field to `Role` means adding it
//! here once, where `apply_role_covers_every_enforcing_field` will
//! notice if it is skipped.

use crate::flags::policy_flags_to_u8;
use crate::policy::Role;
use std::net::Ipv4Addr;

/// Turns a policy domain into the addresses it currently resolves to.
///
/// Injected so [`apply_role`] stays testable without touching the network, and
/// so both modes resolve identically.
pub trait DomainResolver {
    fn resolve(&self, domain: &str) -> Vec<Ipv4Addr>;
}

/// Resolves through the system resolver.
pub struct SystemResolver;

impl DomainResolver for SystemResolver {
    fn resolve(&self, domain: &str) -> Vec<Ipv4Addr> {
        use std::net::ToSocketAddrs;
        // Port is irrelevant; ToSocketAddrs just needs one to parse.
        match (domain, 0u16).to_socket_addrs() {
            Ok(addrs) => addrs
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    // BPF matches on IPv4 only, so v6 answers are dropped
                    // rather than silently treated as covered.
                    std::net::IpAddr::V6(_) => None,
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// Somewhere role rules can be written. Implemented over the daemon's BPF
/// handle and over the bootstrap's raw object.
///
/// Methods take plain data rather than map handles so this crate stays free of
/// libbpf.
pub trait PolicySink {
    type Err;

    fn set_role_flags(&mut self, role_id: u32, flags: u8) -> Result<(), Self::Err>;
    fn add_path_state(&mut self, role_id: u32, pattern: &str, allow: bool)
        -> Result<(), Self::Err>;
    fn add_network_rule(
        &mut self,
        role_id: u32,
        port: u16,
        protocol: u8,
        direction: u8,
        allow: bool,
    ) -> Result<(), Self::Err>;
    fn add_ip_rule(
        &mut self,
        role_id: u32,
        cidr: &str,
        direction: u8,
        allow: bool,
    ) -> Result<(), Self::Err>;
    fn add_domain_rule(&mut self, role_id: u32, domain: &str, allow: bool)
        -> Result<(), Self::Err>;
    fn set_proxy(&mut self, role_id: u32, address: &str, required: bool) -> Result<(), Self::Err>;
    /// Record that `ip` currently resolves to the domain hashed as
    /// `domain_hash`, so BPF can map a connect target back to a name.
    fn cache_resolved_ip(
        &mut self,
        role_id: u32,
        ip: Ipv4Addr,
        domain_hash: u64,
    ) -> Result<(), Self::Err>;
}

/// Directions a rule is written for: 0 = bind, 1 = connect.
const BIND: u8 = 0;
const CONNECT: u8 = 1;

/// Apply every enforcing section of a role.
///
/// Unusable rules are skipped rather than aborting the role -- an unknown
/// protocol or an inverted port range should not stop the rest of the policy
/// being applied -- but the caller is told via the returned skip list so it can
/// log rather than swallow them.
pub fn apply_role<S: PolicySink, R: DomainResolver + ?Sized>(
    sink: &mut S,
    role: &Role,
    resolver: &R,
) -> Result<Vec<String>, S::Err> {
    let role_id = role.id.0;
    let mut skipped = Vec::new();

    sink.set_role_flags(role_id, policy_flags_to_u8(&role.flags))?;

    for p in &role.file_paths {
        sink.add_path_state(role_id, &p.pattern, p.allow)?;
    }

    for r in &role.network_rules {
        match crate::codec::expand_network_rule(&r.protocol, r.port, r.port_start, r.port_end) {
            Some((protocol, ports)) => {
                for port in ports {
                    sink.add_network_rule(role_id, port, protocol, BIND, r.allow)?;
                    sink.add_network_rule(role_id, port, protocol, CONNECT, r.allow)?;
                }
            }
            None => skipped.push(format!("network rule for protocol {:?}", r.protocol)),
        }
    }

    for r in &role.ip_rules {
        let direction = match r.direction.as_str() {
            "bind" => BIND,
            "connect" => CONNECT,
            other => {
                skipped.push(format!("ip rule {} with direction {other:?}", r.cidr));
                continue;
            }
        };
        sink.add_ip_rule(role_id, &r.cidr, direction, r.allow)?;
    }

    for r in &role.domain_rules {
        sink.add_domain_rule(role_id, &r.domain, r.allow)?;

        // BPF matches a connect target by address, so the rule only bites for
        // addresses we have associated with the name.
        let addrs = resolver.resolve(&r.domain);
        if addrs.is_empty() {
            skipped.push(format!(
                "domain rule {} (resolved to no IPv4 address, so it will not match)",
                r.domain
            ));
            continue;
        }
        let hash = crate::hash::fnv1a_hash_u64(&r.domain);
        for ip in addrs {
            sink.cache_resolved_ip(role_id, ip, hash)?;
        }
    }

    if let Some(p) = &role.proxy {
        sink.set_proxy(role_id, &p.address, p.required)?;
    }

    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DomainRule, IpRule, NetworkRule, PathPattern, ProxyConfig};
    use crate::types::{PolicyFlags, RoleId};

    #[derive(Default)]
    struct Recorder {
        flags: Vec<(u32, u8)>,
        paths: Vec<(u32, String, bool)>,
        net: Vec<(u32, u16, u8, u8, bool)>,
        ip: Vec<(u32, String, u8, bool)>,
        domain: Vec<(u32, String, bool)>,
        proxy: Vec<(u32, String, bool)>,
        cached: Vec<(u32, Ipv4Addr, u64)>,
    }

    /// Resolves every name to a fixed address, so tests never touch DNS.
    struct FakeResolver(Vec<Ipv4Addr>);
    impl DomainResolver for FakeResolver {
        fn resolve(&self, _domain: &str) -> Vec<Ipv4Addr> {
            self.0.clone()
        }
    }
    fn resolving() -> FakeResolver {
        FakeResolver(vec!["93.184.216.34".parse().unwrap()])
    }
    fn resolving_nothing() -> FakeResolver {
        FakeResolver(Vec::new())
    }

    impl PolicySink for Recorder {
        type Err = std::convert::Infallible;
        fn set_role_flags(&mut self, r: u32, f: u8) -> Result<(), Self::Err> {
            self.flags.push((r, f));
            Ok(())
        }
        fn add_path_state(&mut self, r: u32, p: &str, a: bool) -> Result<(), Self::Err> {
            self.paths.push((r, p.into(), a));
            Ok(())
        }
        fn add_network_rule(
            &mut self,
            r: u32,
            port: u16,
            proto: u8,
            dir: u8,
            a: bool,
        ) -> Result<(), Self::Err> {
            self.net.push((r, port, proto, dir, a));
            Ok(())
        }
        fn add_ip_rule(&mut self, r: u32, c: &str, d: u8, a: bool) -> Result<(), Self::Err> {
            self.ip.push((r, c.into(), d, a));
            Ok(())
        }
        fn add_domain_rule(&mut self, r: u32, d: &str, a: bool) -> Result<(), Self::Err> {
            self.domain.push((r, d.into(), a));
            Ok(())
        }
        fn set_proxy(&mut self, r: u32, addr: &str, req: bool) -> Result<(), Self::Err> {
            self.proxy.push((r, addr.into(), req));
            Ok(())
        }
        fn cache_resolved_ip(&mut self, r: u32, ip: Ipv4Addr, h: u64) -> Result<(), Self::Err> {
            self.cached.push((r, ip, h));
            Ok(())
        }
    }

    /// A role exercising every enforcing section.
    fn full_role() -> Role {
        Role {
            id: RoleId(7),
            name: "full".into(),
            flags: PolicyFlags {
                allow_file_access: true,
                allow_network: true,
                allow_exec: true,
                require_signed_binary: false,
                allow_setuid: true,
                allow_ptrace: true,
                allow_module_load: true,
                allow_bpf_load: true,
                require_proxy: false,
            },
            file_paths: vec![PathPattern {
                pattern: "/etc/shadow".into(),
                allow: false,
            }],
            network_rules: vec![NetworkRule {
                protocol: "tcp".into(),
                address: None,
                port: Some(443),
                port_start: None,
                port_end: None,
                allow: true,
            }],
            execution_rules: vec![],
            require_signed_binary: false,
            ip_rules: vec![IpRule {
                cidr: "10.0.0.0/8".into(),
                direction: "connect".into(),
                allow: false,
            }],
            domain_rules: vec![DomainRule {
                domain: "api.example.com".into(),
                allow: true,
            }],
            proxy: Some(ProxyConfig {
                address: "127.0.0.1:3128".into(),
                required: true,
            }),
        }
    }

    /// The regression that motivated this module: the bootstrap applied flags,
    /// paths and network rules but silently dropped ip_rules, domain_rules and
    /// proxy. Every enforcing section must reach the sink.
    #[test]
    fn apply_role_covers_every_enforcing_field() {
        let mut rec = Recorder::default();
        let skipped = apply_role(&mut rec, &full_role(), &resolving()).unwrap();
        assert!(skipped.is_empty(), "nothing should be skipped: {skipped:?}");

        assert_eq!(rec.flags.len(), 1, "flags not applied");
        assert_eq!(rec.paths.len(), 1, "file_paths not applied");
        assert!(!rec.net.is_empty(), "network_rules not applied");
        assert_eq!(rec.ip.len(), 1, "ip_rules not applied");
        assert_eq!(rec.domain.len(), 1, "domain_rules not applied");
        assert_eq!(rec.proxy.len(), 1, "proxy not applied");
    }

    #[test]
    fn network_rules_are_written_for_both_directions() {
        let mut rec = Recorder::default();
        apply_role(&mut rec, &full_role(), &resolving()).unwrap();
        let dirs: Vec<u8> = rec.net.iter().map(|n| n.3).collect();
        assert!(dirs.contains(&BIND) && dirs.contains(&CONNECT));
    }

    #[test]
    fn ip_rule_direction_is_translated() {
        let mut role = full_role();
        role.ip_rules[0].direction = "bind".into();
        let mut rec = Recorder::default();
        apply_role(&mut rec, &role, &resolving()).unwrap();
        assert_eq!(rec.ip[0].2, BIND);
    }

    #[test]
    fn an_unknown_ip_direction_is_reported_not_applied() {
        let mut role = full_role();
        role.ip_rules[0].direction = "sideways".into();
        let mut rec = Recorder::default();
        let skipped = apply_role(&mut rec, &role, &resolving()).unwrap();
        assert!(rec.ip.is_empty(), "must not guess a direction");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("sideways"), "{skipped:?}");
    }

    #[test]
    fn an_unusable_network_rule_is_reported_and_the_rest_still_applies() {
        let mut role = full_role();
        role.network_rules.insert(
            0,
            NetworkRule {
                protocol: "icmp".into(),
                address: None,
                port: Some(0),
                port_start: None,
                port_end: None,
                allow: true,
            },
        );
        let mut rec = Recorder::default();
        let skipped = apply_role(&mut rec, &role, &resolving()).unwrap();
        assert_eq!(skipped.len(), 1, "the icmp rule should be reported");
        assert!(!rec.net.is_empty(), "the tcp rule must still be applied");
        assert_eq!(rec.proxy.len(), 1, "later sections must still be applied");
    }

    #[test]
    fn a_role_with_no_optional_sections_applies_only_flags() {
        let mut role = full_role();
        role.file_paths.clear();
        role.network_rules.clear();
        role.ip_rules.clear();
        role.domain_rules.clear();
        role.proxy = None;
        let mut rec = Recorder::default();
        apply_role(&mut rec, &role, &resolving()).unwrap();
        assert_eq!(rec.flags.len(), 1);
        assert!(rec.paths.is_empty() && rec.net.is_empty() && rec.ip.is_empty());
        assert!(rec.domain.is_empty() && rec.proxy.is_empty());
    }

    /// A domain rule only bites for addresses we have associated with the
    /// name, so applying one must also populate the cache.
    #[test]
    fn domain_rules_populate_the_resolved_address_cache() {
        let mut rec = Recorder::default();
        apply_role(&mut rec, &full_role(), &resolving()).unwrap();
        assert_eq!(rec.domain.len(), 1);
        assert_eq!(rec.cached.len(), 1, "resolved address not cached");
        let (role, ip, hash) = rec.cached[0];
        assert_eq!(role, 7);
        assert_eq!(ip, "93.184.216.34".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hash, crate::hash::fnv1a_hash_u64("api.example.com"));
    }

    #[test]
    fn every_resolved_address_is_cached() {
        let mut rec = Recorder::default();
        let r = FakeResolver(vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()]);
        apply_role(&mut rec, &full_role(), &r).unwrap();
        assert_eq!(
            rec.cached.len(),
            2,
            "a name with several addresses needs all of them"
        );
    }

    /// A name that resolves to nothing cannot match, so say so rather than
    /// leaving the operator thinking the rule is in force.
    #[test]
    fn an_unresolvable_domain_is_reported() {
        let mut rec = Recorder::default();
        let skipped = apply_role(&mut rec, &full_role(), &resolving_nothing()).unwrap();
        assert!(rec.cached.is_empty());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("api.example.com"), "{skipped:?}");
        assert!(skipped[0].contains("will not match"), "{skipped:?}");
        assert_eq!(rec.domain.len(), 1, "the rule itself is still written");
    }

    #[test]
    fn every_write_carries_the_roles_own_id() {
        let mut rec = Recorder::default();
        apply_role(&mut rec, &full_role(), &resolving()).unwrap();
        assert!(rec.flags.iter().all(|x| x.0 == 7));
        assert!(rec.paths.iter().all(|x| x.0 == 7));
        assert!(rec.net.iter().all(|x| x.0 == 7));
        assert!(rec.ip.iter().all(|x| x.0 == 7));
        assert!(rec.domain.iter().all(|x| x.0 == 7));
        assert!(rec.proxy.iter().all(|x| x.0 == 7));
        assert!(rec.cached.iter().all(|x| x.0 == 7));
    }
}
