//! Byte layouts for the BPF maps.
//!
//! Every map key and value the userspace loaders write must match the struct
//! definitions in `bpfjailer-bpf/src/main.bpf.c` exactly. A wrong offset or
//! width does not fail loudly — the lookup simply misses and the policy stops
//! applying — so these encoders are kept in one place, away from the libbpf
//! calls, where they can be tested.
//!
//! All integers are native-endian, matching how the BPF side reads them. The
//! one exception is the IP address in [`ip_rule_key`], which is stored in
//! network byte order to match `sin_addr.s_addr`.

use crate::hash::fnv1a_hash_u64;
use std::net::Ipv4Addr;

/// Terminal state meaning "allow", written into `path_state_value.next_state`.
pub const PATH_STATE_ACCEPT: u64 = 0xFFFF_FFFF_FFFF_FFFE;
/// Terminal state meaning "deny".
pub const PATH_STATE_REJECT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// `struct path_state_key { u32 role_id; u64 state; u64 component_hash; }`
pub fn path_state_key(role_id: u32, state: u64, component_hash: u64) -> [u8; 24] {
    let mut k = [0u8; 24];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[8..16].copy_from_slice(&state.to_ne_bytes());
    k[16..24].copy_from_slice(&component_hash.to_ne_bytes());
    k
}

/// `struct path_state_value { u64 next_state; u8 is_terminal; u8 decision; u8 wildcard; u8 _pad; }`
pub fn path_state_value(
    next_state: u64,
    is_terminal: bool,
    allow: bool,
    wildcard: bool,
) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&next_state.to_ne_bytes());
    v[8] = is_terminal as u8;
    v[9] = allow as u8;
    v[10] = wildcard as u8;
    v[11] = 0;
    v
}

/// Split a policy pattern into the components the state machine walks.
///
/// Empty segments and `**` are dropped: `**` means "any depth" and is handled
/// by the walk itself rather than by a transition.
pub fn pattern_components(pattern: &str) -> Vec<&str> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty() && *s != "**")
        .collect()
}

/// Build every `(key, value)` pair for one path pattern.
///
/// Shared by the daemon and the daemonless bootstrap, which previously each
/// had their own copy of this walk.
pub fn path_state_entries(role_id: u32, pattern: &str, allow: bool) -> Vec<([u8; 24], [u8; 16])> {
    let components = pattern_components(pattern);
    let mut out = Vec::with_capacity(components.len());
    let mut state: u64 = 0;

    for (i, component) in components.iter().enumerate() {
        let is_last = i == components.len() - 1;
        let is_wildcard = *component == "*";
        // A wildcard is stored as hash 0, which the BPF side treats as
        // "match any component".
        let component_hash = if is_wildcard {
            0
        } else {
            fnv1a_hash_u64(component)
        };

        let next_state = if is_last {
            if allow {
                PATH_STATE_ACCEPT
            } else {
                PATH_STATE_REJECT
            }
        } else {
            fnv1a_hash_u64(&format!("{}:{}", role_id, components[..=i].join("/")))
        };

        out.push((
            path_state_key(role_id, state, component_hash),
            path_state_value(next_state, is_last, allow, is_wildcard),
        ));
        state = next_state;
    }

    // A pattern ending in "/" names a directory: anything beneath it inherits
    // the decision, expressed as a wildcard transition out of the final state.
    if pattern.ends_with('/') && !out.is_empty() {
        let terminal = if allow {
            PATH_STATE_ACCEPT
        } else {
            PATH_STATE_REJECT
        };
        out.push((
            path_state_key(role_id, state, 0),
            path_state_value(terminal, true, allow, true),
        ));
    }
    out
}

/// `struct net_rule_key { u32 role_id; u16 port; u8 protocol; u8 direction; }`
pub fn net_rule_key(role_id: u32, port: u16, protocol: u8, direction: u8) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[4..6].copy_from_slice(&port.to_ne_bytes());
    k[6] = protocol;
    k[7] = direction;
    k
}

/// `struct domain_rule_key { u32 role_id; u64 domain_hash; }` (4 bytes padding)
pub fn domain_rule_key(role_id: u32, domain: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[8..16].copy_from_slice(&fnv1a_hash_u64(domain).to_ne_bytes());
    k
}

/// `struct exec_enrollment_value { u64 pod_id; u32 role_id; u32 _pad; }`
pub fn enrollment_value(pod_id: u64, role_id: u32) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&pod_id.to_ne_bytes());
    v[8..12].copy_from_slice(&role_id.to_ne_bytes());
    v
}

/// `struct process_info { u64 pod_id; u32 role_id; u8 stack_depth; u8 flags; }`
pub fn process_info_value(pod_id: u64, role_id: u32, stack_depth: u8, flags: u8) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&pod_id.to_ne_bytes());
    v[8..12].copy_from_slice(&role_id.to_ne_bytes());
    v[12] = stack_depth;
    v[13] = flags;
    v
}

/// Parse `a.b.c.d` or `a.b.c.d/len` into an address and prefix length.
///
/// A bare address is treated as `/32`.
pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_str, prefix_len) = match cidr.find('/') {
        Some(pos) => {
            let (ip, prefix) = cidr.split_at(pos);
            let len: u8 = prefix[1..]
                .parse()
                .map_err(|_| format!("Invalid prefix length in CIDR: {cidr}"))?;
            if len > 32 {
                return Err(format!("Prefix length out of range in CIDR: {cidr}"));
            }
            (ip, len)
        }
        None => (cidr, 32u8),
    };
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| format!("Invalid IPv4 address: {ip_str}"))?;
    Ok((ip, prefix_len))
}

/// Apply a prefix mask, returning the network address.
pub fn mask_ipv4(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = match prefix_len {
        0 => 0u32,
        n if n >= 32 => !0u32,
        n => !0u32 << (32 - n),
    };
    Ipv4Addr::from(u32::from_be_bytes(ip.octets()) & mask)
}

/// `struct ip_rule_key { u32 role_id; u32 ip_addr; u8 prefix_len; u8 direction; u8 _pad[2]; }`
///
/// `ip_addr` is stored in network byte order to match `sin_addr.s_addr`.
pub fn ip_rule_key(role_id: u32, ip: Ipv4Addr, prefix_len: u8, direction: u8) -> [u8; 12] {
    let masked = mask_ipv4(ip, prefix_len);
    let mut k = [0u8; 12];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[4..8].copy_from_slice(&masked.octets());
    k[8] = prefix_len;
    k[9] = direction;
    k
}

/// Parse `host:port`.
pub fn parse_proxy_addr(addr: &str) -> Result<(Ipv4Addr, u16), String> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Proxy address must be host:port, got: {addr}"));
    }
    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid proxy IPv4 address: {}", parts[0]))?;
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid proxy port: {}", parts[1]))?;
    Ok((ip, port))
}

/// `struct proxy_config { u32 proxy_ip; u16 proxy_port; u8 require_proxy; u8 _pad; }`
pub fn proxy_config_value(ip: Ipv4Addr, port: u16, required: bool) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[0..4].copy_from_slice(&u32::from_be_bytes(ip.octets()).to_ne_bytes());
    v[4..6].copy_from_slice(&port.to_ne_bytes());
    v[6] = required as u8;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le(bytes: &[u8]) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(bytes);
        u64::from_ne_bytes(b)
    }
    fn le32(bytes: &[u8]) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(bytes);
        u32::from_ne_bytes(b)
    }

    // ---- path state ----

    #[test]
    fn path_state_key_places_fields_at_the_c_offsets() {
        let k = path_state_key(7, 0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00);
        assert_eq!(le32(&k[0..4]), 7, "role_id at 0");
        assert_eq!(&k[4..8], &[0, 0, 0, 0], "padding before the u64");
        assert_eq!(le(&k[8..16]), 0x1122_3344_5566_7788, "state at 8");
        assert_eq!(
            le(&k[16..24]),
            0x99AA_BBCC_DDEE_FF00,
            "component_hash at 16"
        );
    }

    #[test]
    fn path_state_value_places_flags_after_the_u64() {
        let v = path_state_value(PATH_STATE_ACCEPT, true, true, false);
        assert_eq!(le(&v[0..8]), PATH_STATE_ACCEPT);
        assert_eq!((v[8], v[9], v[10], v[11]), (1, 1, 0, 0));
    }

    #[test]
    fn accept_and_reject_sentinels_are_distinct() {
        assert_ne!(PATH_STATE_ACCEPT, PATH_STATE_REJECT);
    }

    #[test]
    fn pattern_components_drops_empty_segments_and_double_star() {
        assert_eq!(pattern_components("/var/www/**"), vec!["var", "www"]);
        assert_eq!(pattern_components("//a///b//"), vec!["a", "b"]);
        assert_eq!(pattern_components("/"), Vec::<&str>::new());
        assert_eq!(pattern_components(""), Vec::<&str>::new());
    }

    #[test]
    fn pattern_components_keeps_single_star() {
        assert_eq!(pattern_components("/a/*/b"), vec!["a", "*", "b"]);
    }

    #[test]
    fn path_state_entries_is_empty_for_a_pattern_with_no_components() {
        assert!(path_state_entries(1, "/", true).is_empty());
        assert!(path_state_entries(1, "/**", true).is_empty());
    }

    #[test]
    fn path_state_entries_emits_one_transition_per_component() {
        assert_eq!(path_state_entries(1, "/etc/ssh/sshd_config", true).len(), 3);
    }

    #[test]
    fn path_state_entries_starts_from_the_root_state() {
        let e = path_state_entries(1, "/etc/passwd", true);
        assert_eq!(le(&e[0].0[8..16]), 0, "first transition leaves state 0");
    }

    #[test]
    fn path_state_entries_chains_state_to_next_state() {
        let e = path_state_entries(1, "/a/b/c", true);
        for w in e.windows(2) {
            let next_state_of_prev = le(&w[0].1[0..8]);
            let state_of_this = le(&w[1].0[8..16]);
            assert_eq!(next_state_of_prev, state_of_this, "states must chain");
        }
    }

    #[test]
    fn only_the_last_component_is_terminal() {
        let e = path_state_entries(1, "/a/b/c", true);
        assert_eq!(e[0].1[8], 0);
        assert_eq!(e[1].1[8], 0);
        assert_eq!(e[2].1[8], 1, "last component is terminal");
        assert_eq!(le(&e[2].1[0..8]), PATH_STATE_ACCEPT);
    }

    #[test]
    fn deny_patterns_terminate_in_reject() {
        let e = path_state_entries(1, "/etc/shadow", false);
        let last = e.last().unwrap();
        assert_eq!(le(&last.1[0..8]), PATH_STATE_REJECT);
        assert_eq!(last.1[9], 0, "decision byte is deny");
    }

    #[test]
    fn wildcard_component_is_stored_as_hash_zero_and_flagged() {
        let e = path_state_entries(1, "/a/*/c", true);
        assert_eq!(le(&e[1].0[16..24]), 0, "wildcard hashes to 0");
        assert_eq!(e[1].1[10], 1, "wildcard flag set");
        assert_eq!(e[0].1[10], 0, "non-wildcard flag clear");
    }

    #[test]
    fn different_roles_produce_different_keys_for_the_same_pattern() {
        let a = path_state_entries(1, "/etc/passwd", true);
        let b = path_state_entries(2, "/etc/passwd", true);
        assert_ne!(a[0].0, b[0].0, "role_id must be part of the key");
    }

    #[test]
    fn distinct_patterns_do_not_share_intermediate_states() {
        let a = path_state_entries(1, "/etc/ssh", true);
        let b = path_state_entries(1, "/var/ssh", true);
        assert_ne!(le(&a[0].1[0..8]), le(&b[0].1[0..8]));
    }

    // ---- other maps ----

    #[test]
    fn trailing_slash_appends_a_wildcard_terminal() {
        let file = path_state_entries(1, "/var/log", false);
        let dir = path_state_entries(1, "/var/log/", false);
        assert_eq!(dir.len(), file.len() + 1, "directory adds one transition");
        let extra = dir.last().unwrap();
        assert_eq!(le(&extra.0[16..24]), 0, "wildcard component");
        assert_eq!(extra.1[8], 1, "terminal");
        assert_eq!(extra.1[10], 1, "wildcard flag");
        assert_eq!(le(&extra.1[0..8]), PATH_STATE_REJECT);
    }

    #[test]
    fn trailing_slash_on_an_empty_pattern_adds_nothing() {
        assert!(path_state_entries(1, "/", true).is_empty());
    }

    #[test]
    fn net_rule_key_layout() {
        let k = net_rule_key(3, 443, 6, 1);
        assert_eq!(le32(&k[0..4]), 3);
        assert_eq!(u16::from_ne_bytes([k[4], k[5]]), 443);
        assert_eq!((k[6], k[7]), (6, 1));
    }

    #[test]
    fn the_domain_rule_key_pads_before_the_hash() {
        let d = domain_rule_key(5, "api.example.com");
        assert_eq!(le32(&d[0..4]), 5);
        assert_eq!(&d[4..8], &[0, 0, 0, 0]);
        assert_eq!(le(&d[8..16]), fnv1a_hash_u64("api.example.com"));
    }

    #[test]
    fn enrollment_value_layout() {
        let v = enrollment_value(0xDEAD_BEEF_1234_5678, 9);
        assert_eq!(le(&v[0..8]), 0xDEAD_BEEF_1234_5678);
        assert_eq!(le32(&v[8..12]), 9);
        assert_eq!(&v[12..16], &[0, 0, 0, 0], "explicit padding stays zero");
    }

    #[test]
    fn process_info_value_layout() {
        let v = process_info_value(42, 7, 3, 0x80);
        assert_eq!(le(&v[0..8]), 42);
        assert_eq!(le32(&v[8..12]), 7);
        assert_eq!((v[12], v[13]), (3, 0x80));
    }

    // ---- CIDR ----

    #[test]
    fn parse_cidr_accepts_prefix_and_bare_address() {
        assert_eq!(
            parse_cidr("10.0.0.0/8").unwrap(),
            ("10.0.0.0".parse().unwrap(), 8)
        );
        assert_eq!(
            parse_cidr("192.168.1.1").unwrap(),
            ("192.168.1.1".parse().unwrap(), 32),
            "a bare address is a /32"
        );
        assert_eq!(parse_cidr("0.0.0.0/0").unwrap().1, 0);
    }

    #[test]
    fn parse_cidr_rejects_malformed_input() {
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/abc",
            "10.0.0.0/33",
            "999.1.1.1",
            "10.0.0.0/",
        ] {
            assert!(parse_cidr(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn mask_ipv4_zeroes_the_host_bits() {
        assert_eq!(
            mask_ipv4("10.1.2.3".parse().unwrap(), 8),
            "10.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            mask_ipv4("192.168.1.130".parse().unwrap(), 24),
            "192.168.1.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            mask_ipv4("1.2.3.4".parse().unwrap(), 32),
            "1.2.3.4".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            mask_ipv4("1.2.3.4".parse().unwrap(), 0),
            "0.0.0.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn ip_rule_key_stores_the_masked_address_in_network_order() {
        let k = ip_rule_key(2, "10.1.2.3".parse().unwrap(), 8, 1);
        assert_eq!(le32(&k[0..4]), 2);
        assert_eq!(
            &k[4..8],
            &[10, 0, 0, 0],
            "network byte order, host bits cleared"
        );
        assert_eq!((k[8], k[9]), (8, 1));
        assert_eq!(&k[10..12], &[0, 0], "padding stays zero");
    }

    #[test]
    fn addresses_in_the_same_network_produce_the_same_key() {
        let a = ip_rule_key(1, "10.1.2.3".parse().unwrap(), 8, 0);
        let b = ip_rule_key(1, "10.9.9.9".parse().unwrap(), 8, 0);
        assert_eq!(a, b, "both are 10.0.0.0/8");
    }

    #[test]
    fn direction_is_part_of_the_key() {
        let bind = ip_rule_key(1, "10.0.0.1".parse().unwrap(), 32, 0);
        let conn = ip_rule_key(1, "10.0.0.1".parse().unwrap(), 32, 1);
        assert_ne!(bind, conn);
    }

    // ---- proxy ----

    #[test]
    fn parse_proxy_addr_accepts_host_port() {
        assert_eq!(
            parse_proxy_addr("127.0.0.1:8080").unwrap(),
            ("127.0.0.1".parse().unwrap(), 8080)
        );
    }

    #[test]
    fn parse_proxy_addr_rejects_malformed_input() {
        for bad in [
            "127.0.0.1",
            "127.0.0.1:",
            ":8080",
            "127.0.0.1:99999",
            "a:b:c",
            "",
        ] {
            assert!(parse_proxy_addr(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn proxy_config_value_layout() {
        let v = proxy_config_value("127.0.0.1".parse().unwrap(), 8080, true);
        assert_eq!(le32(&v[0..4]), u32::from_be_bytes([127, 0, 0, 1]));
        assert_eq!(u16::from_ne_bytes([v[4], v[5]]), 8080);
        assert_eq!(v[6], 1);
        assert_eq!(v[7], 0);
    }
}

/// Protocol numbers written into `net_rule_key.protocol`.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Resolve a policy protocol name to its number.
pub fn parse_protocol(name: &str) -> Option<u8> {
    match name.to_lowercase().as_str() {
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        _ => None,
    }
}

/// The ports a network rule expands to.
///
/// A rule may name a single port, an inclusive range, or neither — the last
/// case means "any port" and is encoded as the single port 0, which the BPF
/// side treats as a wildcard.
///
/// Returns `None` for a rule that must be skipped: an unknown protocol, or an
/// inverted range.
pub fn expand_network_rule(
    protocol: &str,
    port: Option<u16>,
    port_start: Option<u16>,
    port_end: Option<u16>,
) -> Option<(u8, Vec<u16>)> {
    let proto = parse_protocol(protocol)?;
    let ports = match (port_start, port_end) {
        (Some(start), Some(end)) => {
            if start > end {
                return None;
            }
            (start..=end).collect()
        }
        _ => match port {
            Some(p) => vec![p],
            None => vec![0],
        },
    };
    Some((proto, ports))
}

#[cfg(test)]
mod network_rule_tests {
    use super::*;

    #[test]
    fn parses_known_protocols_case_insensitively() {
        assert_eq!(parse_protocol("tcp"), Some(PROTO_TCP));
        assert_eq!(parse_protocol("TCP"), Some(PROTO_TCP));
        assert_eq!(parse_protocol("Udp"), Some(PROTO_UDP));
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert_eq!(parse_protocol("sctp"), None);
        assert_eq!(parse_protocol(""), None);
    }

    #[test]
    fn single_port_expands_to_one_entry() {
        assert_eq!(
            expand_network_rule("tcp", Some(443), None, None),
            Some((PROTO_TCP, vec![443]))
        );
    }

    #[test]
    fn range_expands_inclusively() {
        let (_, ports) = expand_network_rule("tcp", None, Some(8000), Some(8003)).unwrap();
        assert_eq!(ports, vec![8000, 8001, 8002, 8003]);
    }

    #[test]
    fn single_port_range_is_one_port() {
        let (_, ports) = expand_network_rule("udp", None, Some(53), Some(53)).unwrap();
        assert_eq!(ports, vec![53]);
    }

    #[test]
    fn no_port_means_wildcard_zero() {
        assert_eq!(
            expand_network_rule("udp", None, None, None),
            Some((PROTO_UDP, vec![0]))
        );
    }

    #[test]
    fn inverted_range_is_skipped_not_silently_widened() {
        assert_eq!(expand_network_rule("tcp", None, Some(9000), Some(80)), None);
    }

    #[test]
    fn unknown_protocol_skips_the_rule() {
        assert_eq!(expand_network_rule("icmp", Some(0), None, None), None);
    }

    #[test]
    fn range_takes_precedence_over_single_port() {
        let (_, ports) = expand_network_rule("tcp", Some(80), Some(1), Some(3)).unwrap();
        assert_eq!(ports, vec![1, 2, 3], "explicit range wins");
    }

    #[test]
    fn a_half_specified_range_falls_back_to_the_single_port() {
        let (_, ports) = expand_network_rule("tcp", Some(80), Some(8000), None).unwrap();
        assert_eq!(ports, vec![80]);
    }
}

/// `struct dns_cache_key { u32 role_id; u32 ip_addr; }`
///
/// `ip_addr` is network byte order, matching `sin_addr.s_addr` as BPF reads it.
pub fn dns_cache_key(role_id: u32, ip: Ipv4Addr) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[4..8].copy_from_slice(&ip.octets());
    k
}

/// `struct dns_cache_value { u64 domain_hash; u64 timestamp; }`
///
/// `timestamp` is written but not yet consulted: nothing expires entries, so a
/// stale address stays associated with its name until the next policy load.
pub fn dns_cache_value(domain_hash: u64, timestamp: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&domain_hash.to_ne_bytes());
    v[8..16].copy_from_slice(&timestamp.to_ne_bytes());
    v
}

#[cfg(test)]
mod dns_cache_tests {
    use super::*;

    #[test]
    fn dns_cache_key_layout() {
        let k = dns_cache_key(9, "93.184.216.34".parse().unwrap());
        assert_eq!(u32::from_ne_bytes(k[0..4].try_into().unwrap()), 9);
        assert_eq!(&k[4..8], &[93, 184, 216, 34], "network byte order");
    }

    #[test]
    fn dns_cache_value_layout() {
        let v = dns_cache_value(0xAABB_CCDD_1122_3344, 42);
        assert_eq!(
            u64::from_ne_bytes(v[0..8].try_into().unwrap()),
            0xAABB_CCDD_1122_3344
        );
        assert_eq!(u64::from_ne_bytes(v[8..16].try_into().unwrap()), 42);
    }

    #[test]
    fn different_roles_do_not_share_a_cache_entry() {
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        assert_ne!(dns_cache_key(1, ip), dns_cache_key(2, ip));
    }
}

/// A BPF hash lookup compares the *whole* key, padding included. A key struct
/// built with an initializer list leaves its padding as whatever the stack
/// held, so such a lookup matches only when that happens to be zero.
///
/// This cost us a domain rule that enforced roughly one connect in three: the
/// unpadded `dns_cache_key` hit every time while the padded `domain_rule_key`
/// beside it missed at random. These tests fail if a padded key is ever
/// initialized that way again.
/// The walk that consumes `path_state_entries`, mirrored in Rust so the
/// encoder's semantics are pinned by tests rather than only by a booted VM.
///
/// This is a mirror, not the enforcement path: it cannot catch a change made
/// only in the BPF program. It exists because the encoder side had no coverage
/// of what a rule set actually decides, which is how an inert allow-list went
/// unnoticed.
#[cfg(test)]
mod path_walk_semantics {
    use super::*;
    use std::collections::HashMap;

    /// Mirrors MAX_COMPONENTS in the BPF program.
    const MAX_COMPONENTS: usize = 16;

    #[derive(Debug, PartialEq, Eq)]
    enum Decision {
        Allow,
        Deny,
        /// No transition matched. The BPF program returns 0 here and the
        /// caller falls back to the role's allow_file_access flag.
        NoRule,
    }

    fn rules(role: u32, patterns: &[(&str, bool)]) -> HashMap<[u8; 24], [u8; 16]> {
        let mut map = HashMap::new();
        for (pattern, allow) in patterns {
            for (k, v) in path_state_entries(role, pattern, *allow) {
                map.insert(k, v);
            }
        }
        map
    }

    /// Walks a path exactly as check_path_state_machine does: exact component
    /// first, then the wildcard slot, terminal wins, otherwise carry the state.
    fn walk(map: &HashMap<[u8; 24], [u8; 16]>, role: u32, path: &str, truncate: bool) -> Decision {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut state: u64 = 0;

        for component in components.iter().take(MAX_COMPONENTS) {
            let hash = fnv1a_hash_u64(component);
            let value = map
                .get(&path_state_key(role, state, hash))
                .or_else(|| map.get(&path_state_key(role, state, 0)));

            let Some(value) = value else {
                return Decision::NoRule;
            };
            if value[8] == 1 {
                return if value[9] == 1 {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
            }
            let next = u64::from_ne_bytes(value[0..8].try_into().unwrap());
            // The bug this reproduces: the walk held the state in a u32.
            state = if truncate {
                u64::from(next as u32)
            } else {
                next
            };
        }

        match map.get(&path_state_key(role, state, 0)) {
            Some(v) if v[8] == 1 => {
                if v[9] == 1 {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
            _ => Decision::NoRule,
        }
    }

    fn decide(patterns: &[(&str, bool)], path: &str) -> Decision {
        walk(&rules(7, patterns), 7, path, false)
    }

    #[test]
    fn an_allow_list_admits_what_it_lists_and_is_silent_about_the_rest() {
        let list = &[("/etc/*", true), ("/usr/*", true)][..];

        assert_eq!(decide(list, "/etc/hostname"), Decision::Allow);
        assert_eq!(decide(list, "/usr/bin/cat"), Decision::Allow);
        // Not listed: no rule, so the role's allow_file_access decides. With
        // that flag false this denies, which is the intended default-deny --
        // but it must come from the flag, not from the list failing to match.
        assert_eq!(decide(list, "/root/secret.txt"), Decision::NoRule);
    }

    #[test]
    fn an_exact_multi_component_rule_covers_only_that_path() {
        let list = &[("/root/secret.txt", false)][..];

        assert_eq!(decide(list, "/root/secret.txt"), Decision::Deny);
        assert_eq!(decide(list, "/root/other.txt"), Decision::NoRule);
    }

    #[test]
    fn a_wildcard_covers_the_directory_and_nothing_outside_it() {
        let list = &[("/root/*", false)][..];

        assert_eq!(decide(list, "/root/secret.txt"), Decision::Deny);
        assert_eq!(decide(list, "/root/other.txt"), Decision::Deny);
        assert_eq!(decide(list, "/etc/hostname"), Decision::NoRule);
    }

    #[test]
    fn a_single_component_rule_covers_everything_beneath_it() {
        assert_eq!(
            decide(&[("/root", false)], "/root/secret.txt"),
            Decision::Deny
        );
    }

    /// The regression itself. Truncating the carried state to 32 bits turns
    /// every multi-component rule into "no rule", so an allow-list admits
    /// nothing and a deny-list denies nothing -- while single-component rules
    /// keep working, which is what made it look functional.
    #[test]
    fn truncating_the_carried_state_makes_multi_component_rules_inert() {
        let denies = rules(7, &[("/root/secret.txt", false)]);
        assert_eq!(walk(&denies, 7, "/root/secret.txt", false), Decision::Deny);
        assert_eq!(
            walk(&denies, 7, "/root/secret.txt", true),
            Decision::NoRule,
            "a 32-bit state must break this; if it does not, the test no longer              reproduces the bug it is guarding against"
        );

        let allows = rules(7, &[("/etc/*", true)]);
        assert_eq!(walk(&allows, 7, "/etc/hostname", false), Decision::Allow);
        assert_eq!(walk(&allows, 7, "/etc/hostname", true), Decision::NoRule);

        // Single component: unaffected either way.
        let single = rules(7, &[("/root", false)]);
        assert_eq!(walk(&single, 7, "/root/secret.txt", true), Decision::Deny);
    }
}

#[cfg(test)]
mod path_state_chaining {
    use super::*;

    /// The walk in the BPF program carries the state between components. It
    /// held that state in a u32 while these values are u64, so every pattern
    /// with more than one component missed on its second lookup and silently
    /// fell through to the role default. A single-component pattern kept
    /// working, which is why it looked like path rules worked at all.
    #[test]
    fn intermediate_states_do_not_fit_in_a_u32() {
        let entries = path_state_entries(7, "/root/secret.txt", false);
        assert_eq!(entries.len(), 2, "two components, two transitions");

        let next_state = u64::from_ne_bytes(entries[0].1[0..8].try_into().unwrap());
        assert!(
            next_state > u64::from(u32::MAX),
            "intermediate state {next_state:#x} happens to fit in a u32; pick another              pattern for this test, the point is that these values generally do not"
        );
    }

    #[test]
    fn each_component_starts_from_the_state_the_previous_one_produced() {
        let entries = path_state_entries(7, "/var/lib/data", true);
        assert_eq!(entries.len(), 3);

        for pair in entries.windows(2) {
            let produced = u64::from_ne_bytes(pair[0].1[0..8].try_into().unwrap());
            let consumed = u64::from_ne_bytes(pair[1].0[8..16].try_into().unwrap());
            assert_eq!(
                produced, consumed,
                "the chain only walks if each key resumes from the previous next_state;                  truncating either side breaks every multi-component pattern"
            );
        }
    }

    #[test]
    fn a_single_component_pattern_terminates_immediately() {
        let entries = path_state_entries(7, "/root", false);
        assert_eq!(entries.len(), 1);
        let next_state = u64::from_ne_bytes(entries[0].1[0..8].try_into().unwrap());
        assert_eq!(
            next_state, PATH_STATE_REJECT,
            "no intermediate state to carry, which is why this kept working"
        );
    }
}

#[cfg(test)]
mod bpf_key_padding {
    const SRC: &str = include_str!("../../bpfjailer-bpf/src/main.bpf.c");

    fn width(ty: &str) -> Option<usize> {
        match ty {
            "u8" | "s8" | "char" => Some(1),
            "u16" | "s16" | "__be16" => Some(2),
            "u32" | "s32" | "__be32" => Some(4),
            "u64" | "s64" => Some(8),
            _ => None,
        }
    }

    /// Every `struct *key* { .. }` in the BPF source, paired with whether the
    /// C layout rules insert padding into it.
    fn key_structs() -> Vec<(String, bool)> {
        let mut out = Vec::new();
        for (idx, _) in SRC.match_indices("struct ") {
            let rest = &SRC[idx + "struct ".len()..];
            let Some(brace) = rest.find('{') else {
                continue;
            };
            let name = rest[..brace].trim();
            if !name.contains("key") || name.contains(char::is_whitespace) {
                continue;
            }
            let Some(end) = rest.find('}') else { continue };
            if end < brace {
                continue;
            }

            // Strip trailing `//` comments first. Splitting on `;` while they
            // are present pushes the *next* field into a segment that begins
            // with the comment, and dropping that segment loses a real field.
            let body: String = rest[brace + 1..end]
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");

            let mut offset = 0usize;
            let mut widest = 1usize;
            let mut padded = false;
            let mut parsed_all = true;
            for field in body.split(';') {
                let field = field.trim();
                if field.is_empty() {
                    continue;
                }
                let mut parts = field.split_whitespace();
                let (Some(ty), Some(decl)) = (parts.next(), parts.next()) else {
                    continue;
                };
                let Some(w) = width(ty) else {
                    parsed_all = false;
                    break;
                };
                // arrays: `u8 name[4]`
                let count = decl
                    .split_once('[')
                    .and_then(|(_, n)| n.trim_end_matches(']').parse::<usize>().ok())
                    .unwrap_or(1);
                if !offset.is_multiple_of(w) {
                    padded = true;
                    offset += w - offset % w;
                }
                offset += w * count;
                widest = widest.max(w);
            }
            if parsed_all {
                if !offset.is_multiple_of(widest) {
                    padded = true;
                }
                out.push((name.to_string(), padded));
            }
        }
        out
    }

    #[test]
    fn the_source_still_contains_key_structs_to_check() {
        let keys = key_structs();
        assert!(
            keys.len() >= 5,
            "expected to parse several key structs, found {keys:?} -- the parser has \
             probably drifted from the source and is silently checking nothing"
        );
        assert!(
            keys.iter().any(|(_, padded)| *padded),
            "expected at least one padded key; if the layouts genuinely changed so that \
             none are padded, this guard can go, but verify that before deleting it"
        );
    }

    #[test]
    fn no_padded_key_is_built_with_an_initializer_list() {
        let offenders: Vec<_> = key_structs()
            .into_iter()
            .filter(|(_, padded)| *padded)
            .map(|(name, _)| name)
            .filter(|name| SRC.contains(&format!("struct {name} ")))
            .filter(|name| {
                // `struct <name> <var> = {` anywhere means the padding is
                // indeterminate. Zeroing via __builtin_memset is the fix.
                SRC.match_indices(&format!("struct {name} ")).any(|(i, _)| {
                    let tail = &SRC[i..];
                    let line_end = tail.find('\n').unwrap_or(tail.len());
                    tail[..line_end].contains("= {")
                })
            })
            .collect();

        assert!(
            offenders.is_empty(),
            "these padded key structs are built with an initializer list, so their \
             padding is whatever the stack held and map lookups will match only \
             intermittently: {offenders:?}. Declare them, __builtin_memset(&k, 0, \
             sizeof(k)), then assign the fields."
        );
    }
}
