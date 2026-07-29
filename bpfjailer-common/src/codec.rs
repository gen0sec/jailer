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

/// `struct path_rule_key { u32 role_id; u64 path_hash; }` (4 bytes padding)
pub fn path_rule_key(role_id: u32, path: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0..4].copy_from_slice(&role_id.to_ne_bytes());
    k[8..16].copy_from_slice(&fnv1a_hash_u64(path).to_ne_bytes());
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
    fn path_and_domain_rule_keys_pad_before_the_hash() {
        let k = path_rule_key(5, "/etc/shadow");
        assert_eq!(le32(&k[0..4]), 5);
        assert_eq!(&k[4..8], &[0, 0, 0, 0]);
        assert_eq!(le(&k[8..16]), fnv1a_hash_u64("/etc/shadow"));

        let d = domain_rule_key(5, "api.example.com");
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
