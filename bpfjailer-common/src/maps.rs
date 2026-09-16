//! The BPF maps both loaders pin.
//!
//! The daemon and the bootstrap each carried their own copy of this list, and
//! the bootstrap carried a second copy for pinning programs. Copies of a list
//! are how the program lists drifted until one loader enforced three flags the
//! other did not -- see [`crate::programs`]. Same shape, so one list.
//!
//! Pinning is what makes a map outlive the process that filled it: the
//! bootstrap populates the maps and exits, and only what it pinned survives.

/// Maps pinned under `/sys/fs/bpf/bpfjailer`, in the order the loaders write
/// them.
///
/// This is deliberately not every map `main.bpf.c` declares. `path_buf` is
/// per-CPU scratch the BPF side reuses each call and nothing outside needs.
/// `ip_rules`, `domain_rules`, `proxy_config` and `dns_cache` are *not* pinned
/// and that is a known gap, not a decision -- rules written into them by the
/// daemonless bootstrap do not survive it exiting.
pub const PINNED_MAPS: &[&str] = &[
    "task_storage",
    "role_flags",
    "pending_enrollments",
    "network_rules",
    "path_states",
    "exec_states",
    "path_decision_cache",
    "cache_generation",
    "exec_enrollment",
    "cgroup_enrollment",
    "audit_events",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const BPF_SOURCE: &str = include_str!("../../bpfjailer-bpf/src/main.bpf.c");

    /// Map names declared as `} <name> SEC(".maps");` in the BPF source.
    fn declared_maps(src: &str) -> BTreeSet<String> {
        const MARKER: &str = " SEC(\".maps\");";
        src.match_indices(MARKER)
            .filter_map(|(at, _)| {
                let before = &src[..at];
                let name = before.rsplit(|c: char| c.is_whitespace()).next()?;
                (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    .then(|| name.to_string())
            })
            .collect()
    }

    #[test]
    fn the_parser_still_finds_the_maps() {
        let found = declared_maps(BPF_SOURCE);
        assert!(found.len() >= 10, "only found {found:?}");
        assert!(found.contains("role_flags"));
    }

    /// A name here that the BPF side no longer declares fails at pin time, on
    /// a host, rather than in the build.
    #[test]
    fn every_pinned_map_exists_in_the_bpf_source() {
        let declared = declared_maps(BPF_SOURCE);
        let missing: Vec<_> = PINNED_MAPS
            .iter()
            .filter(|m| !declared.contains(**m))
            .collect();
        assert!(
            missing.is_empty(),
            "these maps are pinned but main.bpf.c does not declare them: {missing:?}"
        );
    }

    #[test]
    fn the_list_has_no_duplicates() {
        let unique: BTreeSet<_> = PINNED_MAPS.iter().collect();
        assert_eq!(unique.len(), PINNED_MAPS.len());
    }
}
