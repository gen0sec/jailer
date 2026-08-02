//! Structural checks on the BPF source.
//!
//! Each defect found so far had the same shape: userspace writes a map that no
//! BPF program ever reads. `path_rules` was declared "legacy, kept for
//! compatibility" and populated for years without being consulted;
//! `domain_rules` was written at every policy load while nothing in the kernel
//! looked at it. Both read as enforcement from the outside -- the maps exist,
//! the entries are there, `bpftool map dump` shows them.
//!
//! Nothing links the two halves, so the tests here assert the link directly.

/// The bootstrap and the daemon each search for the compiled object
/// independently. They disagreed: the bootstrap looked in the installed
/// locations and the daemon only in cargo build trees, so a packaged daemon
/// could not start at all while the bootstrap on the same host worked.
#[cfg(test)]
mod loaders_agree_on_installed_paths {
    const BOOTSTRAP: &str = include_str!("../../bpfjailer-bootstrap/src/main.rs");
    const DAEMON: &str = include_str!("../../bpfjailer-daemon/src/bpf_loader.rs");

    const INSTALLED: [&str; 2] = [
        "/usr/lib/bpfjailer/bpfjailer.bpf.o",
        "/usr/share/bpfjailer/bpfjailer.bpf.o",
    ];

    #[test]
    fn both_loaders_search_the_installed_locations() {
        for path in INSTALLED {
            assert!(
                BOOTSTRAP.contains(path),
                "the bootstrap no longer looks in {path}"
            );
            assert!(
                DAEMON.contains(path),
                "the daemon does not look in {path}, so it cannot start from an \
                 installed package even where the bootstrap can"
            );
        }
    }
}

#[cfg(test)]
mod map_has_a_bpf_side_reader {
    /// `bpfjailer-bpf/build.rs` lists five `.bpf.c` files for
    /// `rerun-if-changed`, but calls `compile_bpf_program` on `main.bpf.c`
    /// alone. That one file is the whole loaded object, so it is the only one
    /// whose maps can enforce anything, and the only one checked here.
    ///
    /// The other four are compiled by nothing and loaded by nothing. Their
    /// maps are unreachable no matter what userspace writes to them.
    const SOURCE: &str = include_str!("../../bpfjailer-bpf/src/main.bpf.c");

    /// Comments are stripped before anything is matched: a map named only in a
    /// `// TODO: read foo_map here` would otherwise count as a use.
    fn without_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut chars = src.chars().peekable();
        let mut in_block = false;
        while let Some(c) = chars.next() {
            if in_block {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block = false;
                }
                continue;
            }
            match (c, chars.peek()) {
                ('/', Some('*')) => {
                    chars.next();
                    in_block = true;
                }
                ('/', Some('/')) => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }

    /// Names declared as `} <name> SEC(".maps");`.
    fn declared_maps(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (idx, _) in src.match_indices("SEC(\".maps\")") {
            let head = &src[..idx];
            let Some(brace) = head.rfind('}') else {
                continue;
            };
            let name = head[brace + 1..].trim();
            if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                out.push(name.to_string());
            }
        }
        out
    }

    /// True if the map's address is taken anywhere in the BPF sources. Any
    /// argument position counts: `bpf_perf_event_output` takes the map second,
    /// so matching only the first argument would wrongly flag `audit_events`.
    fn is_referenced(body: &str, name: &str) -> bool {
        body.match_indices(&format!("&{name}")).any(|(i, _)| {
            body[i + name.len() + 1..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_')
        })
    }

    fn stripped() -> String {
        without_comments(SOURCE)
    }

    /// Enrollment matches `bpf_get_current_cgroup_id()`, the task's *leaf*
    /// cgroup. Under a kubelet the leaf is the container scope, whose name
    /// carries the container id, so a policy could only ever name an object
    /// that is replaced on every restart -- enforcement silently lapsed on any
    /// rollout. Matching ancestors as well is what lets a policy name a stable
    /// cgroup such as `kubepods.slice`.
    #[test]
    fn the_exec_hook_matches_ancestor_cgroups_not_only_the_leaf() {
        let body = stripped();
        assert!(
            body.contains("bpf_get_current_ancestor_cgroup_id"),
            "nothing walks the cgroup ancestry, so only the leaf cgroup can be \
             enrolled and enrollment cannot survive a container restart"
        );
    }

    #[test]
    fn the_parser_still_finds_the_maps() {
        let body = stripped();
        let maps = declared_maps(&body);
        assert!(
            maps.len() >= 10,
            "expected to find the map declarations, found {maps:?} -- the parser has \
             drifted from the source and is checking nothing"
        );
        assert!(
            maps.iter().any(|m| m == "role_flags"),
            "role_flags is central to every hook; not finding it means the parser is broken"
        );
    }

    #[test]
    fn every_declared_map_is_used_by_a_bpf_program() {
        let body = stripped();
        let unused: Vec<String> = declared_maps(&body)
            .into_iter()
            .filter(|m| !is_referenced(&body, m))
            .collect();

        assert!(
            unused.is_empty(),
            "these maps are declared, and userspace can pin and populate them, but no \
             BPF program ever touches them: {unused:?}. Such a map looks like \
             enforcement from the outside -- it exists, it has entries -- and enforces \
             nothing. Either wire it up in the BPF program or delete it; do not leave \
             it declared."
        );
    }
}
