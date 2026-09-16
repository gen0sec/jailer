//! The LSM programs both loaders must attach.
//!
//! The daemon and the bootstrap each carried their own list, and the two had
//! drifted: the bootstrap attached `ptrace_access_check`, `kernel_module_request`
//! and `bpf` while the daemon did not, and the daemon attached `socket_sendmsg`
//! while the bootstrap did not. Neither attached all twelve.
//!
//! An unattached program is not a missing feature, it is a silently unenforced
//! one. `role_flags` bits 0x20, 0x40 and 0x80 -- `allow_ptrace`,
//! `allow_module_load`, `allow_bpf_load` -- are tested only inside those three
//! programs, so under the daemon a role denying them was refused nothing, while
//! the same policy under the bootstrap was. Nothing reported the difference:
//! both loaders logged a successful attach of every name in their own list.
//!
//! One list, shared, and a test that ties it to the programs `main.bpf.c`
//! actually declares -- so adding a `SEC("lsm/...")` and forgetting to attach it
//! fails the suite rather than shipping.

/// Every `SEC("lsm/...")` program in `bpfjailer-bpf/src/main.bpf.c`.
///
/// Both loaders attach exactly this set. Keep it sorted the way the BPF source
/// declares them so the diff against that file stays readable.
pub const LSM_PROGRAMS: &[&str] = &[
    "task_alloc",
    "file_open",
    "socket_bind",
    "socket_connect",
    "socket_sendmsg",
    "bprm_check_security",
    "path_rename",
    "sb_mount",
    "sb_umount",
    "ptrace_access_check",
    "kernel_module_request",
    "bpf",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const BPF_SOURCE: &str = include_str!("../../bpfjailer-bpf/src/main.bpf.c");

    /// Program names declared as `SEC("lsm/<name>")` in the BPF source.
    fn declared_programs(src: &str) -> BTreeSet<String> {
        const MARKER: &str = "SEC(\"lsm/";
        src.match_indices(MARKER)
            .filter_map(|(at, _)| {
                let rest = &src[at + MARKER.len()..];
                let end = rest.find('"')?;
                Some(rest[..end].to_string())
            })
            .collect()
    }

    #[test]
    fn the_parser_still_finds_the_programs() {
        let found = declared_programs(BPF_SOURCE);
        assert!(
            found.len() >= 10,
            "only found {found:?} -- the SEC(\"lsm/...\") scan has stopped working"
        );
        assert!(found.contains("file_open"));
    }

    /// The whole point: a program that exists but is never attached enforces
    /// nothing, and nothing else in the build would say so.
    #[test]
    fn the_shared_list_matches_what_the_bpf_source_declares() {
        let declared = declared_programs(BPF_SOURCE);
        let attached: BTreeSet<String> = LSM_PROGRAMS.iter().map(|s| s.to_string()).collect();

        let never_attached: Vec<_> = declared.difference(&attached).collect();
        assert!(
            never_attached.is_empty(),
            "these LSM programs are declared but no loader attaches them, so \
             whatever they enforce is not enforced: {never_attached:?}"
        );

        let not_declared: Vec<_> = attached.difference(&declared).collect();
        assert!(
            not_declared.is_empty(),
            "these names are attached but no longer exist in main.bpf.c, so the \
             attach will fail at load: {not_declared:?}"
        );
    }

    #[test]
    fn the_list_has_no_duplicates() {
        let unique: BTreeSet<_> = LSM_PROGRAMS.iter().collect();
        assert_eq!(unique.len(), LSM_PROGRAMS.len());
    }
}
