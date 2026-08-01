//! Rules about which cgroups may be enrolled.
//!
//! An enrollment covers a cgroup and everything beneath it, which is what lets
//! a policy name something stable like `kubepods.slice` instead of a container
//! scope that is replaced on every restart.
//!
//! It also means a high-level enrollment captures more than the workload. A
//! container runtime does its setup *inside* the container's cgroup: runc's
//! `nsexec` opens `/proc/<pid>/ns/*`, which the kernel gates behind
//! `ptrace_may_access()`. A node-wide role with `allow_ptrace: false`
//! therefore stops containers from starting at all, with the failure surfacing
//! as a runtime error rather than a policy denial:
//!
//! ```text
//! runc create failed: unable to start container process:
//!   nsexec-1: failed to open /proc/32735/ns/ipc: Permission denied
//! ```
//!
//! Roles attached at or above the pod slice have to be permissive enough for
//! the runtime that starts the workload, not only for the workload itself.

/// Inode of the cgroup root. Enrollment matches a cgroup *and its
/// descendants*, and every process on the host descends from the root, so an
/// enrollment here would jail the kubelet, the container runtime, sshd and the
/// loader itself.
pub const ROOT_CGROUP_INO: u64 = 1;

/// Whether a cgroup may carry an enrollment.
pub fn check_enrollable(path: &str, ino: u64) -> Result<(), String> {
    if ino == ROOT_CGROUP_INO {
        return Err(format!(
            "{path} is the cgroup root; enrolling it would apply the role to every \
             process on the host, including the container runtime and this loader"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_cgroup_is_refused() {
        let err = check_enrollable("/sys/fs/cgroup", ROOT_CGROUP_INO)
            .expect_err("enrolling the root cgroup must be refused");
        assert!(
            err.contains("/sys/fs/cgroup"),
            "the error should name the offending path, got {err:?}"
        );
    }

    #[test]
    fn a_pod_slice_is_accepted() {
        assert!(check_enrollable(
            "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice",
            5717
        )
        .is_ok());
    }

    #[test]
    fn the_node_wide_pod_slice_is_accepted() {
        // The whole point of ancestor matching: this must be enrollable.
        assert!(check_enrollable("/sys/fs/cgroup/kubepods.slice", 5287).is_ok());
    }
}
