use crate::bpf_loader::BpfJailerBpf;
use crate::policy::PolicyManager;
use crate::process_tracker::ProcessTracker;
use anyhow::{Context, Result};
use bpfjailer_common::{PodId, RoleId};
use log::{debug, info, warn};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Alternative enrollment methods beyond Unix socket
pub struct AlternativeEnrollment {
    bpf: Arc<BpfJailerBpf>,
    process_tracker: Arc<ProcessTracker>,
    policy_manager: Arc<RwLock<PolicyManager>>,
}

impl AlternativeEnrollment {
    pub fn new(
        bpf: Arc<BpfJailerBpf>,
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
    ) -> Self {
        Self {
            bpf,
            process_tracker,
            policy_manager,
        }
    }

    /// Enroll all processes executing a specific binary
    /// Uses the executable's inode for matching
    pub async fn enroll_by_executable_path(
        &self,
        executable_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!(
            "Setting up executable enrollment: {} -> Pod {} Role {}",
            executable_path, pod_id.0, role_id.0
        );

        if !Path::new(executable_path).exists() {
            return Err(anyhow::anyhow!(
                "Executable path does not exist: {}",
                executable_path
            ));
        }

        // Get the inode of the executable
        let inode = BpfJailerBpf::get_file_inode(executable_path)
            .context("Failed to get executable inode")?;

        // Ensure role policy is loaded
        let pm = self.policy_manager.read().await;
        if let Some(role) = pm.get_role(role_id) {
            let role = role.clone();
            drop(pm);

            // Set up role flags and rules
            self.process_tracker.set_role_policy(role_id, &role.flags)?;
            self.process_tracker
                .apply_network_rules(role_id, &role.network_rules)?;
            self.process_tracker
                .apply_path_rules(role_id, &role.file_paths)?;
        } else {
            return Err(anyhow::anyhow!("Unknown role ID: {}", role_id.0));
        }

        // Add the executable enrollment rule
        self.bpf.add_exec_enrollment(inode, pod_id.0, role_id.0)?;

        info!(
            "Executable enrollment active: {} (inode={}) -> Pod {} Role {}",
            executable_path, inode, pod_id.0, role_id.0
        );
        Ok(())
    }

    /// Remove executable-based enrollment
    pub async fn remove_executable_enrollment(&self, executable_path: &str) -> Result<()> {
        let inode = BpfJailerBpf::get_file_inode(executable_path)
            .context("Failed to get executable inode")?;
        self.bpf.remove_exec_enrollment(inode)?;
        info!("Removed executable enrollment for: {}", executable_path);
        Ok(())
    }

    /// Enroll all processes in a specific cgroup
    pub async fn enroll_by_cgroup_path(
        &self,
        cgroup_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!(
            "Setting up cgroup enrollment: {} -> Pod {} Role {}",
            cgroup_path, pod_id.0, role_id.0
        );

        if !Path::new(cgroup_path).exists() {
            return Err(anyhow::anyhow!(
                "Cgroup path does not exist: {}",
                cgroup_path
            ));
        }

        // Get the cgroup ID
        let cgroup_id =
            BpfJailerBpf::get_cgroup_id(cgroup_path).context("Failed to get cgroup ID")?;

        // Ensure role policy is loaded
        let pm = self.policy_manager.read().await;
        if let Some(role) = pm.get_role(role_id) {
            let role = role.clone();
            drop(pm);

            // Set up role flags and rules
            self.process_tracker.set_role_policy(role_id, &role.flags)?;
            self.process_tracker
                .apply_network_rules(role_id, &role.network_rules)?;
            self.process_tracker
                .apply_path_rules(role_id, &role.file_paths)?;
        } else {
            return Err(anyhow::anyhow!("Unknown role ID: {}", role_id.0));
        }

        // Add the cgroup enrollment rule
        self.bpf
            .add_cgroup_enrollment(cgroup_id, pod_id.0, role_id.0)?;

        info!(
            "Cgroup enrollment active: {} (id={}) -> Pod {} Role {}",
            cgroup_path, cgroup_id, pod_id.0, role_id.0
        );
        Ok(())
    }

    /// Remove cgroup-based enrollment
    pub async fn remove_cgroup_enrollment(&self, cgroup_path: &str) -> Result<()> {
        let cgroup_id =
            BpfJailerBpf::get_cgroup_id(cgroup_path).context("Failed to get cgroup ID")?;
        self.bpf.remove_cgroup_enrollment(cgroup_id)?;
        info!("Removed cgroup enrollment for: {}", cgroup_path);
        Ok(())
    }

    /// Set xattr on executable for enrollment info
    /// Processes can read this and self-enroll
    pub async fn set_xattr_enrollment(
        &self,
        executable_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!(
            "Setting xattr enrollment: {} -> Pod {} Role {}",
            executable_path, pod_id.0, role_id.0
        );

        if !Path::new(executable_path).exists() {
            return Err(anyhow::anyhow!(
                "Executable path does not exist: {}",
                executable_path
            ));
        }

        // Set pod_id xattr
        let pod_xattr = "user.bpfjailer.pod_id";
        let pod_id_bytes = pod_id.0.to_le_bytes();
        xattr::set(executable_path, pod_xattr, &pod_id_bytes)
            .context("Failed to set pod_id xattr")?;

        // Set role_id xattr
        let role_xattr = "user.bpfjailer.role_id";
        let role_id_bytes = role_id.0.to_le_bytes();
        xattr::set(executable_path, role_xattr, &role_id_bytes)
            .context("Failed to set role_id xattr")?;

        info!("Xattr enrollment set on: {}", executable_path);
        Ok(())
    }

    /// Check xattr on executable for enrollment info
    pub async fn check_xattr_enrollment(
        &self,
        executable_path: &str,
    ) -> Result<Option<(PodId, RoleId)>> {
        let pod_xattr = "user.bpfjailer.pod_id";
        let role_xattr = "user.bpfjailer.role_id";

        let pod_value = match xattr::get(executable_path, pod_xattr)? {
            Some(v) => v,
            None => return Ok(None),
        };

        let role_value = match xattr::get(executable_path, role_xattr)? {
            Some(v) => v,
            None => return Ok(None),
        };

        if pod_value.len() != 8 || role_value.len() != 4 {
            warn!("Invalid xattr format on {}", executable_path);
            return Ok(None);
        }

        let pod_id = u64::from_le_bytes([
            pod_value[0],
            pod_value[1],
            pod_value[2],
            pod_value[3],
            pod_value[4],
            pod_value[5],
            pod_value[6],
            pod_value[7],
        ]);
        let role_id =
            u32::from_le_bytes([role_value[0], role_value[1], role_value[2], role_value[3]]);

        debug!(
            "Found xattr enrollment: {} -> Pod {} Role {}",
            executable_path, pod_id, role_id
        );
        Ok(Some((PodId(pod_id), RoleId(role_id))))
    }

    /// Remove xattr enrollment from executable
    pub async fn remove_xattr_enrollment(&self, executable_path: &str) -> Result<()> {
        let pod_xattr = "user.bpfjailer.pod_id";
        let role_xattr = "user.bpfjailer.role_id";

        let _ = xattr::remove(executable_path, pod_xattr);
        let _ = xattr::remove(executable_path, role_xattr);

        info!("Removed xattr enrollment from: {}", executable_path);
        Ok(())
    }

    /// Load enrollment rules from policy file
    pub async fn load_from_policy(&self) -> Result<()> {
        let pm = self.policy_manager.read().await;

        // Load executable enrollments from policy
        for (exec_path, pod_id, role_id) in pm.get_exec_enrollments() {
            if let Err(e) = self
                .enroll_by_executable_path(&exec_path, pod_id, role_id)
                .await
            {
                warn!(
                    "Failed to set up executable enrollment for {}: {}",
                    exec_path, e
                );
            }
        }

        // Load cgroup enrollments from policy
        for (cgroup_path, pod_id, role_id) in pm.get_cgroup_enrollments() {
            if let Err(e) = self
                .enroll_by_cgroup_path(&cgroup_path, pod_id, role_id)
                .await
            {
                warn!(
                    "Failed to set up cgroup enrollment for {}: {}",
                    cgroup_path, e
                );
            }
        }

        Ok(())
    }
}
