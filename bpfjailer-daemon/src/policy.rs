use anyhow::Result;
use bpfjailer_common::{PolicyConfig, PolicyFlags, PodId, Role, RoleId};
use log::info;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;

pub struct PolicyManager {
    config: PolicyConfig,
    role_map: HashMap<RoleId, Arc<Role>>,
}

impl PolicyManager {
    pub fn new() -> Result<Self> {
        let mut config = PolicyConfig::new();
        let mut role_map = HashMap::new();

        // Add default test roles
        // Role 1: Restricted - blocks file, network, exec
        let restricted_role = Role {
            id: RoleId(1),
            name: "restricted".to_string(),
            flags: PolicyFlags {
                allow_file_access: false,
                allow_network: false,
                allow_exec: false,
                require_signed_binary: false,
                allow_setuid: false,
                allow_ptrace: false,
                allow_module_load: false,
                allow_bpf_load: false,
                require_proxy: false,
            },
            file_paths: vec![],
            network_rules: vec![],
            execution_rules: vec![],
            require_signed_binary: false,
            ip_rules: vec![],
            domain_rules: vec![],
            proxy: None,
        };

        // Role 2: Permissive - allows everything
        let permissive_role = Role {
            id: RoleId(2),
            name: "permissive".to_string(),
            flags: PolicyFlags {
                allow_file_access: true,
                allow_network: true,
                allow_exec: true,
                require_signed_binary: false,
                allow_setuid: false,
                allow_ptrace: false,
                allow_module_load: true,
                allow_bpf_load: true,
                require_proxy: false,
            },
            file_paths: vec![],
            network_rules: vec![],
            execution_rules: vec![],
            require_signed_binary: false,
            ip_rules: vec![],
            domain_rules: vec![],
            proxy: None,
        };

        config.roles.insert("restricted".to_string(), restricted_role.clone());
        config.roles.insert("permissive".to_string(), permissive_role.clone());
        role_map.insert(RoleId(1), Arc::new(restricted_role));
        role_map.insert(RoleId(2), Arc::new(permissive_role));

        info!("Initialized with default roles: restricted (1), permissive (2)");

        Ok(Self {
            config,
            role_map,
        })
    }

    pub async fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        info!("Loading policy from {:?}", path.as_ref());
        let content = fs::read_to_string(path).await?;
        self.config = serde_json::from_str(&content)?;

        self.role_map.clear();
        for role in self.config.roles.values() {
            self.role_map.insert(role.id, Arc::new(role.clone()));
        }

        info!("Loaded {} roles", self.role_map.len());
        Ok(())
    }

    pub fn get_role(&self, role_id: RoleId) -> Option<&Arc<Role>> {
        self.role_map.get(&role_id)
    }

    #[allow(dead_code)]
    pub fn get_role_by_name(&self, name: &str) -> Option<&Arc<Role>> {
        self.config.get_role(name).map(|r| {
            self.role_map.get(&r.id).unwrap()
        })
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Get executable enrollments from policy
    pub fn get_exec_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config.exec_enrollments.iter()
            .filter_map(|e| {
                self.config.get_role(&e.role)
                    .map(|r| (e.executable_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }

    /// Get cgroup enrollments from policy
    pub fn get_cgroup_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config.cgroup_enrollments.iter()
            .filter_map(|e| {
                self.config.get_role(&e.role)
                    .map(|r| (e.cgroup_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }
}
