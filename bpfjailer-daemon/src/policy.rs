use anyhow::Result;
use bpfjailer_common::{PodId, PolicyConfig, PolicyFlags, Role, RoleId};
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

        config
            .roles
            .insert("restricted".to_string(), restricted_role.clone());
        config
            .roles
            .insert("permissive".to_string(), permissive_role.clone());
        role_map.insert(RoleId(1), Arc::new(restricted_role));
        role_map.insert(RoleId(2), Arc::new(permissive_role));

        info!("Initialized with default roles: restricted (1), permissive (2)");

        Ok(Self { config, role_map })
    }

    pub async fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        info!("Loading policy from {:?}", path.as_ref());
        let content = fs::read_to_string(path).await?;
        let config: PolicyConfig = serde_json::from_str(&content)?;

        // Refuse a policy that asks for something the BPF side does not
        // enforce. Loading it would leave the operator believing a restriction
        // is in force when nothing implements it -- worse than rejecting it.
        for (name, role) in &config.roles {
            let unenforced = bpfjailer_common::flags::unenforced_flags(&role.flags);
            if !unenforced.is_empty() {
                return Err(anyhow::anyhow!(
                    "role '{}' requests {} which this build does not enforce; \
                     remove the setting or do not rely on it",
                    name,
                    unenforced.join(", ")
                ));
            }
        }
        self.config = config;

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
        self.config
            .get_role(name)
            .map(|r| self.role_map.get(&r.id).unwrap())
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Get executable enrollments from policy
    pub fn get_exec_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config
            .exec_enrollments
            .iter()
            .filter_map(|e| {
                self.config
                    .get_role(&e.role)
                    .map(|r| (e.executable_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }

    /// Get cgroup enrollments from policy
    pub fn get_cgroup_enrollments(&self) -> Vec<(String, PodId, RoleId)> {
        self.config
            .cgroup_enrollments
            .iter()
            .filter_map(|e| {
                self.config
                    .get_role(&e.role)
                    .map(|r| (e.cgroup_path.clone(), PodId(e.pod_id), r.id))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "roles": {
        "web": { "id": 10, "name": "web",
          "flags": {"allow_file_access": true, "allow_network": true, "allow_exec": true,
                    "require_signed_binary": false, "allow_setuid": true, "allow_ptrace": false},
          "file_paths": [], "network_rules": [], "execution_rules": [],
          "require_signed_binary": false },
        "db": { "id": 11, "name": "db",
          "flags": {"allow_file_access": true, "allow_network": false, "allow_exec": false,
                    "require_signed_binary": false, "allow_setuid": true, "allow_ptrace": false},
          "file_paths": [], "network_rules": [], "execution_rules": [],
          "require_signed_binary": false }
      },
      "pods": [],
      "exec_enrollments": [
        {"executable_path": "/usr/bin/nginx", "pod_id": 100, "role": "web"},
        {"executable_path": "/usr/bin/ghost", "pod_id": 101, "role": "does-not-exist"}
      ],
      "cgroup_enrollments": [
        {"cgroup_path": "/sys/fs/cgroup/db", "pod_id": 200, "role": "db"}
      ]
    }"#;

    fn temp_policy(name: &str, body: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("bpfjailer-test-{name}-{}.json", std::process::id()));
        std::fs::write(&p, body).expect("write temp policy");
        p
    }

    #[test]
    fn new_seeds_the_builtin_roles() {
        let pm = PolicyManager::new().expect("new");
        let restricted = pm.get_role(RoleId(1)).expect("role 1");
        let permissive = pm.get_role(RoleId(2)).expect("role 2");
        assert_eq!(restricted.name, "restricted");
        assert_eq!(permissive.name, "permissive");
    }

    #[test]
    fn builtin_restricted_denies_everything() {
        let pm = PolicyManager::new().unwrap();
        let f = &pm.get_role(RoleId(1)).unwrap().flags;
        assert!(!f.allow_file_access && !f.allow_network && !f.allow_exec);
    }

    #[test]
    fn builtin_permissive_allows_the_core_three() {
        let pm = PolicyManager::new().unwrap();
        let f = &pm.get_role(RoleId(2)).unwrap().flags;
        assert!(f.allow_file_access && f.allow_network && f.allow_exec);
    }

    #[test]
    fn unknown_role_id_is_none() {
        let pm = PolicyManager::new().unwrap();
        assert!(pm.get_role(RoleId(9999)).is_none());
    }

    #[tokio::test]
    async fn load_from_file_replaces_the_builtin_roles() {
        let path = temp_policy("replace", SAMPLE);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.expect("load");
        assert!(pm.get_role(RoleId(10)).is_some(), "loaded role present");
        assert!(
            pm.get_role(RoleId(1)).is_none(),
            "builtin roles must be cleared, not merged"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn get_role_by_name_resolves_loaded_roles() {
        let path = temp_policy("byname", SAMPLE);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.unwrap();
        assert_eq!(pm.get_role_by_name("web").unwrap().id, RoleId(10));
        assert!(pm.get_role_by_name("nope").is_none());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn enrollments_referencing_unknown_roles_are_dropped() {
        let path = temp_policy("drop", SAMPLE);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.unwrap();

        let execs = pm.get_exec_enrollments();
        assert_eq!(execs.len(), 1, "the ghost-role enrollment must be dropped");
        assert_eq!(execs[0].0, "/usr/bin/nginx");
        assert_eq!(execs[0].1, PodId(100));
        assert_eq!(execs[0].2, RoleId(10));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cgroup_enrollments_resolve_role_ids() {
        let path = temp_policy("cgroup", SAMPLE);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.unwrap();
        let cg = pm.get_cgroup_enrollments();
        assert_eq!(cg.len(), 1);
        assert_eq!(
            cg[0],
            ("/sys/fs/cgroup/db".to_string(), PodId(200), RoleId(11))
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_from_file_surfaces_missing_file() {
        let mut pm = PolicyManager::new().unwrap();
        assert!(pm.load_from_file("/nonexistent/policy.json").await.is_err());
    }

    /// A policy asking for a flag the BPF side never tests must be refused.
    /// Applying it would leave the operator believing a restriction is in
    /// force when nothing enforces it.
    const UNENFORCED_POLICY: &str = r#"{
      "roles": {
        "signed": { "id": 40, "name": "signed",
          "flags": {"allow_file_access": true, "allow_network": true, "allow_exec": true,
                    "require_signed_binary": true, "allow_setuid": true, "allow_ptrace": false},
          "file_paths": [], "network_rules": [], "execution_rules": [],
          "require_signed_binary": true }
      },
      "pods": []
    }"#;

    #[tokio::test]
    async fn policy_requesting_an_unenforced_flag_is_refused() {
        let path = temp_policy("unenforced", UNENFORCED_POLICY);
        let mut pm = PolicyManager::new().unwrap();
        let err = pm
            .load_from_file(&path)
            .await
            .expect_err("must refuse a policy with unenforced flags");
        let msg = format!("{err:#}");
        assert!(msg.contains("require_signed_binary"), "got: {msg}");
        assert!(
            msg.contains("signed"),
            "message should name the role: {msg}"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Denying setuid is equally unenforced and must also be refused.
    #[tokio::test]
    async fn policy_denying_setuid_is_refused() {
        let body = UNENFORCED_POLICY
            .replace(
                r#""require_signed_binary": true, "allow_setuid": true"#,
                r#""require_signed_binary": false, "allow_setuid": false"#,
            )
            .replace(
                r#""require_signed_binary": true }"#,
                r#""require_signed_binary": false }"#,
            );
        assert!(
            body.contains(r#""allow_setuid": false"#),
            "fixture not patched"
        );
        let path = temp_policy("nosetuid", &body);
        let mut pm = PolicyManager::new().unwrap();
        let err = pm.load_from_file(&path).await.expect_err("must refuse");
        assert!(format!("{err:#}").contains("allow_setuid"), "got: {err:#}");
        let _ = std::fs::remove_file(path);
    }

    /// A refused policy must not partially apply: the previous roles stay.
    #[tokio::test]
    async fn a_refused_policy_leaves_the_previous_config_intact() {
        let path = temp_policy("refused", UNENFORCED_POLICY);
        let mut pm = PolicyManager::new().unwrap();
        let _ = pm.load_from_file(&path).await;
        assert!(
            pm.get_role(RoleId(1)).is_some(),
            "builtin roles must survive a rejected load"
        );
        assert!(
            pm.get_role(RoleId(40)).is_none(),
            "rejected role must not be applied"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn policy_using_only_enforced_flags_loads() {
        let body = SAMPLE.replace(r#""allow_setuid": false"#, r#""allow_setuid": true"#);
        assert!(
            body.contains(r#""allow_setuid": true"#),
            "fixture not patched"
        );
        let path = temp_policy("enforced-only", &body);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.expect("should load");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn load_from_file_surfaces_malformed_json() {
        let path = temp_policy("bad", "{ not json");
        let mut pm = PolicyManager::new().unwrap();
        assert!(pm.load_from_file(&path).await.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn config_exposes_the_loaded_document() {
        let path = temp_policy("config", SAMPLE);
        let mut pm = PolicyManager::new().unwrap();
        pm.load_from_file(&path).await.unwrap();
        assert_eq!(pm.config().roles.len(), 2);
        let _ = std::fs::remove_file(path);
    }
}
