use crate::types::{PolicyFlags, RoleId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPattern {
    pub pattern: String,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub protocol: String,
    pub address: Option<String>,
    /// Single port (e.g., 80)
    pub port: Option<u16>,
    /// Port range start (e.g., 8000). Use with port_end.
    pub port_start: Option<u16>,
    /// Port range end (e.g., 8100). Use with port_start.
    pub port_end: Option<u16>,
    pub allow: bool,
}

/// IP/CIDR-based filtering rule for egress control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    /// IP address or CIDR notation (e.g., "10.0.0.0/8", "192.168.1.1")
    pub cidr: String,
    /// Direction: "connect" or "bind"
    #[serde(default = "default_direction")]
    pub direction: String,
    pub allow: bool,
}

fn default_direction() -> String {
    "connect".to_string()
}

/// Domain-based filtering rule for AI agent egress control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRule {
    /// Domain name (e.g., "api.openai.com")
    pub domain: String,
    pub allow: bool,
}

/// Proxy configuration for forcing traffic through an HTTP proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy address in "host:port" format
    pub address: String,
    /// Whether to require all traffic through this proxy
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRule {
    pub binary_path: String,
    pub args_pattern: Option<String>,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub flags: PolicyFlags,
    pub file_paths: Vec<PathPattern>,
    pub network_rules: Vec<NetworkRule>,
    pub execution_rules: Vec<ExecutionRule>,
    pub require_signed_binary: bool,
    /// IP/CIDR-based egress rules
    #[serde(default)]
    pub ip_rules: Vec<IpRule>,
    /// Domain-based egress rules (requires DNS interception)
    #[serde(default)]
    pub domain_rules: Vec<DomainRule>,
    /// Proxy configuration for egress control
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    pub id: u64,
    pub role_id: RoleId,
    pub stack_depth: u8,
}

/// Auto-enrollment rule for executables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEnrollment {
    pub executable_path: String,
    pub pod_id: u64,
    pub role: String,
}

/// Auto-enrollment rule for cgroups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupEnrollment {
    pub cgroup_path: String,
    pub pod_id: u64,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub roles: HashMap<String, Role>,
    pub pods: Vec<Pod>,
    #[serde(default)]
    pub exec_enrollments: Vec<ExecEnrollment>,
    #[serde(default)]
    pub cgroup_enrollments: Vec<CgroupEnrollment>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyConfig {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            pods: Vec::new(),
            exec_enrollments: Vec::new(),
            cgroup_enrollments: Vec::new(),
        }
    }

    pub fn get_role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    pub fn get_role_by_id(&self, id: RoleId) -> Option<&Role> {
        self.roles.values().find(|r| r.id == id)
    }
}

// =============================================================================
// Preset Security Patterns for AI Agents
// =============================================================================

/// Preset path patterns for blocking access to secrets and sensitive files
pub struct SecretPatterns;

impl SecretPatterns {
    /// Get all default secret protection patterns (deny rules)
    pub fn all() -> Vec<PathPattern> {
        vec![
            // Environment variables (API keys, tokens)
            PathPattern {
                pattern: "/proc/".to_string(),
                allow: false,
            },
            // SSH keys
            PathPattern {
                pattern: "/.ssh/".to_string(),
                allow: false,
            },
            // AWS credentials
            PathPattern {
                pattern: "/.aws/".to_string(),
                allow: false,
            },
            // Google Cloud credentials
            PathPattern {
                pattern: "/.config/gcloud/".to_string(),
                allow: false,
            },
            // Azure credentials
            PathPattern {
                pattern: "/.azure/".to_string(),
                allow: false,
            },
            // Kubernetes config
            PathPattern {
                pattern: "/.kube/".to_string(),
                allow: false,
            },
            // Docker config (contains registry credentials)
            PathPattern {
                pattern: "/.docker/".to_string(),
                allow: false,
            },
            // System password files
            PathPattern {
                pattern: "/etc/shadow".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/etc/gshadow".to_string(),
                allow: false,
            },
            // Common private key locations
            PathPattern {
                pattern: "/etc/ssl/private/".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/etc/pki/".to_string(),
                allow: false,
            },
            // npm/yarn tokens
            PathPattern {
                pattern: "/.npmrc".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/.yarnrc".to_string(),
                allow: false,
            },
            // Git credentials
            PathPattern {
                pattern: "/.git-credentials".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/.netrc".to_string(),
                allow: false,
            },
            // Python/pip
            PathPattern {
                pattern: "/.pypirc".to_string(),
                allow: false,
            },
            // GPG keys
            PathPattern {
                pattern: "/.gnupg/".to_string(),
                allow: false,
            },
        ]
    }

    /// Get patterns for SSH key protection only
    pub fn ssh_keys() -> Vec<PathPattern> {
        vec![PathPattern {
            pattern: "/.ssh/".to_string(),
            allow: false,
        }]
    }

    /// Get patterns for cloud credentials protection
    pub fn cloud_credentials() -> Vec<PathPattern> {
        vec![
            PathPattern {
                pattern: "/.aws/".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/.config/gcloud/".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/.azure/".to_string(),
                allow: false,
            },
            PathPattern {
                pattern: "/.kube/".to_string(),
                allow: false,
            },
        ]
    }

    /// Get patterns for environment/process information protection
    pub fn process_info() -> Vec<PathPattern> {
        vec![PathPattern {
            pattern: "/proc/".to_string(),
            allow: false,
        }]
    }
}

/// Common allowed domains for AI agents
pub struct AllowedDomains;

impl AllowedDomains {
    /// OpenAI API endpoints
    pub fn openai() -> Vec<DomainRule> {
        vec![DomainRule {
            domain: "api.openai.com".to_string(),
            allow: true,
        }]
    }

    /// Anthropic API endpoints
    pub fn anthropic() -> Vec<DomainRule> {
        vec![DomainRule {
            domain: "api.anthropic.com".to_string(),
            allow: true,
        }]
    }

    /// Google AI endpoints
    pub fn google_ai() -> Vec<DomainRule> {
        vec![
            DomainRule {
                domain: "generativelanguage.googleapis.com".to_string(),
                allow: true,
            },
            DomainRule {
                domain: "aiplatform.googleapis.com".to_string(),
                allow: true,
            },
        ]
    }

    /// All major LLM providers
    pub fn all_llm_providers() -> Vec<DomainRule> {
        let mut rules = Vec::new();
        rules.extend(Self::openai());
        rules.extend(Self::anthropic());
        rules.extend(Self::google_ai());
        rules.push(DomainRule {
            domain: "api.cohere.ai".to_string(),
            allow: true,
        });
        rules.push(DomainRule {
            domain: "api.mistral.ai".to_string(),
            allow: true,
        });
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(id: u32, name: &str) -> Role {
        Role {
            id: RoleId(id),
            name: name.to_string(),
            flags: PolicyFlags::default(),
            file_paths: Vec::new(),
            network_rules: Vec::new(),
            execution_rules: Vec::new(),
            require_signed_binary: false,
            ip_rules: Vec::new(),
            domain_rules: Vec::new(),
            proxy: None,
        }
    }

    fn config_with(roles: &[(u32, &str)]) -> PolicyConfig {
        let mut c = PolicyConfig::new();
        for (id, name) in roles {
            c.roles.insert(name.to_string(), role(*id, name));
        }
        c
    }

    #[test]
    fn new_config_is_empty() {
        let c = PolicyConfig::new();
        assert!(c.roles.is_empty());
        assert!(c.pods.is_empty());
        assert!(c.exec_enrollments.is_empty());
        assert!(c.cgroup_enrollments.is_empty());
    }

    #[test]
    fn default_matches_new() {
        let d = PolicyConfig::default();
        assert_eq!(d.roles.len(), PolicyConfig::new().roles.len());
        assert!(d.pods.is_empty());
    }

    #[test]
    fn get_role_finds_by_name() {
        let c = config_with(&[(1, "restricted"), (2, "permissive")]);
        assert_eq!(c.get_role("restricted").unwrap().id, RoleId(1));
        assert_eq!(c.get_role("permissive").unwrap().id, RoleId(2));
    }

    #[test]
    fn get_role_is_none_for_unknown_name() {
        let c = config_with(&[(1, "restricted")]);
        assert!(c.get_role("nope").is_none());
        assert!(c.get_role("").is_none());
        assert!(
            c.get_role("Restricted").is_none(),
            "lookup is case-sensitive"
        );
    }

    #[test]
    fn get_role_by_id_finds_by_id() {
        let c = config_with(&[(1, "a"), (7, "b")]);
        assert_eq!(c.get_role_by_id(RoleId(7)).unwrap().name, "b");
    }

    #[test]
    fn get_role_by_id_is_none_for_unknown_id() {
        let c = config_with(&[(1, "a")]);
        assert!(c.get_role_by_id(RoleId(999)).is_none());
    }

    // ---- deserialisation: the policy file is the security boundary ----

    #[test]
    fn minimal_policy_deserialises_with_defaulted_sections() {
        let json = r#"{ "roles": {}, "pods": [] }"#;
        let c: PolicyConfig = serde_json::from_str(json).expect("should parse");
        assert!(c.exec_enrollments.is_empty());
        assert!(c.cgroup_enrollments.is_empty());
    }

    #[test]
    fn role_deserialises_with_optional_sections_defaulted() {
        let json = r#"{
            "roles": { "r": { "id": 3, "name": "r",
              "flags": {"allow_file_access": true, "allow_network": false,
                        "allow_exec": true, "require_signed_binary": false,
                        "allow_setuid": false, "allow_ptrace": false},
              "file_paths": [], "network_rules": [], "execution_rules": [],
              "require_signed_binary": false } },
            "pods": []
        }"#;
        let c: PolicyConfig = serde_json::from_str(json).expect("should parse");
        let r = c.get_role("r").expect("role r");
        assert_eq!(r.id, RoleId(3));
        assert!(r.ip_rules.is_empty(), "ip_rules should default");
        assert!(r.domain_rules.is_empty(), "domain_rules should default");
        assert!(r.proxy.is_none(), "proxy should default to None");
        // flags without the two #[serde(default)] bits still parse
        assert!(r.flags.allow_file_access);
        assert!(!r.flags.allow_module_load);
        assert!(!r.flags.allow_bpf_load);
    }

    #[test]
    fn ip_rule_direction_defaults_to_connect() {
        let r: IpRule =
            serde_json::from_str(r#"{"cidr":"10.0.0.0/8","allow":true}"#).expect("should parse");
        assert_eq!(r.direction, "connect");
    }

    #[test]
    fn proxy_required_defaults_to_false() {
        let p: ProxyConfig =
            serde_json::from_str(r#"{"address":"127.0.0.1:8080"}"#).expect("should parse");
        assert!(!p.required);
    }

    #[test]
    fn network_rule_accepts_single_port_or_range() {
        let single: NetworkRule =
            serde_json::from_str(r#"{"protocol":"tcp","port":80,"allow":true}"#).unwrap();
        assert_eq!(single.port, Some(80));
        assert!(single.port_start.is_none());

        let range: NetworkRule = serde_json::from_str(
            r#"{"protocol":"tcp","port_start":8000,"port_end":8100,"allow":true}"#,
        )
        .unwrap();
        assert_eq!((range.port_start, range.port_end), (Some(8000), Some(8100)));
        assert!(range.port.is_none());
    }

    #[test]
    fn policy_round_trips_through_json() {
        let mut c = config_with(&[(1, "a")]);
        c.exec_enrollments.push(ExecEnrollment {
            executable_path: "/usr/bin/x".into(),
            pod_id: 42,
            role: "a".into(),
        });
        c.cgroup_enrollments.push(CgroupEnrollment {
            cgroup_path: "/sys/fs/cgroup/x".into(),
            pod_id: 43,
            role: "a".into(),
        });
        let s = serde_json::to_string(&c).expect("serialise");
        let back: PolicyConfig = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back.exec_enrollments[0].pod_id, 42);
        assert_eq!(back.cgroup_enrollments[0].cgroup_path, "/sys/fs/cgroup/x");
        assert!(back.get_role("a").is_some());
    }

    #[test]
    fn malformed_policy_is_rejected_not_silently_defaulted() {
        // A role missing required fields must fail loudly rather than parse
        // into something permissive.
        let json = r#"{ "roles": { "r": { "name": "r" } }, "pods": [] }"#;
        assert!(serde_json::from_str::<PolicyConfig>(json).is_err());
    }

    // ---- preset patterns ----

    #[test]
    fn secret_patterns_are_all_deny_rules() {
        for p in SecretPatterns::all() {
            assert!(!p.allow, "{} should be a deny rule", p.pattern);
            assert!(!p.pattern.is_empty());
        }
    }

    #[test]
    fn secret_patterns_cover_the_documented_categories() {
        let all = SecretPatterns::all();
        let has = |frag: &str| all.iter().any(|p| p.pattern.contains(frag));
        for frag in ["/proc/", "/.ssh/", "/.aws/", "gcloud", "/.azure/"] {
            assert!(has(frag), "expected a pattern covering {frag}");
        }
    }

    #[test]
    fn secret_pattern_subsets_are_contained_in_all() {
        let all: Vec<String> = SecretPatterns::all()
            .iter()
            .map(|p| p.pattern.clone())
            .collect();
        for subset in [
            SecretPatterns::ssh_keys(),
            SecretPatterns::cloud_credentials(),
            SecretPatterns::process_info(),
        ] {
            assert!(!subset.is_empty());
            for p in subset {
                assert!(all.contains(&p.pattern), "{} missing from all()", p.pattern);
                assert!(!p.allow);
            }
        }
    }

    #[test]
    fn llm_provider_domains_are_allow_rules() {
        for d in AllowedDomains::all_llm_providers() {
            assert!(d.allow, "{} should be an allow rule", d.domain);
            assert!(
                d.domain.contains('.'),
                "{} should look like a domain",
                d.domain
            );
        }
    }

    #[test]
    fn all_llm_providers_is_the_union_of_the_individual_sets() {
        let all: Vec<String> = AllowedDomains::all_llm_providers()
            .iter()
            .map(|d| d.domain.clone())
            .collect();
        for subset in [
            AllowedDomains::openai(),
            AllowedDomains::anthropic(),
            AllowedDomains::google_ai(),
        ] {
            assert!(!subset.is_empty());
            for d in subset {
                assert!(all.contains(&d.domain), "{} missing from union", d.domain);
            }
        }
    }
}
