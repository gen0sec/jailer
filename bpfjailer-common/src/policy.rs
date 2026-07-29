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
