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

    /// The deny set the shipped `cis_*` roles carry.
    ///
    /// Aligned to the CIS Distribution Independent Linux Benchmark: the
    /// credential files of 6.1.3/6.1.5/6.1.7/6.1.9, the boot configuration of
    /// 1.4, the audit configuration of 4.1, and the sudoers of 4.1.16. See
    /// `docs/cis-mapping.md` for what that alignment does and does not claim.
    ///
    /// Two properties are deliberate and are what make this set safe to apply
    /// to an arbitrary process:
    ///
    /// * Every pattern is literal and at most three components deep. A rule
    ///   deeper than `MAX_COMPONENTS` never matches, and for a role with
    ///   `allow_file_access` that reads as *allowed* -- a deny that silently
    ///   inverts is worse than no rule.
    /// * Nothing here is a path a process opens in normal operation. The
    ///   `file_open` hook carries no read/write distinction, so a deny denies
    ///   the open outright: `/etc/passwd` and `/etc/group` are therefore
    ///   absent, despite CIS 6.1.2/6.1.4, because denying them would break
    ///   username resolution in every confined service.
    ///
    /// Returned as data so a caller building a role over `DefineRole` gets the
    /// same protection as the shipped JSON. They are asserted equal in tests.
    pub fn cis_hardening() -> Vec<PathPattern> {
        [
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/shadow-",
            "/etc/gshadow-",
            "/root/",
            "/boot/",
            "/etc/audit/",
            "/etc/sudoers",
            "/etc/sudoers.d/",
        ]
        .iter()
        .map(|p| PathPattern {
            pattern: (*p).to_string(),
            allow: false,
        })
        .collect()
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

/// Settings a role asks for that this build does not enforce.
///
/// Extends [`crate::flags::unenforced_flags`] to the parts of a role that are
/// not flags. The rule is the same one the loaders already apply to flags:
/// a policy that asks for a restriction nothing implements is refused, because
/// accepting it leaves the operator believing a restriction is in force.
///
/// `execution_rules` itself is now enforced -- the binary path is walked by the
/// exec hook -- but `args_pattern` is not and cannot be: argv lives in the new
/// process's memory at `bprm` time and is not readable in any way worth
/// trusting. A rule that sets it would silently match on the path alone, which
/// is broader than what was written.
pub fn unenforced_settings(role: &Role) -> Vec<String> {
    let mut out: Vec<String> = crate::flags::unenforced_flags(&role.flags)
        .into_iter()
        .map(String::from)
        .collect();

    if role
        .execution_rules
        .iter()
        .any(|r| r.args_pattern.is_some())
    {
        out.push("execution_rules.args_pattern".to_string());
    }

    // Patterns that overlap in a way the encoder cannot express. Everything
    // else composes -- the broader rule is inherited by the nodes a deeper one
    // creates -- but a `*` component and an inherited decision both need the
    // same key, so that pair is refused rather than half-applied.
    let files: Vec<(&str, bool)> = role
        .file_paths
        .iter()
        .map(|p| (p.pattern.as_str(), p.allow))
        .collect();
    if let Err(conflicts) = crate::codec::path_state_entries_for_role(role.id.0, &files) {
        out.extend(conflicts.into_iter().map(|c| format!("file_paths: {c}")));
    }

    let execs: Vec<(&str, bool)> = role
        .execution_rules
        .iter()
        .map(|e| (e.binary_path.as_str(), e.allow))
        .collect();
    if let Err(conflicts) = crate::codec::path_state_entries_for_role(role.id.0, &execs) {
        out.extend(
            conflicts
                .into_iter()
                .map(|c| format!("execution_rules: {c}")),
        );
    }

    out
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

    fn exec_rule(path: &str, args: Option<&str>) -> ExecutionRule {
        ExecutionRule {
            binary_path: path.to_string(),
            args_pattern: args.map(String::from),
            allow: true,
        }
    }

    /// A rule that only names a binary is enforceable: the exec hook walks the
    /// path with the same state machine file rules use.
    #[test]
    fn an_execution_rule_naming_only_a_path_is_enforced() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.execution_rules = vec![exec_rule("/usr/bin/curl", None)];
        assert!(unenforced_settings(&r).is_empty());
    }

    /// argv is not readable at bprm time, so a rule carrying args_pattern would
    /// silently match on the path alone -- broader than what was written. It is
    /// refused for the same reason require_signed_binary is.
    #[test]
    fn an_execution_rule_with_args_pattern_is_refused() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.execution_rules = vec![exec_rule("/usr/bin/curl", Some("--insecure"))];
        assert_eq!(
            unenforced_settings(&r),
            vec!["execution_rules.args_pattern"]
        );
    }

    /// A `*` under a broader rule cannot be encoded, so the policy is refused
    /// rather than applied with one of the two rules missing.
    #[test]
    fn overlapping_patterns_that_cannot_be_encoded_are_refused() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.file_paths = vec![
            PathPattern {
                pattern: "/tmp/mixed/".into(),
                allow: true,
            },
            PathPattern {
                pattern: "/tmp/mixed/*/data.txt".into(),
                allow: false,
            },
        ];
        let out = unenforced_settings(&r);
        assert_eq!(out.len(), 1, "got {out:?}");
        assert!(out[0].starts_with("file_paths: "), "{}", out[0]);
        assert!(out[0].contains("/tmp/mixed/*/data.txt"), "{}", out[0]);
    }

    /// Overlaps the encoder CAN express must not be refused -- that is the
    /// whole point of the fix, and it is the shape the shipped policy uses.
    #[test]
    fn a_directory_allow_with_a_file_deny_inside_it_is_accepted() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.file_paths = vec![
            PathPattern {
                pattern: "/var/log/".into(),
                allow: true,
            },
            PathPattern {
                pattern: "/var/log/secure".into(),
                allow: false,
            },
        ];
        assert!(unenforced_settings(&r).is_empty());
    }

    /// One rule out of many is enough to refuse the policy: the others being
    /// fine does not make the unenforceable one safe.
    #[test]
    fn one_rule_with_args_pattern_among_several_is_still_refused() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.execution_rules = vec![
            exec_rule("/usr/bin/curl", None),
            exec_rule("/usr/bin/wget", Some("-q")),
            exec_rule("/usr/bin/id", None),
        ];
        assert_eq!(
            unenforced_settings(&r),
            vec!["execution_rules.args_pattern"]
        );
    }

    /// unenforced_settings must keep reporting the flags it wraps, not replace
    /// them.
    #[test]
    fn it_still_reports_the_unenforced_flags_underneath() {
        let mut r = role(1, "web");
        r.flags.allow_setuid = true;
        r.flags.require_signed_binary = true;
        r.execution_rules = vec![exec_rule("/usr/bin/curl", Some("x"))];
        assert_eq!(
            unenforced_settings(&r),
            vec![
                "require_signed_binary".to_string(),
                "execution_rules.args_pattern".to_string()
            ]
        );
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

/// The policy files this repository ships must survive the check both loaders
/// apply to any policy.
///
/// `config/policy.json` is copied to `/etc/bpfjailer/policy.json` by every
/// install path there is, and the bootstrap refuses a policy asking for
/// anything unenforced -- so an example that trips that check is an example
/// that makes the bootstrap exit 1 on a fresh install. It did: every role set
/// `allow_setuid: false`, which cannot be enforced and is therefore refused.
///
/// Nothing tied the shipped examples to the check. This does.
#[cfg(test)]
mod shipped_policies_load {
    use super::*;

    const MAIN: &str = include_str!("../../config/policy.json");
    const DOCKER_EXAMPLE: &str = include_str!("../../examples/docker/policy.json");

    fn assert_accepted(label: &str, json: &str) {
        let config: PolicyConfig =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{label} is not valid: {e}"));
        assert!(!config.roles.is_empty(), "{label} defines no roles");

        for (name, role) in &config.roles {
            let unenforced = unenforced_settings(role);
            assert!(
                unenforced.is_empty(),
                "{label} role '{name}' requests {unenforced:?}, which this build \
                 does not enforce -- the bootstrap refuses such a policy and \
                 exits non-zero, and the daemon falls back to built-in roles"
            );
        }
    }

    #[test]
    fn the_policy_installed_to_etc_is_accepted() {
        assert_accepted("config/policy.json", MAIN);
    }

    #[test]
    fn the_docker_example_policy_is_accepted() {
        assert_accepted("examples/docker/policy.json", DOCKER_EXAMPLE);
    }

    /// The Rust preset and the shipped JSON must carry the same deny set.
    ///
    /// Two ways to get a CIS role exist -- the shipped policy file, and
    /// `SecretPatterns::cis_hardening()` for a caller defining a role at
    /// runtime -- and nothing else would notice them diverging. A caller that
    /// built its role from the preset would then believe it had the protection
    /// the shipped role documents, and quietly have less.
    #[test]
    fn the_preset_and_the_shipped_baseline_role_agree() {
        let config: PolicyConfig = serde_json::from_str(MAIN).expect("valid");
        let shipped: Vec<(String, bool)> = config.roles["cis_baseline"]
            .file_paths
            .iter()
            .map(|p| (p.pattern.clone(), p.allow))
            .collect();
        let preset: Vec<(String, bool)> = crate::policy::SecretPatterns::cis_hardening()
            .into_iter()
            .map(|p| (p.pattern, p.allow))
            .collect();
        assert_eq!(shipped, preset);
    }

    /// The tiers are a ladder in what they permit, not three unrelated roles.
    /// Each step must clear at least one flag and clear none that a looser tier
    /// had already cleared.
    #[test]
    fn the_cis_tiers_get_strictly_stricter() {
        let config: PolicyConfig = serde_json::from_str(MAIN).expect("valid");
        let tiers = ["cis_baseline", "cis_service", "cis_isolated"];

        let granted = |name: &str| -> Vec<&'static str> {
            let f = config.roles[name].flags;
            let mut out = Vec::new();
            for (on, label) in [
                (f.allow_file_access, "file"),
                (f.allow_network, "network"),
                (f.allow_exec, "exec"),
                (f.allow_ptrace, "ptrace"),
                (f.allow_module_load, "module_load"),
                (f.allow_bpf_load, "bpf_load"),
            ] {
                if on {
                    out.push(label);
                }
            }
            out
        };

        for pair in tiers.windows(2) {
            let (looser, tighter) = (granted(pair[0]), granted(pair[1]));
            for g in &tighter {
                assert!(
                    looser.contains(g),
                    "{} grants {g} but the looser {} does not, so the tiers are \
                     not a ladder",
                    pair[1],
                    pair[0]
                );
            }
            assert!(
                tighter.len() < looser.len(),
                "{} grants as much as {}, so it is not a tighter tier",
                pair[1],
                pair[0]
            );
        }
    }

    /// Every tier must deny ptrace, module load and BPF load. Those three are
    /// the flags the BPF side tests outside the path walk, and they are the
    /// whole of what a CIS role can enforce beyond file access.
    #[test]
    fn every_cis_tier_denies_the_privilege_flags() {
        let config: PolicyConfig = serde_json::from_str(MAIN).expect("valid");
        for name in ["cis_baseline", "cis_service", "cis_isolated"] {
            let f = config.roles[name].flags;
            assert!(!f.allow_ptrace, "{name} must deny ptrace");
            assert!(!f.allow_module_load, "{name} must deny module load");
            assert!(!f.allow_bpf_load, "{name} must deny BPF load");
            assert!(f.allow_setuid, "{name} must set allow_setuid: true");
            assert!(!f.require_signed_binary, "{name} must not require signing");
        }
    }

    /// Discrimination control: the assertion above has to be able to fail, or
    /// a policy that loads and one that is refused would look the same here.
    #[test]
    fn a_policy_asking_for_something_unenforced_is_still_caught() {
        let refused = MAIN.replace("\"allow_setuid\": true", "\"allow_setuid\": false");
        assert_ne!(refused, MAIN, "the substitution matched nothing");

        let config: PolicyConfig = serde_json::from_str(&refused).expect("still valid json");
        assert!(
            config
                .roles
                .values()
                .any(|r| !unenforced_settings(r).is_empty()),
            "denying setuid is no longer reported as unenforced, so this check \
             has stopped discriminating"
        );
    }
}
