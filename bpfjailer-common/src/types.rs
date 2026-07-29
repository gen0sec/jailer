use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PodId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub pod_id: PodId,
    pub role_id: RoleId,
    pub stack_depth: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyFlags {
    pub allow_file_access: bool,
    pub allow_network: bool,
    pub allow_exec: bool,
    pub require_signed_binary: bool,
    pub allow_setuid: bool,
    pub allow_ptrace: bool,
    #[serde(default)]
    pub allow_module_load: bool,
    #[serde(default)]
    pub allow_bpf_load: bool,
    /// Require all network traffic to go through a configured proxy
    #[serde(default)]
    pub require_proxy: bool,
}
