use anyhow::{Context, Result};
use bpfjailer_common::{PodId, RoleId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as AsyncUnixStream;

#[derive(Debug, Serialize, Deserialize)]
pub enum EnrollmentRequest {
    Enroll {
        pod_id: PodId,
        role_id: RoleId,
    },
    Query {
        pid: u32,
    },
    // Alternative enrollment management
    EnrollExecutable {
        executable_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    RemoveExecutable {
        executable_path: String,
    },
    /// Install or replace a role, so a caller deciding policy at runtime can
    /// enroll against it. Without this, enrollment can only name roles that
    /// were in the policy file the daemon started with.
    DefineRole {
        role: bpfjailer_common::policy::Role,
    },
    EnrollCgroup {
        cgroup_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    RemoveCgroup {
        cgroup_path: String,
    },
    SetXattr {
        executable_path: String,
        pod_id: PodId,
        role_id: RoleId,
    },
    CheckXattr {
        executable_path: String,
    },
    RemoveXattr {
        executable_path: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum EnrollmentResponse {
    Success,
    Error(String),
    ProcessInfo { pod_id: PodId, role_id: RoleId },
    XattrInfo { pod_id: PodId, role_id: RoleId },
}

pub struct EnrollmentClient {
    socket_path: String,
}

impl EnrollmentClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn enroll(&self, pod_id: PodId, role_id: RoleId) -> Result<()> {
        let mut stream = AsyncUnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to enrollment socket")?;

        let request = EnrollmentRequest::Enroll { pod_id, role_id };
        let request_json = serde_json::to_string(&request)?;

        stream.write_all(request_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let response: EnrollmentResponse =
            serde_json::from_slice(&response_buf).context("Failed to parse enrollment response")?;

        match response {
            EnrollmentResponse::Success => Ok(()),
            EnrollmentResponse::Error(e) => Err(anyhow::anyhow!("Enrollment failed: {}", e)),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }

    pub async fn query(&self, pid: u32) -> Result<(PodId, RoleId)> {
        let mut stream = AsyncUnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to enrollment socket")?;

        let request = EnrollmentRequest::Query { pid };
        let request_json = serde_json::to_string(&request)?;

        stream.write_all(request_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let response: EnrollmentResponse =
            serde_json::from_slice(&response_buf).context("Failed to parse query response")?;

        match response {
            EnrollmentResponse::ProcessInfo { pod_id, role_id } => Ok((pod_id, role_id)),
            EnrollmentResponse::Error(e) => Err(anyhow::anyhow!("Query failed: {}", e)),
            _ => Err(anyhow::anyhow!("Unexpected response type")),
        }
    }
}
