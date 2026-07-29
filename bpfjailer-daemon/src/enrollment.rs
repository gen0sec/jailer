use crate::enrollment_alternatives::AlternativeEnrollment;
use crate::policy::PolicyManager;
use crate::process_tracker::ProcessTracker;
use anyhow::{Context, Result};
use bpfjailer_client::{EnrollmentRequest, EnrollmentResponse};
use log::{debug, error, info};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener as AsyncUnixListener, UnixStream as AsyncUnixStream};
use tokio::sync::RwLock;

const SOCKET_PATH: &str = "/run/bpfjailer/enrollment.sock";

pub struct EnrollmentServer {
    process_tracker: Arc<ProcessTracker>,
    policy_manager: Arc<RwLock<PolicyManager>>,
    alt_enrollment: Arc<AlternativeEnrollment>,
}

impl EnrollmentServer {
    pub fn new(
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
        alt_enrollment: Arc<AlternativeEnrollment>,
    ) -> Self {
        Self {
            process_tracker,
            policy_manager,
            alt_enrollment,
        }
    }

    pub async fn run(&self) -> Result<()> {
        if Path::new(SOCKET_PATH).exists() {
            std::fs::remove_file(SOCKET_PATH)?;
        }

        if let Some(parent) = Path::new(SOCKET_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener =
            AsyncUnixListener::bind(SOCKET_PATH).context("Failed to bind enrollment socket")?;

        info!("Enrollment server listening on {}", SOCKET_PATH);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let process_tracker = self.process_tracker.clone();
                    let policy_manager = self.policy_manager.clone();
                    let alt_enrollment = self.alt_enrollment.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(
                            stream,
                            process_tracker,
                            policy_manager,
                            alt_enrollment,
                        )
                        .await
                        {
                            error!("Error handling enrollment client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        mut stream: AsyncUnixStream,
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
        alt_enrollment: Arc<AlternativeEnrollment>,
    ) -> Result<()> {
        let peer_creds = stream
            .peer_cred()
            .context("Failed to get peer credentials")?;

        let pid = peer_creds.pid().unwrap_or(0);
        debug!("Handling enrollment request from PID {}", pid);

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let request: EnrollmentRequest =
            serde_json::from_str(&line).context("Failed to parse enrollment request")?;

        let response = match request {
            EnrollmentRequest::Enroll { pod_id, role_id } => {
                debug!(
                    "Enrollment request: PID {} -> Pod {} Role {}",
                    pid, pod_id.0, role_id.0
                );

                let pm = policy_manager.read().await;
                match pm.get_role(role_id) {
                    None => EnrollmentResponse::Error(format!("Unknown role ID: {}", role_id.0)),
                    Some(role) => {
                        let role = role.clone();
                        drop(pm); // Release the lock

                        // Set the role policy flags in BPF
                        if let Err(e) = process_tracker.set_role_policy(role_id, &role.flags) {
                            EnrollmentResponse::Error(format!("Failed to set role policy: {}", e))
                        } else {
                            // Apply network rules from the role
                            if let Err(e) =
                                process_tracker.apply_network_rules(role_id, &role.network_rules)
                            {
                                error!("Failed to apply network rules: {}", e);
                            }

                            // Apply path rules from the role
                            if let Err(e) =
                                process_tracker.apply_path_rules(role_id, &role.file_paths)
                            {
                                error!("Failed to apply path rules: {}", e);
                            }

                            match process_tracker.enroll_process(pid as u32, pod_id, role_id) {
                                Ok(()) => EnrollmentResponse::Success,
                                Err(e) => {
                                    EnrollmentResponse::Error(format!("Enrollment failed: {}", e))
                                }
                            }
                        }
                    }
                }
            }
            EnrollmentRequest::Query { pid: query_pid } => {
                debug!("Query request for PID {}", query_pid);
                match process_tracker.get_process_info(query_pid) {
                    Ok(Some((pod_id, role_id))) => {
                        EnrollmentResponse::ProcessInfo { pod_id, role_id }
                    }
                    Ok(None) => {
                        EnrollmentResponse::Error("Process not found or not enrolled".to_string())
                    }
                    Err(e) => EnrollmentResponse::Error(format!("Query failed: {}", e)),
                }
            }
            EnrollmentRequest::EnrollExecutable {
                executable_path,
                pod_id,
                role_id,
            } => {
                debug!(
                    "Enroll executable request: {} -> Pod {} Role {}",
                    executable_path, pod_id.0, role_id.0
                );
                match alt_enrollment
                    .enroll_by_executable_path(&executable_path, pod_id, role_id)
                    .await
                {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => {
                        EnrollmentResponse::Error(format!("Failed to enroll executable: {}", e))
                    }
                }
            }
            EnrollmentRequest::RemoveExecutable { executable_path } => {
                debug!("Remove executable enrollment: {}", executable_path);
                match alt_enrollment
                    .remove_executable_enrollment(&executable_path)
                    .await
                {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!(
                        "Failed to remove executable enrollment: {}",
                        e
                    )),
                }
            }
            EnrollmentRequest::EnrollCgroup {
                cgroup_path,
                pod_id,
                role_id,
            } => {
                debug!(
                    "Enroll cgroup request: {} -> Pod {} Role {}",
                    cgroup_path, pod_id.0, role_id.0
                );
                match alt_enrollment
                    .enroll_by_cgroup_path(&cgroup_path, pod_id, role_id)
                    .await
                {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!("Failed to enroll cgroup: {}", e)),
                }
            }
            EnrollmentRequest::RemoveCgroup { cgroup_path } => {
                debug!("Remove cgroup enrollment: {}", cgroup_path);
                match alt_enrollment.remove_cgroup_enrollment(&cgroup_path).await {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!(
                        "Failed to remove cgroup enrollment: {}",
                        e
                    )),
                }
            }
            EnrollmentRequest::SetXattr {
                executable_path,
                pod_id,
                role_id,
            } => {
                debug!(
                    "Set xattr enrollment: {} -> Pod {} Role {}",
                    executable_path, pod_id.0, role_id.0
                );
                match alt_enrollment
                    .set_xattr_enrollment(&executable_path, pod_id, role_id)
                    .await
                {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => {
                        EnrollmentResponse::Error(format!("Failed to set xattr enrollment: {}", e))
                    }
                }
            }
            EnrollmentRequest::CheckXattr { executable_path } => {
                debug!("Check xattr enrollment: {}", executable_path);
                match alt_enrollment
                    .check_xattr_enrollment(&executable_path)
                    .await
                {
                    Ok(Some((pod_id, role_id))) => {
                        EnrollmentResponse::XattrInfo { pod_id, role_id }
                    }
                    Ok(None) => EnrollmentResponse::Error("No xattr enrollment found".to_string()),
                    Err(e) => EnrollmentResponse::Error(format!(
                        "Failed to check xattr enrollment: {}",
                        e
                    )),
                }
            }
            EnrollmentRequest::RemoveXattr { executable_path } => {
                debug!("Remove xattr enrollment: {}", executable_path);
                match alt_enrollment
                    .remove_xattr_enrollment(&executable_path)
                    .await
                {
                    Ok(()) => EnrollmentResponse::Success,
                    Err(e) => EnrollmentResponse::Error(format!(
                        "Failed to remove xattr enrollment: {}",
                        e
                    )),
                }
            }
        };

        let response_json = serde_json::to_string(&response)?;
        stream.write_all(response_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        Ok(())
    }
}
