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

/// Root-gated integration tests: they bind the real enrollment socket and
/// drive it with the real client. See `bpf_loader::root_integration`.
#[cfg(test)]
mod root_integration {
    use super::*;
    use bpfjailer_client::EnrollmentClient;
    use bpfjailer_common::{PodId, RoleId};
    use tokio::io::AsyncReadExt;

    /// Bring up a server on the real socket path and hand back a client.
    /// Returns None when the environment cannot support it (no root / no BPF).
    async fn server() -> Option<EnrollmentClient> {
        let bpf = Arc::new(crate::bpf_loader::BpfJailerBpf::load().ok()?);
        let tracker = Arc::new(ProcessTracker::new(bpf.clone()).ok()?);
        let pm = Arc::new(RwLock::new(PolicyManager::new().ok()?));
        let alt = Arc::new(AlternativeEnrollment::new(bpf, tracker.clone(), pm.clone()));
        let srv = EnrollmentServer::new(tracker, pm, alt);

        // Clear any socket left by an earlier test: its presence would
        // otherwise look like readiness while nothing is listening.
        let _ = std::fs::remove_file(SOCKET_PATH);

        tokio::spawn(async move {
            let _ = srv.run().await;
        });

        // Readiness is "a connect succeeds", not "the file exists" -- a stale
        // socket file yields ECONNREFUSED.
        for _ in 0..200 {
            if AsyncUnixStream::connect(SOCKET_PATH).await.is_ok() {
                return Some(EnrollmentClient::new(SOCKET_PATH));
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        None
    }

    macro_rules! client_or_skip {
        () => {
            match server().await {
                Some(c) => c,
                None => {
                    eprintln!("skipping: needs root and a BPF-capable kernel");
                    return;
                }
            }
        };
    }

    /// Send a request the typed client has no helper for.
    async fn raw(req: &EnrollmentRequest) -> EnrollmentResponse {
        let mut s = AsyncUnixStream::connect(SOCKET_PATH)
            .await
            .expect("connect");
        let mut json = serde_json::to_vec(req).expect("encode");
        json.push(b'\n');
        s.write_all(&json).await.expect("write");
        s.flush().await.expect("flush");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.expect("read");
        serde_json::from_slice(&buf).expect("decode response")
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn enroll_over_the_socket_succeeds() {
        let c = client_or_skip!();
        c.enroll(PodId(910), RoleId(2)).await.expect("enroll");
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn query_reports_not_enrolled_while_get_process_info_is_a_stub() {
        let c = client_or_skip!();
        // get_process_info always returns None today, so Query answers with an
        // error rather than ProcessInfo. Pinned so a real implementation has
        // to update this deliberately.
        assert!(c.query(std::process::id()).await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn executable_enrollment_over_the_socket_round_trips() {
        let _c = client_or_skip!();
        let exe = std::env::temp_dir().join(format!("bpfjailer-sock-{}", std::process::id()));
        std::fs::copy("/bin/sh", &exe).expect("copy");
        let path = exe.to_str().unwrap().to_string();

        let r = raw(&EnrollmentRequest::EnrollExecutable {
            executable_path: path.clone(),
            pod_id: PodId(920),
            role_id: RoleId(2),
        })
        .await;
        assert!(matches!(r, EnrollmentResponse::Success), "got {r:?}");

        let r = raw(&EnrollmentRequest::RemoveExecutable {
            executable_path: path.clone(),
        })
        .await;
        assert!(matches!(r, EnrollmentResponse::Success), "got {r:?}");
        let _ = std::fs::remove_file(&exe);
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn xattr_requests_round_trip_over_the_socket() {
        let _c = client_or_skip!();
        let exe = std::env::temp_dir().join(format!("bpfjailer-sockx-{}", std::process::id()));
        std::fs::copy("/bin/sh", &exe).expect("copy");
        let path = exe.to_str().unwrap().to_string();

        assert!(matches!(
            raw(&EnrollmentRequest::SetXattr {
                executable_path: path.clone(),
                pod_id: PodId(931),
                role_id: RoleId(2),
            })
            .await,
            EnrollmentResponse::Success
        ));

        match raw(&EnrollmentRequest::CheckXattr {
            executable_path: path.clone(),
        })
        .await
        {
            EnrollmentResponse::XattrInfo { pod_id, role_id } => {
                assert_eq!((pod_id, role_id), (PodId(931), RoleId(2)));
            }
            other => panic!("expected XattrInfo, got {other:?}"),
        }

        assert!(matches!(
            raw(&EnrollmentRequest::RemoveXattr {
                executable_path: path.clone()
            })
            .await,
            EnrollmentResponse::Success
        ));
        let _ = std::fs::remove_file(&exe);
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn a_failing_request_returns_an_error_response_not_a_dropped_connection() {
        let _c = client_or_skip!();
        let r = raw(&EnrollmentRequest::EnrollExecutable {
            executable_path: "/nonexistent/binary".into(),
            pod_id: PodId(1),
            role_id: RoleId(1),
        })
        .await;
        assert!(matches!(r, EnrollmentResponse::Error(_)), "got {r:?}");
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn cgroup_requests_are_answered() {
        let _c = client_or_skip!();
        let r = raw(&EnrollmentRequest::EnrollCgroup {
            cgroup_path: "/sys/fs/cgroup/definitely-not-here".into(),
            pod_id: PodId(1),
            role_id: RoleId(1),
        })
        .await;
        assert!(matches!(r, EnrollmentResponse::Error(_)), "got {r:?}");

        let r = raw(&EnrollmentRequest::RemoveCgroup {
            cgroup_path: "/sys/fs/cgroup/definitely-not-here".into(),
        })
        .await;
        // Removal of an absent entry may succeed or report an error; it must
        // answer either way rather than hanging.
        assert!(matches!(
            r,
            EnrollmentResponse::Success | EnrollmentResponse::Error(_)
        ));
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn malformed_json_does_not_take_the_server_down() {
        let c = client_or_skip!();
        {
            let mut s = AsyncUnixStream::connect(SOCKET_PATH)
                .await
                .expect("connect");
            s.write_all(b"{ not json\n").await.expect("write");
            s.flush().await.expect("flush");
        }
        // The server must still serve the next client.
        c.enroll(PodId(940), RoleId(2))
            .await
            .expect("still serving");
    }
}
