mod bpf_loader;
mod enrollment;
mod enrollment_alternatives;
mod path_matcher;
mod policy;
mod process_tracker;
mod signed_binary;

use anyhow::Result;
use log::{error, info, warn};
use std::env;
use std::path::Path;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;

const DEFAULT_POLICY_PATH: &str = "/etc/bpfjailer/policy.json";
const LOCAL_POLICY_PATH: &str = "config/policy.json";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("BpfJailer daemon starting...");

    let bpf = match bpf_loader::BpfJailerBpf::load() {
        Ok(b) => Arc::new(b),
        Err(e) => {
            error!("Failed to load eBPF programs: {}", e);
            return Err(e);
        }
    };

    // Initialize policy manager with default roles
    let mut policy_manager = policy::PolicyManager::new()?;

    // Load policy from file if available
    let policy_path = env::var("BPFJAILER_POLICY").ok().or_else(|| {
        if Path::new(DEFAULT_POLICY_PATH).exists() {
            Some(DEFAULT_POLICY_PATH.to_string())
        } else if Path::new(LOCAL_POLICY_PATH).exists() {
            Some(LOCAL_POLICY_PATH.to_string())
        } else {
            None
        }
    });

    if let Some(path) = policy_path {
        match policy_manager.load_from_file(&path).await {
            Ok(()) => info!("Loaded policy from {}", path),
            Err(e) => warn!("Failed to load policy from {}: {}", path, e),
        }
    } else {
        info!("No policy file found, using default roles");
    }

    let policy_manager = Arc::new(RwLock::new(policy_manager));
    let process_tracker = Arc::new(process_tracker::ProcessTracker::new(bpf.clone())?);
    let path_matcher = Arc::new(path_matcher::PathMatcher::new(bpf.clone())?);
    let _signed_binary = Arc::new(signed_binary::SignedBinaryManager::new(bpf.clone())?);

    // Compile path patterns from loaded policy and invalidate cache
    {
        let pm = policy_manager.read().await;
        let all_patterns: Vec<String> = pm
            .config()
            .roles
            .values()
            .flat_map(|role| role.file_paths.iter().map(|p| p.pattern.clone()))
            .collect();
        drop(pm);

        if !all_patterns.is_empty() {
            if let Err(e) = path_matcher.compile_patterns(&all_patterns) {
                warn!("Failed to compile path patterns: {}", e);
            }
            // Invalidate cache since path rules may have changed
            if let Err(e) = path_matcher.invalidate_cache() {
                warn!("Failed to invalidate cache: {}", e);
            }
        }
    }

    // Apply every role through the shared walk, so the daemon and the
    // daemonless bootstrap honour exactly the same sections of a policy.
    // Enrollment re-applies flags/paths/network per process; the writes are
    // idempotent, so doing them eagerly here as well is harmless.
    {
        let pm = policy_manager.read().await;
        for (name, role) in &pm.config().roles {
            let mut sink = process_tracker::TrackerSink(&process_tracker);
            match bpfjailer_common::apply::apply_role(
                &mut sink,
                role,
                &bpfjailer_common::apply::SystemResolver,
            ) {
                Ok(skipped) => {
                    for s in skipped {
                        warn!("Role '{}': skipped {}", name, s);
                    }
                }
                Err(e) => warn!("Failed to apply role '{}': {}", name, e),
            }
        }
    }

    // Initialize alternative enrollment methods
    let alt_enrollment = Arc::new(enrollment_alternatives::AlternativeEnrollment::new(
        bpf.clone(),
        process_tracker.clone(),
        policy_manager.clone(),
    ));

    // Load auto-enrollment rules from policy
    if let Err(e) = alt_enrollment.load_from_policy().await {
        warn!("Failed to load auto-enrollment rules: {}", e);
    }

    let enrollment_server = enrollment::EnrollmentServer::new(
        process_tracker.clone(),
        policy_manager.clone(),
        alt_enrollment.clone(),
    );

    let server_handle = tokio::spawn(async move {
        if let Err(e) = enrollment_server.run().await {
            error!("Enrollment server error: {}", e);
        }
    });

    info!("BpfJailer daemon started");
    info!("Press Ctrl+C to shutdown");

    signal::ctrl_c().await?;
    info!("Shutting down...");

    server_handle.abort();

    info!("BpfJailer daemon stopped");
    Ok(())
}
