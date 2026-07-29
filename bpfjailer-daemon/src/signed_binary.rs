use crate::bpf_loader::BpfJailerBpf;
use anyhow::Result;
use log::info;
use std::sync::Arc;

pub struct SignedBinaryManager {
    _bpf: Arc<BpfJailerBpf>,
}

// Signature validation is not wired up yet (README lists it as a stub), so
// these are intentionally unreferenced until the enforcement path lands.
#[allow(dead_code)]
impl SignedBinaryManager {
    pub fn new(bpf: Arc<BpfJailerBpf>) -> Result<Self> {
        info!("Initializing signed binary manager");
        Ok(Self { _bpf: bpf })
    }

    pub fn load_certificates(&self, cert_path: &str) -> Result<()> {
        info!("Loading certificates from {}", cert_path);
        Ok(())
    }

    pub fn validate_binary(&self, binary_path: &str) -> Result<bool> {
        info!("Validating binary: {}", binary_path);
        Ok(false)
    }
}

/// Root-gated tests. See `bpf_loader::root_integration`.
///
/// Signature validation is a stub today; these pin the stub's behaviour so a
/// real implementation has to update them deliberately rather than silently
/// changing what callers get.
#[cfg(test)]
mod root_integration {
    use super::*;

    fn manager() -> Option<SignedBinaryManager> {
        let bpf = Arc::new(BpfJailerBpf::load().ok()?);
        SignedBinaryManager::new(bpf).ok()
    }

    macro_rules! mgr_or_skip {
        () => {
            match manager() {
                Some(m) => m,
                None => {
                    eprintln!("skipping: needs root and a BPF-capable kernel");
                    return;
                }
            }
        };
    }

    #[test]
    #[ignore = "requires root"]
    fn manager_constructs() {
        let _ = mgr_or_skip!();
    }

    #[test]
    #[ignore = "requires root"]
    fn load_certificates_is_a_no_op_stub() {
        let m = mgr_or_skip!();
        m.load_certificates("/etc/bpfjailer/certs")
            .expect("stub returns Ok");
    }

    #[test]
    #[ignore = "requires root"]
    fn validate_binary_currently_rejects_everything() {
        let m = mgr_or_skip!();
        assert!(
            !m.validate_binary("/bin/sh").expect("stub returns Ok"),
            "stub reports every binary as unsigned; enabling require_signed_binary \
             today would deny all execs"
        );
    }
}
