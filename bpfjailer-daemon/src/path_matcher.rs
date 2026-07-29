use crate::bpf_loader::BpfJailerBpf;
use anyhow::{Context, Result};
use log::info;
use std::sync::Arc;

pub struct PathMatcher {
    bpf: Arc<BpfJailerBpf>,
}

impl PathMatcher {
    pub fn new(bpf: Arc<BpfJailerBpf>) -> Result<Self> {
        info!("Initializing path matcher");
        Ok(Self { bpf })
    }

    /// Compile and validate path patterns
    pub fn compile_patterns(&self, patterns: &[String]) -> Result<()> {
        validate_patterns(patterns)
    }
    /// Invalidate the inode cache by incrementing cache generation counter
    pub fn invalidate_cache(&self) -> Result<()> {
        info!("Invalidating path matching cache");
        self.bpf
            .invalidate_cache()
            .context("Failed to invalidate cache")
    }
}

/// Validate path patterns before they are compiled into the state machine.
///
/// Split out of `PathMatcher::compile_patterns` so it can be tested without a
/// loaded BPF object -- it never needed `self`.
pub fn validate_patterns(patterns: &[String]) -> Result<()> {
    info!("Compiling {} path patterns", patterns.len());

    for pattern in patterns {
        if pattern.is_empty() {
            return Err(anyhow::anyhow!("Empty path pattern not allowed"));
        }
        if !pattern.starts_with('/') {
            return Err(anyhow::anyhow!(
                "Path pattern must be absolute (start with /): {}",
                pattern
            ));
        }
        if pattern.contains("***") {
            return Err(anyhow::anyhow!(
                "Invalid wildcard pattern (triple asterisk): {}",
                pattern
            ));
        }
    }

    info!("Validated {} path patterns", patterns.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_absolute_patterns() {
        assert!(validate_patterns(&pats(&["/etc/passwd", "/var/www/**", "/a/*/b"])).is_ok());
    }

    #[test]
    fn accepts_an_empty_pattern_list() {
        assert!(validate_patterns(&[]).is_ok());
    }

    #[test]
    fn rejects_empty_pattern() {
        let err = validate_patterns(&pats(&[""])).unwrap_err().to_string();
        assert!(err.contains("Empty path pattern"), "got: {err}");
    }

    #[test]
    fn rejects_relative_pattern() {
        let err = validate_patterns(&pats(&["etc/passwd"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be absolute"), "got: {err}");
    }

    #[test]
    fn rejects_triple_asterisk() {
        let err = validate_patterns(&pats(&["/var/***/x"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("triple asterisk"), "got: {err}");
    }

    #[test]
    fn rejects_the_whole_batch_if_any_pattern_is_bad() {
        // A single bad pattern must fail the batch rather than be skipped --
        // silently dropping a deny rule would widen the policy.
        assert!(validate_patterns(&pats(&["/good", "bad", "/also/good"])).is_err());
    }

    #[test]
    fn double_asterisk_is_still_allowed() {
        assert!(validate_patterns(&pats(&["/var/**"])).is_ok());
    }
}

/// Root-gated tests for the parts that need a loaded BPF object.
#[cfg(test)]
mod root_integration {
    use super::*;
    use crate::bpf_loader::BpfJailerBpf;

    #[test]
    #[ignore = "requires root"]
    fn new_and_invalidate_cache_work_against_a_loaded_object() {
        let Ok(bpf) = BpfJailerBpf::load() else {
            eprintln!("skipping: needs root and a BPF-capable kernel");
            return;
        };
        let pm = PathMatcher::new(Arc::new(bpf)).expect("construct");
        pm.compile_patterns(&["/etc/ssh/".to_string()])
            .expect("compile");
        pm.invalidate_cache().expect("invalidate");
    }
}
