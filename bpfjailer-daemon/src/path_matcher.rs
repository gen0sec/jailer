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
        info!("Compiling {} path patterns", patterns.len());

        // Validate patterns (basic checks)
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
            // Check for invalid wildcard usage
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

    /// Invalidate the inode cache by incrementing cache generation counter
    pub fn invalidate_cache(&self) -> Result<()> {
        info!("Invalidating path matching cache");
        self.bpf
            .invalidate_cache()
            .context("Failed to invalidate cache")
    }
}
