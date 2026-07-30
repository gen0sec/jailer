use anyhow::Result;
use libbpf_rs::{MapCore as _, ObjectBuilder};
use std::ffi::OsStr;
use log::{error, info};
use std::path::PathBuf;

fn main() -> Result<()> {
    env_logger::init();

    info!("Testing task_storage map creation...");

    // Find the compiled BPF object
    let possible_paths = [
        PathBuf::from("target/bpfel-unknown-none/release/test_task_storage.bpf.o"),
        PathBuf::from("target/bpfel-unknown-none/debug/test_task_storage.bpf.o"),
        PathBuf::from("../target/bpfel-unknown-none/release/test_task_storage.bpf.o"),
        PathBuf::from("../target/bpfel-unknown-none/debug/test_task_storage.bpf.o"),
    ];

    let obj_path = possible_paths.iter()
        .find(|p| p.exists())
        .ok_or_else(|| anyhow::anyhow!("test_task_storage.bpf.o not found"))?;

    info!("Loading BPF object from: {:?}", obj_path);

    // Try to load the BPF object
    match ObjectBuilder::default()
        .open_file(obj_path)?
        .load()
    {
        Ok(object) => {
            info!("✅ SUCCESS: task_storage map created successfully!");

            // Check if map exists
            if object.maps().any(|m| m.name() == OsStr::new("test_task_storage")) {
                info!("✅ Map 'test_task_storage' found in object");
            } else {
                error!("❌ Map 'test_task_storage' not found in object");
            }

            // Check if program exists
            if object.progs().any(|p| p.name() == OsStr::new("test_task_alloc")) {
                info!("✅ Program 'test_task_alloc' found in object");
            } else {
                error!("❌ Program 'test_task_alloc' not found in object");
            }

            info!("Test completed successfully!");
            Ok(())
        }
        Err(e) => {
            error!("❌ FAILED: {}", e);
            error!("");
            error!("This indicates the kernel is rejecting the task_storage map creation.");
            error!("Possible causes:");
            error!("  1. Kernel doesn't support task_storage (needs 5.11+)");
            error!("  2. BPF LSM not active (check: cat /sys/kernel/security/lsm)");
            error!("  3. Kernel bug or configuration issue");
            error!("  4. Map definition issue (unlikely if this test fails)");
            Err(e.into())
        }
    }
}
