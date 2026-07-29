use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();
    let _arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set");

    let bpf_target = if target.contains("aarch64") || target.contains("x86_64") {
        "bpfel-unknown-none"
    } else {
        panic!("Unsupported target architecture: {}", target);
    };

    // Try to use workspace target directory, fallback to crate target
    let workspace_root = env::var("CARGO_MANIFEST_DIR")
        .ok()
        .map(PathBuf::from)
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let obj_dir = if let Some(root) = &workspace_root {
        let ws_target = root.join(format!("target/{}/release", bpf_target));
        if ws_target.parent().map(|p| p.exists()).unwrap_or(false) {
            ws_target.to_string_lossy().to_string()
        } else {
            format!("target/{}/release", bpf_target)
        }
    } else {
        format!("target/{}/release", bpf_target)
    };

    std::fs::create_dir_all(&obj_dir).unwrap();

    let src_files = [
        "src/main.bpf.c",
        "src/process_tracking.bpf.c",
        "src/path_matching.bpf.c",
        "src/networking.bpf.c",
        "src/signed_binary.bpf.c",
    ];

    for src in &src_files {
        println!("cargo:rerun-if-changed={}", src);
    }

    let output = format!("{}/bpfjailer.bpf.o", obj_dir);
    compile_bpf_program("src/main.bpf.c", &output);
}

fn compile_bpf_program(src: &str, output: &str) {
    let mut cmd = Command::new("clang");
    let mut args = Vec::new();

    // Include libbpf headers only
    if PathBuf::from("/usr/include/bpf").exists() {
        args.push("-I".to_string());
        args.push("/usr/include".to_string());
    }

    args.extend_from_slice(&[
        "-O2".to_string(),
        "-g".to_string(),
        "-target".to_string(),
        "bpfel-unknown-none".to_string(),
        "-c".to_string(),
        src.to_string(),
        "-o".to_string(),
        output.to_string(),
        "-Wno-unknown-attributes".to_string(),
        "-Wno-address-of-packed-member".to_string(),
        "-Wno-unused-value".to_string(),
        "-Wno-pointer-sign".to_string(),
        // Enable BTF for task_storage maps
        "-g".to_string(), // Already have this, but ensure it's there for BTF
    ]);

    cmd.args(&args);

    let output_cmd = cmd.output().expect("Failed to execute clang");
    if !output_cmd.status.success() {
        eprintln!(
            "Clang stderr: {}",
            String::from_utf8_lossy(&output_cmd.stderr)
        );
        eprintln!("Clang command: clang {}", args.join(" "));
        panic!("Failed to compile BPF program: {}", src);
    }
}
