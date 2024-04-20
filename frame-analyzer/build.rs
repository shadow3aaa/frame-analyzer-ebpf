use std::{env, fs, process::Command};

use anyhow::Result;

fn main() -> Result<()> {
    build_stub()?;
    Ok(())
}

fn build_stub() -> Result<()> {
    let current_dir = env::current_dir()?;
    let project_path = current_dir.parent().unwrap().join("frame-analyzer-ebpf");
    let target_dir = current_dir.join(".ebpf_target");

    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    #[cfg(debug_assertions)]
    let build_args = vec![
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];
    #[cfg(release_assertions)]
    let build_args = vec![
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--release",
    ];

    /* println!("cargo:warning={:?}", build_args);
    println!("cargo:warning={:?}", project_path);
    println!("cargo:warning={:?}", target_dir); */

    Command::new("cargo")
        .args(build_args)
        .args(["--target-dir", target_dir.as_os_str().to_str().unwrap()])
        .env_remove("RUSTUP_TOOLCHAIN")
        .current_dir(&project_path)
        .output()?;

    Ok(())
}
