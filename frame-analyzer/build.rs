/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::{env, fs, path::Path, process::Command};

use anyhow::Result;

fn main() -> Result<()> {
    build_ebpf()?;
    Ok(())
}

fn build_ebpf() -> Result<()> {
    let current_dir = env::current_dir()?;
    let project_path = current_dir.parent().unwrap().join("frame-analyzer-ebpf");
    let out_dir = env::var("OUT_DIR")?;
    let target_dir = Path::new(&out_dir).join("ebpf_target");
    let target_dir_str = target_dir.to_str().unwrap();

    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    let mut ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir_str,
    ];

    if project_path.exists() {
        println!("cargo:rerun-if-changed=../frame-analyzer-ebpf");
        #[cfg(not(debug_assertions))]
        ebpf_args.push("--release");
        // println!("cargo::warning=Building ebpf from workspace");
        Command::new("cargo")
            .arg("build")
            .args(ebpf_args)
            .env_remove("RUSTUP_TOOLCHAIN")
            .current_dir(&project_path)
            .status()?;
    } else {
        // println!("cargo::warning=Building ebpf from crates.io");
        #[cfg(debug_assertions)]
        ebpf_args.push("--debug");

        let _ = fs::remove_dir_all(target_dir.join("bin")); // clean up
        Command::new("cargo")
            .args(["install", "frame-analyzer-ebpf"])
            .args(ebpf_args)
            .args(["--root", target_dir_str])
            .status()?;

        #[cfg(debug_assertions)]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("debug");

        #[cfg(not(debug_assertions))]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("release");

        let _ = fs::create_dir_all(prefix_dir);
        let to = &prefix_dir.join("frame-analyzer-ebpf");
        fs::rename(target_dir.join("bin").join("frame-analyzer-ebpf"), to)?;
    }

    Ok(())
}
