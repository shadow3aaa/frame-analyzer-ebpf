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
use std::{env, fs, process::Command};

use anyhow::Result;

fn main() -> Result<()> {
    build_ebpf()?;
    Ok(())
}

fn build_ebpf() -> Result<()> {
    println!("cargo:rerun-if-changed=../frame-analyzer-ebpf");

    let current_dir = env::current_dir()?;
    let project_path = current_dir.parent().unwrap().join("frame-analyzer-ebpf");
    let target_dir = current_dir.join(".ebpf_target");

    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    #[cfg(debug_assertions)]
    let ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir.as_path().to_str().unwrap(),
    ];

    #[cfg(not(debug_assertions))]
    let ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir.as_path().to_str().unwrap(),
        "--release",
    ];

    if project_path.exists() {
        Command::new("cargo")
            .arg("build")
            .args(ebpf_args)
            .env_remove("RUSTUP_TOOLCHAIN")
            .current_dir(&project_path)
            .status()?;
    } else {
        Command::new("cargo")
            .args(["install", "frame-analyzer-ebpf"])
            .args(ebpf_args)
            .status()?;
    }

    Ok(())
}
