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
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use frame_analyzer::Analyzer;

/// Simple frame analyzer, print frametime on the screen
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The pid of the target application
    #[arg(short, long)]
    pid: i32,
}

fn main() -> Result<()> {
    let arg = Args::parse();
    let pid = arg.pid;

    let mut analyzer = Analyzer::new()?;
    analyzer.attach_app(pid)?;

    let running = Arc::new(AtomicBool::new(true));

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::Release);
        })?;
    }

    let mut buffer = VecDeque::with_capacity(120);

    while running.load(Ordering::Acquire) {
        if let Some((pid, frametime)) = analyzer.recv() {
            println!("frametime: {frametime:?}, pid: {pid}");
            if buffer.len() >= 120 {
                buffer.pop_back();
            }
            buffer.push_front(frametime);
            if buffer.len() == 120 {
                let fps = 1.0
                    / (buffer.iter().copied().sum::<Duration>() / buffer.len() as u32)
                        .as_secs_f64();
                println!("{fps}");
            }
        }
    }

    Ok(())
}
