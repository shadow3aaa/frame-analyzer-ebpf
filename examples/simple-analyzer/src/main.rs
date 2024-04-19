use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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

    while running.load(Ordering::Acquire) {
        if let Some((_, frametime)) = analyzer.recv() {
            println!("frametime: {frametime:?}");
        }
    }

    Ok(())
}
