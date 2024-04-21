# frame-analyzer-ebpf

[![Crates.io][crates-badge]][crates-url]
![License][license-badge]
[![Build status][build-badge]][build-url]
[![Documentaiton][api-docs-badge]][api-docs]

[crates-badge]: https://img.shields.io/crates/v/frame-analyzer.svg?style=for-the-badge&logo=rust
[crates-url]: https://crates.io/crates/frame-analyzer
[license-badge]: https://img.shields.io/badge/license-GPLv3-blue?style=for-the-badge
[build-badge]: https://img.shields.io/github/actions/workflow/status/aya-rs/aya/ci.yml?style=for-the-badge
[build-url]: https://github.com/aya-rs/aya/actions/workflows/ci.yml
[api-docs-badge]: https://img.shields.io/badge/docs-frame--analyzer-blue.svg?style=for-the-badge&logo=docsdotrs
[api-docs]: https://shadow3aaa.github.io/frame-analyzer-ebpf

Track the frametime of Android apps, based on ebpf & uprobe

- Based on the EBPF and UPROBE implementations, you may need higher privileges (e.g. root) to use this crate properly
- This IS NOT a bin crate, it uses some tricks (see [source](https://github.com/shadow3aaa/frame-analyzer-ebpf?tab=readme-ov-file)) to get it to work like a normal lib crate, even though it includes an EBPF program
- Only 64-bit devices & apps are supported!

## Examples

Simple frametime analyzer, print pid & frametime on the screen

```rust
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
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
```

## LICENSE

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) file for details.
