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
#![warn(clippy::nursery, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
//! # frame-analyzer
//!
//! - This crate is used to monitor the frametime of the target app on the android device
//! - Based on the EBPF and UPROBE implementations, you may need higher privileges (e.g. root) to use this crate properly
//! - This IS NOT a bin crate, it uses some tricks (see [source](https://github.com/shadow3aaa/frame-analyzer-ebpf?tab=readme-ov-file)) to get it to work like a normal lib crate, even though it includes an EBPF program
//!
//! # Examples
//!
//! ```should_panic
//! # use std::sync::{
//! # atomic::{AtomicBool, Ordering},
//! # Arc,
//! # };
//!
//! # use frame_analyzer::Analyzer;
//!
//! # fn main() -> anyhow::Result<()> {
//!     # let app_pid = 1;
//!     let pid = app_pid;
//!     let mut analyzer = Analyzer::new()?;
//!     analyzer.attach_app(pid)?;
//!
//!     let running = Arc::new(AtomicBool::new(true));
//!
//!     {
//!         let running = running.clone();
//!         ctrlc::set_handler(move || {
//!         running.store(false, Ordering::Release);
//!         })?;
//!     }
//!
//!     while running.load(Ordering::Acquire) {
//!         if let Some((pid, frametime)) = analyzer.recv() {
//!             println!("process: {pid}, frametime: {frametime:?}");
//!         }
//!     }
//!
//!     # Ok(())
//! }
//! ```
mod analyze_target;
mod ebpf;
mod error;
mod uprobe;

use std::{
    collections::{HashMap, VecDeque},
    os::unix::io::AsRawFd,
    time::Duration,
};

use mio::{event::Event, unix::SourceFd, Events, Interest, Poll, Token};

use analyze_target::AnalyzeTarget;
pub use error::AnalyzerError;
use error::Result;
use uprobe::UprobeHandler;

pub type Pid = i32;

const EVENT_MAX: usize = 1024;

pub struct Analyzer {
    poll: Poll,
    map: HashMap<Pid, AnalyzeTarget>,
    buffer: VecDeque<Event>,
}

impl Analyzer {
    pub fn new() -> Result<Self> {
        let poll = Poll::new()?;
        let map = HashMap::new();
        let buffer = VecDeque::with_capacity(EVENT_MAX);

        Ok(Self { poll, map, buffer })
    }

    pub fn attach_app(&mut self, pid: Pid) -> Result<()> {
        let mut uprobe = UprobeHandler::attach_app(pid)?;

        self.poll.registry().register(
            &mut SourceFd(&uprobe.ring()?.as_raw_fd()),
            Token(pid as usize),
            Interest::READABLE,
        )?;
        self.map.insert(pid, AnalyzeTarget::new(uprobe));

        Ok(())
    }

    pub fn detach_app(&mut self, pid: Pid) -> Result<()> {
        let mut target = self.map.remove(&pid).ok_or(AnalyzerError::AppNotFound)?;
        self.poll
            .registry()
            .deregister(&mut SourceFd(&target.uprobe.ring()?.as_raw_fd()))?;

        Ok(())
    }

    pub fn recv(&mut self) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            let mut events = Events::with_capacity(EVENT_MAX);
            let _ = self.poll.poll(&mut events, None);
            self.buffer
                .extend(events.into_iter().map(std::borrow::ToOwned::to_owned));
        }

        let event = self.buffer.pop_front()?;
        let Token(pid) = event.token();
        let pid = pid as Pid;
        let frametime = self.map.get_mut(&pid)?.update().ok()?;

        Some((pid, frametime))
    }

    pub fn recv_timeout(&mut self, time: Duration) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            let mut events = Events::with_capacity(EVENT_MAX);
            let _ = self.poll.poll(&mut events, Some(time));
            self.buffer
                .extend(events.into_iter().map(std::borrow::ToOwned::to_owned));
        }

        let event = self.buffer.pop_front()?;
        let Token(pid) = event.token();
        let pid = pid as Pid;
        let frametime = self.map.get_mut(&pid)?.update().ok()?;

        Some((pid, frametime))
    }
}
