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
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
//! # frame-analyzer
//!
//! - This crate is used to monitor the frametime of the target application on the android device
//! - Based on the EBPF and UPROBE implementations, you may need higher privileges (e.g. root) to use this crate properly
//! - This IS NOT a bin crate, it uses some tricks (see [source](https://github.com/shadow3aaa/frame-analyzer-ebpf?tab=readme-ov-file)) to get it to work like a normal lib crate, even though it includes an EBPF program
//! - Only 64-bit devices & apps are supported!
//!
//! # Examples
//!
//! Simple frametime analyzer, print pid & frametime on the screen
//!
//! ```
//! use std::sync::{
//!   atomic::{AtomicBool, Ordering},
//!   Arc,
//! };
//!
//! use frame_analyzer::Analyzer;
//!
//! # fn main() {
//! #   let _ = try_main(); // ignore error
//! # }
//! #
//! # fn try_main() -> anyhow::Result<()> {
//! #   let app_pid_a = 1;
//! #   let app_pid_b = 2;
//! #   let app_pid_c = 3;
//! let mut analyzer = Analyzer::new()?;
//! analyzer.attach_app(app_pid_a)?;
//! analyzer.attach_app(app_pid_b)?;
//! analyzer.attach_app(app_pid_c)?; // muti-apps are supported
//!
//! let running = Arc::new(AtomicBool::new(true));
//!
//! {
//!     let running = running.clone();
//!     ctrlc::set_handler(move || {
//!         running.store(false, Ordering::Release);
//!     })?;
//! }
//! #
//! #   running.store(false, Ordering::Release); // avoid dead-loop in test
//! #
//! while running.load(Ordering::Acquire) {
//!     if let Some((pid, frametime)) = analyzer.recv() {
//!         println!("process: {pid}, frametime: {frametime:?}");
//!     }
//! }
//! #
//! #   Ok(())
//! # }
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

/// The pid of the target application
pub type Pid = i32;

const EVENT_MAX: usize = 1024;

/// The Frame Analyzer
///
/// # Examples
///
/// ```
/// # use frame_analyzer::Analyzer;
/// #
/// #
/// # fn main() {
/// #   let _ = try_main();
/// # }
/// #
/// # fn try_main() -> anyhow::Result<()> {
/// # let app_pid = 1;
/// let mut analyzer = Analyzer::new()?;
/// analyzer.attach_app(app_pid)?;
///
/// if let Some((pid, frametime)) = analyzer.recv() {
///     println!("process: {pid}, frametime: {frametime:?}");
/// }
/// #   Ok(())
/// # }
/// ```
pub struct Analyzer {
    poll: Option<Poll>,
    map: HashMap<Pid, AnalyzeTarget>,
    buffer: VecDeque<Pid>,
}

impl Analyzer {
    /// Create a new analyzer
    ///
    /// # Errors
    ///
    /// This function will make a syscall to the operating system to create the system selector. If this syscall fails, `Analyzer::new` will return with the error.
    /// See [mio Poll](https://docs.rs/mio/0.8.11/mio/poll/struct.Poll.html) docs for more details.
    ///
    /// # Examples
    /// ```
    /// use frame_analyzer::Analyzer;
    ///
    /// #
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// let analyzer = Analyzer::new()?;
    /// #   Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        let poll = None;
        let map = HashMap::new();
        let buffer = VecDeque::with_capacity(EVENT_MAX);

        Ok(Self { poll, map, buffer })
    }

    /// Attach the Analyzer to the target application
    /// If attach the same application multiple times, `Analyzer::attach_app` will directly return `Ok` without attaching again
    ///
    /// # Errors
    ///
    /// `Analyzer::attach_app` will return an error in these cases
    ///
    /// - Target application is not 64-bit
    /// - Target application is not using /system/lib64/libgui.so (this will only happen if you use this crate on a non-Android platform)
    /// - Current user does not have enough permissions to load the built-in ebpf program into the kernel, in which case it will return `BpfProgramError`
    ///
    /// # Examples
    ///
    /// ```
    /// # use frame_analyzer::Analyzer;
    /// #
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// #   let mut analyzer = Analyzer::new()?;
    /// #   let app_pid = 2;
    /// analyzer.attach_app(app_pid)?;
    /// #   Ok(())
    /// # }
    /// ```
    pub fn attach_app(&mut self, pid: Pid) -> Result<()> {
        if self.contains(pid) {
            return Ok(());
        }

        let uprobe = UprobeHandler::attach_app(pid)?;
        self.map.insert(pid, AnalyzeTarget::new(uprobe));
        self.register_poll()?;

        Ok(())
    }

    /// Detach the Analyzer from the target application
    ///
    /// # Errors
    ///
    /// `Analyzer::detach_app` returns `AppNotFound` if the target app is not already attached by `Analyzer::attach`
    ///
    /// # Examples
    ///
    /// ```
    /// # use frame_analyzer::Analyzer;
    /// #
    /// #
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// let mut analyzer = Analyzer::new()?;
    /// #   let app_pid = 2;
    /// analyzer.attach_app(app_pid)?;
    /// // Do some useful work for awhile
    /// analyzer.detach_app(app_pid)?; // if you don't detach here, analyzer will auto detach it when itself go dropped
    /// #   Ok(())
    /// # }
    /// ```
    pub fn detach_app(&mut self, pid: Pid) -> Result<()> {
        if !self.contains(pid) {
            return Ok(());
        }

        self.map.remove(&pid).ok_or(AnalyzerError::AppNotFound)?;
        self.register_poll()?;

        Ok(())
    }

    /// Detach the Analyzer from all attached apps
    ///
    /// # Examples
    ///
    /// ```
    /// # use frame_analyzer::Analyzer;
    /// #
    /// #
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// let mut analyzer = Analyzer::new()?;
    /// #   let app_pid = 2;
    /// analyzer.attach_app(app_pid);
    /// // Do some useful work for awhile
    /// analyzer.detach_apps(); // if you don't detach here, analyzer will auto detach it when itself go dropped
    /// #   Ok(())
    /// # }
    /// ```
    pub fn detach_apps(&mut self) {
        self.map.clear();
    }

    /// Attempts to wait for a frametime value on this analyzer
    /// `Analyzer::recv` will always block the current thread if there is no data available
    ///
    /// # Examples
    /// ```
    /// # use frame_analyzer::Analyzer;
    /// #
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// #   let mut analyzer = Analyzer::new()?;
    /// #   let app_pid = 2;
    /// analyzer.attach_app(app_pid)?;
    ///
    /// if let Some((pid, frametime)) = analyzer.recv() {
    ///     println!("process: {pid}, frametime: {frametime:?}");
    ///     // and use it for further analyze...
    /// }
    ///
    /// analyzer.detach_app(app_pid)?; // if you don't detach here, analyzer will auto detach it when itself go dropped
    /// #   Ok(())
    /// # }
    /// ```
    pub fn recv(&mut self) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            if let Some(ref mut poll) = self.poll {
                let mut events = Events::with_capacity(EVENT_MAX);
                let _ = poll.poll(&mut events, None);

                self.buffer.extend(events.iter().map(event_to_pid));
            }

            let _ = self.register_poll();
        }

        let pid = self.buffer.pop_front()?;
        let frametime = self.map.get_mut(&pid)?.update()?;

        Some((pid, frametime))
    }

    /// Attempts to wait for a value on this receiver, returning `None` if it waits more than timeout
    /// `Analyzer::recv_timeout` will always block the current thread if there is no data available
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    /// # use frame_analyzer::Analyzer;
    ///
    /// # fn main() {
    /// #   let _ = try_main();
    /// # }
    /// #
    /// # fn try_main() -> anyhow::Result<()> {
    /// #   let mut analyzer = Analyzer::new()?;
    /// #   let app_pid = 2;
    /// analyzer.attach_app(app_pid)?;
    ///
    /// if let Some((pid, frametime)) = analyzer.recv_timeout(Duration::from_secs(1)) {
    ///     println!("process: {pid}, frametime: {frametime:?}");
    ///     // and use it for further analyze...
    /// }
    ///
    /// analyzer.detach_app(app_pid)?; // if you don't detach here, analyzer will auto detach it when itself go dropped
    /// #   Ok(())
    /// # }
    /// ```
    pub fn recv_timeout(&mut self, time: Duration) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            if let Some(ref mut poll) = self.poll {
                let mut events = Events::with_capacity(EVENT_MAX);
                let _ = poll.poll(&mut events, Some(time));

                self.buffer.extend(events.iter().map(event_to_pid));
            }

            let _ = self.register_poll();
        }

        let pid = self.buffer.pop_front()?;
        let frametime = self.map.get_mut(&pid)?.update()?;

        Some((pid, frametime))
    }

    /// Whether the target application has been attached by the `Analyzer`
    #[must_use]
    pub fn contains(&self, app: Pid) -> bool {
        self.map.contains_key(&app)
    }

    /// An iterator visiting all attched pids in arbitrary order
    pub fn pids(&self) -> impl Iterator<Item = Pid> + '_ {
        self.map.keys().copied()
    }

    fn register_poll(&mut self) -> Result<()> {
        let poll = Poll::new()?;

        for (pid, handler) in &mut self.map {
            poll.registry().register(
                &mut SourceFd(&handler.uprobe.ring()?.as_raw_fd()),
                Token(*pid as usize),
                Interest::READABLE,
            )?;
        }

        self.poll = Some(poll);
        Ok(())
    }
}

fn event_to_pid(event: &Event) -> Pid {
    let token = event.token();
    let Token(pid) = token;
    pid as Pid
}
