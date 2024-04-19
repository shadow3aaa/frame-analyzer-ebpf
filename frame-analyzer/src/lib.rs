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
            self.buffer.extend(events.into_iter().map(|e| e.to_owned()));
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
            self.buffer.extend(events.into_iter().map(|e| e.to_owned()));
        }

        let event = self.buffer.pop_front()?;
        let Token(pid) = event.token();
        let pid = pid as Pid;
        let frametime = self.map.get_mut(&pid)?.update().ok()?;

        Some((pid, frametime))
    }
}
