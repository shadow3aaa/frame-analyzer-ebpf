use std::{mem, ptr, time::Duration};

use frame_analyzer_ebpf_common::FrameSignal;

use crate::{
    error::{AnalyzerError, Result},
    uprobe::UprobeHandler,
};

pub struct AnalyzeTarget {
    pub uprobe: UprobeHandler,
    ktime_us_last: u64,
}

impl AnalyzeTarget {
    pub fn new(uprobe: UprobeHandler) -> Self {
        Self {
            uprobe,
            ktime_us_last: 0,
        }
    }

    pub fn update(&mut self) -> Result<Duration> {
        let mut frametime = 0;
        while let Some(item) = self.uprobe.ring()?.next() {
            let frame = try_read(&item)?;
            frametime = frame.ktime_ns.saturating_sub(self.ktime_us_last);
            self.ktime_us_last = frame.ktime_ns;
        }

        Ok(Duration::from_nanos(frametime))
    }
}

fn try_read(buf: &[u8]) -> Result<FrameSignal> {
    if buf.len() < mem::size_of::<FrameSignal>() {
        return Err(AnalyzerError::MapError);
    }

    let signal = unsafe { ptr::read_unaligned(buf.as_ptr() as *const FrameSignal) };
    Ok(signal)
}
