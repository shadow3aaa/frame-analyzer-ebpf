use std::{ptr, time::Duration};

use frame_analyzer_ebpf_common::FrameSignal;

use crate::{error::Result, uprobe::UprobeHandler};

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
        if let Some(item) = self.uprobe.ring()?.next() {
            let frame = unsafe { trans(&item) };
            frametime = frame.ktime_ns.saturating_sub(self.ktime_us_last);
            self.ktime_us_last = frame.ktime_ns;
        }

        Ok(Duration::from_nanos(frametime))
    }
}

unsafe fn trans(buf: &[u8]) -> FrameSignal {
    ptr::read_unaligned(buf.as_ptr() as *const FrameSignal)
}
