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

const unsafe fn trans(buf: &[u8]) -> FrameSignal {
    ptr::read_unaligned(buf.as_ptr().cast::<FrameSignal>())
}
