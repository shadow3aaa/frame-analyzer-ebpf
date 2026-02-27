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
use std::{collections::VecDeque, ptr, time::Duration};

use frame_analyzer_ebpf_common::FrameSignal;

use crate::uprobe::UprobeHandler;

pub struct AnalyzeTarget {
    pub uprobe: UprobeHandler,
    last_ktime_ns: Option<u64>,
    frametimes: VecDeque<Duration>,
}

impl AnalyzeTarget {
    pub fn new(uprobe: UprobeHandler) -> Self {
        Self {
            uprobe,
            last_ktime_ns: None,
            frametimes: VecDeque::with_capacity(144),
        }
    }

    pub fn update(&mut self) -> Option<Duration> {
        let mut ring = self.uprobe.ring().unwrap();
        let item = ring.next()?;
        let event = unsafe { trans(&item) };
        // Track the global queueBuffer cadence instead of per-buffer cadence.
        // On devices with deep buffer queues, per-buffer deltas can alias to 1/N FPS.
        const MIN_FRAME_NS: u64 = 1_000_000;
        const MAX_FRAME_NS: u64 = 200_000_000;

        if let Some(last_ns) = self.last_ktime_ns {
            let frametime_ns = event.ktime_ns.saturating_sub(last_ns);
            if (MIN_FRAME_NS..=MAX_FRAME_NS).contains(&frametime_ns) {
                if self.frametimes.len() >= 144 {
                    self.frametimes.pop_back();
                }
                self.frametimes
                    .push_front(Duration::from_nanos(frametime_ns));
            }
        }
        self.last_ktime_ns = Some(event.ktime_ns);

        self.frametimes.front().copied()
    }
}

const unsafe fn trans(buf: &[u8]) -> FrameSignal {
    unsafe { ptr::read_unaligned(buf.as_ptr().cast::<FrameSignal>()) }
}
