#![no_std]

#[repr(C)]
pub struct FrameSignal {
    pub ktime_ns: u64,
}

impl FrameSignal {
    pub const fn new(ktime_ns: u64) -> Self {
        Self { ktime_ns }
    }
}
