#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, map},
    programs::ProbeContext,
    maps::RingBuf,
    helpers::gen::bpf_ktime_get_ns,
};

use frame_analyzer_ebpf_common::FrameSignal;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(0, 0);

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_frame_analyzer_ebpf(_ctx: ProbeContext) -> Result<u32, u32> {
    if let Some(mut entry) = RING_BUF.reserve::<FrameSignal>(0) {
        let ktime_ns = unsafe { bpf_ktime_get_ns()
        };
        entry.write(FrameSignal::new(ktime_ns));
        entry.submit(0);
    }
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
