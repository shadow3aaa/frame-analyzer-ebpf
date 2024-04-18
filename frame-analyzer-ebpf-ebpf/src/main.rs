#![no_std]
#![no_main]

use aya_ebpf::{
    macros::uprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_frame_analyzer_ebpf(ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
