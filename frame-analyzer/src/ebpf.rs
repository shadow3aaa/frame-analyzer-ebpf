use aya::{include_bytes_aligned, Bpf};
use ctor::ctor;

use crate::error::Result;

#[ctor]
fn ebpf_workround() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

pub fn load_bpf() -> Result<Bpf> {
    // This will include eBPF object file as raw bytes at compile-time and load it at runtime.
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../.ebpf_target/bpfel-unknown-none/debug/frame-analyzer-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../.ebpf_target/bpfel-unknown-none/release/frame-analyzer-ebpf"
    ))?;

    Ok(bpf)
}
