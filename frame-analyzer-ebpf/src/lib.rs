use aya::{include_bytes_aligned, programs::UProbe, Bpf, BpfError};
use lazy_static::lazy_static;

lazy_static! {
    static ref _INIT: () = {
        ebpf_workround();
    };
}

fn ebpf_workround() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
}

pub fn attach(pid: i32) -> Result<(), BpfError> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/frame-analyzer-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/frame-analyzer-ebpf"
    ))?;

    let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach(
        Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi"),
        0,
        "/system/lib64/libgui.so",
        Some(pid),
    )?;

    Ok(())
}
