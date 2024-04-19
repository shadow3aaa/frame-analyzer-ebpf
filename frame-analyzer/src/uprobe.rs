use aya::{
    maps::{MapData, RingBuf},
    programs::{uprobe::UProbeLinkId, UProbe},
    Bpf,
};
use std::mem;

use crate::{ebpf::load_bpf, error::Result};

pub struct UprobeHandler {
    bpf: Bpf,
    id: Option<UProbeLinkId>,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        let mut id = None;
        mem::swap(&mut self.id, &mut id);
        if let Ok(program) = self.get_program() {
            if let Some(id) = id {
                let _ = program.detach(id);
                self.id = None;
            }
        }
    }
}

impl UprobeHandler {
    pub fn attach_app(pid: i32) -> Result<Self> {
        let mut bpf = load_bpf()?;

        let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf").unwrap().try_into()?;
        program.load()?;

        let id = program.attach(
            Some("_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi"),
            0,
            "/system/lib64/libgui.so",
            Some(pid),
        )?;

        Ok(Self { bpf, id: Some(id) })
    }

    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        let ring: RingBuf<&mut MapData> = RingBuf::try_from(self.bpf.map_mut("RING_BUF").unwrap())?;
        Ok(ring)
    }

    fn get_program(&mut self) -> Result<&mut UProbe> {
        let program: &mut UProbe = self
            .bpf
            .program_mut("frame_analyzer_ebpf")
            .unwrap()
            .try_into()?;
        Ok(program)
    }
}
