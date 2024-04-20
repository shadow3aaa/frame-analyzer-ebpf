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
