use packed_struct::prelude::*;
use anyhow::Result;
use serde::Serialize;

const MZ_MAGIC: u16 = 0x5a4d;
const EXE_PARAGRAPH_SIZE: usize = 16;
const EXE_BLOCK_SIZE: usize = 512;


// http://www.delorie.com/djgpp/doc/exe/
#[derive(PackedStruct,Serialize,Default,Debug)]
#[packed_struct(endian="lsb")]
pub struct DosMzHeader {
    pub magic: u16,
    pub last_block_used_bytes: u16,
    pub num_blocks: u16,
    pub num_relocs: u16,
    pub header_size_in_paragraphs: u16,
    pub paragraphs_needed: u16,
    pub max_paragraphs: u16,
    pub init_ss: u16,
    pub init_sp: u16,
    pub checksum: u16,
    pub init_ip: u16,
    pub init_cs: u16,
    pub first_reloc_offset: u16,
    pub overlay_nr: u16
}

#[derive(PackedStruct,Serialize,Default,Debug)]
#[packed_struct(endian="lsb")]
pub struct DosMzRelocation {
    pub offset: u16,
    pub segment: u16,
}

#[derive(Serialize,Default,Debug)]
pub struct DosMzInfo {
    pub header: DosMzHeader,
    pub relocs: Vec<DosMzRelocation>,
    pub data_offset: usize,
    pub payload_offset: usize,
}

fn determine_exe_payload_offset(header: &DosMzHeader) -> Option<usize> {
    if header.magic != MZ_MAGIC { return None; }
    let mut extra_data_start = header.num_blocks as usize * EXE_BLOCK_SIZE;
    if header.last_block_used_bytes != 0 {
        extra_data_start -= EXE_BLOCK_SIZE - header.last_block_used_bytes as usize;
    }
    Some(extra_data_start)
}

impl DosMzInfo {
    pub fn new(data: &[u8]) -> Result<DosMzInfo> {
        let mut info:DosMzInfo = Default::default();

        info.header = DosMzHeader::unpack_from_slice(&data[0..28])?;
        info.data_offset = info.header.header_size_in_paragraphs as usize * EXE_PARAGRAPH_SIZE;
        info.payload_offset = determine_exe_payload_offset(&info.header).expect("cannot parse EXE header");

        for n in 0..info.header.num_relocs {
            let offset: usize = (info.header.first_reloc_offset + 4 * n).into();
            let reloc = DosMzRelocation::unpack_from_slice(&data[offset..offset+4]).expect("unable to parse relocation entry");
            info.relocs.push(reloc);
        }

        Ok(info)
    }
}
