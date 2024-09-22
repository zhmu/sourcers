// The MS-DOS Encyclopedia, Ray Duncan
// page 688 details FIXUPP
// "Microsoft Product Support Services Application Note (Text File)"
//    SS0288: RELOCATABLE OBJECT MODULE FORMAT

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::str;

use std::collections::HashMap;
use log::{info, debug};

const RECORD_TYPE_THEADR: u8 = 0x80;
const RECORD_TYPE_COMENT: u8 = 0x88;
const RECORD_TYPE_MODEND: u8 = 0x8a;
const RECORD_TYPE_EXTDEF: u8 = 0x8c;
const RECORD_TYPE_TYPDEF: u8 = 0x8e;
const RECORD_TYPE_LNAMES: u8 = 0x96;
const RECORD_TYPE_SEGDEF: u8 = 0x98;
const RECORD_TYPE_GRPDEF: u8 = 0x9a;
const RECORD_TYPE_FIXUPP: u8 = 0x9c;
const RECORD_TYPE_LEDATA: u8 = 0xa0;
const RECORD_TYPE_LIDATA: u8 = 0xa2;
const RECORD_TYPE_LPUBDEF: u8 = 0xb6;

fn read_binary(rdr: &mut Cursor<&Vec<u8>>) -> Result<Vec<u8>> {
    let data_len = rdr.read_u8()? as usize;
    let mut data = vec![ 0; data_len ];
    rdr.read_exact(&mut data)?;
    Ok(data)
}

fn read_string(rdr: &mut Cursor<&Vec<u8>>) -> Result<String> {
    let name = read_binary(rdr)?;
    Ok(str::from_utf8(&name).unwrap_or("<corrupt>").to_string())
}

fn read_data_block(rdr: &mut Cursor<&Vec<u8>>) -> Result<Vec<u8>> {
    let repeat_count = rdr.read_u16::<LittleEndian>()? as usize;
    let block_count = rdr.read_u16::<LittleEndian>()?;
    let data = if block_count == 0 {
        read_binary(rdr)?
    } else {
        let mut data = Vec::<u8>::new();
        for _ in 0..block_count {
            let piece = read_data_block(rdr)?;
            data.extend(&piece);
        }
        data
    };
    let mut result = Vec::<u8>::new();
    for _ in 0..repeat_count {
        result.extend(&data);
    }
    Ok(result)
}

#[test]
fn test_read_data_block()
{
    let input = vec![
        0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x40, 0x41, 0x02, 0x00, 0x00, 0x00, 0x02, 0x50, 0x51
    ];
    let mut rdr = Cursor::new(&input);
    let result = read_data_block(&mut rdr).unwrap();
    let expected = vec![
        0x40, 0x41, 0x40, 0x41, 0x40, 0x41, // 3 repeats
         0x50, 0x51, 0x50, 0x51, // 2 repeats
        0x40, 0x41, 0x40, 0x41, 0x40, 0x41, // 3 repeats
         0x50, 0x51, 0x50, 0x51 // 2 repeats
    ];
    assert_eq!(result, expected);

}

pub enum SegmentAlign {
    RelocatableByteAligned,
    RelocatableWordAligned,
    RelocatableParagraphAligned,
    RelocatablePageAligned,
}

pub enum SegmentCombine {
    Private,
    Public,
    Stack,
    Common
}

pub struct Segment {
    pub align: SegmentAlign,
    pub combine: SegmentCombine,
    pub data: Vec<u8>,
    pub name_index: usize,
    pub fixups: HashMap<usize, Fixup>
}

pub struct Group {
    pub name_index: usize,
    pub seg_indices: Vec<usize>
}

pub struct External {
    pub name: String
}

#[derive(Debug)]
pub enum Relative {
    SegmentRelative,
    SelfRelative,
}

#[derive(Debug)]
pub enum Location {
    LowOrderByte,
    Offset,
    Segment,
    Pointer,
    HighOrderByte,
    LoaderResolvedOffset
}

#[derive(Debug)]
pub enum Frame {
    SegmentIndex(usize),
    GroupIndex(usize),
}

#[derive(Debug)]
pub enum TargetFixup {
    SegmentIndexAndDisplacement(usize, u16),
    SegmentIndexOnly(usize),
    GroupIndexOnly(usize),
    ExternalIndex(usize)
}

#[derive(Debug)]
pub struct Fixup {
    pub relative: Relative,
    pub location: Location,
    pub frame: Frame,
    pub offset: usize,
    pub target_fixup: TargetFixup
}

pub struct Object {
    pub segments: Vec<Segment>,
    pub groups: Vec<Group>,
    pub names: Vec<String>,
    pub externals: Vec<External>,
}

impl Object {
    pub fn new(data: &[u8]) -> Result<Self> {
        let mut segments = Vec::<Segment>::new();
        let mut groups = Vec::<Group>::new();
        let mut names = Vec::<String>::new();
        let mut externals = Vec::<External>::new();

        let mut rdr = Cursor::new(data);
        let mut last_segment_index: usize = usize::MAX;
        let mut last_segment_offset: usize = usize::MAX;
        while rdr.position() < data.len() as u64 {
            let record_type = rdr.read_u8()?;
            let record_length = rdr.read_u16::<LittleEndian>()?;
            let mut record_content = vec![ 0; (record_length - 1) as usize ];
            rdr.read_exact(&mut record_content)?;
            let _record_checksum = rdr.read_u8()?;
            // TODO: verify checksum (maybe)

            let mut rrdr = Cursor::new(&record_content);
            match record_type {
                RECORD_TYPE_THEADR => {
                    let title = read_string(&mut rrdr)?;
                    info!("Translator Header - '{}'", title);
                },
                RECORD_TYPE_LNAMES => {
                    while rrdr.position() < record_content.len() as u64 {
                        let name = read_string(&mut rrdr)?;
                        names.push(name);
                    }
                    info!("List of Names - {:?}", names);
                },
                RECORD_TYPE_SEGDEF => {
                    info!("Segment Definitions");
                    let acbp = rrdr.read_u8()?;
                    let seg_a = acbp >> 5;
                    if seg_a == 0 { todo!("handle SEGDEF A=0"); }
                    let seg_c = (acbp >> 2) & 7;
                    let seg_b = (acbp >> 1) & 1;
                    let seg_p = acbp & 1;

                    let seg_len = rrdr.read_u16::<LittleEndian>()?;

                    let seg_name_index = rrdr.read_u8()?;
                    let seg_class_index = rrdr.read_u8()?;
                    let seg_overlay_index = rrdr.read_u8()?;
                    debug!("  acbp {:x} -> a {} c {} b {} p {}",
                        acbp, seg_a, seg_c, seg_b, seg_p);
                    debug!("  length {:x} name_index {} class_index {} overlay_index {}",
                        seg_len, seg_name_index, seg_class_index, seg_overlay_index);

                    let align = match seg_a {
                        1 => SegmentAlign::RelocatableByteAligned,
                        2 => SegmentAlign::RelocatableWordAligned,
                        3 => SegmentAlign::RelocatableParagraphAligned,
                        4 => SegmentAlign::RelocatablePageAligned,
                        _ => unreachable!(),
                    };
                    let combine = match seg_c {
                        0 => SegmentCombine::Private,
                        2 | 4 | 7 => SegmentCombine::Public,
                        5 => SegmentCombine::Stack,
                        6 => SegmentCombine::Common,
                        _ => unreachable!(),
                    };
                    let size = if seg_b != 0 && seg_len == 0 { 65536 } else { seg_len as usize };
                    segments.push(Segment{ align, combine, data: vec![ 0u8; size ], name_index: (seg_name_index - 1) as usize, fixups: HashMap::new() });

                },
                RECORD_TYPE_TYPDEF => {
                    info!("Type Definition");
                    // Note: we ignore this field - it doesn't seem to match the
                    // explanation given in the MS-DOS Encyclopedia (p. 6871)
                    let n = rrdr.read_u8()?;
                    assert!(n == 0);
                    rrdr.seek(SeekFrom::End(0))?;
                },
                RECORD_TYPE_GRPDEF => {
                    let grp_name_index = rrdr.read_u8()?;
                    let mut seg_indices = Vec::<usize>::new();
                    while rrdr.position() < record_content.len() as u64 {
                        let ff_index = rrdr.read_u8()?;
                        assert!(ff_index == 0xff);
                        let seg_index = rrdr.read_u8()?;
                        seg_indices.push((seg_index - 1) as usize);
                    }
                    info!("Group Definition - grp_name_index {}: {:?}", grp_name_index, seg_indices);
                    groups.push(Group{ name_index: (grp_name_index - 1) as usize, seg_indices })
                },
                RECORD_TYPE_EXTDEF => {
                    while rrdr.position() < record_content.len() as u64 {
                        let ext_name = read_string(&mut rrdr)?;
                        let _type_index = rrdr.read_u8()?;
                        externals.push(External{ name: ext_name });
                    }
                    info!("External Definition ({} entries)", externals.len());
                },
                RECORD_TYPE_LIDATA => {
                    let seg_index = rrdr.read_u8()?;
                    let idata_offset = rrdr.read_u16::<LittleEndian>()? as usize;
                    let mut data = Vec::<u8>::new();
                    while rrdr.position() < record_content.len() as u64 {
                        let block = read_data_block(&mut rrdr)?;
                        data.extend(block);
                    }
                    info!("Local Iterated Data - seg_index {} idata_offset {} ({} bytes)", seg_index, idata_offset, data.len());

                    last_segment_offset = idata_offset;
                    last_segment_index = (seg_index - 1) as usize;
                    let seg = &mut segments[last_segment_index];
                    assert!(idata_offset + data.len() <= seg.data.len());
                    seg.data[idata_offset..idata_offset + data.len()].clone_from_slice(&data);
                },
                RECORD_TYPE_FIXUPP => {
                    info!("Fixup");
                    let mut fixups = Vec::<Fixup>::new();
                    while rrdr.position() < record_content.len() as u64 {
                        let v = rrdr.read_u8()?;
                        if (v & 0x80) == 0 {
                            // Thread
                            let method = (v >> 2) & 7;
                            let t_nr = v & 3;
                            let t_index  = rrdr.read_u8()?;
                            debug!("thread {:x} -> method {} nr {} t_index {}", v, method, t_nr, t_index);
                            todo!("support threads");
                        } else {
                            // Fixup
                            let w = rrdr.read_u8()?;
                            let locat = ((v as u16) << 8) + w as u16;
                            let locat_m = (locat >> 14) & 1;
                            let locat_s = (locat >> 13) & 1;
                            let locat_loc = (locat >> 10) & 7;
                            let locat_offs = locat & 0x3ff;
                            let fixdat = rrdr.read_u8()?;
                            let fixdat_f = (fixdat >> 7) & 1;
                            let fixdat_frame = (fixdat >> 4) & 7;
                            let fixdat_t = (fixdat >> 3) & 1;
                            let fixdat_p = (fixdat >> 2) & 1;
                            let fixdat_targt = fixdat & 3;
                            let fr_datum = rrdr.read_u8()?;
                            let t_datum = rrdr.read_u8()?;
                            debug!("  fixup, locat {:x} -> m {} s {} loc {} offs {:x}",
                                locat, locat_m, locat_s, locat_loc, locat_offs);
                            debug!("    fixdat {:x} -> f {} frame {} t {} p {} targt {}",
                                fixdat, fixdat_f, fixdat_frame, fixdat_t, fixdat_p, fixdat_targt);
                            debug!("    fr_datum {:x}", fr_datum);
                            debug!("    t_datum {:x}", t_datum);
                            let displacement = if fixdat_p == 0 {
                                rrdr.read_u16::<LittleEndian>()?
                            } else {
                                0
                            };

                            let relative = if locat_m != 0 { Relative::SegmentRelative } else { Relative::SelfRelative };
                            let location = match locat_loc {
                                0 => Location::LowOrderByte,
                                1 => Location::Offset,
                                2 => Location::Segment,
                                3 => Location::Pointer,
                                4 => Location::HighOrderByte,
                                5 => Location::LoaderResolvedOffset,
                                _ => unreachable!()
                            };
                            assert!(fixdat_f == 0); // no support for threads
                            assert!(fixdat_t == 0); // no support for threads
                            let frame = match fixdat_frame { // F=0, Table 19-2
                                0 => Frame::SegmentIndex((fr_datum - 1) as usize),
                                1 => Frame::GroupIndex((fr_datum - 1) as usize),
                                2 | 4 | 5 => todo!("unimplemented fixdat frame type"),
                                _ => unreachable!()
                            };
                            let p_targ = (fixdat_p << 2) | fixdat_targt;
                            let target_fixup = match p_targ { // T=0, Table 19-3
                                0 => TargetFixup::SegmentIndexAndDisplacement((t_datum - 1) as usize, displacement),
                                4 => TargetFixup::SegmentIndexOnly((t_datum - 1) as usize),
                                5 => TargetFixup::GroupIndexOnly((t_datum - 1) as usize),
                                6 => TargetFixup::ExternalIndex((t_datum - 1) as usize),
                                1 | 2 | 3 | 7 => todo!("unimplemented target_fixup"),
                                _ => unreachable!()
                            };

                            fixups.push(Fixup{ relative, location, frame, offset: last_segment_offset + (locat_offs as usize), target_fixup });
                        }
                    }

                    for fixup in fixups {
                        let r = segments[last_segment_index].fixups.insert(fixup.offset, fixup);
                        if let Some(r) = r {
                            println!("??? duplicate fixup for offset {} in segment index {}", r.offset, last_segment_index);
                        }
                    }
                },
                RECORD_TYPE_LEDATA => {
                    let seg_index = rrdr.read_u8()?;
                    let edata_offset = rrdr.read_u16::<LittleEndian>()? as usize;
                    let num_bytes = (record_length - 3 - 1) as usize;
                    let mut data = vec![ 0u8; num_bytes ];
                    rrdr.read_exact(&mut data)?;
                    info!("Local Enumerated Data - seg_index {} edata_offset {} ({} bytes)", seg_index, edata_offset, data.len());

                    last_segment_offset = edata_offset;
                    last_segment_index = (seg_index - 1) as usize;
                    let seg = &mut segments[last_segment_index];
                    assert!(edata_offset + data.len() <= seg.data.len());
                    seg.data[edata_offset..edata_offset + data.len()].clone_from_slice(&data);
                },
                RECORD_TYPE_COMENT => {
                    let c_attrib = rrdr.read_u8()?;
                    let c_class = rrdr.read_u8()?;
                    let mut data = vec![ 0u8; (record_length - 1 - 2) as usize ];
                    rrdr.read_exact(&mut data)?;
                    info!("Comment - attrib {} class {} data {:x?}", c_attrib, c_class, data);
                },
                RECORD_TYPE_MODEND => {
                    let m_type = rrdr.read_u8()?;
                    info!("Module End - type {}", m_type);
                },
                RECORD_TYPE_LPUBDEF => {
                    println!("{:x?}", record_content);
                    while rrdr.position() < record_content.len() as u64 {
                        let l_base_group_seg_frame = rrdr.read_u16::<LittleEndian>()?;
                        let l_name = read_string(&mut rrdr)?;
                        //let l_pub_offset = rrdr.read_u16::<LittleEndian>()?;
                        let l_type_index = rrdr.read_u8()?;
                        println!("{} {} {}", l_base_group_seg_frame, l_name, l_type_index);
                    }
                    info!("Local public names");
                },
                _ => {
                    todo!("unrecognized record type {:x} ({} bytes)", record_type, record_content.len());
                }
            }
            // Must have processed the full record
            assert!(rrdr.position() == record_content.len() as u64);
        }
        Ok(Object{ segments, groups, names, externals })
    }
}
