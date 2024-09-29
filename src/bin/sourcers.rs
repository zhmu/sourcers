/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2024 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use log::info;
use capstone::prelude::*;
use capstone_sys::x86_insn;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Write;
use capstone::arch::x86::X86OperandType;
use std::io::Cursor;
use byteorder::LittleEndian;
use byteorder::ReadBytesExt;

use clap::Parser;
use clap_num::maybe_hex;
use std::path::PathBuf;

use sourcers::{object, dos_exe};
use anyhow::Result;

#[derive(clap::ValueEnum,Default,Clone)]
enum OutputType {
    #[default]
    /// Assembly file, suitable for use in WASM
    Asm,
    /// Map file, suitable for analysis
    Map
}

#[derive(clap::ValueEnum,Default,Clone)]
enum InputType {
    #[default]
    /// Raw binary
    Raw,
    /// Object file
    Object,
    /// Executable file (DOS MZ)
    Exe,
}

#[derive(clap::ValueEnum,Default,Clone,PartialEq)]
enum Bits {
    #[clap(name="16")]
    Bits16,
    #[default]
    #[clap(name="32")]
    Bits32,
    #[clap(name="64")]
    Bits64,
}

/// Somewhat intelligent disassembler
#[derive(Parser)]
struct Cli {
    #[clap(long, default_value_t, value_enum)]
    /// Output file format
    format: OutputType,
    #[clap(long, default_value_t, value_enum)]
    /// Input file format
    r#type: InputType,
    #[clap(long, default_value_t, value_enum)]
    /// Number of bits in the input format
    bits: Bits,
    #[clap(long, default_value_t=0, value_parser=maybe_hex::<u64>)]
    /// Base of file in memory
    base: u64,
    /// Input file
    input: PathBuf
}

#[derive(Debug)]
enum Reference {
    SegmentDisplacement(usize, u32),
    Segment(usize),
    Group(usize),
    External(usize),
    ExeReloc(),
}

#[derive(Debug)]
struct External {
    name: String,
}

#[derive(Debug)]
struct Group {
    name: String,
    segments: Vec<usize>,
}

struct Segment {
    name: String,
    segment: u64,
    offset: u64,
    data: Vec<u8>,
    labels: Vec<String>,
    references: HashMap<u64, Reference>,
    markers: MarkerMap,
}

impl Segment {
    fn new(name: String) -> Self {
        Self{ name, segment: 0, offset: 0, data: Vec::new(), labels: Vec::new(), references: HashMap::new(), markers: MarkerMap::new() }
    }

    fn add_label(&mut self, label: String) -> usize {
        let num = self.labels.len();
        self.labels.push(label);
        num
    }
}

struct Target {
    segments: Vec<Segment>,
    externals: Vec<External>,
    groups: Vec<Group>,
}

impl Target {
    fn new() -> Self {
        Self{segments: Vec::new(), externals: Vec::new(), groups: Vec::new() }
    }
}

fn print_instr(i: &capstone::Insn, arch_detail: &ArchDetail) {
    let ops = arch_detail.operands();

    println!("; {}", i);
    println!(";    operands: {}", ops.len());
    for op in ops {
        println!(";        {:?}", op);
    }
}

fn get_x86_op(op: &capstone::arch::ArchOperand) -> &capstone::arch::x86::X86Operand {
    match op {
        capstone::arch::ArchOperand::X86Operand(o) => o,
        _ => unreachable!()
    }
}

fn get_op_imm(op: &capstone::arch::x86::X86Operand) -> Option<u64> {
    match op.op_type {
        capstone::arch::x86::X86OperandType::Imm(imm) => Some(imm as u64),
        _ => None
    }
}

enum Label {
    Entry,
    Code(u64),
    Data(u64),
}

fn use_label(seg: &mut Segment, label: Label) -> usize {
    let label = match label {
        Label::Entry => "entry".to_string(),
        Label::Code(offset) => format!("loc_{:x}", offset),
        Label::Data(offset) => format!("data_{:x}", offset),
    };
    seg.add_label(label)
}

fn format_value(value: i64) -> String {
    if value >= 0 {
        return if value < 16 {
            format!("{}", value)
        } else if value < 0xa0 {
            format!("{:X}h", value)
        } else {
            format!("0{:X}h", value)
        }
    } else {
        format!("{}", value)
    }
}

fn is_branch(i: &capstone::Insn) -> bool {
    match x86_insn::from(i.id().0) {
        x86_insn::X86_INS_JAE | x86_insn::X86_INS_JA | x86_insn::X86_INS_JBE |
        x86_insn::X86_INS_JB | x86_insn::X86_INS_JCXZ | x86_insn::X86_INS_JECXZ |
        x86_insn::X86_INS_JE | x86_insn::X86_INS_JGE | x86_insn::X86_INS_JG |
        x86_insn::X86_INS_JLE | x86_insn::X86_INS_JL | x86_insn::X86_INS_JNE |
        x86_insn::X86_INS_JNO | x86_insn::X86_INS_JNP | x86_insn::X86_INS_JNS |
        x86_insn::X86_INS_JO | x86_insn::X86_INS_JP | x86_insn::X86_INS_JRCXZ |
        x86_insn::X86_INS_JS | x86_insn::X86_INS_JMP |
        x86_insn::X86_INS_CALL | x86_insn::X86_INS_LOOP |
        x86_insn::X86_INS_LOOPE | x86_insn::X86_INS_LOOPNE => true,
        _ => false
    }
}

fn determine_op_prefix(ops: &[capstone::arch::ArchOperand]) -> String {
    let mut op_size: Option<u8> = None;
    if let Some(first_op) = ops.first() {
        let first_op = get_x86_op(&first_op);
        op_size = Some(first_op.size);
    }

    match op_size {
        None => { "".to_string() },
        Some(1) => { "byte ptr ".to_string() },
        Some(2) => { "word ptr ".to_string() },
        Some(4) => { "dword ptr ".to_string() },
        Some(_) => { unreachable!(); }
    }
}

fn lookup_reference<'a>(seg: &'a Segment, insn: &capstone::Insn) -> Option<&'a Reference> {
    // TODO: How to get the address of the operand??
    let insns_base = insn.address() - seg.offset;

    let mut result: Vec<&Reference> = Vec::new();
    for n in insns_base..(insns_base + insn.bytes().len() as u64)  {
        if let Some(refe) = seg.references.get(&n) {
            result.push(refe);
        }
    }

    if result.is_empty() { return None; }
    if result.len() > 1 {
        todo!("matched multiple references {:?}", result);
    }
    return Some(result[0]);
}

fn format_reference(target: &Target, refe: &Reference) -> String {
    match refe {
        Reference::SegmentDisplacement(seg_idx, disp) => {
            // TODO We have no way of knowing whether this is a code/data reference...
            //  ... unless we look at the instruction
            let seg = &target.segments[*seg_idx];
            format!("todo_{}_{:04x}", seg.name, *disp)
        },
        Reference::Segment(seg_idx) => {
            let seg = &target.segments[*seg_idx];
            format!("{}", seg.name)
        },
        Reference::Group(group_idx) => {
            let group = &target.groups[*group_idx];
            format!("{}", group.name)
        },
        Reference::External(ext_idx) => {
            let ext = &target.externals[*ext_idx];
            format!("{}", ext.name)
        },
        Reference::ExeReloc() => {
            format!("exe<>")
        }
    }
}

fn format_operand(cs: &Capstone, target: &Target, seg: &Segment, insn: &capstone::Insn, ops: &[capstone::arch::ArchOperand], op: &capstone::arch::x86::X86Operand) -> String {
    match op.op_type {
        X86OperandType::Reg(r) =>  {
            let r = cs.reg_name(r).unwrap();
            format!("{}", r)
        },
        X86OperandType::Imm(i) => {
            if let Some(refe) = lookup_reference(seg, insn) {
                format!("{}", format_reference(target, refe))
            } else {
                format!("{}", format_value(i as i64))
            }
        },
        X86OperandType::Mem(m) => {
            let seg_reg = m.segment();
            let base = m.base();
            let index = m.index();
            let scale = m.scale();
            let disp = m.disp();
            assert!(scale == 1);

            let mut args = determine_op_prefix(ops);

            if seg_reg != RegId::INVALID_REG {
                let r = cs.reg_name(seg_reg).unwrap();
                write!(args, "{}:", r).unwrap();
            }
            args += "[";

            let mut addr = String::new();
            if base != RegId::INVALID_REG {
                let r = cs.reg_name(base).unwrap();
                write!(addr, "{}", r).unwrap();
            }
            if index != RegId::INVALID_REG {
                if !addr.is_empty() { addr += "+"; }
                let r = cs.reg_name(index).unwrap();
                write!(addr, "{}", r).unwrap();
            }
            if disp != 0 {
                if !addr.is_empty() { addr += "+"; }
                if let Some(label) = find_label(seg, disp as u64) {
                    write!(addr, "{}", label).unwrap();
                } else {
                    write!(addr, "{}", format_value(disp)).unwrap();
                }
            }

            if let Some(refe) = lookup_reference(seg, insn) {
                // TODO How do we properly integrate this?
                // Now we can have things like
                // "mov  word ptr [data_ASSEMBLY_0c35si+data_ASSEMBLY_001b],data_ASSEMBLY_0c35"
                // And we should not add the initial data_ASSEMBLY_0c35 here...
                args += &format!("{}", format_reference(target, refe));
            }
            args += &addr;
            args += "]";
            args
        },
        X86OperandType::Invalid => { unreachable!() }
    }
}

type MarkerMap = HashMap<u64, Marker>;

fn find_label(seg: &Segment, offset: u64) -> Option<&String> {
    if let Some(marker) = seg.markers.get(&offset) {
        return match marker {
            Marker::CodeLabel(idx) => Some(&seg.labels[*idx]),
            Marker::DataSingle(idx, _) => Some(&seg.labels[*idx]),
            Marker::DataIndexed(idx, _) => Some(&seg.labels[*idx]),
        };
    }
    None
}

fn format_instruction_args_default(cs: &Capstone, target: &Target, i: &capstone::Insn, seg: &Segment, ops: &[capstone::arch::ArchOperand]) -> String {
    let mut args = String::new();
    for op in ops {
        if !args.is_empty() { args += ","; }
        let op = get_x86_op(&op);
        args += &format_operand(cs, target, seg, i, &ops, &op);
    }
    args
}

fn format_instruction(cs: &Capstone, target: &Target, seg: &Segment, i: &capstone::Insn) -> String {
    let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
    let arch_detail: ArchDetail = detail.arch_detail();
    let ops = arch_detail.operands();

    // If it's a branch instruction, look up the code label instead
    let mut args = String::new();
    if is_branch(i) {
        assert!(ops.len() == 1);
        if let Some(value) = get_op_imm(get_x86_op(&ops[0])) {
            if let Some(label) = find_label(seg, value as u64) {
                write!(args, "{}", label).unwrap();
            } else {
                write!(args, "{}", format_value(value as i64)).unwrap();
            }
        } else {
            args += &format_operand(cs, target, seg, i, &ops, get_x86_op(&ops[0]));
        }
    } else {
        match x86_insn::from(i.id().0) {
            x86_insn::X86_INS_LCALL | x86_insn::X86_INS_LJMP => {
                // If we have two intermediate arguments, resolve the label
                if ops.len() == 2 {
                    let seg = get_op_imm(get_x86_op(&ops[0])).unwrap();
                    let off = get_op_imm(get_x86_op(&ops[1])).unwrap();

                    if let Some(seg) = target.segments.iter().find(|s| s.segment == seg) {
                        if let Some(label) = find_label(seg, off) {
                            args = format!("{},{}", seg.name, label);
                        } else {
                            args = format!("{},{}", seg.name, format_value(off as i64));
                        }
                    } else {
                        args = format!("{},{}", format_value(seg as i64), format_value(off as i64));
                    }
                } else {
                    args = format_instruction_args_default(cs, target, i, seg, &ops)
                }
            },
            _ => {
                args = format_instruction_args_default(cs, target, i, seg, &ops)
            }
        }
    }
    format!("{:4} {}", i.mnemonic().unwrap(), args)
}

#[derive(Debug,Clone)]
enum Marker {
    CodeLabel(usize),
    /// Single data reference without indexing
    DataSingle(usize, u8),
    /// Indexes data array
    DataIndexed(usize, u8),
}

impl Marker {
    fn is_code(&self) -> bool {
        match self {
            Marker::CodeLabel(_) => true,
            _ => false
        }
    }

    fn is_data(&self) -> bool {
        match self {
            Marker::DataSingle(_, _) | Marker::DataIndexed(_, _) => true,
            _ => false
        }
    }
}

fn isolate_data_op(seg: &mut Segment, op: &capstone::arch::x86::X86Operand) -> Option<(u64, Marker)> {
    match op.op_type {
        X86OperandType::Reg(_r) =>  {
            None
        },
        X86OperandType::Imm(_i) => {
            None
        },
        X86OperandType::Mem(m) => {
            let base = m.base();
            let _index = m.index();
            let scale = m.scale();
            let disp = m.disp() as u64;
            assert!(scale == 1);

            if disp >= seg.data.len() as u64 { return None; }

            let label_idx = use_label(seg, Label::Data(disp));
            if base != RegId::INVALID_REG {
                // Relative to some address, with a base address
                return Some((disp, Marker::DataIndexed(label_idx, op.size)));
            }
            Some((disp as u64, Marker::DataSingle(label_idx, op.size)))
        },
        X86OperandType::Invalid => { unreachable!() }
    }
}

fn is_ascii(v: u8) -> bool {
    match v {
        b'A'..=b'Z' |
        b'a'..=b'z' |
        b'0'..=b'9' |
        b'!'..=b')' |
        b' ' | b'_' | b'-' | b'+' | b'=' => true,
        _ => false
    }
}

/// - isolate data (if something reads/writes to it, it's data)
fn identify_data<'a>(cs: &Capstone, seg: &mut Segment, insns: &capstone::Instructions<'a>) {
    for i in insns.as_ref() {
        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        if is_branch(i) {
            // Already handled by identify_code()
            continue;
        }

        match x86_insn::from(i.id().0) {
            x86_insn::X86_INS_MOV | x86_insn::X86_INS_MOVZX | x86_insn::X86_INS_MOVSX => {
                info!("Move");
                for op in &ops {
                    let op = get_x86_op(op);
                    if let Some((offset, marker)) = isolate_data_op(seg, op) {
                        seg.markers.insert(offset, marker);
                    }
                }
            },
            x86_insn::X86_INS_LCALL | x86_insn::X86_INS_LJMP => {
            },
            x86_insn::X86_INS_LEA => {
                // TODO We could do something here, as it's usually used to calculate data offset..
            },
            x86_insn::X86_INS_ENTER | x86_insn::X86_INS_LEAVE => {
            },
            x86_insn::X86_INS_RET | x86_insn::X86_INS_RETF | x86_insn::X86_INS_IRET => {
            },
            x86_insn::X86_INS_PUSH | x86_insn::X86_INS_POP |
            x86_insn::X86_INS_PUSHF | x86_insn::X86_INS_POPF |
            x86_insn::X86_INS_PUSHAW | x86_insn::X86_INS_POPAW |
            x86_insn::X86_INS_PUSHAL | x86_insn::X86_INS_POPAL => {
            },
            x86_insn::X86_INS_AND | x86_insn::X86_INS_OR | x86_insn::X86_INS_NOT | x86_insn::X86_INS_XOR |
            x86_insn::X86_INS_SHL | x86_insn::X86_INS_SHR | x86_insn::X86_INS_ROL | x86_insn::X86_INS_ROR |
            x86_insn::X86_INS_RCL | x86_insn::X86_INS_RCR | x86_insn::X86_INS_TEST | x86_insn::X86_INS_XCHG => {
                // TODO This can also identify data
            },
            x86_insn::X86_INS_NOP => { },
            x86_insn::X86_INS_AAA | x86_insn::X86_INS_AAD | x86_insn::X86_INS_AAM | x86_insn::X86_INS_AAS |
            x86_insn::X86_INS_DAA | x86_insn::X86_INS_DAS => { },
            x86_insn::X86_INS_CMP | x86_insn::X86_INS_ADD | x86_insn::X86_INS_SUB | 
            x86_insn::X86_INS_ADC | x86_insn::X86_INS_SBB |
            x86_insn::X86_INS_INC | x86_insn::X86_INS_DEC |
            x86_insn::X86_INS_MUL | x86_insn::X86_INS_IMUL | x86_insn::X86_INS_DIV | x86_insn::X86_INS_IDIV |
            x86_insn::X86_INS_CWDE | x86_insn::X86_INS_CDQ | x86_insn::X86_INS_NEG => {
            },
            x86_insn::X86_INS_IN | x86_insn::X86_INS_OUT |
            x86_insn::X86_INS_INSB | x86_insn::X86_INS_INSW | x86_insn::X86_INS_INSD |
            x86_insn::X86_INS_OUTSB | x86_insn::X86_INS_OUTSW | x86_insn::X86_INS_OUTSD => { },
            x86_insn::X86_INS_INT | x86_insn::X86_INS_CLI | x86_insn::X86_INS_STI | x86_insn::X86_INS_INT3 => { },
            x86_insn::X86_INS_LODSB | x86_insn::X86_INS_LODSW | x86_insn::X86_INS_LODSD |
            x86_insn::X86_INS_STOSB | x86_insn::X86_INS_STOSW | x86_insn::X86_INS_STOSD |
            x86_insn::X86_INS_MOVSB | x86_insn::X86_INS_MOVSW | x86_insn::X86_INS_MOVSD |
            x86_insn::X86_INS_CMPSB | x86_insn::X86_INS_CMPSW | x86_insn::X86_INS_CMPSD => {
                // We could do something with the values in ds:si / es:di now...
            },
            x86_insn::X86_INS_LDS | x86_insn::X86_INS_LES | x86_insn::X86_INS_LFS | x86_insn::X86_INS_LGS => {
                // Allows us to identify a pointer
            },
            x86_insn::X86_INS_STC | x86_insn::X86_INS_CLC | x86_insn::X86_INS_CMC |
            x86_insn::X86_INS_STD | x86_insn::X86_INS_CLD => { },
            x86_insn::X86_INS_BOUND => { },
            x86_insn::X86_INS_REPNE => {
                // We should look into the embedded instruction, it's a string instruction
            },
            x86_insn::X86_INS_LAHF | x86_insn::X86_INS_SAHF => { },
            x86_insn::X86_INS_ARPL | x86_insn::X86_INS_LIDT | x86_insn::X86_INS_SIDT |
            x86_insn::X86_INS_LGDT | x86_insn::X86_INS_SGDT => { },
            _ => {
                print_instr(&i, &arch_detail);
                println!("; *** unrecognized instruction id {:?}", i.id())
            }
        }
    }
}

fn print_code(args: &Cli, cs: &Capstone, target: &Target, seg: &Segment, code: &[u8], code_base: u64) {
    let insns = cs
        .disasm_all(code, code_base)
        .expect("Failed to disassemble");

    let mut last_offset: usize = 0;
    for i in insns.as_ref() {
        if let Some(label) = find_label(seg, i.address()) {
            println!("{}:", label);
        }

        // let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        // let arch_detail: ArchDetail = detail.arch_detail();
        // let ops = arch_detail.operands();

        let s = format_instruction(&cs, target, seg, &i);
        //print_instr(i, &arch_detail);
        match args.format {
            OutputType::Asm => {
                println!("    {}", s);
            },
            OutputType::Map => {
                let code_offset = (i.address() - code_base) as usize;
                let bytes = &code[code_offset..code_offset + i.bytes().len()];
                let mut repr = String::new();
                for b in bytes {
                    repr += &format!("{:02x}", b);
                }
                println!("{:04x}:{:04x}  {:22}{}", seg.segment, i.address(), repr, s);
            },
        }
        match x86_insn::from(i.id().0) {
            x86_insn::X86_INS_RET | x86_insn::X86_INS_JMP => {
                println!();
            },
            _ => {}
        }

        last_offset = (i.address() - code_base) as usize + i.bytes().len();
    }

    if last_offset < code.len() {
        print_data(args, seg, &code[last_offset..], code_base + last_offset as u64, 1);
    }
}

fn print_data(args: &Cli, seg: &Segment, data: &[u8], cur_offset: u64, size: u64) {
    let prefix = match size {
        1 => "db",
        2 => "dw",
        4 => "dd",
        _ => unreachable!()
    };

    let mut rdr = Cursor::new(data);
    let mut num = 0;
    let values_per_line = 8 / size;
    while rdr.position() + size <= data.len() as u64 {
        if num == 0 {
            match args.format {
                OutputType::Asm => {
                    print!("    {} ", prefix);
                },
                OutputType::Map => {
                    let mut b = String::new();
                    for n in 0..(values_per_line * size) {
                        let offs = (rdr.position() + n) as usize;
                        if offs == data.len() { break; }
                        b += &format!("{:02x}", data[offs]);
                    }
                    print!("{:04x}:{:04x}  {:22}{}", seg.segment, cur_offset + rdr.position(), b, prefix);
                },
            }
        }
        let value = match size {
            1 => rdr.read_u8().unwrap() as u32,
            2 => rdr.read_u16::<LittleEndian>().unwrap() as u32,
            4 => rdr.read_u32::<LittleEndian>().unwrap() as u32,
            _ => unreachable!()
        };
        if num != 0 { print!(", "); }
        print!(" {value:>width$}", value=format_value(value as i64), width=3+size as usize);
        num += 1;
        if num == values_per_line {
            println!();
            num = 0;
        }
    }
    if num != 0 { println!(); }
    if rdr.position() == data.len() as u64 { return; }

    assert!(size != 1);
    print_data(&args, seg, &data[rdr.position() as usize..], cur_offset + rdr.position(), 1);
}

fn output_segment(args: &Cli, cs: &Capstone, target: &Target, seg_idx: usize) {
    let seg = &target.segments[seg_idx];
    println!("; {} at {:x}:{:x}", seg.name, seg.segment, seg.offset);
    println!("{:12}    segment byte public", seg.name);
    println!("                assume  cs:{}, ds:{}", seg.name, seg.name);

    let mut initial_map: Vec<(u64, Marker)> = seg.markers.clone().into_iter().collect();
    initial_map.sort_by_key(|v| v.0);

    // Ensure only items in range survive
    let mut flat_map: Vec<(u64, Marker)> = Vec::new();

    let initial_marker = (seg.offset, Marker::CodeLabel(usize::MAX));
    if let Some(_) = seg.markers.get(&0) {
        // There's an initial marker - overwrite it in the result
        initial_map[0] = initial_marker;
    } else {
        flat_map.push(initial_marker);
    }

    for (offset, marker) in initial_map {
        if offset < seg.data.len() as u64 {
            flat_map.push((offset, marker));
        }
    }
    // Always insert a dummy final argument so the loop covers the entire segment
    flat_map.push((seg.data.len() as u64 + seg.offset, Marker::CodeLabel(usize::MAX)));

    for n in 0..flat_map.len() - 1 {
        let (cur_offs, cur_marker) = &flat_map[n];
        let (next_offs, _next_marker) = &flat_map[n+1];
        if cur_marker.is_code() {
            let code = &seg.data[(*cur_offs - seg.offset) as usize..(*next_offs - seg.offset) as usize];
            print_code(&args, &cs, target, &seg, &code, *cur_offs);
        } else if cur_marker.is_data() {
            if let Some(label) = find_label(seg, *cur_offs) {
                println!("{}:", label);
            }

            let size = match cur_marker {
                Marker::DataSingle(_, size) | Marker::DataIndexed(_, size) => *size,
                _ => unreachable!()
            } as u64;

            let data = &seg.data[*cur_offs as usize..*next_offs as usize];
            print_data(&args, seg, &data, *cur_offs, size);
        }
    }

    println!("{:12}    ends", seg.name);
    println!();
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
enum SegmentReference {
    Code(u64, u64),
}

// Attempts to identify further code branches
fn identify_code<'a>(cs: &Capstone, seg: &mut Segment, insns: &capstone::Instructions<'a>, seg_refs: &mut HashSet<SegmentReference>) {
    for i in insns.as_ref() {
        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        if is_branch(i) {
            assert!(ops.len() == 1);
            if let Some(value) = get_op_imm(get_x86_op(&ops[0])) {
                let label_idx = use_label(seg, Label::Code(value));
                seg.markers.insert(value, Marker::CodeLabel(label_idx));
            }
            continue;
        }

        match x86_insn::from(i.id().0) {
            x86_insn::X86_INS_LCALL | x86_insn::X86_INS_LJMP => {
                // Only consider this a code reference if we have a relocation to it
                // TODO This will only work properly for EXE files ...
                if let Some(_) = lookup_reference(seg, i) {
                    assert!(ops.len() == 2);
                    if let Some(seg) = get_op_imm(get_x86_op(&ops[0])) {
                        if let Some(off) = get_op_imm(get_x86_op(&ops[1])) {
                            seg_refs.insert(SegmentReference::Code(seg, off));
                        }
                    }
                }
            },
            _ => {}
        }
    }
}

fn load_raw(args: &Cli, file_content: Vec<u8>) -> Result<Target> {
    let mut seg = Segment::new("seg_a".to_string());
    seg.data = file_content;
    seg.offset = args.base;

    let mut target = Target::new();
    target.segments.push(seg);
    Ok(target)
}

fn load_object(_args: &Cli, file_content: Vec<u8>) -> Result<Target> {
    let mut target = Target::new();
    let object = object::Object::new(&file_content)?;
    for obj_seg in &object.segments {
        let segment_name = &object.names[obj_seg.name_index];
        let mut seg = Segment::new(segment_name.to_string());
        seg.data = obj_seg.data.clone();
        seg.offset = 0;
        target.segments.push(seg);
    }
    for external in &object.externals {
        target.externals.push(External{
            name: external.name.clone()
        });
    }
    for group in &object.groups {
        let group_name = &object.names[group.name_index];
        target.groups.push(Group{
            name: group_name.to_string(),
            segments: group.seg_indices.clone()
        });
    }
    for (seg_index, obj_seg) in object.segments.iter().enumerate() {
        let seg = &mut target.segments[seg_index];
        for (addr, fixup) in &obj_seg.fixups {
            match fixup.target_fixup {
                object::TargetFixup::SegmentIndexAndDisplacement(seg_idx, disp) => {
                    seg.references.insert(*addr as u64, Reference::SegmentDisplacement(seg_idx, disp as u32));
                },
                object::TargetFixup::SegmentIndexOnly(seg_idx) => {
                    seg.references.insert(*addr as u64, Reference::Segment(seg_idx));
                },
                object::TargetFixup::GroupIndexOnly(group_idx) => {
                    seg.references.insert(*addr as u64, Reference::Group(group_idx));
                },
                object::TargetFixup::ExternalIndex(ext_idx) => {
                    seg.references.insert(*addr as u64, Reference::External(ext_idx));
                },
            }
        }
    }
    Ok(target)
}

fn load_executable(_args: &Cli, file_content: Vec<u8>) -> Result<Target> {
    let info = dos_exe::DosMzInfo::new(&file_content)?;

    let mut exe_length = (info.header.num_blocks * 512) as usize;
    if info.header.last_block_used_bytes != 0 {
        exe_length -= (512 - info.header.last_block_used_bytes) as usize;
    }

    let payload_start = (info.header.header_size_in_paragraphs * 16) as usize;
    println!("payload_start {} exe_length {}", payload_start, exe_length);
    let payload = &file_content[payload_start..exe_length];

    // Use the relocations to identify segments containing data
    let mut offsets: Vec<u16> = info.relocs.iter().map(|r| r.segment * 16).collect();
    offsets.push(info.header.init_cs);
    offsets.sort();
    offsets.dedup();
    // Add final offset so the length covers everything
    offsets.push(payload.len() as u16);

    let mut target = Target::new();
    for n in 0..offsets.len() - 1 {
        let cur_offset = offsets[n] as usize;
        let next_offset = offsets[n + 1] as usize;
        let mut seg = Segment::new(format!("seg_{}", n));
        seg.segment = (cur_offset / 16) as u64;
        seg.offset = 0;
        seg.data = payload[cur_offset..next_offset].to_vec();
        for reloc in &info.relocs {
            if reloc.segment as usize != cur_offset * 16 { continue; }
            seg.references.insert(reloc.offset as u64, Reference::ExeReloc());
        }
        target.segments.push(seg);
    }

    // Create initial entry point marker
    let init_seg_idx = offsets.iter().position(|&v| v == info.header.init_cs).unwrap();
    let init_seg = &mut target.segments[init_seg_idx];
    let label_idx = use_label(init_seg, Label::Entry);
    init_seg.markers.insert(info.header.init_ip as u64, Marker::CodeLabel(label_idx));
    Ok(target)
}

fn load_target(args: &Cli, file_content: Vec<u8>) -> Result<Target> {
    let target;
    match args.r#type {
        InputType::Raw => {
            target = load_raw(args, file_content)?;
        },
        InputType::Object => {
            target = load_object(args, file_content)?;
        },
        InputType::Exe => {
            target = load_executable(args, file_content)?;
        }
    };
    Ok(target)
}

fn print_output(cs: &Capstone, args: &Cli, target: &Target) {
    for external in &target.externals {
        println!("EXTRN {}:BYTE", external.name);
    }

    for group in &target.groups {
        let mut segs = String::new();
        for seg_idx in &group.segments {
            if !segs.is_empty() { segs += " "; }
            segs += &target.segments[*seg_idx].name;
        }
        println!("{} GROUP {}", group.name, segs);
    }

    for seg_idx in 0..target.segments.len() {
        output_segment(&args, &cs, &target, seg_idx);
    }
    println!("                end");
}

fn main() -> Result<()> {
    let args = Cli::parse();

    let file_content = std::fs::read(&args.input).unwrap();
    let mut target = load_target(&args, file_content).expect("unable to load target");

    let mode = match args.bits {
        Bits::Bits16 => arch::x86::ArchMode::Mode16,
        Bits::Bits32 => arch::x86::ArchMode::Mode32,
        Bits::Bits64 => arch::x86::ArchMode::Mode64,
    };
    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .detail(true)
        .build()
        .unwrap();

    // Step 1: identify code segments by looking at jumps/calls
    //
    // TODO    Long jumps/calls will only work for EXE files because we rely on a relocation being
    //         present to know a lcall/ljmp is valid
    loop {
        let mut seg_refs: HashSet<SegmentReference> = HashSet::new();
        for seg_idx in 0..target.segments.len() {
            let seg = &mut target.segments[seg_idx];
            let insns = cs
                .disasm_all(&seg.data, seg.offset)
                .unwrap();

            identify_code(&cs, seg, &insns, &mut seg_refs);
        }

        // Split references by segment
        let mut refs_by_seg: HashMap<u64, Vec<SegmentReference>> = HashMap::new();
        for sref in &seg_refs {
            let seg = match sref { SegmentReference::Code(sg, _) => *sg };
            let v = refs_by_seg.entry(seg).or_insert_with(|| Vec::new());
            v.push(sref.clone());
        }

        // Sort the segments and see if they are all known
        let mut new_segments: Vec<u64> = Vec::new();
        for (seg_val, refs) in &refs_by_seg {
            if let Some(seg) = target.segments.iter_mut().find(|s| s.segment as u64 == *seg_val) {
                // Add all code references
                for rf in refs {
                    match rf {
                        SegmentReference::Code(_, off) => {
                            let label_idx = use_label(seg, Label::Code(*off));
                            seg.markers.insert(*off, Marker::CodeLabel(label_idx));
                        }
                    }
                }
                continue;
            }
            new_segments.push(*seg_val);
        }
        if new_segments.is_empty() { break; }

        todo!("introduce new segments {:x?}", new_segments);
    }

    // Step 2: identify data references
    for seg_idx in 0..target.segments.len() {
        let seg = &mut target.segments[seg_idx];
        let insns = cs
            .disasm_all(&seg.data, seg.offset)
            .unwrap();

        identify_data(&cs, seg, &insns);
    }

    print_output(&cs, &args, &target);
    Ok(())
} 
