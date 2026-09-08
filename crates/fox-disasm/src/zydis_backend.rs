//! Zydis-based disassembler backend for x86/x64.
//! Uses zydis 4.x API.
//!
//! P0-2: Structured operands, FLAGS semantics, RIP-relative effective address.

use super::{Disassembler, Instruction, MemoryOperand, Operand, OperandKind};
use fox_arch::Architecture;
use fox_core::{FoxError, FoxResult};
use zydis::ffi::DecodedOperandKind;
use zydis::{
    Decoder, Formatter, MachineMode, OperandAction, OperandArrayVec, OperandVisibility, StackWidth,
};

const MAX_OPERANDS: usize = 10;

pub struct ZydisDisassembler {
    decoder: Decoder,
    arch: Architecture,
}

impl ZydisDisassembler {
    pub fn new(arch: Architecture) -> FoxResult<Self> {
        let decoder = match arch {
            Architecture::X64 => Decoder::new(MachineMode::LONG_64, StackWidth::_64)
                .map_err(|e| FoxError::DisassemblyError(format!("Zydis init: {:?}", e)))?,
            Architecture::X86 => Decoder::new(MachineMode::LONG_COMPAT_32, StackWidth::_32)
                .map_err(|e| FoxError::DisassemblyError(format!("Zydis init: {:?}", e)))?,
            other => {
                return Err(FoxError::UnsupportedArchitecture(
                    other.display_name().to_string(),
                ))
            }
        };

        Ok(ZydisDisassembler { decoder, arch })
    }
}

impl Disassembler for ZydisDisassembler {
    fn architecture(&self) -> Architecture {
        self.arch
    }

    fn disassemble(&self, data: &[u8], address: u64) -> FoxResult<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut offset = 0usize;
        let mut current_addr = address;

        while offset < data.len() {
            match self.disassemble_one(&data[offset..], current_addr)? {
                Some(inst) => {
                    offset += inst.length;
                    current_addr += inst.length as u64;
                    instructions.push(inst);
                }
                None => {
                    offset += 1;
                    current_addr += 1;
                }
            }
        }

        Ok(instructions)
    }

    fn disassemble_one(&self, data: &[u8], address: u64) -> FoxResult<Option<Instruction>> {
        match self
            .decoder
            .decode_first::<OperandArrayVec<MAX_OPERANDS>>(data)
        {
            Ok(Some(decoded)) => {
                let length = decoded.length as usize;
                let raw_bytes = data[..length.min(data.len())].to_vec();

                let formatter = Formatter::intel();
                let full_text = formatter
                    .format(Some(address), &decoded)
                    .unwrap_or_else(|_| format!("{:?}", decoded.mnemonic));

                let (mnemonic, operands) = match full_text.find(' ') {
                    Some(idx) => (
                        full_text[..idx].to_string(),
                        full_text[idx + 1..].to_string(),
                    ),
                    None => (full_text, String::new()),
                };

                let mnemonic_lower = mnemonic.to_lowercase();
                let is_call = mnemonic_lower == "call";
                let is_ret = mnemonic_lower == "ret" || mnemonic_lower.starts_with("ret");
                let is_jump = mnemonic_lower.starts_with('j') && !is_call;
                let is_conditional_jump = is_jump && mnemonic_lower != "jmp";

                let (jump_target, call_target) = if (is_jump || is_call) && !operands.is_empty() {
                    parse_absolute_address(&operands)
                        .map(|target| {
                            if is_call {
                                (None, Some(target))
                            } else {
                                (Some(target), None)
                            }
                        })
                        .unwrap_or((None, None))
                } else {
                    (None, None)
                };

                // P0-2: Parse structured operands
                let (operands_structured, implicit_reads, implicit_writes) =
                    Self::parse_operands(&decoded, address, length);

                let (writes_flags, reads_flags) = Self::flags_semantics(&mnemonic_lower);

                Ok(Some(Instruction {
                    address,
                    length,
                    mnemonic,
                    operands,
                    raw_bytes,
                    is_call,
                    is_ret,
                    is_jump,
                    is_conditional_jump,
                    jump_target,
                    call_target,
                    operands_structured,
                    implicit_reads,
                    implicit_writes,
                    writes_flags,
                    reads_flags,
                }))
            }
            Ok(None) => Ok(None),
            Err(_) => Ok(None),
        }
    }
}

impl ZydisDisassembler {
    fn parse_operands(
        decoded: &zydis::Instruction<OperandArrayVec<MAX_OPERANDS>>,
        address: u64,
        length: usize,
    ) -> (Vec<Operand>, Vec<String>, Vec<String>) {
        let mut explicit = Vec::new();
        let mut implicit_reads = Vec::new();
        let mut implicit_writes = Vec::new();

        for op in decoded.operands().iter() {
            let is_implicit = op.visibility == OperandVisibility::HIDDEN
                || op.visibility == OperandVisibility::IMPLICIT;

            let is_read = op.action.contains(OperandAction::READ)
                || op.action.contains(OperandAction::CONDREAD);
            let is_write = op.action.contains(OperandAction::WRITE)
                || op.action.contains(OperandAction::CONDWRITE);

            let operand = match &op.kind {
                DecodedOperandKind::Reg(reg) => {
                    let reg_name = format!("{:?}", reg).to_lowercase();
                    if reg_name == "none" {
                        continue;
                    }
                    Operand {
                        kind: OperandKind::Register,
                        register: Some(reg_name.clone()),
                        immediate: None,
                        memory: None,
                        width: op.size,
                        is_read,
                        is_write,
                        is_implicit,
                    }
                }
                DecodedOperandKind::Imm(imm) => Operand {
                    kind: OperandKind::Immediate,
                    register: None,
                    immediate: Some(imm.value),
                    memory: None,
                    width: op.size,
                    is_read,
                    is_write: false,
                    is_implicit,
                },
                DecodedOperandKind::Mem(mem) => {
                    let base_reg = format!("{:?}", mem.base).to_lowercase();
                    let index_reg = format!("{:?}", mem.index).to_lowercase();
                    let base = if base_reg == "none" {
                        None
                    } else {
                        Some(base_reg.clone())
                    };
                    let index = if index_reg == "none" {
                        None
                    } else {
                        Some(index_reg)
                    };
                    let is_rip = base_reg == "rip";
                    let disp = if mem.disp.has_displacement {
                        mem.disp.displacement
                    } else {
                        0
                    };

                    let effective_address = if is_rip {
                        Some(
                            address
                                .wrapping_add(length as u64)
                                .wrapping_add(disp as u64),
                        )
                    } else {
                        None
                    };

                    Operand {
                        kind: OperandKind::Memory,
                        register: None,
                        immediate: None,
                        memory: Some(MemoryOperand {
                            base,
                            index,
                            scale: mem.scale,
                            displacement: disp,
                            size: (op.size / 8) as u8,
                            is_rip_relative: is_rip,
                            effective_address,
                        }),
                        width: op.size,
                        is_read,
                        is_write,
                        is_implicit,
                    }
                }
                _ => continue,
            };

            if is_implicit {
                if is_read {
                    if let Some(ref reg) = operand.register {
                        implicit_reads.push(reg.clone());
                    }
                }
                if is_write {
                    if let Some(ref reg) = operand.register {
                        implicit_writes.push(reg.clone());
                    }
                }
            } else {
                explicit.push(operand);
            }
        }

        (explicit, implicit_reads, implicit_writes)
    }

    fn flags_semantics(mnemonic: &str) -> (bool, bool) {
        let writes = matches!(
            mnemonic,
            "add"
                | "sub"
                | "adc"
                | "sbb"
                | "inc"
                | "dec"
                | "neg"
                | "and"
                | "or"
                | "xor"
                | "not"
                | "shl"
                | "shr"
                | "sar"
                | "imul"
                | "mul"
                | "idiv"
                | "div"
                | "cmp"
                | "test"
                | "bt"
                | "bts"
                | "btr"
                | "btc"
                | "bsf"
                | "bsr"
                | "cmc"
                | "clc"
                | "stc"
                | "cld"
                | "std"
        );
        let reads = (mnemonic.starts_with('j') && mnemonic != "jmp" && mnemonic.len() > 1)
            || matches!(
                mnemonic,
                "cmovz"
                    | "cmovnz"
                    | "cmove"
                    | "cmovne"
                    | "cmovg"
                    | "cmovge"
                    | "cmovl"
                    | "cmovle"
                    | "setz"
                    | "setnz"
                    | "sete"
                    | "setne"
                    | "setg"
                    | "setge"
                    | "setl"
                    | "setle"
                    | "adc"
                    | "sbb"
                    | "cmc"
                    | "lahf"
            );
        (writes, reads)
    }
}

fn parse_absolute_address(operands: &str) -> Option<u64> {
    let cleaned = operands.trim();
    if let Some(hex_str) = cleaned.strip_prefix("0x") {
        let hex_str: String = hex_str
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        return u64::from_str_radix(&hex_str, 16).ok();
    }
    if cleaned.starts_with(|c: char| c.is_ascii_hexdigit()) && cleaned.len() > 4 {
        let hex_str: String = cleaned
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if hex_str.len() >= 4 {
            if let Ok(val) = u64::from_str_radix(&hex_str, 16) {
                return Some(val);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_simple_x64() {
        let code = [0x55, 0x48, 0x89, 0xE5, 0xC3];
        let disasm = ZydisDisassembler::new(Architecture::X64).unwrap();
        let result = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result[2].is_ret);
    }

    #[test]
    fn test_structured_operands_exist() {
        let code = [0x48, 0x89, 0xD8]; // mov rax, rbx
        let disasm = ZydisDisassembler::new(Architecture::X64).unwrap();
        let result = disasm.disassemble(&code, 0x1000).unwrap();
        assert!(!result[0].operands_structured.is_empty());
    }

    #[test]
    fn test_flags_semantics() {
        assert_eq!(ZydisDisassembler::flags_semantics("add"), (true, false));
        assert_eq!(ZydisDisassembler::flags_semantics("mov"), (false, false));
        assert!(ZydisDisassembler::flags_semantics("jz").1);
    }
}
