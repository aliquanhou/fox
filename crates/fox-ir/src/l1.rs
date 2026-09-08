//! FOX IR L1 — Instruction-level IR with full semantics
//!
//! P0-2: Uses structured operands from fox-disasm (not text parsing).
//! Every IR instruction records:
//! - explicit register reads/writes
//! - implicit register reads/writes (RSP, RIP, etc.)
//! - FLAGS read/write
//! - operand width and access mode
//! - memory addressing details (base/index/scale/disp/effective_address)

use crate::{IRInstruction, IROp, IROperand, OperandAccess};
use fox_core::{Address, Evidence, EvidenceKind};
use fox_disasm::{Instruction, OperandKind};

/// IR L1 translator.
pub struct IRTranslator;

impl IRTranslator {
    /// Translate a single machine instruction to IR L1 with full semantics.
    pub fn translate(inst: &Instruction) -> IRInstruction {
        let op = Self::map_mnemonic(&inst.mnemonic);
        let operands = Self::translate_operands(inst);

        let (reads_registers, writes_registers) = Self::collect_register_io(&operands);

        IRInstruction {
            address: Address(inst.address),
            op,
            operands,
            original_mnemonic: Some(inst.mnemonic.clone()),
            original_operands: Some(inst.operands.clone()),
            size: inst.length as u8,
            reads_registers,
            writes_registers,
            implicit_reads: inst.implicit_reads.clone(),
            implicit_writes: inst.implicit_writes.clone(),
            reads_flags: inst.reads_flags,
            writes_flags: inst.writes_flags,
        }
    }

    /// Translate a sequence of instructions.
    pub fn translate_all(instructions: &[Instruction]) -> Vec<IRInstruction> {
        instructions.iter().map(Self::translate).collect()
    }

    /// Translate structured operands from disassembly to IR operands.
    fn translate_operands(inst: &Instruction) -> Vec<IROperand> {
        let mut result = Vec::new();

        for op in &inst.operands_structured {
            let access = match (op.is_read, op.is_write) {
                (true, true) => OperandAccess::ReadWrite,
                (true, false) => OperandAccess::Read,
                (false, true) => OperandAccess::Write,
                _ => OperandAccess::Read, // default
            };

            let ir_op = match op.kind {
                OperandKind::Register => IROperand::Register {
                    name: op.register.clone().unwrap_or_default(),
                    width: op.width,
                    access,
                },
                OperandKind::Immediate => {
                    IROperand::Immediate {
                        value: op.immediate.unwrap_or(0),
                        width: op.width,
                        is_signed: false, // determined by context
                    }
                }
                OperandKind::Memory => {
                    if let Some(ref mem) = op.memory {
                        IROperand::Memory {
                            base: mem.base.clone(),
                            index: mem.index.clone(),
                            scale: mem.scale,
                            displacement: mem.displacement,
                            size: mem.size,
                            access,
                            is_rip_relative: mem.is_rip_relative,
                            effective_address: mem.effective_address,
                        }
                    } else {
                        continue;
                    }
                }
            };
            result.push(ir_op);
        }

        // Add FLAGS operand if instruction writes or reads flags
        if inst.writes_flags || inst.reads_flags {
            let flags_access = match (inst.reads_flags, inst.writes_flags) {
                (true, true) => OperandAccess::ReadWrite,
                (true, false) => OperandAccess::Read,
                (false, true) => OperandAccess::Write,
                _ => unreachable!(),
            };
            result.push(IROperand::Flags {
                access: flags_access,
            });
        }

        result
    }

    /// Collect explicit register reads and writes from IR operands.
    fn collect_register_io(operands: &[IROperand]) -> (Vec<String>, Vec<String>) {
        let mut reads = Vec::new();
        let mut writes = Vec::new();

        for op in operands {
            match op {
                IROperand::Register { name, access, .. } => match access {
                    OperandAccess::Read => reads.push(name.clone()),
                    OperandAccess::Write => writes.push(name.clone()),
                    OperandAccess::ReadWrite => {
                        reads.push(name.clone());
                        writes.push(name.clone());
                    }
                },
                IROperand::Memory { base, index, .. } => {
                    // Base and index registers are always read
                    if let Some(b) = base {
                        reads.push(b.clone());
                    }
                    if let Some(i) = index {
                        reads.push(i.clone());
                    }
                }
                _ => {}
            }
        }

        reads.sort();
        reads.dedup();
        writes.sort();
        writes.dedup();
        (reads, writes)
    }

    /// Map x86/x64 mnemonic to IROp.
    fn map_mnemonic(mnemonic: &str) -> IROp {
        let m = mnemonic.to_lowercase();
        match m.as_str() {
            // Data movement
            "mov" => IROp::Mov,
            "lea" => IROp::Lea,
            "push" => IROp::Push,
            "pop" => IROp::Pop,
            "movzx" | "movsx" => IROp::Mov,
            "xchg" => IROp::Mov,

            // Arithmetic
            "add" => IROp::Add,
            "sub" => IROp::Sub,
            "adc" => IROp::Add,
            "sbb" => IROp::Sub,
            "imul" | "mul" => IROp::Mul,
            "idiv" | "div" => IROp::Div,
            "inc" => IROp::Inc,
            "dec" => IROp::Dec,
            "neg" => IROp::Neg,

            // Bitwise
            "and" => IROp::And,
            "or" => IROp::Or,
            "xor" => IROp::Xor,
            "not" => IROp::Not,
            "shl" | "sal" => IROp::Shl,
            "shr" => IROp::Shr,
            "sar" => IROp::Sar,
            "rol" => IROp::Rotl,
            "ror" => IROp::Rotr,

            // Comparison
            "cmp" => IROp::Cmp,
            "test" => IROp::Test,

            // Control flow
            "jmp" => IROp::Jump,
            "call" => IROp::Call,
            "ret" | "retn" => IROp::Return,
            "nop" => IROp::Nop,
            "hlt" => IROp::Halt,
            "int" | "int3" => IROp::Int,
            "syscall" => IROp::Syscall,
            "enter" => IROp::Enter,
            "leave" => IROp::Leave,

            // Conditional jumps map to CondJump
            m if m.starts_with('j') && m != "jmp" && m.len() > 1 => IROp::CondJump,

            // Setcc
            m if m.starts_with("set") => IROp::SetFlag,

            // Unknown
            other => IROp::Unknown(other.to_string()),
        }
    }
}

/// Build evidence for an IR instruction translation.
pub fn ir_evidence(inst: &Instruction) -> fox_core::EvidenceList {
    let mut ev = fox_core::EvidenceList::new();
    ev.push(
        Evidence::new(EvidenceKind::ValidInstructionDecoded)
            .with_address(inst.address)
            .with_weight(0.9),
    );
    ev.push(
        Evidence::new(EvidenceKind::BlockTerminator {
            mnemonic: inst.mnemonic.clone(),
        })
        .with_address(inst.address)
        .with_weight(0.8),
    );
    ev
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_disasm::{MemoryOperand, Operand};

    fn make_inst(mnemonic: &str, ops: Vec<Operand>) -> Instruction {
        Instruction {
            address: 0x1000,
            length: 3,
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            raw_bytes: vec![],
            is_call: false,
            is_ret: false,
            is_jump: false,
            is_conditional_jump: false,
            jump_target: None,
            call_target: None,
            operands_structured: ops,
            implicit_reads: vec![],
            implicit_writes: vec![],
            writes_flags: false,
            reads_flags: false,
        }
    }

    fn reg_op(name: &str, width: u16, read: bool, write: bool) -> Operand {
        Operand {
            kind: OperandKind::Register,
            register: Some(name.to_string()),
            immediate: None,
            memory: None,
            width,
            is_read: read,
            is_write: write,
            is_implicit: false,
        }
    }

    #[test]
    fn test_mov_register_semantics() {
        // mov rax, rbx → rax=write, rbx=read
        let inst = make_inst(
            "mov",
            vec![
                reg_op("rax", 64, false, true),
                reg_op("rbx", 64, true, false),
            ],
        );
        let ir = IRTranslator::translate(&inst);
        assert_eq!(ir.op, IROp::Mov);
        assert_eq!(ir.writes_registers, vec!["rax"]);
        assert_eq!(ir.reads_registers, vec!["rbx"]);
        assert!(!ir.writes_flags);
    }

    #[test]
    fn test_add_flags_semantics() {
        let mut inst = make_inst(
            "add",
            vec![
                reg_op("rax", 64, false, true),
                reg_op("rbx", 64, true, false),
            ],
        );
        inst.writes_flags = true;
        let ir = IRTranslator::translate(&inst);
        assert!(ir.writes_flags);
        assert!(ir
            .operands
            .iter()
            .any(|o| matches!(o, IROperand::Flags { .. })));
    }

    #[test]
    fn test_memory_operand_semantics() {
        // mov eax, [rbx+rcx*4+0x10]
        let mem_op = Operand {
            kind: OperandKind::Memory,
            register: None,
            immediate: None,
            memory: Some(MemoryOperand {
                base: Some("rbx".to_string()),
                index: Some("rcx".to_string()),
                scale: 4,
                displacement: 0x10,
                size: 4,
                is_rip_relative: false,
                effective_address: None,
            }),
            width: 32,
            is_read: true,
            is_write: false,
            is_implicit: false,
        };
        let inst = make_inst("mov", vec![reg_op("eax", 32, false, true), mem_op]);
        let ir = IRTranslator::translate(&inst);
        // Memory base/index should be in reads
        assert!(ir.reads_registers.contains(&"rbx".to_string()));
        assert!(ir.reads_registers.contains(&"rcx".to_string()));
        assert!(ir.writes_registers.contains(&"eax".to_string()));
    }

    #[test]
    fn test_cmp_reads_and_writes_flags() {
        let mut inst = make_inst(
            "cmp",
            vec![
                reg_op("rax", 64, true, false),
                reg_op("rbx", 64, true, false),
            ],
        );
        inst.writes_flags = true;
        let ir = IRTranslator::translate(&inst);
        assert!(ir.writes_flags);
        assert!(!ir.reads_flags);
        // CMP reads both operands, writes none
        assert_eq!(ir.reads_registers.len(), 2);
        assert!(ir.writes_registers.is_empty());
    }

    #[test]
    fn test_map_conditional_jump() {
        assert_eq!(IRTranslator::map_mnemonic("jz"), IROp::CondJump);
        assert_eq!(IRTranslator::map_mnemonic("jmp"), IROp::Jump);
    }

    #[test]
    fn test_implicit_operands_preserved() {
        let mut inst = make_inst("push", vec![reg_op("rax", 64, true, false)]);
        inst.implicit_reads = vec!["rsp".to_string()];
        inst.implicit_writes = vec!["rsp".to_string()];
        let ir = IRTranslator::translate(&inst);
        assert!(ir.implicit_reads.contains(&"rsp".to_string()));
        assert!(ir.implicit_writes.contains(&"rsp".to_string()));
        assert!(ir.all_reads().contains(&"rsp"));
        assert!(ir.all_writes().contains(&"rsp"));
    }
}
