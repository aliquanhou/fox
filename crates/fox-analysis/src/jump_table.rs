//! Jump Table Recovery for MSVC x64.
//!
//! Detects compiler-generated switch dispatch patterns and resolves
//! indirect jump targets from jump tables.
//!
//! Typical MSVC x64 pattern:
//! ```asm
//! cmp    ecx, N          ; bounds check
//! jnbe   default         ; out-of-bounds 鈫?default
//! movsxd rax, ecx        ; sign-extend index
//! lea    rdx, [image_base]  ; load base
//! mov    ecx, [rdx+rax*4+disp]  ; load relative offset
//! add    rcx, rdx        ; 鈫?absolute address
//! jmp    rcx             ; indirect jump
//! ```

use fox_binary::Binary;
use fox_core::{Address, Evidence, EvidenceKind};
use fox_disasm::Instruction;
use serde::{Deserialize, Serialize};

/// A recovered jump table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpTable {
    /// Address of the indirect JMP instruction.
    pub dispatch_address: Address,
    /// Address of the jump table in the binary.
    pub table_address: Address,
    /// Size of each entry in bytes (typically 4 for relative offsets).
    pub entry_size: u8,
    /// Number of entries.
    pub entry_count: usize,
    /// Base address added to each entry (image base for relative tables).
    pub base_address: Option<u64>,
    /// Index register used.
    pub index_register: Option<String>,
    /// Resolved target addresses.
    pub targets: Vec<u64>,
    /// Default target (from bounds check branch), if found.
    pub default_target: Option<u64>,
    /// Confidence in this recovery.
    pub confidence: f64,
    /// Evidence supporting this jump table.
    pub evidence: Vec<Evidence>,
}

/// Classification of an indirect branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndirectBranchKind {
    JumpTable,
    IndirectTailCall,
    IndirectCall,
    SwitchDispatch,
    UnknownIndirectBranch,
}

/// Result of analyzing an indirect jump instruction.
pub struct IndirectBranchAnalysis {
    pub kind: IndirectBranchKind,
    pub jump_table: Option<JumpTable>,
}

/// Recover jump tables from indirect jumps in a function.
///
/// Scans the function's instructions for the MSVC x64 switch dispatch pattern
/// and resolves jump table targets.
pub fn recover_jump_tables(binary: &Binary, instructions: &[Instruction]) -> Vec<JumpTable> {
    let mut results = Vec::new();

    for (i, inst) in instructions.iter().enumerate() {
        if !inst.is_jump || inst.jump_target.is_some() {
            continue; // only indirect jumps (no direct target)
        }

        // Check if this is a register indirect jump: jmp reg
        let jump_reg = match &inst.operands_structured.first() {
            Some(op) if op.kind == fox_disasm::OperandKind::Register => match &op.register {
                Some(r) => r.clone(),
                None => continue,
            },
            _ => continue,
        };

        // Try to recover jump table by scanning backwards
        if let Some(jt) = recover_msvc_x64_jump_table(binary, instructions, i, &jump_reg) {
            results.push(jt);
        }
    }

    results
}

/// Recover an MSVC x64 jump table given the indirect JMP instruction index.
fn recover_msvc_x64_jump_table(
    binary: &Binary,
    instructions: &[Instruction],
    jmp_idx: usize,
    jump_reg: &str,
) -> Option<JumpTable> {
    let mut evidence = Vec::new();
    let jmp_inst = &instructions[jmp_idx];

    // Scan backwards up to 12 instructions to find the table setup
    let scan_start = jmp_idx.saturating_sub(12);
    let mut table_load_inst: Option<&Instruction> = None;
    let mut base_reg: Option<String> = None;
    let mut index_reg: Option<String> = None;
    let mut add_inst: Option<&Instruction> = None;
    let mut bounds_check_target: Option<u64> = None;

    for idx in (scan_start..jmp_idx).rev() {
        let inst = &instructions[idx];
        let mn = inst.mnemonic.to_lowercase();

        // Look for: add reg, base_reg (relative 鈫?absolute)
        if mn == "add" && add_inst.is_none() {
            if let (Some(dst), Some(src)) = (
                inst.operands_structured.first(),
                inst.operands_structured.get(1),
            ) {
                if dst.register.as_deref() == Some(jump_reg) {
                    add_inst = Some(inst);
                    base_reg = src.register.clone();
                }
            }
            continue;
        }

        // Look for: mov reg, [base + index*scale + disp] (table lookup)
        if mn == "mov" && table_load_inst.is_none() {
            if let (Some(dst), Some(src)) = (
                inst.operands_structured.first(),
                inst.operands_structured.get(1),
            ) {
                if dst.register.as_deref() == Some(jump_reg) && src.memory.is_some() {
                    table_load_inst = Some(inst);
                    if let Some(mem) = &src.memory {
                        index_reg = mem.index.clone();
                    }
                }
            }
            continue;
        }

        // Look for bounds check: cmp reg, N; jcc default
        if mn == "cmp" && bounds_check_target.is_none() {
            // The next instruction should be a conditional jump
            if idx + 1 < instructions.len() {
                let next = &instructions[idx + 1];
                if next.is_conditional_jump {
                    bounds_check_target = next.jump_target;
                }
            }
        }
    }

    let table_load = table_load_inst?;
    let base = base_reg?;

    // Find the base address from LEA or MOV
    let mut base_address: Option<u64> = None;
    for idx in (scan_start..jmp_idx).rev() {
        let inst = &instructions[idx];
        let mn = inst.mnemonic.to_lowercase();

        // lea reg, [rip+disp] 鈫?RIP-relative effective address
        if mn == "lea" {
            if let (Some(dst), Some(src)) = (
                inst.operands_structured.first(),
                inst.operands_structured.get(1),
            ) {
                if dst.register.as_deref() == Some(base.as_str()) {
                    if let Some(mem) = &src.memory {
                        if mem.is_rip_relative {
                            base_address = mem.effective_address;
                            evidence.push(
                                Evidence::new(EvidenceKind::JumpTablePattern)
                                    .with_address(inst.address)
                                    .with_detail(format!(
                                        "LEA {} base=0x{:X}",
                                        base,
                                        base_address.unwrap_or(0)
                                    ))
                                    .with_weight(0.8),
                            );
                        }
                    }
                }
            }
        }
    }

    // Parse the memory operand to get table address
    let mem = table_load.operands_structured.get(1)?.memory.as_ref()?;
    let scale = mem.scale as u64;
    let disp = mem.displacement;

    // Table address = base + disp (if base is image base loaded via LEA)
    let table_rva: u64 = if base_address.is_some() {
        // base is image base, disp is RVA offset (must be non-negative)
        if disp < 0 {
            return None;
        }
        disp as u64
    } else {
        // Try RIP-relative or absolute
        if mem.is_rip_relative {
            let ea = mem.effective_address?;
            if ea < binary.image_base {
                return None;
            }
            ea - binary.image_base
        } else {
            if disp < 0 {
                return None;
            }
            disp as u64
        }
    };

    let table_va = binary.image_base.checked_add(table_rva)?;
    let entry_size = if scale == 4 { 4u8 } else { 8u8 };

    // Determine entry count from bounds check
    let entry_count = match bounds_check_target {
        Some(_) => {
            // Find cmp instruction to get max index
            let mut max_idx: Option<u64> = None;
            for idx in (scan_start..jmp_idx).rev() {
                if instructions[idx].mnemonic.to_lowercase() == "cmp" {
                    if let Some(imm_op) = instructions[idx].operands_structured.get(1) {
                        max_idx = imm_op.immediate;
                    }
                    break;
                }
            }
            max_idx.map(|m| (m + 1) as usize).unwrap_or(0)
        }
        None => 0,
    };

    if entry_count == 0 || entry_count > 256 {
        return None; // unreasonable
    }

    // Read table entries from binary
    let table_offset = rva_to_offset(binary, table_rva)?;

    let data = &binary.raw_data;
    let mut targets = Vec::new();
    let base_va = base_address.unwrap_or(binary.image_base);

    for e in 0..entry_count {
        let entry_off = table_offset + e * entry_size as usize;
        if entry_off + entry_size as usize > data.len() {
            break;
        }
        let entry_val = if entry_size == 4 {
            u32::from_le_bytes([
                data[entry_off],
                data[entry_off + 1],
                data[entry_off + 2],
                data[entry_off + 3],
            ]) as u64
        } else {
            u64::from_le_bytes([
                data[entry_off],
                data[entry_off + 1],
                data[entry_off + 2],
                data[entry_off + 3],
                data[entry_off + 4],
                data[entry_off + 5],
                data[entry_off + 6],
                data[entry_off + 7],
            ])
        };

        // Relative offset 鈫?absolute address
        let target = base_va.checked_add(entry_val)?;
        targets.push(target);
    }

    evidence.push(
        Evidence::new(EvidenceKind::JumpTablePattern)
            .with_address(jmp_inst.address)
            .with_detail(format!(
                "JMP {} via table @ 0x{:X}, {} entries",
                jump_reg, table_va, entry_count
            ))
            .with_weight(0.9),
    );

    evidence.push(
        Evidence::new(EvidenceKind::JumpTableTarget)
            .with_address(table_va)
            .with_detail(format!(
                "Table entries: {:?}",
                targets
                    .iter()
                    .map(|t| format!("0x{:X}", t))
                    .collect::<Vec<_>>()
            ))
            .with_weight(0.85),
    );

    Some(JumpTable {
        dispatch_address: Address(jmp_inst.address),
        table_address: Address(table_va),
        entry_size,
        entry_count,
        base_address,
        index_register: index_reg,
        targets,
        default_target: bounds_check_target,
        confidence: 0.85,
        evidence,
    })
}

/// Convert RVA to file offset using section table.
fn rva_to_offset(binary: &Binary, rva: u64) -> Option<usize> {
    for section in &binary.sections {
        if rva >= section.virtual_address
            && rva < section.virtual_address + section.virtual_size as u64
        {
            let offset = section.raw_offset + (rva - section.virtual_address) as usize;
            if offset < binary.raw_data.len() {
                return Some(offset);
            }
        }
    }
    None
}

/// Classify an indirect branch instruction.
pub fn classify_indirect_branch(inst: &Instruction) -> IndirectBranchKind {
    if !inst.is_jump && !inst.is_call {
        return IndirectBranchKind::UnknownIndirectBranch;
    }

    if inst.jump_target.is_some() || inst.call_target.is_some() {
        return IndirectBranchKind::UnknownIndirectBranch; // direct branch
    }

    let first_op = match inst.operands_structured.first() {
        Some(op) => op,
        None => return IndirectBranchKind::UnknownIndirectBranch,
    };

    if inst.is_call {
        return IndirectBranchKind::IndirectCall;
    }

    // jmp reg 鈥?could be jump table or tail call
    if first_op.kind == fox_disasm::OperandKind::Register {
        // We can't distinguish without context; caller should use
        // recover_jump_tables for JumpTable detection
        return IndirectBranchKind::UnknownIndirectBranch;
    }

    // jmp [mem] 鈥?likely indirect tail call or vtable dispatch
    if first_op.memory.is_some() {
        return IndirectBranchKind::IndirectTailCall;
    }

    IndirectBranchKind::UnknownIndirectBranch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_indirect_call() {
        let inst = Instruction {
            address: 0x1000,
            length: 2,
            mnemonic: "call".to_string(),
            operands: "rax".to_string(),
            raw_bytes: vec![0xFF, 0xD0],
            is_call: true,
            is_ret: false,
            is_jump: false,
            is_conditional_jump: false,
            jump_target: None,
            call_target: None,
            operands_structured: vec![fox_disasm::Operand {
                kind: fox_disasm::OperandKind::Register,
                register: Some("rax".to_string()),
                immediate: None,
                memory: None,
                width: 64,
                is_read: true,
                is_write: false,
                is_implicit: false,
            }],
            implicit_reads: vec![],
            implicit_writes: vec![],
            reads_flags: false,
            writes_flags: false,
        };
        assert_eq!(
            classify_indirect_branch(&inst),
            IndirectBranchKind::IndirectCall
        );
    }
}
