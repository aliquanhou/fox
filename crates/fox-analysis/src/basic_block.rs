//! FOX Basic Block Engine
//!
//! Implements real basic block segmentation via recursive descent.
//!
//! Block Entry = Function Entry OR Branch Target OR Instruction after Conditional Branch
//! Block Terminator = Unconditional JMP OR Conditional Jcc OR RET OR Indirect JMP
//!
//! CALL is NOT a block terminator by default — execution returns to next instruction.

use fox_core::{Address, CfgEdge, EdgeKind, Evidence, EvidenceKind};
use fox_disasm::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A basic block with instructions and control flow edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: Address,
    pub end_address: Address,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<CfgEdge>,
    pub predecessors: Vec<usize>,
}

impl BasicBlock {
    pub fn new(id: usize, start: Address) -> Self {
        BasicBlock {
            id,
            start_address: start,
            end_address: start,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// The terminator instruction (last instruction if it's a branch/ret).
    pub fn terminator(&self) -> Option<&Instruction> {
        self.instructions
            .last()
            .filter(|i| i.is_jump || i.is_ret || i.is_conditional_jump)
    }

    /// Whether this block ends with a terminator.
    pub fn is_terminated(&self) -> bool {
        self.terminator().is_some()
    }
}

/// Result of basic block analysis for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBlocks {
    pub function_address: Address,
    pub blocks: Vec<BasicBlock>,
    pub entry_block: usize,
    /// Addresses that could not be disassembled (invalid instruction bytes)
    pub invalid_addresses: Vec<u64>,
}

/// Basic Block Engine.
pub struct BasicBlockEngine;

impl BasicBlockEngine {
    /// Analyze a single function starting at `entry_address`.
    ///
    /// Uses recursive descent disassembly:
    /// 1. Start at entry, linear sweep until terminator
    /// 2. At conditional branch: queue both target and fallthrough
    /// 3. At unconditional jump: queue target
    /// 4. At ret: stop
    /// 5. At call: continue to fallthrough (call is not terminator)
    ///
    /// `data` is the section bytes, `base_address` is the VA of data[0].
    pub fn analyze_function(
        data: &[u8],
        base_address: u64,
        entry_address: u64,
        disassembler: &dyn fox_disasm::Disassembler,
    ) -> FunctionBlocks {
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut block_by_start: BTreeMap<u64, usize> = BTreeMap::new();
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        let mut invalid_addresses: Vec<u64> = Vec::new();
        let mut worklist: Vec<u64> = vec![entry_address];

        // Helper: convert VA to data offset
        let va_to_offset = |va: u64| -> Option<usize> {
            if va >= base_address {
                let off = (va - base_address) as usize;
                if off < data.len() {
                    Some(off)
                } else {
                    None
                }
            } else {
                None
            }
        };

        while let Some(start_va) = worklist.pop() {
            if visited.contains(&start_va) {
                continue;
            }
            visited.insert(start_va);

            let start_off = match va_to_offset(start_va) {
                Some(o) => o,
                None => {
                    invalid_addresses.push(start_va);
                    continue;
                }
            };

            // Linear sweep from start_va
            let mut block = BasicBlock::new(blocks.len(), Address(start_va));
            let mut current_va = start_va;
            let mut current_off = start_off;

            loop {
                if current_off >= data.len() {
                    break;
                }

                match disassembler.disassemble_one(&data[current_off..], current_va) {
                    Ok(Some(inst)) => {
                        let is_terminator = inst.is_jump || inst.is_ret;
                        block.instructions.push(inst.clone());
                        block.end_address = Address(current_va + inst.length as u64);
                        current_off += inst.length;
                        current_va += inst.length as u64;

                        if is_terminator {
                            // Process successors based on terminator type
                            Self::process_terminator(
                                &inst,
                                block.id,
                                &mut worklist,
                                &mut block.successors,
                                current_va,
                                va_to_offset,
                            );
                            break;
                        }
                        // Non-terminator: continue linear sweep
                        // But check if next address is already a block start (branch target)
                        if visited.contains(&current_va) || block_by_start.contains_key(&current_va)
                        {
                            // This is a fallthrough into an existing block
                            let fallthrough_edge =
                                CfgEdge::new(EdgeKind::Fallthrough, block.id, current_va)
                                    .with_target(0, current_va)
                                    .with_evidence(
                                        Evidence::new(EvidenceKind::FallthroughEdge)
                                            .with_address(current_va)
                                            .with_weight(0.9),
                                    );
                            block.successors.push(fallthrough_edge);
                            worklist.push(current_va);
                            break;
                        }
                    }
                    Ok(None) => {
                        // Invalid instruction — mark and stop this block
                        invalid_addresses.push(current_va);
                        break;
                    }
                    Err(_) => {
                        invalid_addresses.push(current_va);
                        break;
                    }
                }
            }

            // If block has no instructions, skip
            if block.instructions.is_empty() {
                continue;
            }

            // If block doesn't end with terminator and has no fallthrough edge yet,
            // add fallthrough to next address (if within bounds)
            if !block.is_terminated() && block.successors.is_empty() {
                let next_va = block.end_address.0;
                if va_to_offset(next_va).is_some() {
                    let fallthrough_edge = CfgEdge::new(EdgeKind::Fallthrough, block.id, next_va)
                        .with_target(0, next_va)
                        .with_evidence(
                            Evidence::new(EvidenceKind::FallthroughEdge)
                                .with_address(next_va)
                                .with_weight(0.9),
                        );
                    block.successors.push(fallthrough_edge);
                    worklist.push(next_va);
                }
            }

            block_by_start.insert(start_va, block.id);
            blocks.push(block);
        }

        // Resolve successor target_block indices
        let block_start_to_id: BTreeMap<u64, usize> =
            blocks.iter().map(|b| (b.start_address.0, b.id)).collect();

        for block in &mut blocks {
            for edge in &mut block.successors {
                if let Some(target_va) = edge.target_address {
                    if let Some(&target_id) = block_start_to_id.get(&target_va) {
                        edge.target_block = Some(target_id);
                    }
                }
            }
        }

        // Build predecessors
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        for block in &blocks {
            for edge in &block.successors {
                if let Some(target_id) = edge.target_block {
                    if target_id < predecessors.len() {
                        predecessors[target_id].push(block.id);
                    }
                }
            }
        }
        for (i, preds) in predecessors.into_iter().enumerate() {
            if i < blocks.len() {
                blocks[i].predecessors = preds;
            }
        }

        FunctionBlocks {
            function_address: Address(entry_address),
            blocks,
            entry_block: 0, // first block is always entry (worklist starts with entry)
            invalid_addresses,
        }
    }

    /// Process a terminator instruction and add appropriate successors.
    fn process_terminator(
        inst: &Instruction,
        block_id: usize,
        worklist: &mut Vec<u64>,
        successors: &mut Vec<CfgEdge>,
        next_va: u64,
        va_to_offset: impl Fn(u64) -> Option<usize>,
    ) {
        if inst.is_ret {
            // RET: no successors (return edge is implicit)
            let ret_edge = CfgEdge::new(EdgeKind::Return, block_id, inst.address).with_evidence(
                Evidence::new(EvidenceKind::ReturnEdge)
                    .with_address(inst.address)
                    .with_weight(1.0),
            );
            successors.push(ret_edge);
            return;
        }

        if inst.is_conditional_jump {
            // Jcc: two successors — true (target) and false (fallthrough)
            if let Some(target) = inst.jump_target {
                if va_to_offset(target).is_some() {
                    let true_edge = CfgEdge::new(EdgeKind::ConditionalTrue, block_id, inst.address)
                        .with_target(0, target) // target_block resolved later
                        .with_evidence(
                            Evidence::new(EvidenceKind::ConditionalTrueEdge)
                                .with_address(inst.address)
                                .with_weight(0.95),
                        );
                    successors.push(true_edge);
                    worklist.push(target);
                } else {
                    // Target out of bounds
                    let true_edge = CfgEdge::new(EdgeKind::ConditionalTrue, block_id, inst.address)
                        .with_evidence(
                            Evidence::new(EvidenceKind::ConditionalTrueEdge)
                                .with_address(inst.address)
                                .with_weight(0.95),
                        );
                    successors.push(true_edge);
                }
            } else {
                // Indirect conditional jump (rare)
                let edge = CfgEdge::new(EdgeKind::IndirectJump, block_id, inst.address)
                    .with_evidence(
                        Evidence::new(EvidenceKind::IndirectJumpEdge)
                            .with_address(inst.address)
                            .with_weight(0.5),
                    );
                successors.push(edge);
            }

            // False = fallthrough
            if va_to_offset(next_va).is_some() {
                let false_edge = CfgEdge::new(EdgeKind::ConditionalFalse, block_id, inst.address)
                    .with_target(0, next_va)
                    .with_evidence(
                        Evidence::new(EvidenceKind::ConditionalFalseEdge)
                            .with_address(next_va)
                            .with_weight(0.95),
                    );
                successors.push(false_edge);
                worklist.push(next_va);
            }
            return;
        }

        if inst.is_jump {
            // Unconditional JMP
            if let Some(target) = inst.jump_target {
                if va_to_offset(target).is_some() {
                    let jmp_edge =
                        CfgEdge::new(EdgeKind::UnconditionalJump, block_id, inst.address)
                            .with_target(0, target)
                            .with_evidence(
                                Evidence::new(EvidenceKind::UnconditionalJumpEdge)
                                    .with_address(inst.address)
                                    .with_weight(0.98),
                            );
                    successors.push(jmp_edge);
                    worklist.push(target);
                } else {
                    let jmp_edge =
                        CfgEdge::new(EdgeKind::UnconditionalJump, block_id, inst.address)
                            .with_evidence(
                                Evidence::new(EvidenceKind::UnconditionalJumpEdge)
                                    .with_address(inst.address)
                                    .with_weight(0.98),
                            );
                    successors.push(jmp_edge);
                }
            } else {
                // Indirect JMP
                let edge = CfgEdge::new(EdgeKind::IndirectJump, block_id, inst.address)
                    .with_evidence(
                        Evidence::new(EvidenceKind::IndirectJumpEdge)
                            .with_address(inst.address)
                            .with_weight(0.5),
                    );
                successors.push(edge);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_arch::Architecture;
    use fox_disasm::create_disassembler;

    #[test]
    fn test_simple_linear_function() {
        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
        let disasm = create_disassembler(Architecture::X64).unwrap();
        let result = BasicBlockEngine::analyze_function(&code, 0x1000, 0x1000, disasm.as_ref());

        assert_eq!(result.blocks.len(), 1);
        assert_eq!(result.blocks[0].instructions.len(), 5);
        assert!(result.blocks[0].is_terminated());
        assert_eq!(result.blocks[0].successors.len(), 1);
        assert_eq!(result.blocks[0].successors[0].kind, EdgeKind::Return);
    }

    #[test]
    fn test_conditional_branch() {
        // xor eax, eax; test eax, eax; jz 0x100B; mov eax, 1; jmp 0x100D; mov eax, 2; ret
        // 0x1000: 31 C0          xor eax, eax
        // 0x1002: 85 C0          test eax, eax
        // 0x1004: 74 05          jz 0x100B
        // 0x1006: B8 01 00 00 00 mov eax, 1
        // 0x100B: B8 02 00 00 00 mov eax, 2  (wait, this overlaps...)
        // Let me use a simpler pattern
        // 0x1000: 31 C0          xor eax, eax
        // 0x1002: 85 C0          test eax, eax
        // 0x1004: 74 03          jz 0x1009
        // 0x1006: 90             nop
        // 0x1007: 90             nop
        // 0x1009: C3             ret
        let code = [0x31, 0xC0, 0x85, 0xC0, 0x74, 0x03, 0x90, 0x90, 0xC3];
        let disasm = create_disassembler(Architecture::X64).unwrap();
        let result = BasicBlockEngine::analyze_function(&code, 0x1000, 0x1000, disasm.as_ref());

        // Should have at least 2 blocks: entry (ending at jz) and target/fallthrough merge
        assert!(result.blocks.len() >= 2);

        // First block should end with conditional jump
        let first = &result.blocks[0];
        assert!(first.is_terminated());
        assert!(first.instructions.last().unwrap().is_conditional_jump);

        // Should have ConditionalTrue and ConditionalFalse edges
        let has_true = first
            .successors
            .iter()
            .any(|e| e.kind == EdgeKind::ConditionalTrue);
        let has_false = first
            .successors
            .iter()
            .any(|e| e.kind == EdgeKind::ConditionalFalse);
        assert!(has_true, "Missing ConditionalTrue edge");
        assert!(has_false, "Missing ConditionalFalse edge");
    }

    #[test]
    fn test_unconditional_jump() {
        // jmp 0x1004; nop; nop; 0x1004: ret
        // 0x1000: EB 02 -> jmp 0x1004 (0x1000+2+2)
        // 0x1002: 90    -> nop
        // 0x1003: 90    -> nop
        // 0x1004: C3    -> ret
        let code = [0xEB, 0x02, 0x90, 0x90, 0xC3];
        let disasm = create_disassembler(Architecture::X64).unwrap();
        let result = BasicBlockEngine::analyze_function(&code, 0x1000, 0x1000, disasm.as_ref());

        assert!(result.blocks.len() >= 2);
        let first = &result.blocks[0];
        assert!(first
            .successors
            .iter()
            .any(|e| e.kind == EdgeKind::UnconditionalJump));
    }
}
