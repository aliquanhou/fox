//! FOX Cross-Domain Value Flow (P0-4.4)
//!
//! Bridges Register SSA and Memory SSA into a unified value flow graph.
//!
//! Core principle (per architecture audit correction):
//!   RAX RegisterDef
//!       鈫?RegisterUse (in Store)
//!   MemoryDef([rsp+8])
//!       鈫?MemoryUse (in Load)
//!   RCX RegisterDef (value from memory)
//!       鈫?RegisterUse
//!
//! This module CONSUMES existing Register SSA and Memory SSA as sealed base
//! layers. It does NOT modify them.
//!
//! Modules:
//! - 4.4.1 Memory DataFlow: MemoryUse 鈫?reaching MemoryDef (cross-CFG)
//! - 4.4.2 Cross-domain Value Flow: Register 鈫?Memory bridge
//! - 4.4.3 Basic Alias Classification: MustAlias / MayAlias / NoAlias
//! - 4.4.4 Function Pointer Propagation: LEA 鈫?Store 鈫?Load 鈫?call resolution

#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

use fox_core::{Evidence, EvidenceKind};
use fox_ir::{IRFunction, IROp, IROperand, OperandAccess};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::memory_ssa::{MemorySSAFunction, MemoryVariable};
use crate::ssa::{SSAFunction, SSAOperand};

// ============================================================================
// 4.4.3 Basic Alias Classification
// ============================================================================

/// Alias relationship between two memory variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AliasClass {
    /// Definitely the same memory location
    MustAlias,
    /// May be the same location (conservative)
    MayAlias,
    /// Definitely different locations
    NoAlias,
    /// Cannot determine
    Unknown,
}

/// Classify alias relationship between two MemoryVariables.
pub fn classify_alias(a: &MemoryVariable, b: &MemoryVariable) -> AliasClass {
    match (a, b) {
        (
            MemoryVariable::Stack {
                base: ba,
                displacement: da,
            },
            MemoryVariable::Stack {
                base: bb,
                displacement: db,
            },
        ) => {
            if ba == bb && da == db {
                AliasClass::MustAlias
            } else {
                // Conservative: cannot prove different stack slots are non-overlapping
                // (e.g., RSP+8 vs RBP-8 after frame setup may alias). Always MayAlias.
                AliasClass::MayAlias
            }
        }
        (MemoryVariable::Global { address: aa }, MemoryVariable::Global { address: ab }) => {
            if aa == ab {
                AliasClass::MustAlias
            } else {
                AliasClass::NoAlias
            }
        }
        (MemoryVariable::Heap, MemoryVariable::Heap) => AliasClass::MayAlias,
        (MemoryVariable::Unknown, MemoryVariable::Unknown) => AliasClass::MayAlias,
        (MemoryVariable::Heap, MemoryVariable::Unknown)
        | (MemoryVariable::Unknown, MemoryVariable::Heap) => AliasClass::MayAlias,
        (MemoryVariable::Stack { .. }, MemoryVariable::Heap)
        | (MemoryVariable::Heap, MemoryVariable::Stack { .. }) => AliasClass::NoAlias,
        (MemoryVariable::Stack { .. }, MemoryVariable::Unknown)
        | (MemoryVariable::Unknown, MemoryVariable::Stack { .. }) => AliasClass::MayAlias,
        (MemoryVariable::Global { .. }, MemoryVariable::Heap)
        | (MemoryVariable::Heap, MemoryVariable::Global { .. }) => AliasClass::NoAlias,
        (MemoryVariable::Global { .. }, MemoryVariable::Unknown)
        | (MemoryVariable::Unknown, MemoryVariable::Global { .. }) => AliasClass::MayAlias,
        (MemoryVariable::Stack { .. }, MemoryVariable::Global { .. })
        | (MemoryVariable::Global { .. }, MemoryVariable::Stack { .. }) => AliasClass::NoAlias,
    }
}

// ============================================================================
// Value Flow Nodes & Edges
// ============================================================================

/// A register definition point (from Register SSA).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisterDefRef {
    pub block_id: usize,
    pub inst_index: usize,
    pub register: String,
    pub version: u32,
}

/// A register use point (from Register SSA).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisterUseRef {
    pub block_id: usize,
    pub inst_index: usize,
    pub operand_index: usize,
    pub register: String,
    pub version: u32,
}

/// Edge: RegisterUse (in Store) 鈫?MemoryDef.
/// The value in the register flows into memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterToMemoryEdge {
    pub register_use: RegisterUseRef,
    pub register_def: RegisterDefRef,
    pub memory_def: (usize, usize, MemoryVariable, u32),
}

/// Edge: MemoryUse (in Load) 鈫?RegisterDef.
/// The value from memory flows into a register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryToRegisterEdge {
    pub memory_use: (usize, usize, MemoryVariable, u32),
    pub memory_def: (usize, usize, MemoryVariable, u32),
    pub register_def: RegisterDefRef,
}

/// A resolved function pointer candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPointerCandidate {
    pub call_block: usize,
    pub call_inst: usize,
    pub call_register: String,
    pub target_address: Option<u64>,
    pub confidence: f64,
    pub evidence: String,
    pub resolution_kind: ResolutionKind,
}

/// How an indirect call was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionKind {
    /// Resolved via LEA 鈫?Store 鈫?Load 鈫?call chain
    LeaStoreLoadChain,
    /// Resolved via direct LEA 鈫?register 鈫?call
    LeaDirect,
    /// Resolved via IAT (already handled by callgraph)
    Iat,
    /// Could not resolve
    Unresolved,
}

// ============================================================================
// Cross-Domain Value Flow
// ============================================================================

/// Unified value flow graph bridging Register SSA and Memory SSA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainValueFlow {
    /// Edges: RegisterUse 鈫?MemoryDef (Store source register value 鈫?memory)
    pub register_to_memory: Vec<RegisterToMemoryEdge>,
    /// Edges: MemoryUse 鈫?RegisterDef (Load memory value 鈫?register)
    pub memory_to_register: Vec<MemoryToRegisterEdge>,
    /// Function pointer candidates for indirect calls
    pub function_pointer_candidates: Vec<FunctionPointerCandidate>,
    /// Alias classification summary
    pub alias_pairs_checked: usize,
    pub must_alias_count: usize,
    pub may_alias_count: usize,
    pub no_alias_count: usize,
    /// Evidence
    pub evidence: Vec<Evidence>,
}

impl CrossDomainValueFlow {
    /// Build cross-domain value flow from Register SSA + Memory SSA + IR.
    ///
    /// Consumes sealed layers, does not modify them.
    pub fn build(
        ir_func: &IRFunction,
        reg_ssa: &SSAFunction,
        mem_ssa: Option<&MemorySSAFunction>,
    ) -> Self {
        let mut register_to_memory = Vec::new();
        let mut memory_to_register = Vec::new();
        let mut must_alias = 0;
        let mut may_alias = 0;
        let mut no_alias = 0;
        let mut alias_pairs = 0;

        // Build lookup: (block_id, inst_index) -> SSAInstruction
        let mut ssa_inst_lookup: HashMap<(usize, usize), &crate::ssa::SSAInstruction> =
            HashMap::new();
        for block in &reg_ssa.basic_blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                ssa_inst_lookup.insert((block.id, idx), inst);
            }
        }

        // Build lookup: (block_id, inst_index) -> IRInstruction
        let mut ir_inst_lookup: HashMap<(usize, usize), &fox_ir::IRInstruction> = HashMap::new();
        for block in &ir_func.basic_blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                ir_inst_lookup.insert((block.id, idx), inst);
            }
        }

        // === 4.4.2 Cross-domain bridge (only if Memory SSA exists) ===
        if let Some(mem_ssa) = mem_ssa {
            // Bridge 1: RegisterUse 鈫?MemoryDef (Store's source register)
            for mem_def in &mem_ssa.definitions {
                let key = (mem_def.block_id, mem_def.inst_index);
                let ssa_inst = match ssa_inst_lookup.get(&key) {
                    Some(i) => *i,
                    None => continue,
                };

                // Find the source register operand (access=Read) matching mem_def.source_register
                if let Some(src_reg) = &mem_def.source_register {
                    for (op_idx, op) in ssa_inst.operands.iter().enumerate() {
                        if let SSAOperand::Variable { name, version } = op {
                            if name == src_reg {
                                // This is the register use in the Store
                                // Trace to its register definition via use-def chains
                                let reg_def = reg_ssa
                                    .use_def_chains
                                    .get(&(mem_def.block_id, mem_def.inst_index, op_idx))
                                    .map(|(db, di, v)| RegisterDefRef {
                                        block_id: *db,
                                        inst_index: *di,
                                        register: name.clone(),
                                        version: *v,
                                    });

                                if let Some(rd) = reg_def {
                                    register_to_memory.push(RegisterToMemoryEdge {
                                        register_use: RegisterUseRef {
                                            block_id: mem_def.block_id,
                                            inst_index: mem_def.inst_index,
                                            operand_index: op_idx,
                                            register: name.clone(),
                                            version: *version,
                                        },
                                        register_def: rd,
                                        memory_def: (
                                            mem_def.block_id,
                                            mem_def.inst_index,
                                            mem_def.variable.clone(),
                                            mem_ssa
                                                .variable_versions
                                                .get(&mem_def.variable)
                                                .copied()
                                                .unwrap_or(0),
                                        ),
                                    });
                                }
                                break;
                            }
                        }
                    }
                }

                // Alias classification: compare this def's variable with all uses
                for mem_use in &mem_ssa.uses {
                    alias_pairs += 1;
                    match classify_alias(&mem_def.variable, &mem_use.variable) {
                        AliasClass::MustAlias => must_alias += 1,
                        AliasClass::MayAlias => may_alias += 1,
                        AliasClass::NoAlias => no_alias += 1,
                        AliasClass::Unknown => {}
                    }
                }
            }

            // Bridge 2: MemoryUse 鈫?RegisterDef (Load's destination register)
            for mem_use in &mem_ssa.uses {
                let key = (mem_use.block_id, mem_use.inst_index);
                let ssa_inst = match ssa_inst_lookup.get(&key) {
                    Some(i) => *i,
                    None => continue,
                };

                // Find the destination register operand (access=Write) matching mem_use.destination_register
                if let Some(dest_reg) = &mem_use.destination_register {
                    for op in ssa_inst.operands.iter() {
                        if let SSAOperand::Variable { name, version } = op {
                            if name == dest_reg {
                                // This register definition gets its value from memory
                                // Trace the memory use to its memory def
                                let mem_def_ref = mem_ssa
                                    .use_def_chains
                                    .get(&(
                                        mem_use.block_id,
                                        mem_use.inst_index,
                                        mem_use.operand_index,
                                    ))
                                    .map(|(db, di, v)| (*db, *di, mem_use.variable.clone(), *v));

                                memory_to_register.push(MemoryToRegisterEdge {
                                    memory_use: (
                                        mem_use.block_id,
                                        mem_use.inst_index,
                                        mem_use.variable.clone(),
                                        mem_ssa
                                            .variable_versions
                                            .get(&mem_use.variable)
                                            .copied()
                                            .unwrap_or(0),
                                    ),
                                    memory_def: mem_def_ref.unwrap_or((
                                        usize::MAX,
                                        usize::MAX,
                                        mem_use.variable.clone(),
                                        0,
                                    )),
                                    register_def: RegisterDefRef {
                                        block_id: mem_use.block_id,
                                        inst_index: mem_use.inst_index,
                                        register: name.clone(),
                                        version: *version,
                                    },
                                });
                                break;
                            }
                        }
                    }
                }
            } // end for mem_use
        } // end if let Some(mem_ssa)

        // === 4.4.4 Function Pointer Propagation ===
        let function_pointer_candidates = Self::propagate_function_pointers(
            ir_func,
            reg_ssa,
            &register_to_memory,
            &memory_to_register,
            &ssa_inst_lookup,
            &ir_inst_lookup,
        );

        let mut evidence = Vec::new();
        evidence.push(
            Evidence::new(EvidenceKind::DataFlowAnalysis)
                .with_weight(0.88)
                .with_detail(format!(
                    "CrossDomainValueFlow: {} reg鈫抦em edges, {} mem鈫抮eg edges, {} FP candidates",
                    register_to_memory.len(),
                    memory_to_register.len(),
                    function_pointer_candidates.len()
                )),
        );

        Self {
            register_to_memory,
            memory_to_register,
            function_pointer_candidates,
            alias_pairs_checked: alias_pairs,
            must_alias_count: must_alias,
            may_alias_count: may_alias,
            no_alias_count: no_alias,
            evidence,
        }
    }

    /// Propagate function pointers through value flow to resolve indirect calls.
    ///
    /// Minimal chain: LEA reg, [func_addr] 鈫?Store [mem], reg 鈫?Load reg2, [mem] 鈫?call reg2
    /// Also handles: LEA reg, [func_addr] 鈫?call reg (direct)
    #[allow(clippy::too_many_arguments)]
    fn propagate_function_pointers(
        ir_func: &IRFunction,
        reg_ssa: &SSAFunction,
        reg_to_mem: &[RegisterToMemoryEdge],
        mem_to_reg: &[MemoryToRegisterEdge],
        ssa_inst_lookup: &HashMap<(usize, usize), &crate::ssa::SSAInstruction>,
        ir_inst_lookup: &HashMap<(usize, usize), &fox_ir::IRInstruction>,
    ) -> Vec<FunctionPointerCandidate> {
        let mut candidates = Vec::new();

        // Find all indirect calls: IROp::Call with register target
        for block in &ir_func.basic_blocks {
            for (inst_idx, inst) in block.instructions.iter().enumerate() {
                if inst.op != IROp::Call {
                    continue;
                }

                // Check if call target is a register (indirect call)
                let call_reg = inst.operands.iter().find_map(|op| match op {
                    IROperand::Register {
                        name,
                        access: OperandAccess::Read,
                        ..
                    } => Some(name.clone()),
                    _ => None,
                });

                let call_reg = match call_reg {
                    Some(r) => r,
                    None => continue, // direct call, not indirect
                };
                let call_reg_clone = call_reg.clone();

                // Try to resolve via value flow
                let resolved = Self::resolve_indirect_call(
                    block.id,
                    inst_idx,
                    &call_reg,
                    reg_ssa,
                    reg_to_mem,
                    mem_to_reg,
                    ssa_inst_lookup,
                    ir_inst_lookup,
                );

                match resolved {
                    Some((addr, kind, confidence, evidence_str)) => {
                        candidates.push(FunctionPointerCandidate {
                            call_block: block.id,
                            call_inst: inst_idx,
                            call_register: call_reg_clone,
                            target_address: Some(addr),
                            confidence,
                            evidence: evidence_str,
                            resolution_kind: kind,
                        });
                    }
                    None => {
                        candidates.push(FunctionPointerCandidate {
                            call_block: block.id,
                            call_inst: inst_idx,
                            call_register: call_reg,
                            target_address: None,
                            confidence: 0.0,
                            evidence: format!(
                                "Indirect call at block {} inst {}: could not resolve via value flow",
                                block.id, inst_idx
                            ),
                            resolution_kind: ResolutionKind::Unresolved,
                        });
                    }
                }
            }
        }

        candidates
    }

    /// Resolve a single indirect call through value flow chains.
    #[allow(clippy::too_many_arguments)]
    fn resolve_indirect_call(
        call_block: usize,
        call_inst: usize,
        call_reg: &str,
        reg_ssa: &SSAFunction,
        reg_to_mem: &[RegisterToMemoryEdge],
        mem_to_reg: &[MemoryToRegisterEdge],
        ssa_inst_lookup: &HashMap<(usize, usize), &crate::ssa::SSAInstruction>,
        ir_inst_lookup: &HashMap<(usize, usize), &fox_ir::IRInstruction>,
    ) -> Option<(u64, ResolutionKind, f64, String)> {
        // Step 1: Find the register use at the call instruction
        let call_key = (call_block, call_inst);
        let ssa_inst = ssa_inst_lookup.get(&call_key)?;

        let call_op_idx = ssa_inst.operands.iter().position(|op| match op {
            SSAOperand::Variable { name, .. } => name == call_reg,
            _ => false,
        })?;

        // Step 2: Trace call register to its definition via Register SSA use-def
        let (def_block, def_inst, _version) =
            reg_ssa
                .use_def_chains
                .get(&(call_block, call_inst, call_op_idx))?;

        if *def_block == usize::MAX {
            return None; // undefined
        }

        // Step 3: Check what instruction defines the register
        let def_ir = ir_inst_lookup.get(&(*def_block, *def_inst))?;

        match def_ir.op {
            // Case A: LEA reg, [addr] 鈥?direct function address load
            IROp::Lea => {
                // Find the memory operand with effective_address
                for op in &def_ir.operands {
                    if let IROperand::Memory {
                        effective_address: Some(addr),
                        ..
                    } = op
                    {
                        return Some((
                            *addr,
                            ResolutionKind::LeaDirect,
                            0.95,
                            format!(
                                "LEA {} at {:#x} loads address {:#x}",
                                call_reg, def_ir.address.0, addr
                            ),
                        ));
                    }
                }
                None
            }
            // Case B: MOV reg, [mem] 鈥?value came from memory, trace through Memory SSA
            IROp::Mov | IROp::Load => {
                // Find the memory_to_register edge for this definition
                let m2r = mem_to_reg.iter().find(|e| {
                    e.register_def.block_id == *def_block
                        && e.register_def.inst_index == *def_inst
                        && e.register_def.register == call_reg
                })?;

                // Get the memory def that this use traces to
                let (md_block, md_inst, md_var, _md_ver) = m2r.memory_def.clone();
                if md_block == usize::MAX {
                    return None;
                }

                // Find the register_to_memory edge for this memory def
                let r2m = reg_to_mem.iter().find(|e| {
                    e.memory_def.0 == md_block
                        && e.memory_def.1 == md_inst
                        && e.memory_def.2 == md_var
                })?;

                // Trace the source register to its definition
                let src_def_block = r2m.register_def.block_id;
                let src_def_inst = r2m.register_def.inst_index;
                let src_def_reg = &r2m.register_def.register;

                // Check if source definition is LEA
                let src_ir = ir_inst_lookup.get(&(src_def_block, src_def_inst))?;
                if src_ir.op == IROp::Lea {
                    for op in &src_ir.operands {
                        if let IROperand::Memory {
                            effective_address: Some(addr),
                            ..
                        } = op
                        {
                            return Some((
                                *addr,
                                ResolutionKind::LeaStoreLoadChain,
                                0.85,
                                format!(
                                    "LEA {} at {:#x} 鈫?Store [{:?}] 鈫?Load {} 鈫?call {} (chain resolution)",
                                    src_def_reg, src_ir.address.0, md_var, call_reg, call_reg
                                ),
                            ));
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Trace a value from a register use back through cross-domain flow.
    /// Returns a human-readable chain description.
    pub fn trace_register_value(
        &self,
        block_id: usize,
        inst_index: usize,
        register: &str,
    ) -> Option<String> {
        // Find memory_to_register edge where this register is defined from memory
        let m2r = self.memory_to_register.iter().find(|e| {
            e.register_def.block_id == block_id
                && e.register_def.inst_index == inst_index
                && e.register_def.register == register
        })?;

        let (md_block, md_inst, md_var, _) = m2r.memory_def.clone();
        if md_block == usize::MAX {
            return Some(format!(
                "{} 鈫?memory[{:?}] (undefined)",
                register, m2r.memory_use.2
            ));
        }

        // Find register_to_memory edge for the source
        let r2m = self.register_to_memory.iter().find(|e| {
            e.memory_def.0 == md_block && e.memory_def.1 == md_inst && e.memory_def.2 == md_var
        })?;

        Some(format!(
            "{} 鈫?memory[{:?}] 鈫?{} (def at block {} inst {})",
            register,
            md_var,
            r2m.register_def.register,
            r2m.register_def.block_id,
            r2m.register_def.inst_index
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use fox_core::Address;
    use fox_ir::memory::{MemoryAnalysis, MemoryLocation, MemoryOperation, MemoryOperationKind};
    use fox_ir::{IRBasicBlock, IRFunction, IRInstruction, IROp, IROperand, OperandAccess};

    // Helper builders
    fn reg(name: &str, access: OperandAccess) -> IROperand {
        IROperand::Register {
            name: name.into(),
            width: 64,
            access,
        }
    }

    fn mem_operand(access: OperandAccess) -> IROperand {
        IROperand::Memory {
            base: Some("RSP".into()),
            index: None,
            scale: 1,
            displacement: 8,
            size: 8,
            access,
            is_rip_relative: false,
            effective_address: None,
        }
    }

    fn lea_operand(addr: u64) -> IROperand {
        IROperand::Memory {
            base: Some("RIP".into()),
            index: None,
            scale: 1,
            displacement: 0,
            size: 8,
            access: OperandAccess::Read,
            is_rip_relative: true,
            effective_address: Some(addr),
        }
    }

    fn mk_inst(addr: u64, op: IROp, operands: Vec<IROperand>) -> IRInstruction {
        IRInstruction {
            address: Address(addr),
            op,
            operands,
            original_mnemonic: None,
            original_operands: None,
            size: 0,
            reads_registers: vec![],
            writes_registers: vec![],
            implicit_reads: vec![],
            implicit_writes: vec![],
            reads_flags: false,
            writes_flags: false,
        }
    }

    fn stack_loc(disp: i64) -> MemoryLocation {
        MemoryLocation::Stack {
            base_register: "RSP".into(),
            displacement: disp,
            size: 64,
        }
    }

    fn mem_op(
        addr: u64,
        kind: MemoryOperationKind,
        loc: MemoryLocation,
        dest: Option<&str>,
        src: Option<&str>,
    ) -> MemoryOperation {
        MemoryOperation {
            instruction_address: addr,
            kind,
            location: loc,
            destination_register: dest.map(String::from),
            source_register: src.map(String::from),
            evidence_detail: format!("test op {:#x}", addr),
        }
    }

    // Test 1: Alias classification 鈥?same stack slot = MustAlias
    #[test]
    fn test_alias_must_alias_same_stack() {
        let a = MemoryVariable::Stack {
            base: "RSP".into(),
            displacement: 8,
        };
        let b = MemoryVariable::Stack {
            base: "RSP".into(),
            displacement: 8,
        };
        assert_eq!(classify_alias(&a, &b), AliasClass::MustAlias);
    }

    // Test 2: Alias classification 鈥?different stack slots = NoAlias (far apart)
    // Test 2: Alias classification — different stack slots = MayAlias (conservative, cannot prove non-overlap)
    #[test]
    fn test_alias_different_stack_conservative() {
        let a = MemoryVariable::Stack {
            base: "RSP".into(),
            displacement: 8,
        };
        let b = MemoryVariable::Stack {
            base: "RSP".into(),
            displacement: 512,
        };
        assert_eq!(classify_alias(&a, &b), AliasClass::MayAlias);
    }

    // Test 3: Alias classification 鈥?heap = MayAlias
    #[test]
    fn test_alias_heap_may_alias() {
        assert_eq!(
            classify_alias(&MemoryVariable::Heap, &MemoryVariable::Heap),
            AliasClass::MayAlias
        );
    }

    // Test 4: Alias classification 鈥?stack vs heap = NoAlias
    #[test]
    fn test_alias_stack_vs_heap() {
        let a = MemoryVariable::Stack {
            base: "RSP".into(),
            displacement: 8,
        };
        assert_eq!(
            classify_alias(&a, &MemoryVariable::Heap),
            AliasClass::NoAlias
        );
    }

    // Test 5: Cross-domain bridge 鈥?Store then Load creates both edges
    #[test]
    fn test_cross_domain_bridge_store_load() {
        // b0: mov rax, 42 ; mov [rsp+8], rax ; mov rcx, [rsp+8]
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1020),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![
                        reg("RAX", OperandAccess::Write),
                        IROperand::Immediate {
                            value: 42,
                            width: 64,
                            is_signed: false,
                        },
                    ],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![
                        mem_operand(OperandAccess::Write),
                        reg("RAX", OperandAccess::Read),
                    ],
                ),
                mk_inst(
                    0x100a,
                    IROp::Mov,
                    vec![
                        reg("RCX", OperandAccess::Write),
                        mem_operand(OperandAccess::Read),
                    ],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            stack_loc(8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x100a,
            MemoryOperationKind::Load,
            stack_loc(8),
            Some("RCX"),
            None,
        ));

        let reg_ssa = crate::ssa::SSAConstructor::construct_proper(&ir);
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem).unwrap();
        let vf = CrossDomainValueFlow::build(&ir, &reg_ssa, Some(&mem_ssa));

        // Should have 1 register鈫抦emory edge (Store source RAX)
        assert_eq!(
            vf.register_to_memory.len(),
            1,
            "should have 1 reg鈫抦em edge, got {}",
            vf.register_to_memory.len()
        );
        assert_eq!(vf.register_to_memory[0].register_def.register, "RAX");

        // Should have 1 memory鈫抮egister edge (Load dest RCX)
        assert_eq!(
            vf.memory_to_register.len(),
            1,
            "should have 1 mem鈫抮eg edge, got {}",
            vf.memory_to_register.len()
        );
        assert_eq!(vf.memory_to_register[0].register_def.register, "RCX");
    }

    // Test 6: trace_register_value follows cross-domain chain
    #[test]
    fn test_trace_register_value_cross_domain() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1020),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![
                        reg("RAX", OperandAccess::Write),
                        IROperand::Immediate {
                            value: 42,
                            width: 64,
                            is_signed: false,
                        },
                    ],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![
                        mem_operand(OperandAccess::Write),
                        reg("RAX", OperandAccess::Read),
                    ],
                ),
                mk_inst(
                    0x100a,
                    IROp::Mov,
                    vec![
                        reg("RCX", OperandAccess::Write),
                        mem_operand(OperandAccess::Read),
                    ],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            stack_loc(8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x100a,
            MemoryOperationKind::Load,
            stack_loc(8),
            Some("RCX"),
            None,
        ));

        let reg_ssa = crate::ssa::SSAConstructor::construct_proper(&ir);
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem).unwrap();
        let vf = CrossDomainValueFlow::build(&ir, &reg_ssa, Some(&mem_ssa));

        // RCX at inst 2 should trace to memory 鈫?RAX
        let trace = vf.trace_register_value(0, 2, "RCX");
        assert!(trace.is_some(), "should have trace for RCX");
        let trace = trace.unwrap();
        assert!(trace.contains("RCX"), "trace should mention RCX");
        assert!(trace.contains("RAX"), "trace should mention RAX (source)");
    }

    // Test 7: Function pointer 鈥?LEA direct 鈫?call
    #[test]
    fn test_function_pointer_lea_direct() {
        // b0: lea rax, [0x401000] ; call rax
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Lea,
                    vec![reg("RAX", OperandAccess::Write), lea_operand(0x401000)],
                ),
                mk_inst(0x1005, IROp::Call, vec![reg("RAX", OperandAccess::Read)]),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };

        let mem = MemoryAnalysis::new();
        let reg_ssa = crate::ssa::SSAConstructor::construct_proper(&ir);
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem);
        let vf = CrossDomainValueFlow::build(&ir, &reg_ssa, mem_ssa.as_ref());

        // Should have 1 candidate for the indirect call
        assert_eq!(vf.function_pointer_candidates.len(), 1);
        let cand = &vf.function_pointer_candidates[0];
        assert_eq!(cand.target_address, Some(0x401000));
        assert_eq!(cand.resolution_kind, ResolutionKind::LeaDirect);
    }

    // Test 8: Function pointer 鈥?LEA 鈫?Store 鈫?Load 鈫?call chain
    #[test]
    fn test_function_pointer_lea_store_load_chain() {
        // b0: lea rax, [0x402000] ; mov [rsp+10h], rax ; mov rcx, [rsp+10h] ; call rcx
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1020),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Lea,
                    vec![reg("RAX", OperandAccess::Write), lea_operand(0x402000)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![
                        IROperand::Memory {
                            base: Some("RSP".into()),
                            index: None,
                            scale: 1,
                            displacement: 16,
                            size: 8,
                            access: OperandAccess::Write,
                            is_rip_relative: false,
                            effective_address: None,
                        },
                        reg("RAX", OperandAccess::Read),
                    ],
                ),
                mk_inst(
                    0x100a,
                    IROp::Mov,
                    vec![
                        reg("RCX", OperandAccess::Write),
                        IROperand::Memory {
                            base: Some("RSP".into()),
                            index: None,
                            scale: 1,
                            displacement: 16,
                            size: 8,
                            access: OperandAccess::Read,
                            is_rip_relative: false,
                            effective_address: None,
                        },
                    ],
                ),
                mk_inst(0x100f, IROp::Call, vec![reg("RCX", OperandAccess::Read)]),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            stack_loc(16),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x100a,
            MemoryOperationKind::Load,
            stack_loc(16),
            Some("RCX"),
            None,
        ));

        let reg_ssa = crate::ssa::SSAConstructor::construct_proper(&ir);
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem).unwrap();
        let vf = CrossDomainValueFlow::build(&ir, &reg_ssa, Some(&mem_ssa));

        // Should resolve the indirect call via chain
        assert!(
            !vf.function_pointer_candidates.is_empty(),
            "should have FP candidate"
        );
        let cand = &vf.function_pointer_candidates[0];
        assert_eq!(
            cand.target_address,
            Some(0x402000),
            "should resolve to 0x402000 via LEA鈫扴tore鈫扡oad chain"
        );
        assert_eq!(cand.resolution_kind, ResolutionKind::LeaStoreLoadChain);
    }

    // Test 9: Unresolved indirect call stays Unresolved
    #[test]
    fn test_unresolved_indirect_call() {
        // b0: call rax (rax has no visible definition in this function)
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![mk_inst(
                0x1000,
                IROp::Call,
                vec![reg("RAX", OperandAccess::Read)],
            )],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };

        let mem = MemoryAnalysis::new();
        let reg_ssa = crate::ssa::SSAConstructor::construct_proper(&ir);
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem);
        let vf = CrossDomainValueFlow::build(&ir, &reg_ssa, mem_ssa.as_ref());

        assert_eq!(vf.function_pointer_candidates.len(), 1);
        assert_eq!(
            vf.function_pointer_candidates[0].resolution_kind,
            ResolutionKind::Unresolved
        );
        assert_eq!(vf.function_pointer_candidates[0].target_address, None);
    }

    // Test 10: No memory operations 鈫?empty cross-domain edges
    #[test]
    fn test_no_memory_operations_empty_edges() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![mk_inst(
                0x1000,
                IROp::Mov,
                vec![
                    reg("RAX", OperandAccess::Write),
                    reg("RBX", OperandAccess::Read),
                ],
            )],
            successors: vec![],
            predecessors: vec![],
        };
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![b0],
        };
        let mem = MemoryAnalysis::new();
        let mem_ssa = crate::memory_ssa::MemorySSAConstructor::construct(&ir, &mem);
        assert!(mem_ssa.is_none());
    }
}
