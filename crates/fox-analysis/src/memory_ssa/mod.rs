//! FOX Memory SSA Construction (P0-4.3)
//!
//! Builds Memory SSA on top of P0-4.2 MemoryAnalysis semantics.
//!
//! Core principle: every MemoryUse must trace to a specific MemoryDef
//! (block, instruction, version). Version numbers alone are NOT sufficient.
//!
//! Memory variable identity:
//! - Stack { base, disp }  → exact identity
//! - Global { address }    → exact identity
//! - Heap                  → conservative (all heap = one variable)
//! - Unknown               → conservative (all unknown = one variable)
//!
//! Reuses existing DominatorTree and phi-placement algorithm from Register SSA.
//! Does NOT implement alias analysis — Heap/Unknown are intentionally conservative.

#![allow(clippy::type_complexity)]

use fox_core::{Evidence, EvidenceKind};
use fox_ir::memory::{MemoryAnalysis, MemoryLocation, MemoryOperationKind};
use fox_ir::IRFunction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::dominators::DominatorTree;

// ============================================================================
// Memory Variable Identity
// ============================================================================

/// A memory variable identity — the "variable" being versioned in Memory SSA.
///
/// Two memory operations reference the same MemoryVariable if they MAY alias.
/// Stack and Global have exact identity; Heap and Unknown are conservative.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryVariable {
    /// Stack slot: base register + displacement (exact identity)
    Stack { base: String, displacement: i64 },
    /// Global variable: exact address (exact identity)
    Global { address: u64 },
    /// Heap: conservative — all heap accesses may alias (single variable)
    Heap,
    /// Unknown: conservative — may alias with anything (single variable)
    Unknown,
}

impl MemoryVariable {
    /// Build a MemoryVariable from a MemoryLocation.
    pub fn from_location(loc: &MemoryLocation) -> Self {
        match loc {
            MemoryLocation::Stack {
                base_register,
                displacement,
                ..
            } => MemoryVariable::Stack {
                base: base_register.clone(),
                displacement: *displacement,
            },
            MemoryLocation::Global { address, .. } => MemoryVariable::Global { address: *address },
            MemoryLocation::Heap { .. } => MemoryVariable::Heap,
            MemoryLocation::Unknown { .. } => MemoryVariable::Unknown,
        }
    }

    /// Human-readable name for evidence / debugging.
    pub fn name(&self) -> String {
        match self {
            MemoryVariable::Stack { base, displacement } => {
                format!("stack[{}+{:#x}]", base, displacement)
            }
            MemoryVariable::Global { address } => format!("global[{:#x}]", address),
            MemoryVariable::Heap => "heap".to_string(),
            MemoryVariable::Unknown => "unknown_mem".to_string(),
        }
    }
}

// ============================================================================
// Memory Definition / Use
// ============================================================================

/// A memory definition (Store or ReadWrite operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDef {
    pub block_id: usize,
    pub inst_index: usize,
    pub address: u64,
    pub variable: MemoryVariable,
    pub kind: MemoryOperationKind,
    pub source_register: Option<String>,
    pub evidence: String,
}

/// A memory use (Load or ReadWrite operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUse {
    pub block_id: usize,
    pub inst_index: usize,
    pub operand_index: usize,
    pub address: u64,
    pub variable: MemoryVariable,
    pub kind: MemoryOperationKind,
    pub destination_register: Option<String>,
    pub evidence: String,
}

/// A Memory Phi node at a join point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPhiNode {
    pub block_id: usize,
    pub variable: MemoryVariable,
    /// Incoming: (predecessor_block_id, memory_version)
    pub incoming: Vec<(usize, u32)>,
    pub result_version: u32,
}

// ============================================================================
// Memory SSA Function
// ============================================================================

/// Memory SSA form of a function.
///
/// Coexists with Register SSA (SSAFunction) — does not replace it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySSAFunction {
    pub name: String,
    pub address: u64,
    /// All memory variables discovered in this function
    pub memory_variables: Vec<MemoryVariable>,
    /// Memory phi nodes placed at dominance frontiers
    pub phi_nodes: Vec<MemoryPhiNode>,
    /// Max version per memory variable
    pub variable_versions: HashMap<MemoryVariable, u32>,
    /// Memory definitions (Store/ReadWrite)
    pub definitions: Vec<MemoryDef>,
    /// Memory uses (Load/ReadWrite)
    pub uses: Vec<MemoryUse>,
    /// Use-def chain: (block_id, inst_index, operand_index) -> (def_block, def_inst, version)
    /// operand_index = usize::MAX for phi uses
    pub use_def_chains: HashMap<(usize, usize, usize), (usize, usize, u32)>,
    /// Def-use chain: (block_id, inst_index) -> Vec<(use_block, use_inst, operand_idx)>
    pub def_use_chains: HashMap<(usize, usize), Vec<(usize, usize, usize)>>,
    /// Evidence
    pub evidence: Vec<Evidence>,
}

// ============================================================================
// Constructor
// ============================================================================

/// Memory SSA constructor.
pub struct MemorySSAConstructor;

impl MemorySSAConstructor {
    /// Construct Memory SSA from an IR function and its MemoryAnalysis.
    ///
    /// Returns None if there are no memory operations (nothing to version).
    pub fn construct(
        ir_func: &IRFunction,
        mem_analysis: &MemoryAnalysis,
    ) -> Option<MemorySSAFunction> {
        if mem_analysis.operations.is_empty() {
            return None;
        }

        // Step 1: Map each MemoryOperation to (block_id, inst_index) by address
        let op_locations = Self::map_operations_to_blocks(ir_func, mem_analysis);

        // Step 2: Build MemoryVariables and separate defs/uses
        let mut variables: HashSet<MemoryVariable> = HashSet::new();
        let mut defs: Vec<MemoryDef> = Vec::new();
        let mut uses: Vec<MemoryUse> = Vec::new();

        for (op, &(block_id, inst_index)) in mem_analysis.operations.iter().zip(op_locations.iter())
        {
            let variable = MemoryVariable::from_location(&op.location);
            variables.insert(variable.clone());

            match op.kind {
                MemoryOperationKind::Store => {
                    defs.push(MemoryDef {
                        block_id,
                        inst_index,
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        source_register: op.source_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                }
                MemoryOperationKind::Load => {
                    uses.push(MemoryUse {
                        block_id,
                        inst_index,
                        operand_index: 0, // memory operand index (approximation)
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        destination_register: op.destination_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                }
                MemoryOperationKind::ReadWrite => {
                    // ReadWrite is both a def (result→memory) and a use (read memory)
                    defs.push(MemoryDef {
                        block_id,
                        inst_index,
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        source_register: op.source_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                    uses.push(MemoryUse {
                        block_id,
                        inst_index,
                        operand_index: 0,
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        destination_register: op.destination_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                }
                MemoryOperationKind::Unknown => {
                    // Unknown operations: treat as both def and use conservatively
                    defs.push(MemoryDef {
                        block_id,
                        inst_index,
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        source_register: op.source_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                    uses.push(MemoryUse {
                        block_id,
                        inst_index,
                        operand_index: 0,
                        address: op.instruction_address,
                        variable: variable.clone(),
                        kind: op.kind,
                        destination_register: op.destination_register.clone(),
                        evidence: op.evidence_detail.clone(),
                    });
                }
            }
        }

        if variables.is_empty() {
            return None;
        }

        // Step 3: Collect definition blocks per variable
        let mut def_blocks: HashMap<MemoryVariable, HashSet<usize>> = HashMap::new();
        for def in &defs {
            def_blocks
                .entry(def.variable.clone())
                .or_default()
                .insert(def.block_id);
        }

        // Step 4: Compute DominatorTree (reuse existing)
        let mut succ_map: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut pred_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for block in &ir_func.basic_blocks {
            succ_map.insert(block.id, block.successors.clone());
            pred_map.insert(block.id, block.predecessors.clone());
        }
        let dom_tree = DominatorTree::compute(
            &succ_map,
            &pred_map,
            ir_func.entry_block,
            ir_func.basic_blocks.len(),
        );

        // Step 5: Phi placement (iterative dominance frontier)
        let mut phi_placement: HashMap<usize, HashSet<MemoryVariable>> = HashMap::new();
        for (var, defs_set) in &def_blocks {
            let mut worklist: Vec<usize> = defs_set.iter().cloned().collect();
            let mut has_phi: HashSet<usize> = HashSet::new();
            while let Some(block) = worklist.pop() {
                for &frontier_block in dom_tree.frontier(block) {
                    if !has_phi.contains(&frontier_block) {
                        has_phi.insert(frontier_block);
                        phi_placement
                            .entry(frontier_block)
                            .or_default()
                            .insert(var.clone());
                        if !defs_set.contains(&frontier_block) {
                            worklist.push(frontier_block);
                        }
                    }
                }
            }
        }

        // Step 6: Dominator-tree DFS renaming with version stacks
        let mut version_counter: HashMap<MemoryVariable, u32> = HashMap::new();
        let mut version_stack: HashMap<MemoryVariable, Vec<u32>> = HashMap::new();
        // version_def: (var, version) -> (block_id, inst_idx) where inst_idx=usize::MAX means phi
        let mut version_def: HashMap<(MemoryVariable, u32), (usize, usize)> = HashMap::new();
        let mut all_phi_nodes: Vec<MemoryPhiNode> = Vec::new();
        let mut use_def: HashMap<(usize, usize, usize), (usize, usize, u32)> = HashMap::new();
        let mut def_use: HashMap<(usize, usize), Vec<(usize, usize, usize)>> = HashMap::new();
        let mut block_exit_versions: HashMap<usize, HashMap<MemoryVariable, u32>> = HashMap::new();

        // Build a lookup: (block_id, inst_index) -> MemoryDef
        let def_lookup: HashMap<(usize, usize), &MemoryDef> = defs
            .iter()
            .map(|d| ((d.block_id, d.inst_index), d))
            .collect();
        // Build a lookup: (block_id, inst_index) -> Vec<&MemoryUse>
        let mut use_lookup: HashMap<(usize, usize), Vec<&MemoryUse>> = HashMap::new();
        for u in &uses {
            use_lookup
                .entry((u.block_id, u.inst_index))
                .or_default()
                .push(u);
        }

        Self::rename_block_dfs(
            ir_func.entry_block,
            ir_func,
            &phi_placement,
            &dom_tree,
            &def_lookup,
            &use_lookup,
            &mut version_counter,
            &mut version_stack,
            &mut version_def,
            &mut all_phi_nodes,
            &mut use_def,
            &mut def_use,
            &mut block_exit_versions,
        );

        // Step 7: Fill phi incoming edges
        for phi in &mut all_phi_nodes {
            let preds = pred_map.get(&phi.block_id).cloned().unwrap_or_default();
            let mut incoming = Vec::new();
            for pred in preds {
                if let Some(exit_vers) = block_exit_versions.get(&pred) {
                    if let Some(ver) = exit_vers.get(&phi.variable) {
                        incoming.push((pred, *ver));
                    } else {
                        incoming.push((pred, 0)); // undefined -> version 0
                    }
                } else {
                    incoming.push((pred, 0));
                }
            }
            phi.incoming = incoming;
        }

        // Build evidence
        let mut evidence = Vec::new();
        evidence.push(
            Evidence::new(EvidenceKind::DataFlowAnalysis)
                .with_weight(0.9)
                .with_detail(format!(
                    "Memory SSA: {} variables, {} phi nodes, {} defs, {} uses",
                    variables.len(),
                    all_phi_nodes.len(),
                    defs.len(),
                    uses.len()
                )),
        );

        Some(MemorySSAFunction {
            name: ir_func.name.clone(),
            address: ir_func.address.0,
            memory_variables: variables.into_iter().collect(),
            phi_nodes: all_phi_nodes,
            variable_versions: version_counter,
            definitions: defs,
            uses,
            use_def_chains: use_def,
            def_use_chains: def_use,
            evidence,
        })
    }

    /// Map each MemoryOperation to its (block_id, inst_index) by instruction address.
    fn map_operations_to_blocks(
        ir_func: &IRFunction,
        mem_analysis: &MemoryAnalysis,
    ) -> Vec<(usize, usize)> {
        // Build address -> (block_id, inst_index) lookup
        let mut addr_lookup: HashMap<u64, (usize, usize)> = HashMap::new();
        for block in &ir_func.basic_blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                addr_lookup.insert(inst.address.0, (block.id, idx));
            }
        }

        mem_analysis
            .operations
            .iter()
            .map(|op| {
                addr_lookup
                    .get(&op.instruction_address)
                    .copied()
                    .unwrap_or((usize::MAX, usize::MAX))
            })
            .collect()
    }

    /// Recursive DFS renaming on dominator tree for memory variables.
    #[allow(clippy::too_many_arguments)]
    fn rename_block_dfs(
        block_id: usize,
        ir_func: &IRFunction,
        phi_placement: &HashMap<usize, HashSet<MemoryVariable>>,
        dom_tree: &DominatorTree,
        def_lookup: &HashMap<(usize, usize), &MemoryDef>,
        use_lookup: &HashMap<(usize, usize), Vec<&MemoryUse>>,
        version_counter: &mut HashMap<MemoryVariable, u32>,
        version_stack: &mut HashMap<MemoryVariable, Vec<u32>>,
        version_def: &mut HashMap<(MemoryVariable, u32), (usize, usize)>,
        all_phi_nodes: &mut Vec<MemoryPhiNode>,
        use_def: &mut HashMap<(usize, usize, usize), (usize, usize, u32)>,
        def_use: &mut HashMap<(usize, usize), Vec<(usize, usize, usize)>>,
        block_exit_versions: &mut HashMap<usize, HashMap<MemoryVariable, u32>>,
    ) {
        let block = match ir_func.basic_blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => return,
        };

        let mut pushed_versions: Vec<MemoryVariable> = Vec::new();

        // Process phi nodes at block entry (they define new versions)
        if let Some(phi_vars) = phi_placement.get(&block_id) {
            for var in phi_vars {
                let new_ver = Self::push_version(var, version_counter, version_stack);
                pushed_versions.push(var.clone());
                version_def.insert((var.clone(), new_ver), (block_id, usize::MAX));
                let phi = MemoryPhiNode {
                    block_id,
                    variable: var.clone(),
                    incoming: Vec::new(), // filled later
                    result_version: new_ver,
                };
                all_phi_nodes.push(phi);
                def_use.entry((block_id, usize::MAX)).or_default();
            }
        }

        // Process instructions in order
        for (inst_idx, _inst) in block.instructions.iter().enumerate() {
            let key = (block_id, inst_idx);

            // Process memory uses first (read before write in same instruction for RMW)
            if let Some(inst_uses) = use_lookup.get(&key) {
                for u in inst_uses {
                    let cur_ver = version_stack
                        .get(&u.variable)
                        .and_then(|s| s.last().copied())
                        .unwrap_or(0);
                    // Record use-def: trace to exact definition
                    if let Some(&(def_block, def_inst)) =
                        version_def.get(&(u.variable.clone(), cur_ver))
                    {
                        use_def.insert(
                            (block_id, inst_idx, u.operand_index),
                            (def_block, def_inst, cur_ver),
                        );
                        def_use.entry((def_block, def_inst)).or_default().push((
                            block_id,
                            inst_idx,
                            u.operand_index,
                        ));
                    } else {
                        use_def.insert(
                            (block_id, inst_idx, u.operand_index),
                            (usize::MAX, usize::MAX, cur_ver),
                        );
                    }
                }
            }

            // Process memory definitions (Store/ReadWrite)
            if let Some(def) = def_lookup.get(&key) {
                let new_ver = Self::push_version(&def.variable, version_counter, version_stack);
                pushed_versions.push(def.variable.clone());
                version_def.insert((def.variable.clone(), new_ver), (block_id, inst_idx));
                def_use.entry((block_id, inst_idx)).or_default();
            }
        }

        // Record exit versions for phi filling
        let mut exit_vers = HashMap::new();
        for (var, stack) in version_stack.iter() {
            if let Some(&top) = stack.last() {
                exit_vers.insert(var.clone(), top);
            }
        }
        block_exit_versions.insert(block_id, exit_vers);

        // Recurse into dominator children
        for &child in dom_tree.children(block_id) {
            Self::rename_block_dfs(
                child,
                ir_func,
                phi_placement,
                dom_tree,
                def_lookup,
                use_lookup,
                version_counter,
                version_stack,
                version_def,
                all_phi_nodes,
                use_def,
                def_use,
                block_exit_versions,
            );
        }

        // Pop versions pushed in this block
        for var in pushed_versions {
            if let Some(stack) = version_stack.get_mut(&var) {
                stack.pop();
            }
        }
    }

    /// Push a new version for a memory variable, return the new version number.
    fn push_version(
        var: &MemoryVariable,
        counter: &mut HashMap<MemoryVariable, u32>,
        stack: &mut HashMap<MemoryVariable, Vec<u32>>,
    ) -> u32 {
        let cur = counter.entry(var.clone()).or_insert(0);
        *cur += 1;
        let new_ver = *cur;
        stack.entry(var.clone()).or_default().push(new_ver);
        new_ver
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

    // Helper: build a simple IR function with memory operations
    fn make_ir_with_mem(blocks: Vec<IRBasicBlock>) -> (IRFunction, MemoryAnalysis) {
        let ir = IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: blocks,
        };
        let mem = MemoryAnalysis::new();
        (ir, mem)
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
            evidence_detail: format!("test op at {:#x}", addr),
        }
    }

    fn stack_loc(base: &str, disp: i64) -> MemoryLocation {
        MemoryLocation::Stack {
            base_register: base.into(),
            displacement: disp,
            size: 64,
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

    fn reg(name: &str, access: OperandAccess) -> IROperand {
        IROperand::Register {
            name: name.into(),
            width: 64,
            access,
        }
    }

    fn mem_operand() -> IROperand {
        IROperand::Memory {
            base: Some("RSP".into()),
            index: None,
            scale: 1,
            displacement: 8,
            size: 64,
            access: OperandAccess::Read,
            is_rip_relative: false,
            effective_address: None,
        }
    }

    // Test 1: Linear store then load — use must trace to def
    #[test]
    fn test_linear_store_load_use_def() {
        // block 0: mov [rsp+8], rax (Store) ; mov rcx, [rsp+8] (Load)
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![reg("RCX", OperandAccess::Write), mem_operand()],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Load,
            stack_loc("RSP", 8),
            Some("RCX"),
            None,
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");

        // Should have 1 variable (stack[RSP+8])
        assert_eq!(mssa.memory_variables.len(), 1);
        // Should have 1 def, 1 use
        assert_eq!(mssa.definitions.len(), 1);
        assert_eq!(mssa.uses.len(), 1);
        // No phi (linear)
        assert!(mssa.phi_nodes.is_empty());

        // The use at (0, 1) must trace to the def at (0, 0)
        let use_key = (0usize, 1usize, 0usize);
        let def = mssa
            .use_def_chains
            .get(&use_key)
            .expect("use-def should exist");
        assert_eq!(def.0, 0, "def should be in block 0");
        assert_eq!(def.1, 0, "def should be instruction 0 (the Store)");
        assert_eq!(def.2, 1, "def version should be 1");

        // Def-use: the Store should list the Load as a use
        let def_key = (0usize, 0usize);
        let uses = mssa
            .def_use_chains
            .get(&def_key)
            .expect("def-use should exist");
        assert!(!uses.is_empty(), "Store def should have at least one use");
    }

    // Test 2: if-else with stores in both branches → Memory Phi at join
    #[test]
    fn test_if_else_memory_phi() {
        // b0: if cond -> b1, b2
        // b1: mov [rsp+8], rax (Store) -> b3
        // b2: mov [rsp+8], rbx (Store) -> b3
        // b3: mov rcx, [rsp+8] (Load)
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![mk_inst(0x1000, IROp::Jump, vec![])],
            successors: vec![1, 2],
            predecessors: vec![],
        };
        let b1 = IRBasicBlock {
            id: 1,
            start_address: Address(0x1010),
            end_address: Address(0x1018),
            instructions: vec![mk_inst(
                0x1010,
                IROp::Mov,
                vec![mem_operand(), reg("RAX", OperandAccess::Read)],
            )],
            successors: vec![3],
            predecessors: vec![0],
        };
        let b2 = IRBasicBlock {
            id: 2,
            start_address: Address(0x1020),
            end_address: Address(0x1028),
            instructions: vec![mk_inst(
                0x1020,
                IROp::Mov,
                vec![mem_operand(), reg("RBX", OperandAccess::Read)],
            )],
            successors: vec![3],
            predecessors: vec![0],
        };
        let b3 = IRBasicBlock {
            id: 3,
            start_address: Address(0x1030),
            end_address: Address(0x1038),
            instructions: vec![mk_inst(
                0x1030,
                IROp::Mov,
                vec![reg("RCX", OperandAccess::Write), mem_operand()],
            )],
            successors: vec![],
            predecessors: vec![1, 2],
        };
        let (ir, _) = make_ir_with_mem(vec![b0, b1, b2, b3]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1010,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1020,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RBX"),
        ));
        mem.add_operation(mem_op(
            0x1030,
            MemoryOperationKind::Load,
            stack_loc("RSP", 8),
            Some("RCX"),
            None,
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");

        // Block 3 should have a Memory Phi for stack[RSP+8]
        let phi_at_b3: Vec<_> = mssa.phi_nodes.iter().filter(|p| p.block_id == 3).collect();
        assert!(!phi_at_b3.is_empty(), "Block 3 should have a memory phi");
        assert_eq!(
            phi_at_b3[0].incoming.len(),
            2,
            "Phi should have 2 incoming (b1, b2)"
        );

        // The Load at b3 should trace to the phi (version from phi)
        let use_key = (3usize, 0usize, 0usize);
        let def = mssa
            .use_def_chains
            .get(&use_key)
            .expect("use-def should exist");
        assert_eq!(def.0, 3, "use should trace to phi in block 3");
        assert_eq!(def.1, usize::MAX, "phi def has inst_index=MAX");
    }

    // Test 3: Different stack slots are different variables
    #[test]
    fn test_different_stack_slots_separate_variables() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![mem_operand(), reg("RBX", OperandAccess::Read)],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            stack_loc("RSP", 16),
            None,
            Some("RBX"),
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");
        assert_eq!(
            mssa.memory_variables.len(),
            2,
            "should have 2 distinct stack variables"
        );
    }

    // Test 4: Same stack slot is same variable
    #[test]
    fn test_same_stack_slot_same_variable() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![mem_operand(), reg("RBX", OperandAccess::Read)],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RBX"),
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");
        assert_eq!(
            mssa.memory_variables.len(),
            1,
            "should have 1 stack variable"
        );
        // Two defs → version should be 2
        let var = &mssa.memory_variables[0];
        assert_eq!(mssa.variable_versions.get(var).copied().unwrap_or(0), 2);
    }

    // Test 5: Global memory variable
    #[test]
    fn test_global_memory_variable() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![reg("RCX", OperandAccess::Write), mem_operand()],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            MemoryLocation::Global {
                address: 0x2000,
                size: 64,
                rip_relative: true,
            },
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Load,
            MemoryLocation::Global {
                address: 0x2000,
                size: 64,
                rip_relative: true,
            },
            Some("RCX"),
            None,
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");
        assert_eq!(mssa.memory_variables.len(), 1);
        assert!(matches!(
            mssa.memory_variables[0],
            MemoryVariable::Global { .. }
        ));
    }

    // Test 6: Heap is conservative (all heap = one variable)
    #[test]
    fn test_heap_conservative_single_variable() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1010),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![mem_operand(), reg("RBX", OperandAccess::Read)],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            MemoryLocation::Heap {
                base_register: "RAX".into(),
                index_register: None,
                scale: 1,
                displacement: 8,
                size: 64,
            },
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Store,
            MemoryLocation::Heap {
                base_register: "RBX".into(),
                index_register: None,
                scale: 1,
                displacement: 16,
                size: 64,
            },
            None,
            Some("RBX"),
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");
        // Both heap accesses → single conservative variable
        assert_eq!(mssa.memory_variables.len(), 1);
        assert!(matches!(mssa.memory_variables[0], MemoryVariable::Heap));
    }

    // Test 7: ReadWrite is both def and use
    #[test]
    fn test_readwrite_both_def_and_use() {
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![mk_inst(
                0x1000,
                IROp::Add,
                vec![mem_operand(), reg("RAX", OperandAccess::Read)],
            )],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::ReadWrite,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");
        assert_eq!(mssa.definitions.len(), 1, "ReadWrite should create 1 def");
        assert_eq!(mssa.uses.len(), 1, "ReadWrite should create 1 use");
    }

    // Test 8: Loop with memory store → version increments
    #[test]
    fn test_loop_memory_versioning() {
        // Standard loop with pre-header:
        // b0 (pre-header): -> b1
        // b1 (loop header): preds=[b0, b2], Store [rsp+8], rax -> b2
        // b2 (loop body): Load rcx, [rsp+8] -> b1, b3
        // b3 (exit):
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![],
            successors: vec![1],
            predecessors: vec![],
        };
        let b1 = IRBasicBlock {
            id: 1,
            start_address: Address(0x1010),
            end_address: Address(0x1018),
            instructions: vec![mk_inst(
                0x1010,
                IROp::Mov,
                vec![mem_operand(), reg("RAX", OperandAccess::Read)],
            )],
            successors: vec![2],
            predecessors: vec![0, 2],
        };
        let b2 = IRBasicBlock {
            id: 2,
            start_address: Address(0x1020),
            end_address: Address(0x1028),
            instructions: vec![mk_inst(
                0x1020,
                IROp::Mov,
                vec![reg("RCX", OperandAccess::Write), mem_operand()],
            )],
            successors: vec![1, 3],
            predecessors: vec![1],
        };
        let b3 = IRBasicBlock {
            id: 3,
            start_address: Address(0x1030),
            end_address: Address(0x1038),
            instructions: vec![],
            successors: vec![],
            predecessors: vec![2],
        };
        let (ir, _) = make_ir_with_mem(vec![b0, b1, b2, b3]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1010,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1020,
            MemoryOperationKind::Load,
            stack_loc("RSP", 8),
            Some("RCX"),
            None,
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");

        // Loop header b1 has 2 preds (b0 pre-header, b2 back edge) → should have phi
        let phi_at_b1: Vec<_> = mssa.phi_nodes.iter().filter(|p| p.block_id == 1).collect();
        assert!(
            !phi_at_b1.is_empty(),
            "Loop header b1 should have a memory phi"
        );
        assert_eq!(
            phi_at_b1[0].incoming.len(),
            2,
            "Phi should have 2 incoming (b0, b2)"
        );

        // Variable should have multiple versions (phi + store)
        let var = &mssa.memory_variables[0];
        let max_ver = mssa.variable_versions.get(var).copied().unwrap_or(0);
        assert!(
            max_ver >= 2,
            "should have at least 2 versions (phi + store), got {}",
            max_ver
        );

        // The Load at b2 should trace to either the phi (b1) or the store (b1)
        let use_key = (2usize, 0usize, 0usize);
        let def = mssa
            .use_def_chains
            .get(&use_key)
            .expect("use-def should exist");
        assert_eq!(def.0, 1, "use should trace to block 1 (phi or store)");
    }

    // Test 9: No memory operations → None
    #[test]
    fn test_no_memory_operations_returns_none() {
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
        let (ir, mem) = make_ir_with_mem(vec![b0]);
        assert!(MemorySSAConstructor::construct(&ir, &mem).is_none());
    }

    // Test 10: Def-use chain completeness
    #[test]
    fn test_def_use_chain_completeness() {
        // Store [rsp+8], rax ; Load rcx, [rsp+8] ; Load rdx, [rsp+8]
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1020),
            instructions: vec![
                mk_inst(
                    0x1000,
                    IROp::Mov,
                    vec![mem_operand(), reg("RAX", OperandAccess::Read)],
                ),
                mk_inst(
                    0x1005,
                    IROp::Mov,
                    vec![reg("RCX", OperandAccess::Write), mem_operand()],
                ),
                mk_inst(
                    0x100a,
                    IROp::Mov,
                    vec![reg("RDX", OperandAccess::Write), mem_operand()],
                ),
            ],
            successors: vec![],
            predecessors: vec![],
        };
        let (ir, _) = make_ir_with_mem(vec![b0]);

        let mut mem = MemoryAnalysis::new();
        mem.add_operation(mem_op(
            0x1000,
            MemoryOperationKind::Store,
            stack_loc("RSP", 8),
            None,
            Some("RAX"),
        ));
        mem.add_operation(mem_op(
            0x1005,
            MemoryOperationKind::Load,
            stack_loc("RSP", 8),
            Some("RCX"),
            None,
        ));
        mem.add_operation(mem_op(
            0x100a,
            MemoryOperationKind::Load,
            stack_loc("RSP", 8),
            Some("RDX"),
            None,
        ));

        let mssa = MemorySSAConstructor::construct(&ir, &mem).expect("should construct");

        // The Store def should have 2 uses (both Loads)
        let def_key = (0usize, 0usize);
        let uses = mssa
            .def_use_chains
            .get(&def_key)
            .expect("def-use should exist");
        assert_eq!(uses.len(), 2, "Store should have exactly 2 uses");

        // Both uses should trace to the same def
        for (use_block, use_inst, _) in uses {
            let use_key = (*use_block, *use_inst, 0usize);
            let def = mssa
                .use_def_chains
                .get(&use_key)
                .expect("use-def should exist");
            assert_eq!(def.0, 0);
            assert_eq!(def.1, 0);
        }
    }
}
