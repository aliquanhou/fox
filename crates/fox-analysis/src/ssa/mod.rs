//! FOX SSA Construction
//!
//! P0-2.5: Variable Versioning, Phi Placement, Renaming.
#![allow(clippy::type_complexity)]
//!
//! Based on Cytron et al. algorithm:
//! 1. Compute Dominance Frontier
//! 2. Place Phi functions at join points
//! 3. Rename variables in dominator-tree DFS order

use fox_core::{Evidence, EvidenceKind};
use fox_ir::{IRFunction, IROperand, OperandAccess};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A Phi node in SSA form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiNode {
    pub block_id: usize,
    pub variable: String,
    /// Incoming values: (predecessor_block_id, variable_version)
    pub incoming: Vec<(usize, u32)>,
    pub result_version: u32,
}

/// SSA-form function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSAFunction {
    pub name: String,
    pub address: u64,
    pub basic_blocks: Vec<SSABasicBlock>,
    pub entry_block: usize,
    pub phi_nodes: Vec<PhiNode>,
    pub variable_versions: HashMap<String, u32>, // max version per variable
    pub evidence: Vec<Evidence>,
    /// Use-def chains: (block_id, inst_index, operand_index) -> (def_block, def_inst, version)
    #[serde(default)]
    pub use_def_chains: HashMap<(usize, usize, usize), (usize, usize, u32)>,
    /// Def-use chains: (block_id, inst_index) -> Vec<(use_block, use_inst, operand_idx)>
    #[serde(default)]
    pub def_use_chains: HashMap<(usize, usize), Vec<(usize, usize, usize)>>,
    /// Whether this SSA was constructed with proper dominator-tree renaming
    #[serde(default)]
    pub proper_renaming: bool,
}

/// SSA basic block with renamed instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSABasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<SSAInstruction>,
    pub phi_nodes: Vec<PhiNode>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

/// SSA instruction with versioned operands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSAInstruction {
    pub address: u64,
    pub op: String,
    pub operands: Vec<SSAOperand>,
    pub original_mnemonic: String,
}

/// SSA operand (versioned variable or constant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SSAOperand {
    /// Versioned register variable: name.version
    Variable { name: String, version: u32 },
    /// Constant value
    Constant(u64),
    /// Memory reference (not yet versioned)
    Memory { description: String },
    /// Label / branch target
    Label(String),
}

/// SSA constructor.
pub struct SSAConstructor;

impl SSAConstructor {
    /// Construct SSA form from an IR function.
    ///
    /// This is a simplified SSA construction for registers only.
    /// Memory operands are preserved as-is (P0-2.6+ will add memory SSA).
    pub fn construct(ir_func: &IRFunction) -> SSAFunction {
        // Step 1: Collect all registers and their definition points
        let mut def_blocks: HashMap<String, HashSet<usize>> = HashMap::new();
        for block in &ir_func.basic_blocks {
            for inst in &block.instructions {
                for reg in inst.all_writes() {
                    def_blocks
                        .entry(reg.to_string())
                        .or_default()
                        .insert(block.id);
                }
            }
        }

        // Step 2: Compute dominator tree (simplified for SSA)
        let (_dom, idom) = Self::compute_dominators(ir_func);

        // Step 3: Compute dominance frontier
        let df = Self::compute_dominance_frontier(ir_func, &idom);

        // Step 4: Phi placement
        let mut phi_placement: HashMap<usize, HashSet<String>> = HashMap::new();
        for (var, defs) in &def_blocks {
            let mut worklist: Vec<usize> = defs.iter().cloned().collect();
            let mut has_phi: HashSet<usize> = HashSet::new();

            while let Some(block) = worklist.pop() {
                if let Some(frontier) = df.get(&block) {
                    for &frontier_block in frontier {
                        if !has_phi.contains(&frontier_block) {
                            has_phi.insert(frontier_block);
                            phi_placement
                                .entry(frontier_block)
                                .or_default()
                                .insert(var.clone());
                            if !defs.contains(&frontier_block) {
                                worklist.push(frontier_block);
                            }
                        }
                    }
                }
            }
        }

        // Step 5: Renaming (simplified: assign versions per definition)
        let mut variable_versions: HashMap<String, u32> = HashMap::new();
        let mut ssa_blocks = Vec::new();
        let mut all_phi_nodes = Vec::new();

        for block in &ir_func.basic_blocks {
            let mut ssa_insts = Vec::new();
            let mut block_phis = Vec::new();

            // Add phi nodes for this block
            if let Some(phi_vars) = phi_placement.get(&block.id) {
                for var in phi_vars {
                    let version = variable_versions.entry(var.clone()).or_insert(0);
                    *version += 1;
                    let phi = PhiNode {
                        block_id: block.id,
                        variable: var.clone(),
                        incoming: Vec::new(), // filled in later
                        result_version: *version,
                    };
                    block_phis.push(phi.clone());
                    all_phi_nodes.push(phi);
                }
            }

            // Rename instructions
            for inst in &block.instructions {
                let mut ssa_operands = Vec::new();
                for op in &inst.operands {
                    match op {
                        IROperand::Register { name, access, .. } => {
                            if matches!(access, OperandAccess::Write | OperandAccess::ReadWrite) {
                                // New definition: increment version
                                let version = variable_versions.entry(name.clone()).or_insert(0);
                                *version += 1;
                                ssa_operands.push(SSAOperand::Variable {
                                    name: name.clone(),
                                    version: *version,
                                });
                            } else {
                                // Use: current version
                                let version = variable_versions.get(name).copied().unwrap_or(0);
                                ssa_operands.push(SSAOperand::Variable {
                                    name: name.clone(),
                                    version,
                                });
                            }
                        }
                        IROperand::Immediate { value, .. } => {
                            ssa_operands.push(SSAOperand::Constant(*value));
                        }
                        IROperand::Memory {
                            base,
                            index,
                            displacement,
                            ..
                        } => {
                            let desc = format!(
                                "[{}{}{}{}]",
                                base.clone().unwrap_or_default(),
                                if index.is_some() { "+" } else { "" },
                                index.clone().unwrap_or_default(),
                                if *displacement != 0 {
                                    format!("+{:#x}", displacement)
                                } else {
                                    String::new()
                                }
                            );
                            ssa_operands.push(SSAOperand::Memory { description: desc });
                        }
                        IROperand::Label(l) => {
                            ssa_operands.push(SSAOperand::Label(l.clone()));
                        }
                        IROperand::Flags { .. } => {
                            ssa_operands.push(SSAOperand::Variable {
                                name: "FLAGS".to_string(),
                                version: 0,
                            });
                        }
                        _ => {
                            ssa_operands.push(SSAOperand::Memory {
                                description: "unknown".to_string(),
                            });
                        }
                    }
                }

                ssa_insts.push(SSAInstruction {
                    address: inst.address.0,
                    op: format!("{:?}", inst.op),
                    operands: ssa_operands,
                    original_mnemonic: inst.original_mnemonic.clone().unwrap_or_default(),
                });
            }

            ssa_blocks.push(SSABasicBlock {
                id: block.id,
                start_address: block.start_address.0,
                end_address: block.end_address.0,
                instructions: ssa_insts,
                phi_nodes: block_phis,
                successors: block.successors.clone(),
                predecessors: block.predecessors.clone(),
            });
        }

        let mut evidence = Vec::new();
        evidence.push(Evidence::new(EvidenceKind::SSAConstruction).with_weight(0.85));
        evidence.push(
            Evidence::new(EvidenceKind::Heuristic {
                description: format!(
                    "SSA: {} phi nodes, {} variables versioned",
                    all_phi_nodes.len(),
                    variable_versions.len()
                ),
            })
            .with_weight(0.7),
        );

        SSAFunction {
            name: ir_func.name.clone(),
            address: ir_func.address.0,
            basic_blocks: ssa_blocks,
            entry_block: ir_func.entry_block,
            phi_nodes: all_phi_nodes,
            variable_versions,
            evidence,
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            proper_renaming: false,
        }
    }

    /// Construct SSA with proper dominator-tree DFS renaming (P0-3.3).
    ///
    /// Uses Cytron et al. algorithm:
    /// 1. Compute dominator tree + dominance frontier
    /// 2. Place phi nodes at dominance frontiers
    /// 3. Rename in dominator-tree DFS order with per-variable version stacks
    /// 4. Fill phi incoming edges
    /// 5. Build use-def and def-use chains
    pub fn construct_proper(ir_func: &IRFunction) -> SSAFunction {
        use crate::dominators::DominatorTree;

        // Step 1: Collect definition blocks
        let mut def_blocks: HashMap<String, HashSet<usize>> = HashMap::new();
        for block in &ir_func.basic_blocks {
            for inst in &block.instructions {
                for reg in inst.all_writes() {
                    def_blocks
                        .entry(reg.to_string())
                        .or_default()
                        .insert(block.id);
                }
            }
        }

        // Step 2: Compute dominator tree
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

        // Step 3: Phi placement (iterative dominance frontier algorithm)
        let mut phi_placement: HashMap<usize, HashSet<String>> = HashMap::new();
        for (var, defs) in &def_blocks {
            let mut worklist: Vec<usize> = defs.iter().cloned().collect();
            let mut has_phi: HashSet<usize> = HashSet::new();
            while let Some(block) = worklist.pop() {
                for &frontier_block in dom_tree.frontier(block) {
                    if !has_phi.contains(&frontier_block) {
                        has_phi.insert(frontier_block);
                        phi_placement
                            .entry(frontier_block)
                            .or_default()
                            .insert(var.clone());
                        if !defs.contains(&frontier_block) {
                            worklist.push(frontier_block);
                        }
                    }
                }
            }
        }

        // Step 4: Proper renaming via dominator-tree DFS
        let mut version_counter: HashMap<String, u32> = HashMap::new();
        let mut version_stack: HashMap<String, Vec<u32>> = HashMap::new();
        // Track definition location for each version: (var, version) -> (block_id, inst_idx)
        // inst_idx = usize::MAX means phi node definition
        let mut version_def: HashMap<(String, u32), (usize, usize)> = HashMap::new();
        let mut ssa_blocks: HashMap<usize, SSABasicBlock> = HashMap::new();
        let mut all_phi_nodes: Vec<PhiNode> = Vec::new();
        let mut use_def: HashMap<(usize, usize, usize), (usize, usize, u32)> = HashMap::new();
        let mut def_use: HashMap<(usize, usize), Vec<(usize, usize, usize)>> = HashMap::new();

        // Track current version for each variable at each block exit (for phi filling)
        let mut block_exit_versions: HashMap<usize, HashMap<String, u32>> = HashMap::new();

        Self::rename_block_dfs(
            ir_func.entry_block,
            ir_func,
            &phi_placement,
            &dom_tree,
            &mut version_counter,
            &mut version_stack,
            &mut version_def,
            &mut ssa_blocks,
            &mut all_phi_nodes,
            &mut use_def,
            &mut def_use,
            &mut block_exit_versions,
        );

        // Step 5: Fill phi incoming edges
        for phi in &mut all_phi_nodes {
            let block = phi.block_id;
            let preds = pred_map.get(&block).cloned().unwrap_or_default();
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

        // Update phi nodes in blocks
        for phi in &all_phi_nodes {
            if let Some(bb) = ssa_blocks.get_mut(&phi.block_id) {
                if let Some(existing) = bb.phi_nodes.iter_mut().find(|p| p.variable == phi.variable)
                {
                    existing.incoming = phi.incoming.clone();
                }
            }
        }

        // Sort blocks by id
        let mut blocks_vec: Vec<SSABasicBlock> = ssa_blocks.into_values().collect();
        blocks_vec.sort_by_key(|b| b.id);

        let max_versions: HashMap<String, u32> = version_counter.clone();

        let mut evidence = Vec::new();
        evidence.push(Evidence::new(EvidenceKind::SSAConstruction).with_weight(0.92));
        evidence.push(
            Evidence::new(EvidenceKind::Heuristic {
                description: format!(
                    "Proper SSA: {} phi nodes, {} variables, DFS renaming",
                    all_phi_nodes.len(),
                    max_versions.len()
                ),
            })
            .with_weight(0.8),
        );

        SSAFunction {
            name: ir_func.name.clone(),
            address: ir_func.address.0,
            basic_blocks: blocks_vec,
            entry_block: ir_func.entry_block,
            phi_nodes: all_phi_nodes,
            variable_versions: max_versions,
            evidence,
            use_def_chains: use_def,
            def_use_chains: def_use,
            proper_renaming: true,
        }
    }

    /// Recursive DFS renaming on dominator tree.
    #[allow(clippy::too_many_arguments)]
    fn rename_block_dfs(
        block_id: usize,
        ir_func: &IRFunction,
        phi_placement: &HashMap<usize, HashSet<String>>,
        dom_tree: &crate::dominators::DominatorTree,
        version_counter: &mut HashMap<String, u32>,
        version_stack: &mut HashMap<String, Vec<u32>>,
        version_def: &mut HashMap<(String, u32), (usize, usize)>,
        ssa_blocks: &mut HashMap<usize, SSABasicBlock>,
        all_phi_nodes: &mut Vec<PhiNode>,
        use_def: &mut HashMap<(usize, usize, usize), (usize, usize, u32)>,
        def_use: &mut HashMap<(usize, usize), Vec<(usize, usize, usize)>>,
        block_exit_versions: &mut HashMap<usize, HashMap<String, u32>>,
    ) {
        let block = match ir_func.basic_blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => return,
        };

        let mut pushed_versions: Vec<String> = Vec::new();
        let mut ssa_insts = Vec::new();
        let mut block_phis = Vec::new();

        // Process phi nodes at block entry (they define new versions)
        if let Some(phi_vars) = phi_placement.get(&block_id) {
            for var in phi_vars {
                let new_ver = Self::push_version(var, version_counter, version_stack);
                pushed_versions.push(var.clone());
                version_def.insert((var.clone(), new_ver), (block_id, usize::MAX));
                let phi = PhiNode {
                    block_id,
                    variable: var.clone(),
                    incoming: Vec::new(), // filled later
                    result_version: new_ver,
                };
                block_phis.push(phi.clone());
                all_phi_nodes.push(phi);
                // Record def-use for phi
                def_use.entry((block_id, usize::MAX)).or_default();
            }
        }

        // Process instructions
        for (inst_idx, inst) in block.instructions.iter().enumerate() {
            let mut ssa_operands = Vec::new();

            for (op_idx, op) in inst.operands.iter().enumerate() {
                match op {
                    IROperand::Register { name, access, .. } => {
                        if matches!(access, OperandAccess::Write | OperandAccess::ReadWrite) {
                            // Definition: new version
                            let new_ver = Self::push_version(name, version_counter, version_stack);
                            pushed_versions.push(name.clone());
                            version_def.insert((name.clone(), new_ver), (block_id, inst_idx));
                            ssa_operands.push(SSAOperand::Variable {
                                name: name.clone(),
                                version: new_ver,
                            });
                            // Record def-use
                            def_use.entry((block_id, inst_idx)).or_default();
                        } else {
                            // Use: current version from stack, trace to exact definition
                            let cur_ver = version_stack
                                .get(name)
                                .and_then(|s| s.last().copied())
                                .unwrap_or(0);
                            ssa_operands.push(SSAOperand::Variable {
                                name: name.clone(),
                                version: cur_ver,
                            });
                            // Record use-def: trace to exact definition via version_def
                            if let Some(&(def_block, def_inst)) =
                                version_def.get(&(name.clone(), cur_ver))
                            {
                                use_def.insert(
                                    (block_id, inst_idx, op_idx),
                                    (def_block, def_inst, cur_ver),
                                );
                                def_use
                                    .entry((def_block, def_inst))
                                    .or_default()
                                    .push((block_id, inst_idx, op_idx));
                            } else {
                                use_def.insert(
                                    (block_id, inst_idx, op_idx),
                                    (usize::MAX, usize::MAX, cur_ver),
                                );
                            }
                        }
                    }
                    IROperand::Immediate { value, .. } => {
                        ssa_operands.push(SSAOperand::Constant(*value));
                    }
                    IROperand::Memory {
                        base,
                        index,
                        displacement,
                        ..
                    } => {
                        let desc = format!(
                            "[{}{}{}{}]",
                            base.clone().unwrap_or_default(),
                            if index.is_some() { "+" } else { "" },
                            index.clone().unwrap_or_default(),
                            if *displacement != 0 {
                                format!("+{:#x}", displacement)
                            } else {
                                String::new()
                            }
                        );
                        ssa_operands.push(SSAOperand::Memory { description: desc });
                    }
                    IROperand::Label(l) => {
                        ssa_operands.push(SSAOperand::Label(l.clone()));
                    }
                    IROperand::Flags { .. } => {
                        let cur_ver = version_stack
                            .get("FLAGS")
                            .and_then(|s| s.last().copied())
                            .unwrap_or(0);
                        ssa_operands.push(SSAOperand::Variable {
                            name: "FLAGS".to_string(),
                            version: cur_ver,
                        });
                    }
                    _ => {
                        ssa_operands.push(SSAOperand::Memory {
                            description: "unknown".to_string(),
                        });
                    }
                }
            }

            ssa_insts.push(SSAInstruction {
                address: inst.address.0,
                op: format!("{:?}", inst.op),
                operands: ssa_operands,
                original_mnemonic: inst.original_mnemonic.clone().unwrap_or_default(),
            });
        }

        // Record exit versions for phi filling
        let mut exit_vers = HashMap::new();
        for (var, stack) in version_stack.iter() {
            if let Some(&top) = stack.last() {
                exit_vers.insert(var.clone(), top);
            }
        }
        block_exit_versions.insert(block_id, exit_vers);

        ssa_blocks.insert(
            block_id,
            SSABasicBlock {
                id: block_id,
                start_address: block.start_address.0,
                end_address: block.end_address.0,
                instructions: ssa_insts,
                phi_nodes: block_phis,
                successors: block.successors.clone(),
                predecessors: block.predecessors.clone(),
            },
        );

        // Recurse into dominator children
        for &child in dom_tree.children(block_id) {
            Self::rename_block_dfs(
                child,
                ir_func,
                phi_placement,
                dom_tree,
                version_counter,
                version_stack,
                version_def,
                ssa_blocks,
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

    /// Push a new version for a variable, return the new version number.
    fn push_version(
        var: &str,
        counter: &mut HashMap<String, u32>,
        stack: &mut HashMap<String, Vec<u32>>,
    ) -> u32 {
        let cur = counter.entry(var.to_string()).or_insert(0);
        *cur += 1;
        let new_ver = *cur;
        stack.entry(var.to_string()).or_default().push(new_ver);
        new_ver
    }

    /// Simplified dominator computation for SSA.
    fn compute_dominators(
        ir_func: &IRFunction,
    ) -> (
        HashMap<usize, HashSet<usize>>,
        HashMap<usize, Option<usize>>,
    ) {
        let n = ir_func.basic_blocks.len();
        let entry = ir_func.entry_block;
        let all: HashSet<usize> = (0..n).collect();

        let mut pred_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for block in &ir_func.basic_blocks {
            pred_map.insert(block.id, block.predecessors.clone());
        }

        let mut dom: HashMap<usize, HashSet<usize>> = HashMap::new();
        for b in 0..n {
            if b == entry {
                dom.insert(b, [entry].iter().cloned().collect());
            } else {
                dom.insert(b, all.clone());
            }
        }

        let mut changed = true;
        let mut iters = 0;
        while changed && iters < 500 {
            changed = false;
            iters += 1;
            for b in 0..n {
                if b == entry {
                    continue;
                }
                let preds = pred_map.get(&b).cloned().unwrap_or_default();
                if preds.is_empty() {
                    continue;
                }

                let mut new_dom: Option<HashSet<usize>> = None;
                for p in &preds {
                    let p_dom = dom.get(p).cloned().unwrap_or_default();
                    new_dom = Some(match new_dom {
                        None => p_dom,
                        Some(acc) => acc.intersection(&p_dom).cloned().collect(),
                    });
                }
                let mut new_dom = new_dom.unwrap_or_default();
                new_dom.insert(b);
                if new_dom != *dom.get(&b).unwrap() {
                    dom.insert(b, new_dom);
                    changed = true;
                }
            }
        }

        let mut idom: HashMap<usize, Option<usize>> = HashMap::new();
        for b in 0..n {
            if b == entry {
                idom.insert(b, None);
                continue;
            }
            let b_dom = dom.get(&b).cloned().unwrap_or_default();
            let mut candidate: Option<usize> = None;
            for d in &b_dom {
                if *d == b {
                    continue;
                }
                let d_dom = dom.get(d).cloned().unwrap_or_default();
                if b_dom
                    .iter()
                    .filter(|&&x| x != b && x != *d)
                    .all(|x| d_dom.contains(x))
                {
                    candidate = Some(*d);
                    break;
                }
            }
            idom.insert(b, candidate);
        }

        (dom, idom)
    }

    /// Simplified dominance frontier.
    fn compute_dominance_frontier(
        ir_func: &IRFunction,
        idom: &HashMap<usize, Option<usize>>,
    ) -> HashMap<usize, HashSet<usize>> {
        let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();
        for block in &ir_func.basic_blocks {
            df.insert(block.id, HashSet::new());
        }

        for block in &ir_func.basic_blocks {
            if block.predecessors.len() >= 2 {
                for p in &block.predecessors {
                    let mut runner = *p;
                    while Some(runner) != idom.get(&block.id).cloned().unwrap_or(None) {
                        df.entry(runner).or_default().insert(block.id);
                        runner = idom.get(&runner).cloned().unwrap_or(None).unwrap_or(runner);
                        if runner == *p {
                            break;
                        }
                    }
                }
            }
        }
        df
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_core::Address;
    use fox_ir::{IRBasicBlock, IRFunction, IRInstruction, IROp, IROperand, OperandAccess};

    fn make_ir_func() -> IRFunction {
        // Simple if-then-else:
        // block 0: x = 1; if cond goto 1 else 2
        // block 1: x = 2; goto 3
        // block 2: x = 3; goto 3
        // block 3: use(x)
        let b0 = IRBasicBlock {
            id: 0,
            start_address: Address(0x1000),
            end_address: Address(0x1008),
            instructions: vec![IRInstruction {
                address: Address(0x1000),
                op: IROp::Mov,
                operands: vec![
                    IROperand::Register {
                        name: "x".into(),
                        width: 64,
                        access: OperandAccess::Write,
                    },
                    IROperand::Immediate {
                        value: 1,
                        width: 64,
                        is_signed: false,
                    },
                ],
                original_mnemonic: Some("mov".into()),
                original_operands: None,
                size: 5,
                reads_registers: vec![],
                writes_registers: vec!["x".into()],
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }],
            successors: vec![1, 2],
            predecessors: vec![],
        };
        let b1 = IRBasicBlock {
            id: 1,
            start_address: Address(0x1010),
            end_address: Address(0x1018),
            instructions: vec![IRInstruction {
                address: Address(0x1010),
                op: IROp::Mov,
                operands: vec![
                    IROperand::Register {
                        name: "x".into(),
                        width: 64,
                        access: OperandAccess::Write,
                    },
                    IROperand::Immediate {
                        value: 2,
                        width: 64,
                        is_signed: false,
                    },
                ],
                original_mnemonic: Some("mov".into()),
                original_operands: None,
                size: 5,
                reads_registers: vec![],
                writes_registers: vec!["x".into()],
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }],
            successors: vec![3],
            predecessors: vec![0],
        };
        let b2 = IRBasicBlock {
            id: 2,
            start_address: Address(0x1020),
            end_address: Address(0x1028),
            instructions: vec![IRInstruction {
                address: Address(0x1020),
                op: IROp::Mov,
                operands: vec![
                    IROperand::Register {
                        name: "x".into(),
                        width: 64,
                        access: OperandAccess::Write,
                    },
                    IROperand::Immediate {
                        value: 3,
                        width: 64,
                        is_signed: false,
                    },
                ],
                original_mnemonic: Some("mov".into()),
                original_operands: None,
                size: 5,
                reads_registers: vec![],
                writes_registers: vec!["x".into()],
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }],
            successors: vec![3],
            predecessors: vec![0],
        };
        let b3 = IRBasicBlock {
            id: 3,
            start_address: Address(0x1030),
            end_address: Address(0x1038),
            instructions: vec![IRInstruction {
                address: Address(0x1030),
                op: IROp::Mov,
                operands: vec![
                    IROperand::Register {
                        name: "y".into(),
                        width: 64,
                        access: OperandAccess::Write,
                    },
                    IROperand::Register {
                        name: "x".into(),
                        width: 64,
                        access: OperandAccess::Read,
                    },
                ],
                original_mnemonic: Some("mov".into()),
                original_operands: None,
                size: 3,
                reads_registers: vec!["x".into()],
                writes_registers: vec!["y".into()],
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }],
            successors: vec![],
            predecessors: vec![1, 2],
        };

        IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            basic_blocks: vec![b0, b1, b2, b3],
            entry_block: 0,
        }
    }

    #[test]
    fn test_ssa_phi_at_join() {
        let ir_func = make_ir_func();
        let ssa = SSAConstructor::construct(&ir_func);

        // Block 3 is a join point, should have a phi for x
        let block3 = &ssa.basic_blocks[3];
        assert!(
            !block3.phi_nodes.is_empty(),
            "Block 3 should have phi nodes"
        );
        assert!(block3.phi_nodes.iter().any(|p| p.variable == "x"));
    }

    #[test]
    fn test_ssa_variable_versioning() {
        let ir_func = make_ir_func();
        let ssa = SSAConstructor::construct(&ir_func);

        // x should have multiple versions (defined in b0, b1, b2, and phi in b3)
        let x_versions = ssa.variable_versions.get("x").copied().unwrap_or(0);
        assert!(
            x_versions >= 3,
            "x should have at least 3 versions, got {}",
            x_versions
        );
    }

    #[test]
    fn test_ssa_evidence_present() {
        let ir_func = make_ir_func();
        let ssa = SSAConstructor::construct(&ir_func);
        assert!(!ssa.evidence.is_empty());
    }

    #[test]
    fn test_proper_ssa_if_else() {
        // b0: x=1 -> b1,b2
        // b1: x=2 -> b3
        // b2: x=3 -> b3
        // b3: use(x)
        let ir_func = make_if_else_func();
        let ssa = SSAConstructor::construct_proper(&ir_func);

        assert!(ssa.proper_renaming, "Should use proper renaming");
        // Block 3 should have a phi for x
        let b3 = ssa.basic_blocks.iter().find(|b| b.id == 3).unwrap();
        assert!(
            b3.phi_nodes.iter().any(|p| p.variable == "x"),
            "Block 3 should have phi for x"
        );
        // Phi should have 2 incoming (from b1 and b2)
        let phi = b3.phi_nodes.iter().find(|p| p.variable == "x").unwrap();
        assert_eq!(phi.incoming.len(), 2, "Phi should have 2 incoming edges");
    }

    #[test]
    fn test_proper_ssa_version_stacking() {
        // Linear: x=1, x=x+1, use(x)
        let ir_func = make_linear_func();
        let ssa = SSAConstructor::construct_proper(&ir_func);
        let x_versions = ssa.variable_versions.get("x").copied().unwrap_or(0);
        assert!(
            x_versions >= 2,
            "x should have at least 2 versions (two writes), got {}",
            x_versions
        );
    }

    #[test]
    fn test_proper_ssa_use_def_precision() {
        // Linear: x=1 (inst0), x=x+1 (inst1), y=x (inst2 uses x)
        // The use of x in inst2 should trace to inst1 (the most recent def), not inst0
        let ir_func = make_linear_func();
        let ssa = SSAConstructor::construct_proper(&ir_func);

        // Block 0, inst2 (y = x) should have a use-def entry for x
        // use_def key: (block_id, inst_idx, operand_idx)
        // The third instruction (index 2) reads x as operand 1
        let use_key = (0usize, 2usize, 1usize);
        let def = ssa.use_def_chains.get(&use_key);
        assert!(
            def.is_some(),
            "use-def chain should exist for x use in inst2"
        );
        let (def_block, def_inst, _ver) = def.unwrap();
        assert_eq!(*def_block, 0, "definition should be in block 0");
        assert_eq!(
            *def_inst, 1,
            "x use in inst2 should trace to inst1 (ADD), not inst0 (MOV)"
        );
    }

    #[test]
    fn test_proper_ssa_def_use_chain() {
        // Verify def-use: definition of x in inst1 should list inst2 as a use
        let ir_func = make_linear_func();
        let ssa = SSAConstructor::construct_proper(&ir_func);

        let def_key = (0usize, 1usize); // ADD x, 1 defines x
        let uses = ssa.def_use_chains.get(&def_key);
        assert!(
            uses.is_some(),
            "def-use chain should exist for x def in inst1"
        );
        assert!(
            !uses.unwrap().is_empty(),
            "x def in inst1 should have at least one use"
        );
    }

    fn make_if_else_func() -> IRFunction {
        use fox_core::Address;
        use fox_ir::{IRInstruction, IROp, IROperand, OperandAccess};

        let mk = |addr: u64,
                  op: IROp,
                  operands: Vec<IROperand>,
                  reads: Vec<&str>,
                  writes: Vec<&str>|
         -> IRInstruction {
            IRInstruction {
                address: Address(addr),
                op,
                operands,
                original_mnemonic: None,
                original_operands: None,
                size: 0,
                reads_registers: reads.into_iter().map(String::from).collect(),
                writes_registers: writes.into_iter().map(String::from).collect(),
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }
        };
        let rw = |n: &str, a: OperandAccess| IROperand::Register {
            name: n.into(),
            width: 64,
            access: a,
        };
        let imm = |v: u64| IROperand::Immediate {
            value: v,
            width: 64,
            is_signed: false,
        };

        IRFunction {
            name: "test".into(),
            address: Address(0x1000),
            entry_block: 0,
            basic_blocks: vec![
                fox_ir::IRBasicBlock {
                    id: 0,
                    start_address: Address(0x1000),
                    end_address: Address(0x1010),
                    instructions: vec![mk(
                        0x1000,
                        IROp::Mov,
                        vec![rw("x", OperandAccess::Write), imm(1)],
                        vec![],
                        vec!["x"],
                    )],
                    successors: vec![1, 2],
                    predecessors: vec![],
                },
                fox_ir::IRBasicBlock {
                    id: 1,
                    start_address: Address(0x1010),
                    end_address: Address(0x1020),
                    instructions: vec![mk(
                        0x1010,
                        IROp::Mov,
                        vec![rw("x", OperandAccess::Write), imm(2)],
                        vec![],
                        vec!["x"],
                    )],
                    successors: vec![3],
                    predecessors: vec![0],
                },
                fox_ir::IRBasicBlock {
                    id: 2,
                    start_address: Address(0x1020),
                    end_address: Address(0x1030),
                    instructions: vec![mk(
                        0x1020,
                        IROp::Mov,
                        vec![rw("x", OperandAccess::Write), imm(3)],
                        vec![],
                        vec!["x"],
                    )],
                    successors: vec![3],
                    predecessors: vec![0],
                },
                fox_ir::IRBasicBlock {
                    id: 3,
                    start_address: Address(0x1030),
                    end_address: Address(0x1040),
                    instructions: vec![mk(
                        0x1030,
                        IROp::Mov,
                        vec![rw("y", OperandAccess::Write), rw("x", OperandAccess::Read)],
                        vec!["x"],
                        vec!["y"],
                    )],
                    successors: vec![],
                    predecessors: vec![1, 2],
                },
            ],
        }
    }

    fn make_linear_func() -> IRFunction {
        use fox_core::Address;
        use fox_ir::{IRInstruction, IROp, IROperand, OperandAccess};

        let mk = |addr: u64,
                  op: IROp,
                  operands: Vec<IROperand>,
                  reads: Vec<&str>,
                  writes: Vec<&str>|
         -> IRInstruction {
            IRInstruction {
                address: Address(addr),
                op,
                operands,
                original_mnemonic: None,
                original_operands: None,
                size: 0,
                reads_registers: reads.into_iter().map(String::from).collect(),
                writes_registers: writes.into_iter().map(String::from).collect(),
                implicit_reads: vec![],
                implicit_writes: vec![],
                reads_flags: false,
                writes_flags: false,
            }
        };
        let rw = |n: &str, a: OperandAccess| IROperand::Register {
            name: n.into(),
            width: 64,
            access: a,
        };
        let imm = |v: u64| IROperand::Immediate {
            value: v,
            width: 64,
            is_signed: false,
        };

        IRFunction {
            name: "linear".into(),
            address: Address(0x2000),
            entry_block: 0,
            basic_blocks: vec![fox_ir::IRBasicBlock {
                id: 0,
                start_address: Address(0x2000),
                end_address: Address(0x2020),
                instructions: vec![
                    mk(
                        0x2000,
                        IROp::Mov,
                        vec![rw("x", OperandAccess::Write), imm(1)],
                        vec![],
                        vec!["x"],
                    ),
                    mk(
                        0x2005,
                        IROp::Add,
                        vec![rw("x", OperandAccess::ReadWrite), imm(1)],
                        vec!["x"],
                        vec!["x"],
                    ),
                    mk(
                        0x200a,
                        IROp::Mov,
                        vec![rw("y", OperandAccess::Write), rw("x", OperandAccess::Read)],
                        vec!["x"],
                        vec!["y"],
                    ),
                ],
                successors: vec![],
                predecessors: vec![],
            }],
        }
    }
}
