//! FOX Data Flow Analysis
//!
//! P0-3.2: CFG-aware iterative data flow analysis.
#![allow(clippy::type_complexity)]
//!
//! Implements:
//! - Reaching Definitions (forward, may-analysis)
//! - Live Variables (backward, may-analysis)
//! - Constant Propagation (forward, must-analysis)
//!
//! All analyses operate on basic block CFG with predecessor/successor
//! transfer functions and iterate to fixed point.
//!
//! P0-2 flow-insensitive versions are retained as `compute_flow_insensitive`.

use fox_core::{Evidence, EvidenceKind};
use fox_ir::{IRInstruction, IROperand, OperandAccess};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Reaching Definitions (CFG-aware)
// ============================================================================

/// A definition point: (block_id, instruction_index, register_name)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Definition {
    pub block_id: usize,
    pub inst_index: usize,
    pub address: u64,
    pub register: String,
}

/// CFG-aware Reaching Definitions result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachingDefinitionsCfg {
    /// Map: block_id -> IN set (definitions reaching block entry)
    pub in_sets: HashMap<usize, Vec<Definition>>,
    /// Map: block_id -> OUT set (definitions reaching block exit)
    pub out_sets: HashMap<usize, Vec<Definition>>,
    /// GEN set per block
    pub gen_sets: HashMap<usize, Vec<Definition>>,
    /// Number of iterations to fixed point
    pub iterations: usize,
}

impl ReachingDefinitionsCfg {
    /// Compute reaching definitions on a CFG.
    ///
    /// `blocks`: list of (block_id, instructions, predecessors, successors)
    pub fn compute(
        blocks: &[(usize, &[IRInstruction], &[usize], &[usize])],
        entry_block: usize,
    ) -> Self {
        let block_ids: Vec<usize> = blocks.iter().map(|(id, ..)| *id).collect();
        let block_index: HashMap<usize, usize> = block_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();

        // Compute GEN sets first
        let mut gen: HashMap<usize, Vec<Definition>> = HashMap::new();
        let mut all_defs: Vec<Definition> = Vec::new();

        for (block_id, insts, _, _) in blocks {
            let mut block_gen = Vec::new();
            for (idx, inst) in insts.iter().enumerate() {
                for reg in inst.all_writes() {
                    let def = Definition {
                        block_id: *block_id,
                        inst_index: idx,
                        address: inst.address.0,
                        register: reg.to_string(),
                    };
                    // Kill previous definitions of same register in this block
                    block_gen.retain(|d: &Definition| d.register != reg);
                    block_gen.push(def.clone());
                    all_defs.push(def);
                }
            }
            gen.insert(*block_id, block_gen);
        }

        // Compute KILL sets: KILL[B] = all defs of same register not in GEN[B]
        let mut kill: HashMap<usize, HashSet<(String, usize)>> = HashMap::new();
        for (block_id, _insts, _, _) in blocks {
            let block_gen = gen.get(block_id).cloned().unwrap_or_default();
            let gen_regs: HashSet<String> = block_gen.iter().map(|d| d.register.clone()).collect();
            let mut block_kill = HashSet::new();
            for def in &all_defs {
                if gen_regs.contains(&def.register) && def.block_id != *block_id {
                    block_kill.insert((def.register.clone(), def.block_id));
                }
            }
            kill.insert(*block_id, block_kill);
        }

        // Initialize: OUT[entry] = GEN[entry], others = empty
        let mut out: HashMap<usize, HashSet<Definition>> = HashMap::new();
        for &id in &block_ids {
            out.insert(id, HashSet::new());
        }
        if let Some(entry_gen) = gen.get(&entry_block) {
            out.get_mut(&entry_block)
                .unwrap()
                .extend(entry_gen.iter().cloned());
        }

        // Iterate to fixed point
        let mut iterations = 0;
        let mut changed = true;
        while changed && iterations < 1000 {
            changed = false;
            iterations += 1;

            for &id in &block_ids {
                if id == entry_block {
                    continue; // entry OUT is fixed
                }

                let idx = block_index[&id];
                let preds = blocks[idx].2;

                // IN[B] = ∪ OUT[P] for P in pred(B)
                let mut in_set: HashSet<Definition> = HashSet::new();
                for &p in preds {
                    if let Some(p_out) = out.get(&p) {
                        in_set.extend(p_out.iter().cloned());
                    }
                }

                // OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
                let block_gen = gen.get(&id).cloned().unwrap_or_default();
                let block_kill = kill.get(&id).cloned().unwrap_or_default();
                let mut new_out: HashSet<Definition> = block_gen.iter().cloned().collect();
                for def in &in_set {
                    if !block_kill.contains(&(def.register.clone(), def.block_id)) {
                        new_out.insert(def.clone());
                    }
                }

                if new_out != *out.get(&id).unwrap() {
                    out.insert(id, new_out);
                    changed = true;
                }
            }
        }

        // Compute IN sets for output
        let mut in_sets: HashMap<usize, Vec<Definition>> = HashMap::new();
        let mut out_sets: HashMap<usize, Vec<Definition>> = HashMap::new();

        for &id in &block_ids {
            let idx = block_index[&id];
            let preds = blocks[idx].2;
            let mut in_set: HashSet<Definition> = HashSet::new();
            for &p in preds {
                if let Some(p_out) = out.get(&p) {
                    in_set.extend(p_out.iter().cloned());
                }
            }
            let mut in_vec: Vec<Definition> = in_set.into_iter().collect();
            in_vec.sort_by_key(|d| (d.register.clone(), d.address));
            in_sets.insert(id, in_vec);

            let mut out_vec: Vec<Definition> = out
                .get(&id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            out_vec.sort_by_key(|d| (d.register.clone(), d.address));
            out_sets.insert(id, out_vec);
        }

        let gen_sets: HashMap<usize, Vec<Definition>> = gen
            .into_iter()
            .map(|(k, mut v)| {
                v.sort_by_key(|d| (d.register.clone(), d.address));
                (k, v)
            })
            .collect();

        ReachingDefinitionsCfg {
            in_sets,
            out_sets,
            gen_sets,
            iterations,
        }
    }
}

// ============================================================================
// Live Variables (CFG-aware)
// ============================================================================

/// CFG-aware Live Variables result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVariablesCfg {
    /// Map: block_id -> IN set (live at block entry)
    pub in_sets: HashMap<usize, Vec<String>>,
    /// Map: block_id -> OUT set (live at block exit)
    pub out_sets: HashMap<usize, Vec<String>>,
    /// USE set per block (used before definition)
    pub use_sets: HashMap<usize, Vec<String>>,
    /// DEF set per block
    pub def_sets: HashMap<usize, Vec<String>>,
    /// Number of iterations to fixed point
    pub iterations: usize,
}

impl LiveVariablesCfg {
    /// Compute live variables on a CFG (backward analysis).
    pub fn compute(blocks: &[(usize, &[IRInstruction], &[usize], &[usize])]) -> Self {
        let block_ids: Vec<usize> = blocks.iter().map(|(id, ..)| *id).collect();
        let block_index: HashMap<usize, usize> = block_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();

        // Compute USE and DEF sets per block
        let mut use_set: HashMap<usize, HashSet<String>> = HashMap::new();
        let mut def_set: HashMap<usize, HashSet<String>> = HashMap::new();

        for (block_id, insts, _, _) in blocks {
            let mut u = HashSet::new();
            let mut d = HashSet::new();
            for inst in insts.iter() {
                // Uses before defs in this instruction
                for reg in inst.all_reads() {
                    if !d.contains(reg) {
                        u.insert(reg.to_string());
                    }
                }
                for reg in inst.all_writes() {
                    d.insert(reg.to_string());
                }
            }
            use_set.insert(*block_id, u);
            def_set.insert(*block_id, d);
        }

        // Initialize IN/OUT to empty
        let mut in_map: HashMap<usize, HashSet<String>> = HashMap::new();
        let mut out_map: HashMap<usize, HashSet<String>> = HashMap::new();
        for &id in &block_ids {
            in_map.insert(id, HashSet::new());
            out_map.insert(id, HashSet::new());
        }

        // Backward iterate to fixed point
        let mut iterations = 0;
        let mut changed = true;
        while changed && iterations < 1000 {
            changed = false;
            iterations += 1;

            // Process in reverse order (backward analysis)
            for &id in block_ids.iter().rev() {
                let idx = block_index[&id];
                let succs = blocks[idx].3;

                // OUT[B] = ∪ IN[S] for S in succ(B)
                let mut new_out: HashSet<String> = HashSet::new();
                for &s in succs {
                    if let Some(s_in) = in_map.get(&s) {
                        new_out.extend(s_in.iter().cloned());
                    }
                }

                // IN[B] = USE[B] ∪ (OUT[B] - DEF[B])
                let block_use = use_set.get(&id).cloned().unwrap_or_default();
                let block_def = def_set.get(&id).cloned().unwrap_or_default();
                let mut new_in = block_use;
                for var in &new_out {
                    if !block_def.contains(var) {
                        new_in.insert(var.clone());
                    }
                }

                if new_in != *in_map.get(&id).unwrap() || new_out != *out_map.get(&id).unwrap() {
                    in_map.insert(id, new_in);
                    out_map.insert(id, new_out);
                    changed = true;
                }
            }
        }

        // Convert to sorted vecs
        let to_sorted = |m: HashMap<usize, HashSet<String>>| -> HashMap<usize, Vec<String>> {
            m.into_iter()
                .map(|(k, v)| {
                    let mut vec: Vec<String> = v.into_iter().collect();
                    vec.sort();
                    (k, vec)
                })
                .collect()
        };

        LiveVariablesCfg {
            in_sets: to_sorted(in_map),
            out_sets: to_sorted(out_map),
            use_sets: to_sorted(use_set),
            def_sets: to_sorted(def_set),
            iterations,
        }
    }
}

// ============================================================================
// Constant Propagation (CFG-aware)
// ============================================================================

/// A constant value at a program point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantValue {
    pub value: u64,
    pub register: String,
    pub defined_at: u64,
    pub confidence: f32,
}

/// CFG-aware Constant Propagation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantPropagationCfg {
    /// Map: block_id -> constants at block entry
    pub in_constants: HashMap<usize, Vec<ConstantValue>>,
    /// Map: block_id -> constants at block exit
    pub out_constants: HashMap<usize, Vec<ConstantValue>>,
    /// Number of iterations
    pub iterations: usize,
    /// Total constants propagated
    pub propagated_count: usize,
}

impl ConstantPropagationCfg {
    /// Compute constant propagation on a CFG.
    ///
    /// Uses a simple lattice: Top (unknown) → Constant → Bottom (overdefined).
    /// At join points: if all predecessors agree on a constant, it survives;
    /// otherwise it becomes overdefined (dropped).
    pub fn compute(
        blocks: &[(usize, &[IRInstruction], &[usize], &[usize])],
        entry_block: usize,
    ) -> Self {
        let block_ids: Vec<usize> = blocks.iter().map(|(id, ..)| *id).collect();
        let block_index: HashMap<usize, usize> = block_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();

        // State: register -> Option<u64> (None = overdefined/unknown)
        type State = HashMap<String, Option<u64>>;

        let mut in_state: HashMap<usize, State> = HashMap::new();
        let mut out_state: HashMap<usize, State> = HashMap::new();
        for &id in &block_ids {
            in_state.insert(id, HashMap::new());
            out_state.insert(id, HashMap::new());
        }

        let mut iterations = 0;
        let mut changed = true;
        let mut total_propagated = 0usize;

        while changed && iterations < 500 {
            changed = false;
            iterations += 1;

            for &id in &block_ids {
                let idx = block_index[&id];
                let preds = blocks[idx].2;
                let insts = blocks[idx].1;

                // Join: IN[B] = meet of OUT[P] for all P
                let mut new_in: State = HashMap::new();
                if id == entry_block {
                    // Entry: empty state
                } else if !preds.is_empty() {
                    // Collect all registers from all predecessors
                    let mut all_regs: HashSet<String> = HashSet::new();
                    for &p in preds {
                        if let Some(p_out) = out_state.get(&p) {
                            all_regs.extend(p_out.keys().cloned());
                        }
                    }
                    for reg in all_regs {
                        let mut values: Vec<Option<u64>> = Vec::new();
                        for &p in preds {
                            let val = out_state
                                .get(&p)
                                .and_then(|s| s.get(&reg).cloned())
                                .unwrap_or(None);
                            values.push(val);
                        }
                        // Meet: all Some(v) with same v -> Some(v); else None
                        let first = values[0];
                        let all_same = values.iter().all(|v| *v == first);
                        if all_same {
                            new_in.insert(reg, first);
                        } else {
                            new_in.insert(reg, None); // overdefined
                        }
                    }
                }

                // Transfer: apply instructions
                let mut new_out = new_in.clone();
                for inst in insts {
                    match inst.op {
                        fox_ir::IROp::Mov => {
                            if inst.operands.len() >= 2 {
                                if let (Some(dst), Some(src_val)) = (
                                    Self::write_reg(&inst.operands[0]),
                                    Self::imm_val(&inst.operands[1]),
                                ) {
                                    new_out.insert(dst, Some(src_val));
                                    total_propagated += 1;
                                } else if let (Some(dst), Some(src_reg)) = (
                                    Self::write_reg(&inst.operands[0]),
                                    Self::read_reg(&inst.operands[1]),
                                ) {
                                    let src_val = new_out.get(&src_reg).cloned().unwrap_or(None);
                                    new_out.insert(dst, src_val);
                                }
                            }
                        }
                        fox_ir::IROp::Add => {
                            if inst.operands.len() >= 2 {
                                if let (Some(dst), Some(imm)) = (
                                    Self::write_reg(&inst.operands[0]),
                                    Self::imm_val(&inst.operands[1]),
                                ) {
                                    let cur = new_out.get(&dst).cloned().unwrap_or(None);
                                    if let Some(cur_val) = cur {
                                        new_out.insert(dst, Some(cur_val.wrapping_add(imm)));
                                        total_propagated += 1;
                                    }
                                }
                            }
                        }
                        fox_ir::IROp::Sub => {
                            if inst.operands.len() >= 2 {
                                if let (Some(dst), Some(imm)) = (
                                    Self::write_reg(&inst.operands[0]),
                                    Self::imm_val(&inst.operands[1]),
                                ) {
                                    let cur = new_out.get(&dst).cloned().unwrap_or(None);
                                    if let Some(cur_val) = cur {
                                        new_out.insert(dst, Some(cur_val.wrapping_sub(imm)));
                                        total_propagated += 1;
                                    }
                                }
                            }
                        }
                        _ => {
                            // Non-constant instruction: kill destination constants
                            for reg in inst.all_writes() {
                                new_out.insert(reg.to_string(), None);
                            }
                        }
                    }
                }

                if new_in != *in_state.get(&id).unwrap() || new_out != *out_state.get(&id).unwrap()
                {
                    in_state.insert(id, new_in);
                    out_state.insert(id, new_out);
                    changed = true;
                }
            }
        }

        // Convert to output format
        let to_constants = |state: &State| -> Vec<ConstantValue> {
            state
                .iter()
                .filter_map(|(reg, val)| {
                    val.map(|v| ConstantValue {
                        value: v,
                        register: reg.clone(),
                        defined_at: 0,
                        confidence: 0.9,
                    })
                })
                .collect()
        };

        let in_constants: HashMap<usize, Vec<ConstantValue>> = in_state
            .iter()
            .map(|(k, v)| (*k, to_constants(v)))
            .collect();
        let out_constants: HashMap<usize, Vec<ConstantValue>> = out_state
            .iter()
            .map(|(k, v)| (*k, to_constants(v)))
            .collect();

        ConstantPropagationCfg {
            in_constants,
            out_constants,
            iterations,
            propagated_count: total_propagated,
        }
    }

    fn write_reg(op: &IROperand) -> Option<String> {
        match op {
            IROperand::Register { name, access, .. } => {
                if matches!(access, OperandAccess::Write | OperandAccess::ReadWrite) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn read_reg(op: &IROperand) -> Option<String> {
        match op {
            IROperand::Register { name, access, .. } => {
                if matches!(access, OperandAccess::Read | OperandAccess::ReadWrite) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn imm_val(op: &IROperand) -> Option<u64> {
        match op {
            IROperand::Immediate { value, .. } => Some(*value),
            _ => None,
        }
    }
}

// ============================================================================
// Combined CFG-aware Data Flow Result
// ============================================================================

/// Combined CFG-aware data flow analysis for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgDataFlowResult {
    pub function_address: u64,
    pub reaching_definitions: ReachingDefinitionsCfg,
    pub live_variables: LiveVariablesCfg,
    pub constant_propagation: ConstantPropagationCfg,
    pub evidence: Vec<Evidence>,
}

impl CfgDataFlowResult {
    /// Run all CFG-aware analyses on a function's CFG.
    ///
    /// `blocks`: slice of (block_id, instructions, predecessors, successors)
    pub fn analyze(
        function_address: u64,
        blocks: &[(usize, &[IRInstruction], &[usize], &[usize])],
        entry_block: usize,
    ) -> Self {
        let rd = ReachingDefinitionsCfg::compute(blocks, entry_block);
        let lv = LiveVariablesCfg::compute(blocks);
        let cp = ConstantPropagationCfg::compute(blocks, entry_block);

        let mut evidence = Vec::new();
        evidence.push(
            Evidence::new(EvidenceKind::DataFlowAnalysis)
                .with_address(function_address)
                .with_weight(0.9),
        );
        evidence.push(
            Evidence::new(EvidenceKind::Heuristic {
                description: format!(
                    "CFG-aware DF: RD={} iters, LV={} iters, CP={} iters, {} constants",
                    rd.iterations, lv.iterations, cp.iterations, cp.propagated_count
                ),
            })
            .with_weight(0.75),
        );

        CfgDataFlowResult {
            function_address,
            reaching_definitions: rd,
            live_variables: lv,
            constant_propagation: cp,
            evidence,
        }
    }
}

// ============================================================================
// Flow-insensitive versions (retained from P0-2 for backward compatibility)
// ============================================================================

/// Flow-insensitive reaching definitions (P0-2, retained for compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachingDefinitions {
    pub reaching: HashMap<u64, Vec<Definition>>,
    pub definitions: HashMap<String, Vec<u64>>,
}

impl ReachingDefinitions {
    pub fn compute(instructions: &[IRInstruction]) -> Self {
        let mut definitions: HashMap<String, Vec<u64>> = HashMap::new();
        let mut reaching: HashMap<u64, Vec<Definition>> = HashMap::new();

        for inst in instructions {
            for reg in inst.all_writes() {
                definitions
                    .entry(reg.to_string())
                    .or_default()
                    .push(inst.address.0);
            }
        }

        for inst in instructions {
            let mut defs = Vec::new();
            let mut seen = HashSet::new();
            for reg in inst.all_reads() {
                if let Some(addrs) = definitions.get(reg) {
                    for &addr in addrs {
                        if addr < inst.address.0 && seen.insert((reg.to_string(), addr)) {
                            defs.push(Definition {
                                block_id: 0,
                                inst_index: 0,
                                address: addr,
                                register: reg.to_string(),
                            });
                        }
                    }
                }
            }
            defs.sort_by_key(|d| (d.register.clone(), d.address));
            reaching.insert(inst.address.0, defs);
        }

        ReachingDefinitions {
            reaching,
            definitions,
        }
    }

    pub fn reaching_at(&self, address: u64) -> &[Definition] {
        self.reaching
            .get(&address)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// Flow-insensitive live variables (P0-2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVariables {
    pub live_after: HashMap<u64, Vec<String>>,
    pub live_before: HashMap<u64, Vec<String>>,
}

impl LiveVariables {
    pub fn compute(instructions: &[IRInstruction]) -> Self {
        let mut live_after: HashMap<u64, Vec<String>> = HashMap::new();
        let mut live_before: HashMap<u64, Vec<String>> = HashMap::new();
        let n = instructions.len();

        for i in (0..n).rev() {
            let inst = &instructions[i];
            let mut live: HashSet<String> = HashSet::new();
            for reg in inst.all_reads() {
                live.insert(reg.to_string());
            }
            for later in &instructions[i + 1..n] {
                for reg in later.all_reads() {
                    live.insert(reg.to_string());
                }
            }
            let mut live_vec: Vec<String> = live.into_iter().collect();
            live_vec.sort();
            live_after.insert(inst.address.0, live_vec.clone());
            let mut before: HashSet<String> = live_vec.iter().cloned().collect();
            for reg in inst.all_writes() {
                before.remove(reg);
            }
            for reg in inst.all_reads() {
                before.insert(reg.to_string());
            }
            let mut before_vec: Vec<String> = before.into_iter().collect();
            before_vec.sort();
            live_before.insert(inst.address.0, before_vec);
        }

        LiveVariables {
            live_after,
            live_before,
        }
    }
}

/// Flow-insensitive constant propagation (P0-2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstantPropagation {
    pub constants_at: HashMap<u64, Vec<ConstantValue>>,
    pub propagated_count: usize,
}

impl ConstantPropagation {
    pub fn compute(instructions: &[IRInstruction]) -> Self {
        let mut constants_at: HashMap<u64, Vec<ConstantValue>> = HashMap::new();
        let mut current: HashMap<String, ConstantValue> = HashMap::new();
        let mut propagated = 0usize;

        for inst in instructions {
            match inst.op {
                fox_ir::IROp::Mov => {
                    if inst.operands.len() >= 2 {
                        if let (Some(dst), Some(src)) = (
                            inst.operands[0].as_register_write(),
                            inst.operands[1].as_immediate(),
                        ) {
                            let cv = ConstantValue {
                                value: src,
                                register: dst.clone(),
                                defined_at: inst.address.0,
                                confidence: 0.95,
                            };
                            current.insert(dst, cv);
                            propagated += 1;
                        }
                    }
                }
                fox_ir::IROp::Add => {
                    if inst.operands.len() >= 2 {
                        if let (Some(dst), Some(imm)) = (
                            inst.operands[0].as_register_write(),
                            inst.operands[1].as_immediate(),
                        ) {
                            if let Some(existing) = current.get(&dst) {
                                let new_val = existing.value.wrapping_add(imm);
                                current.insert(
                                    dst.clone(),
                                    ConstantValue {
                                        value: new_val,
                                        register: dst.clone(),
                                        defined_at: inst.address.0,
                                        confidence: existing.confidence * 0.9,
                                    },
                                );
                                propagated += 1;
                            }
                        }
                    }
                }
                fox_ir::IROp::Sub => {
                    if inst.operands.len() >= 2 {
                        if let (Some(dst), Some(imm)) = (
                            inst.operands[0].as_register_write(),
                            inst.operands[1].as_immediate(),
                        ) {
                            if let Some(existing) = current.get(&dst) {
                                let new_val = existing.value.wrapping_sub(imm);
                                current.insert(
                                    dst.clone(),
                                    ConstantValue {
                                        value: new_val,
                                        register: dst.clone(),
                                        defined_at: inst.address.0,
                                        confidence: existing.confidence * 0.9,
                                    },
                                );
                                propagated += 1;
                            }
                        }
                    }
                }
                _ => {
                    for reg in inst.all_writes() {
                        current.remove(reg);
                    }
                }
            }
            let snapshot: Vec<ConstantValue> = current.values().cloned().collect();
            constants_at.insert(inst.address.0, snapshot);
        }

        ConstantPropagation {
            constants_at,
            propagated_count: propagated,
        }
    }
}

/// Flow-insensitive combined result (P0-2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowResult {
    pub function_address: u64,
    pub reaching_definitions: ReachingDefinitions,
    pub live_variables: LiveVariables,
    pub constant_propagation: ConstantPropagation,
    pub evidence: Vec<Evidence>,
}

impl DataFlowResult {
    pub fn analyze(function_address: u64, instructions: &[IRInstruction]) -> Self {
        let reaching = ReachingDefinitions::compute(instructions);
        let live = LiveVariables::compute(instructions);
        let constants = ConstantPropagation::compute(instructions);
        DataFlowResult {
            function_address,
            reaching_definitions: reaching,
            live_variables: live,
            constant_propagation: constants,
            evidence: vec![Evidence::new(EvidenceKind::DataFlowAnalysis).with_weight(0.85)],
        }
    }
}

// Helper trait extensions for IROperand
trait IROperandExt {
    fn as_register_write(&self) -> Option<String>;
    fn as_immediate(&self) -> Option<u64>;
}

impl IROperandExt for IROperand {
    fn as_register_write(&self) -> Option<String> {
        match self {
            IROperand::Register { name, access, .. } => {
                if matches!(access, OperandAccess::Write | OperandAccess::ReadWrite) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    fn as_immediate(&self) -> Option<u64> {
        match self {
            IROperand::Immediate { value, .. } => Some(*value),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_core::Address;
    use fox_ir::{IRInstruction, IROp, IROperand, OperandAccess};

    fn make_ir(
        addr: u64,
        op: IROp,
        operands: Vec<IROperand>,
        reads: Vec<&str>,
        writes: Vec<&str>,
    ) -> IRInstruction {
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
    }

    fn reg(name: &str, access: OperandAccess) -> IROperand {
        IROperand::Register {
            name: name.into(),
            width: 64,
            access,
        }
    }
    fn imm(v: u64) -> IROperand {
        IROperand::Immediate {
            value: v,
            width: 64,
            is_signed: false,
        }
    }

    #[test]
    fn test_cfg_reaching_definitions_if_else() {
        // block 0: x = 1; goto 1,2
        // block 1: x = 2; goto 3
        // block 2: x = 3; goto 3
        // block 3: use(x)
        let b0 = vec![make_ir(
            0x1000,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(1)],
            vec![],
            vec!["x"],
        )];
        let b1 = vec![make_ir(
            0x1010,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(2)],
            vec![],
            vec!["x"],
        )];
        let b2 = vec![make_ir(
            0x1020,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(3)],
            vec![],
            vec!["x"],
        )];
        let b3 = vec![make_ir(
            0x1030,
            IROp::Mov,
            vec![
                reg("y", OperandAccess::Write),
                reg("x", OperandAccess::Read),
            ],
            vec!["x"],
            vec!["y"],
        )];

        let blocks: Vec<(usize, &[IRInstruction], &[usize], &[usize])> = vec![
            (0, &b0, &[], &[1, 2]),
            (1, &b1, &[0], &[3]),
            (2, &b2, &[0], &[3]),
            (3, &b3, &[1, 2], &[]),
        ];

        let rd = ReachingDefinitionsCfg::compute(&blocks, 0);
        // At block 3 entry, both definitions of x (from b1 and b2) should reach
        let in3 = rd.in_sets.get(&3).unwrap();
        let x_defs: Vec<_> = in3.iter().filter(|d| d.register == "x").collect();
        assert_eq!(x_defs.len(), 2, "Both x definitions should reach block 3");
    }

    #[test]
    fn test_cfg_live_variables() {
        let b0 = vec![make_ir(
            0x1000,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(1)],
            vec![],
            vec!["x"],
        )];
        let b1 = vec![make_ir(
            0x1010,
            IROp::Mov,
            vec![
                reg("y", OperandAccess::Write),
                reg("x", OperandAccess::Read),
            ],
            vec!["x"],
            vec!["y"],
        )];

        let blocks: Vec<(usize, &[IRInstruction], &[usize], &[usize])> =
            vec![(0, &b0, &[], &[1]), (1, &b1, &[0], &[])];

        let lv = LiveVariablesCfg::compute(&blocks);
        // x should be live-out of block 0 (used in block 1)
        let out0 = lv.out_sets.get(&0).unwrap();
        assert!(out0.contains(&"x".to_string()));
    }

    #[test]
    fn test_cfg_constant_propagation_join() {
        // b0: x=1 -> b1,b2
        // b1: x=2 -> b3
        // b2: x=3 -> b3
        // b3: x is overdefined (different constants from b1 and b2)
        let b0 = vec![make_ir(
            0x1000,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(1)],
            vec![],
            vec!["x"],
        )];
        let b1 = vec![make_ir(
            0x1010,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(2)],
            vec![],
            vec!["x"],
        )];
        let b2 = vec![make_ir(
            0x1020,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(3)],
            vec![],
            vec!["x"],
        )];
        let b3 = vec![make_ir(
            0x1030,
            IROp::Mov,
            vec![
                reg("y", OperandAccess::Write),
                reg("x", OperandAccess::Read),
            ],
            vec!["x"],
            vec!["y"],
        )];

        let blocks: Vec<(usize, &[IRInstruction], &[usize], &[usize])> = vec![
            (0, &b0, &[], &[1, 2]),
            (1, &b1, &[0], &[3]),
            (2, &b2, &[0], &[3]),
            (3, &b3, &[1, 2], &[]),
        ];

        let cp = ConstantPropagationCfg::compute(&blocks, 0);
        // At block 3 entry, x should be overdefined (not constant) because b1 and b2 disagree
        let in3 = cp.in_constants.get(&3).unwrap();
        let x_const = in3.iter().find(|c| c.register == "x");
        assert!(
            x_const.is_none(),
            "x should be overdefined at join of different constants"
        );
    }

    #[test]
    fn test_cfg_constant_propagation_same_constant() {
        // b0: x=1 -> b1,b2
        // b1: (no x write) -> b3
        // b2: (no x write) -> b3
        // b3: x should still be 1
        let b0 = vec![make_ir(
            0x1000,
            IROp::Mov,
            vec![reg("x", OperandAccess::Write), imm(1)],
            vec![],
            vec!["x"],
        )];
        let b1 = vec![make_ir(0x1010, IROp::Nop, vec![], vec![], vec![])];
        let b2 = vec![make_ir(0x1020, IROp::Nop, vec![], vec![], vec![])];
        let b3 = vec![make_ir(
            0x1030,
            IROp::Mov,
            vec![
                reg("y", OperandAccess::Write),
                reg("x", OperandAccess::Read),
            ],
            vec!["x"],
            vec!["y"],
        )];

        let blocks: Vec<(usize, &[IRInstruction], &[usize], &[usize])> = vec![
            (0, &b0, &[], &[1, 2]),
            (1, &b1, &[0], &[3]),
            (2, &b2, &[0], &[3]),
            (3, &b3, &[1, 2], &[]),
        ];

        let cp = ConstantPropagationCfg::compute(&blocks, 0);
        let in3 = cp.in_constants.get(&3).unwrap();
        let x_const = in3.iter().find(|c| c.register == "x");
        assert!(
            x_const.is_some(),
            "x should be constant at join of same constant"
        );
        assert_eq!(x_const.unwrap().value, 1);
    }
}
