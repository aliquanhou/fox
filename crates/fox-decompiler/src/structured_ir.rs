//! P0-6.6A: Decompiler Structured IR
//!
//! Aggregates existing analysis results (Expression, Condition, Control
//! Structure) into a unified DecompilerFunction -> Vec<Statement> model.
//!
//! This is a CONSUMER layer: it reads existing sealed analysis data and
//! produces structured statements. It does NOT modify CFG, SSA, Memory SSA,
//! Expression Recovery, Condition Recovery, or Function Reality.
//!
//! Key principles:
//! - Unknown is a first-class statement (never fabricate if/else)
//! - Every statement has Evidence tracing back to instructions/blocks
//! - Placeholder variables are marked as SSAPlaceholder (not "real variables")
//! - Resource budget from day one (no OOM/stack overflow on large functions)
//! - CallStmt does NOT recover arguments (that's a later phase)

use fox_analysis::cfg::FunctionCfg;
use fox_analysis::ssa::SSAFunction;
use fox_core::EdgeKind;

use crate::condition::ConditionRecovery;
use crate::control_structure::{ControlStructure, StructureEvidence};
use crate::expression::{CallTarget, Expression, ExpressionRecovery, PhiIncoming};

// ---------------------------------------------------------------------------
// Data Model
// ---------------------------------------------------------------------------

/// A decompiled function with structured statements.
#[derive(Debug, Clone)]
pub struct DecompilerFunction {
    /// Function address.
    pub address: u64,
    /// Function name (if known from symbols/imports).
    pub name: Option<String>,
    /// Top-level statements in control-flow order.
    pub statements: Vec<Statement>,
    /// Evidence for the function as a whole.
    pub evidence: FunctionEvidence,
}

/// A single structured statement.
#[derive(Debug, Clone)]
pub enum Statement {
    /// Assignment: lhs = rhs
    Assign {
        lhs: AssignTarget,
        rhs: Expression,
        evidence: StatementEvidence,
    },
    /// if (condition) { then } else { else } [-> merge]
    If {
        condition: ConditionRecovery,
        then_body: Vec<Statement>,
        else_body: Vec<Statement>,
        merge_block: Option<usize>,
        evidence: StatementEvidence,
    },
    /// if (condition) { return ... };  // guard clause / early return
    GuardClause {
        condition: ConditionRecovery,
        body: Vec<Statement>,
        return_value: Option<Expression>,
        evidence: StatementEvidence,
    },
    /// return [value];
    Return {
        value: Option<Expression>,
        evidence: StatementEvidence,
    },
    /// call target(args);  // as statement
    CallStmt {
        target: CallTarget,
        /// Recovered arguments (from PUSH instructions before call).
        /// Empty = no arguments recovered (not necessarily zero args).
        arguments: Vec<Expression>,
        /// Whether arguments are known to be complete (all PUSHes found).
        arguments_complete: bool,
        /// P0-7.2.1: Call behavior annotation (return value consumer).
        behavior: Option<CallBehavior>,
        evidence: StatementEvidence,
    },
    /// Unstructured control flow: /* reason */ goto target;
    Unknown {
        reason: String,
        condition: Option<ConditionRecovery>,
        goto_target: Option<u64>,
        evidence: StatementEvidence,
    },
    /// Phi node assignment (SSA phi, may be elided by emitter).
    PhiAssign {
        lhs: AssignTarget,
        incoming: Vec<PhiIncoming>,
        evidence: StatementEvidence,
    },
}

/// Assignment target.
#[derive(Debug, Clone)]
pub enum AssignTarget {
    /// SSA variable (register with version). Origin: SSAPlaceholder.
    Variable {
        name: String,
        version: u32,
        /// Explicitly marks this as a placeholder, not a recovered variable.
        origin: VariableOrigin,
    },
    /// Memory location (stack offset, etc.).
    Memory { address: Box<Expression> },
    /// Unknown / not recoverable.
    Unknown,
}

/// Where a variable name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableOrigin {
    /// SSA placeholder (register name + version). NOT a recovered variable.
    SSAPlaceholder,
    /// Future: recovered from stack analysis (not implemented in P0-6.6A).
    #[allow(dead_code)]
    Recovered,
}

/// Evidence for a single statement.
#[derive(Debug, Clone)]
pub struct StatementEvidence {
    /// Source instruction addresses (may be multiple).
    pub instruction_addresses: Vec<u64>,
    /// Source CFG block IDs.
    pub block_ids: Vec<usize>,
    /// Human-readable detection rationale.
    pub reason: String,
}

/// Evidence for the function as a whole.
#[derive(Debug, Clone)]
pub struct FunctionEvidence {
    /// Number of SSA instructions processed.
    pub ssa_instructions: usize,
    /// Number of CFG blocks processed.
    pub cfg_blocks: usize,
    /// Number of control structures recovered.
    pub control_structures: usize,
    /// Number of unknown/unstructured statements.
    pub unknown_statements: usize,
    /// Whether resource budget was hit (truncation occurred).
    pub budget_exhausted: bool,
}

/// P0-7.2.1: Call behavior annotation.
///
/// Describes what happens to the call's return value (eax) after the call.
/// This is a Consumer Layer — it only organizes existing SSA/Condition facts,
/// it does not infer business semantics.
#[derive(Debug, Clone)]
pub enum CallBehavior {
    /// Return value used in a condition: call → test/cmp eax → CondJump.
    ReturnUsedInCondition {
        /// Recovered condition (from P0-6.3A ConditionRecovery).
        condition: crate::condition::ConditionRecovery,
        /// Address of the FLAGS-producing instruction (test/cmp).
        consumer_instruction: u64,
        /// Address of the conditional jump.
        branch_instruction: u64,
    },
    /// Return value used by a non-branch instruction (mov, push, add, etc.).
    ReturnUsedByInstruction {
        /// Address of the instruction consuming eax.
        consumer_instruction: u64,
        /// Op name of the consumer instruction.
        consumer_op: String,
    },
    /// Return value has no consumer within the scan window.
    NoConsumer,
}

// ---------------------------------------------------------------------------
// Resource Budget
// ---------------------------------------------------------------------------

/// Resource budget for structured IR construction.
#[derive(Debug, Clone)]
pub struct StructuredIRBudget {
    /// Maximum total statements (top-level + nested).
    pub max_statements: usize,
    /// Maximum nesting depth for If/GuardClause bodies.
    pub max_depth: usize,
    /// Current statement count (shared across all recursion).
    current_statements: usize,
    /// Whether budget was exhausted.
    exhausted: bool,
}

impl Default for StructuredIRBudget {
    fn default() -> Self {
        Self {
            max_statements: 5000,
            max_depth: 32,
            current_statements: 0,
            exhausted: false,
        }
    }
}

impl StructuredIRBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to allocate one statement. Returns false if budget exhausted.
    fn allocate(&mut self) -> bool {
        if self.current_statements >= self.max_statements {
            self.exhausted = true;
            return false;
        }
        self.current_statements += 1;
        true
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builds structured IR from existing analysis results.
pub struct StructuredIRBuilder {
    expr_engine: ExpressionRecovery,
    budget: StructuredIRBudget,
    /// P0-6.10: Resolved call targets from CallGraph, keyed by call instruction address.
    call_targets: Option<std::collections::HashMap<u64, CallTarget>>,
}

impl Default for StructuredIRBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StructuredIRBuilder {
    pub fn new() -> Self {
        Self {
            expr_engine: ExpressionRecovery::new(),
            budget: StructuredIRBudget::new(),
            call_targets: None,
        }
    }

    pub fn with_budget(mut self, budget: StructuredIRBudget) -> Self {
        self.budget = budget;
        self
    }

    /// P0-6.10: Provide resolved call targets from CallGraph.
    /// Key = call instruction address, Value = resolved CallTarget.
    pub fn with_call_targets(
        mut self,
        targets: std::collections::HashMap<u64, CallTarget>,
    ) -> Self {
        self.call_targets = Some(targets);
        self
    }

    /// Build structured IR for a single function.
    pub fn build(
        &mut self,
        cfg: &FunctionCfg,
        ssa: &SSAFunction,
        control_structures: Vec<ControlStructure>,
    ) -> DecompilerFunction {
        let total_ssa_instrs: usize = ssa.basic_blocks.iter().map(|b| b.instructions.len()).sum();

        // Phase 1: Build flat statement list per CFG block
        let mut block_statements: std::collections::HashMap<usize, Vec<Statement>> =
            std::collections::HashMap::new();

        for (block_id, cfg_block) in cfg.blocks.iter().enumerate() {
            let mut stmts = Vec::new();

            // Find corresponding SSA block
            if let Some(ssa_block) = ssa.basic_blocks.get(block_id) {
                // Phi nodes
                for phi in &ssa_block.phi_nodes {
                    if !self.budget.allocate() {
                        break;
                    }
                    let incoming: Vec<PhiIncoming> = phi
                        .incoming
                        .iter()
                        .map(|(pred_block, version)| PhiIncoming {
                            block_id: *pred_block,
                            value: Box::new(Expression::Variable {
                                name: phi.variable.clone(),
                                version: *version,
                            }),
                        })
                        .collect();
                    stmts.push(Statement::PhiAssign {
                        lhs: AssignTarget::Variable {
                            name: phi.variable.clone(),
                            version: phi.result_version,
                            origin: VariableOrigin::SSAPlaceholder,
                        },
                        incoming,
                        evidence: StatementEvidence {
                            instruction_addresses: vec![ssa_block.start_address],
                            block_ids: vec![block_id],
                            reason: format!(
                                "SSA phi node for {} ({} incoming)",
                                phi.variable,
                                phi.incoming.len()
                            ),
                        },
                    });
                }

                // Instructions
                for (inst_idx, inst) in ssa_block.instructions.iter().enumerate() {
                    if self.budget.is_exhausted() {
                        break;
                    }

                    // Call instruction -> CallStmt
                    if inst.op == "Call" {
                        if !self.budget.allocate() {
                            break;
                        }
                        let target = self.extract_call_target(inst);
                        let (arguments, args_complete) =
                            self.recover_call_arguments(ssa, block_id, inst_idx);
                        let behavior = self.detect_call_behavior(ssa, block_id, inst_idx);
                        stmts.push(Statement::CallStmt {
                            target,
                            arguments,
                            arguments_complete: args_complete,
                            behavior,
                            evidence: StatementEvidence {
                                instruction_addresses: vec![inst.address],
                                block_ids: vec![block_id],
                                reason: format!("Call instruction ({})", inst.original_mnemonic),
                            },
                        });
                        continue;
                    }

                    // Instruction with destination -> Assign
                    if inst.destination_operand_idx.is_some() {
                        if !self.budget.allocate() {
                            break;
                        }
                        let expr = self.expr_engine.recover_definition(ssa, block_id, inst_idx);
                        let lhs = self.extract_destination(inst);
                        stmts.push(Statement::Assign {
                            lhs,
                            rhs: expr,
                            evidence: StatementEvidence {
                                instruction_addresses: vec![inst.address],
                                block_ids: vec![block_id],
                                reason: format!(
                                    "SSA definition from {} (op={})",
                                    inst.original_mnemonic, inst.op
                                ),
                            },
                        });
                    }
                }
            }

            // Return edge -> Return statement
            for edge in &cfg_block.successors {
                if edge.kind == EdgeKind::Return {
                    if !self.budget.allocate() {
                        break;
                    }
                    let ret_val = self.expr_engine.recover_return_value(ssa);
                    stmts.push(Statement::Return {
                        value: ret_val,
                        evidence: StatementEvidence {
                            instruction_addresses: vec![edge.source_instruction],
                            block_ids: vec![block_id],
                            reason: "CFG Return edge".to_string(),
                        },
                    });
                }
            }

            if !stmts.is_empty() {
                block_statements.insert(block_id, stmts);
            }
        }

        // Phase 2: Build control structure map (branch_block -> Statement).
        // Do NOT push to top_level yet — we need BFS execution order (P0-6.8 fix).
        let mut branch_to_structure: std::collections::HashMap<usize, Statement> =
            std::collections::HashMap::new();
        let mut structure_body_blocks: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let cs_count = control_structures.len();

        for cs in &control_structures {
            if self.budget.is_exhausted() {
                break;
            }
            match cs {
                ControlStructure::IfElse(if_else) => {
                    let then_body =
                        self.take_block_statements(&mut block_statements, if_else.then_block);
                    let else_body =
                        self.take_block_statements(&mut block_statements, if_else.else_block);
                    structure_body_blocks.insert(if_else.then_block);
                    structure_body_blocks.insert(if_else.else_block);

                    if self.budget.allocate() {
                        branch_to_structure.insert(
                            if_else.branch_block,
                            Statement::If {
                                condition: if_else.condition.clone(),
                                then_body,
                                else_body,
                                merge_block: if_else.merge_block,
                                evidence: Self::structure_evidence(
                                    &if_else.evidence,
                                    "If/Else with bounded common merge",
                                ),
                            },
                        );
                    }
                }
                ControlStructure::GuardClause(guard) => {
                    let body = self.take_block_statements(&mut block_statements, guard.body_block);
                    let return_value = self.extract_return_from_block(cfg, ssa, guard.return_block);
                    structure_body_blocks.insert(guard.body_block);
                    structure_body_blocks.insert(guard.return_block);

                    if self.budget.allocate() {
                        branch_to_structure.insert(
                            guard.branch_block,
                            Statement::GuardClause {
                                condition: guard.condition.clone(),
                                body,
                                return_value,
                                evidence: Self::structure_evidence(
                                    &guard.evidence,
                                    "Guard clause / early return (immediate CFG Return edge)",
                                ),
                            },
                        );
                    }
                }
                ControlStructure::Unknown(unknown) => {
                    let goto_target = Self::find_goto_target(cfg, unknown.branch_block);

                    if self.budget.allocate() {
                        branch_to_structure.insert(
                            unknown.branch_block,
                            Statement::Unknown {
                                reason: unknown.reason.clone(),
                                condition: Some(unknown.condition.clone()),
                                goto_target,
                                evidence: Self::structure_evidence(
                                    &unknown.evidence,
                                    &format!("Unstructured control flow: {}", unknown.reason),
                                ),
                            },
                        );
                    }
                }
            }
        }

        // Build address -> block_id map for BFS traversal
        let mut address_to_block: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::new();
        for (id, block) in cfg.blocks.iter().enumerate() {
            address_to_block.insert(block.start_address.0, id);
        }

        // Phase 3: BFS from entry block (block 0), output in execution order.
        // P0-6.8 fix: previously control structures were output before entry block code.
        let mut top_level: Vec<Statement> = Vec::new();
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();

        if !cfg.blocks.is_empty() {
            queue.push_back(0);
        }

        while let Some(block_id) = queue.pop_front() {
            if visited.contains(&block_id) {
                continue;
            }
            visited.insert(block_id);

            if let Some(struct_stmt) = branch_to_structure.get(&block_id) {
                // Branch block: output its own flat statements first (CMP/TEST etc.),
                // then output the control structure (if/guard/unknown from Jcc).
                if let Some(stmts) = block_statements.get(&block_id) {
                    for s in stmts {
                        if self.budget.allocate() {
                            top_level.push(s.clone());
                        } else {
                            break;
                        }
                    }
                }
                top_level.push(struct_stmt.clone());
            } else if !structure_body_blocks.contains(&block_id) {
                // Normal block: output its flat statements
                if let Some(stmts) = block_statements.get(&block_id) {
                    for s in stmts {
                        if self.budget.allocate() {
                            top_level.push(s.clone());
                        } else {
                            break;
                        }
                    }
                }
            }

            // Add successors to BFS queue
            if let Some(block) = cfg.blocks.get(block_id) {
                for edge in &block.successors {
                    if let Some(target_addr) = edge.target_address {
                        if let Some(&target_id) = address_to_block.get(&target_addr) {
                            if !visited.contains(&target_id) {
                                queue.push_back(target_id);
                            }
                        }
                    }
                }
            }
        }

        // Phase 4: Append unreachable blocks (not visited, not body blocks) in address order
        let mut remaining_blocks: Vec<(usize, u64)> = cfg
            .blocks
            .iter()
            .enumerate()
            .filter(|(id, _)| !visited.contains(id) && !structure_body_blocks.contains(id))
            .map(|(id, b)| (id, b.start_address.0))
            .collect();
        remaining_blocks.sort_by_key(|(_, addr)| *addr);

        for (block_id, _) in remaining_blocks {
            if let Some(stmts) = block_statements.get(&block_id) {
                for stmt in stmts {
                    if self.budget.allocate() {
                        top_level.push(stmt.clone());
                    } else {
                        break;
                    }
                }
            }
        }

        // Count unknown statements
        let unknown_count = top_level
            .iter()
            .filter(|s| matches!(s, Statement::Unknown { .. }))
            .count();

        DecompilerFunction {
            address: cfg.function_address.0,
            name: if cfg.function_name.is_empty() {
                None
            } else {
                Some(cfg.function_name.clone())
            },
            statements: top_level,
            evidence: FunctionEvidence {
                ssa_instructions: total_ssa_instrs,
                cfg_blocks: cfg.blocks.len(),
                control_structures: cs_count,
                unknown_statements: unknown_count,
                budget_exhausted: self.budget.is_exhausted(),
            },
        }
    }

    // --- Helper methods ---

    fn take_block_statements(
        &self,
        block_statements: &mut std::collections::HashMap<usize, Vec<Statement>>,
        block_id: usize,
    ) -> Vec<Statement> {
        block_statements.remove(&block_id).unwrap_or_default()
    }

    fn extract_destination(&self, inst: &fox_analysis::ssa::SSAInstruction) -> AssignTarget {
        if let Some(idx) = inst.destination_operand_idx {
            if let Some(op) = inst.operands.get(idx) {
                match op {
                    fox_analysis::ssa::SSAOperand::Variable { name, version } => {
                        return AssignTarget::Variable {
                            name: name.clone(),
                            version: *version,
                            origin: VariableOrigin::SSAPlaceholder,
                        };
                    }
                    fox_analysis::ssa::SSAOperand::Memory { description } => {
                        return AssignTarget::Memory {
                            address: Box::new(Expression::Unknown {
                                reason: format!("memory address: {}", description),
                            }),
                        };
                    }
                    _ => {}
                }
            }
        }
        AssignTarget::Unknown
    }

    fn extract_call_target(&self, inst: &fox_analysis::ssa::SSAInstruction) -> CallTarget {
        // P0-6.10: First check CallGraph-resolved targets (most reliable).
        if let Some(ref targets) = self.call_targets {
            if let Some(t) = targets.get(&inst.address) {
                return t.clone();
            }
        }
        // Fallback: try to find target from SSA operands.
        for op in &inst.operands {
            match op {
                fox_analysis::ssa::SSAOperand::Label(s) => {
                    // Try to parse as hex address
                    if let Ok(addr) = u64::from_str_radix(s.trim_start_matches("0x"), 16) {
                        return CallTarget::Address(addr);
                    }
                    return CallTarget::Symbol(s.clone());
                }
                fox_analysis::ssa::SSAOperand::Constant(v) => return CallTarget::Address(*v),
                _ => {}
            }
        }
        CallTarget::Unknown
    }

    /// P0-6.10: Recover call arguments from PUSH instructions immediately before
    /// the call in the same basic block. Only reliable for cdecl/stdcall stack args.
    /// Returns (arguments, complete). complete=true means all preceding PUSHes
    /// were recovered; false means some were skipped/truncated.
    fn recover_call_arguments(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        call_idx: usize,
    ) -> (Vec<Expression>, bool) {
        let block = match ssa.basic_blocks.get(block_id) {
            Some(b) => b,
            None => return (Vec::new(), false),
        };

        // Walk backwards from the call instruction, collecting consecutive PUSHes.
        // Stop at any non-PUSH instruction (except NOP/align padding).
        let mut push_indices: Vec<usize> = Vec::new();
        let mut i = call_idx;
        while i > 0 {
            i -= 1;
            let prev = &block.instructions[i];
            if prev.op == "Push" {
                push_indices.push(i);
            } else if prev.op == "Nop" {
                continue; // skip padding
            } else {
                break;
            }
        }

        if push_indices.is_empty() {
            return (Vec::new(), false);
        }

        // PUSHes are collected backwards from call: closest PUSH = first arg.
        // This is already the correct C-like argument order (arg1, arg2, arg3).
        // DO NOT reverse — that would produce (arg3, arg2, arg1).
        // P0-6.10 Independent Audit: reverse() was a P1 bug, now removed.

        // Limit to 8 args to avoid explosion.
        let max_args = 8;
        let complete = push_indices.len() <= max_args;
        let args: Vec<Expression> = push_indices
            .iter()
            .take(max_args)
            .map(|&idx| {
                // P0-6.11: Use recover_use() to get the PUSH source operand (the
                // value being pushed), NOT recover_definition() which asks what
                // the PUSH instruction defines (ESP/memory → always Unknown).
                self.expr_engine.recover_use(ssa, block_id, idx, 0)
            })
            // P0-6.10: Filter out Unknown expressions — if we can't recover
            // the pushed value, don't pretend it's an argument.
            .filter(|e| !matches!(e, Expression::Unknown { .. }))
            .collect();

        // If we filtered out args, they're not complete.
        let complete = complete && args.len() == push_indices.len().min(max_args);

        (args, complete)
    }

    /// P0-7.2.1: Detect what happens to the call's return value (eax).
    ///
    /// Scans forward from the call instruction in the same basic block,
    /// looking for the first instruction that uses eax.
    ///
    /// This is a Consumer Layer — it only organizes existing SSA facts.
    /// It does NOT infer business semantics or guess API behavior.
    fn detect_call_behavior(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
    ) -> Option<CallBehavior> {
        let block = ssa.basic_blocks.get(block_id)?;
        // Scan forward up to 8 instructions
        let scan_limit = (inst_idx + 9).min(block.instructions.len());

        for i in (inst_idx + 1)..scan_limit {
            let inst = &block.instructions[i];

            // Check if this instruction uses eax (the return register)
            let uses_eax = inst.operands.iter().any(|op| {
                matches!(op, fox_analysis::ssa::SSAOperand::Variable { name, .. } if name == "eax")
            });
            if !uses_eax {
                continue;
            }

            // Case A: test/cmp eax → CondJump (return used in condition)
            if (inst.op == "Test" || inst.op == "Cmp")
                && i + 1 < block.instructions.len()
                && block.instructions[i + 1].op == "CondJump"
            {
                let condition = crate::condition::recover_condition(ssa, block_id, i + 1);
                return Some(CallBehavior::ReturnUsedInCondition {
                    condition,
                    consumer_instruction: inst.address,
                    branch_instruction: block.instructions[i + 1].address,
                });
            }

            // Case B: return value used by a regular instruction
            return Some(CallBehavior::ReturnUsedByInstruction {
                consumer_instruction: inst.address,
                consumer_op: inst.op.clone(),
            });
        }

        // No consumer found in scan window
        Some(CallBehavior::NoConsumer)
    }

    fn extract_return_from_block(
        &self,
        cfg: &FunctionCfg,
        ssa: &SSAFunction,
        block_id: usize,
    ) -> Option<Expression> {
        // Check if this block has a Return edge
        if let Some(block) = cfg.blocks.get(block_id) {
            for edge in &block.successors {
                if edge.kind == EdgeKind::Return {
                    return self.expr_engine.recover_return_value(ssa);
                }
            }
        }
        None
    }

    fn find_goto_target(cfg: &FunctionCfg, branch_block: usize) -> Option<u64> {
        // For unknown control structures, find the fallthrough target
        if let Some(block) = cfg.blocks.get(branch_block) {
            for edge in &block.successors {
                if edge.kind == EdgeKind::Fallthrough || edge.kind == EdgeKind::ConditionalFalse {
                    return edge.target_address;
                }
            }
        }
        None
    }

    fn structure_evidence(se: &StructureEvidence, reason: &str) -> StatementEvidence {
        let mut addrs = vec![se.branch_address];
        if let Some(merge) = se.merge_address {
            addrs.push(merge);
        }
        StatementEvidence {
            instruction_addresses: addrs,
            block_ids: vec![],
            reason: reason.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Display (for debugging / dogfood output)
// ---------------------------------------------------------------------------

impl std::fmt::Display for DecompilerFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.name.as_deref().unwrap_or("unknown");
        writeln!(f, "// Function @ 0x{:X} ({})", self.address, name)?;
        writeln!(
            f,
            "// SSA instrs: {}, CFG blocks: {}, CS: {}, Unknown: {}, Budget: {}",
            self.evidence.ssa_instructions,
            self.evidence.cfg_blocks,
            self.evidence.control_structures,
            self.evidence.unknown_statements,
            if self.evidence.budget_exhausted {
                "EXHAUSTED"
            } else {
                "ok"
            }
        )?;
        writeln!(f, "void func_{:X}() {{", self.address)?;
        for stmt in &self.statements {
            Self::fmt_statement(f, stmt, 1)?;
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl DecompilerFunction {
    fn fmt_statement(
        f: &mut std::fmt::Formatter<'_>,
        stmt: &Statement,
        depth: usize,
    ) -> std::fmt::Result {
        let indent = "  ".repeat(depth);
        match stmt {
            Statement::Assign { lhs, rhs, .. } => {
                writeln!(f, "{}{} = {};", indent, Self::fmt_target(lhs), rhs)
            }
            Statement::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                writeln!(f, "{}if ({}) {{", indent, Self::fmt_condition(condition))?;
                for s in then_body {
                    Self::fmt_statement(f, s, depth + 1)?;
                }
                if !else_body.is_empty() {
                    writeln!(f, "{}}} else {{", indent)?;
                    for s in else_body {
                        Self::fmt_statement(f, s, depth + 1)?;
                    }
                }
                writeln!(f, "{}}}", indent)
            }
            Statement::GuardClause {
                condition,
                body,
                return_value,
                ..
            } => {
                writeln!(f, "{}if ({}) {{", indent, Self::fmt_condition(condition))?;
                for s in body {
                    Self::fmt_statement(f, s, depth + 1)?;
                }
                if let Some(val) = return_value {
                    writeln!(f, "{}  return {};", indent, val)?;
                } else {
                    writeln!(f, "{}  return;", indent)?;
                }
                writeln!(f, "{}}}", indent)
            }
            Statement::Return { value, .. } => {
                if let Some(val) = value {
                    writeln!(f, "{}return {};", indent, val)
                } else {
                    writeln!(f, "{}return;", indent)
                }
            }
            Statement::CallStmt {
                target,
                arguments,
                arguments_complete,
                behavior,
                ..
            } => {
                let args_str: Vec<String> = arguments.iter().map(|a| format!("{}", a)).collect();
                let args_display = if arguments.is_empty() {
                    if *arguments_complete {
                        "".to_string()
                    } else {
                        "/* arguments unresolved */".to_string()
                    }
                } else if *arguments_complete {
                    args_str.join(", ")
                } else {
                    format!("{}, ...", args_str.join(", "))
                };
                let behavior_comment = match behavior {
                    Some(CallBehavior::ReturnUsedInCondition { .. }) => {
                        " /* return used in condition */"
                    }
                    Some(CallBehavior::ReturnUsedByInstruction { consumer_op, .. }) => {
                        &format!(" /* return consumed by {} */", consumer_op)
                    }
                    Some(CallBehavior::NoConsumer) => " /* return unused */",
                    None => "",
                };
                writeln!(
                    f,
                    "{}{}({});{}",
                    indent,
                    Self::fmt_call_target(target),
                    args_display,
                    behavior_comment
                )
            }
            Statement::Unknown {
                reason,
                goto_target,
                ..
            } => {
                if let Some(addr) = goto_target {
                    writeln!(f, "{}/* FOX: {} */ goto loc_{:X};", indent, reason, addr)
                } else {
                    writeln!(f, "{}/* FOX: {} */", indent, reason)
                }
            }
            Statement::PhiAssign { lhs, incoming, .. } => {
                let inc: Vec<String> = incoming
                    .iter()
                    .map(|p| format!("{}@blk{}", p.value, p.block_id))
                    .collect();
                writeln!(
                    f,
                    "{}{} = phi({}); /* SSA phi */",
                    indent,
                    Self::fmt_target(lhs),
                    inc.join(", ")
                )
            }
        }
    }

    fn fmt_target(t: &AssignTarget) -> String {
        match t {
            AssignTarget::Variable { name, version, .. } => format!("{}.v{}", name, version),
            AssignTarget::Memory { address } => format!("*({})", address),
            AssignTarget::Unknown => "?".to_string(),
        }
    }

    fn fmt_call_target(t: &CallTarget) -> String {
        match t {
            CallTarget::Address(addr) => format!("call_{:X}", addr),
            CallTarget::Symbol(name) => name.clone(),
            CallTarget::Unknown => "call_unknown".to_string(),
        }
    }

    fn fmt_condition(c: &ConditionRecovery) -> String {
        match c {
            ConditionRecovery::Resolved(cond) => format!("{}", cond),
            ConditionRecovery::ProducerNotCmpTest { producer_op, .. } => {
                format!("/* condition from {} (not CMP/TEST) */", producer_op)
            }
            ConditionRecovery::ProducerNotFound { .. } => {
                "/* condition: FLAGS producer not found */".to_string()
            }
            ConditionRecovery::NotConditionalJump => "/* not a conditional jump */".to_string(),
        }
    }
}
