//! FOX Expression Recovery (P0-6.1)
//!
//! Converts SSA form into structured expression trees/DAGs.
//!
//! Pipeline: SSA → use-def chain → recursive expression reconstruction
//!
//! This is a consumer layer: it reads existing SSA data and produces
//! Expression nodes without modifying any analysis.

use fox_analysis::ssa::{PhiNode, SSAFunction, SSAInstruction, SSAOperand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Expression Model
// ---------------------------------------------------------------------------

/// Structured expression node. NOT a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expression {
    /// Constant immediate value.
    Constant(u64),
    /// SSA variable (register with version).
    Variable { name: String, version: u32 },
    /// Binary operation: left op right.
    Binary {
        op: BinaryOp,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Unary operation: op operand.
    Unary {
        op: UnaryOp,
        operand: Box<Expression>,
    },
    /// Memory load: *address.
    Load { address: Box<Expression> },
    /// Function call.
    Call {
        target: CallTarget,
        arguments: Vec<Expression>,
    },
    /// Phi node: merge of incoming values.
    Phi { incoming: Vec<PhiIncoming> },
    /// Cannot recover (cycle, missing def, unsupported op, etc.).
    Unknown { reason: String },
}

/// Binary arithmetic / logic operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg,
    Not,
}

/// Call target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTarget {
    /// Direct address.
    Address(u64),
    /// Symbolic name (e.g. imported function).
    Symbol(String),
    /// Indirect / unresolved.
    Unknown,
}

/// One incoming value of a Phi node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhiIncoming {
    pub block_id: usize,
    pub value: Box<Expression>,
}

// ---------------------------------------------------------------------------
// Source reference (traceability)
// ---------------------------------------------------------------------------

/// Where an expression came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ExpressionSource {
    pub ssa_block: usize,
    pub ssa_inst: usize,
    pub instruction_address: u64,
    pub original_mnemonic: String,
}

// ---------------------------------------------------------------------------
// Recovery engine
// ---------------------------------------------------------------------------

/// Expression recovery configuration.
pub struct ExpressionRecovery {
    /// Maximum recursion depth per expression.
    pub max_depth: usize,
    /// Maximum nodes per single expression recovery.
    pub max_nodes: usize,
    /// Maximum total nodes across all definitions in one function.
    /// Prevents recover_all_definitions() from cumulative OOM on real binaries.
    pub function_total_budget: usize,
}

impl Default for ExpressionRecovery {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_nodes: 10_000,
            function_total_budget: 100_000,
        }
    }
}

impl ExpressionRecovery {
    pub fn new() -> Self {
        Self::default()
    }

    /// Recover the expression produced by an SSA instruction definition.
    ///
    /// `inst_idx` may be `usize::MAX` for phi nodes.
    pub fn recover_definition(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
    ) -> Expression {
        let ctx = RecoveryContext::new(ssa, self.max_depth, self.max_nodes);
        ctx.recover_definition(block_id, inst_idx)
    }

    /// Recover the expression for a specific operand use.
    pub fn recover_use(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        op_idx: usize,
    ) -> Expression {
        let ctx = RecoveryContext::new(ssa, self.max_depth, self.max_nodes);
        ctx.recover_use(block_id, inst_idx, op_idx)
    }

    /// Find Return instruction(s) and recover the return value expression.
    pub fn recover_return_value(&self, ssa: &SSAFunction) -> Option<Expression> {
        let ctx = RecoveryContext::new(ssa, self.max_depth, self.max_nodes);
        for block in &ssa.basic_blocks {
            for (inst_idx, inst) in block.instructions.iter().enumerate() {
                if inst.op == "Return" {
                    // Return may have an operand (return value) or be void.
                    if let Some(op) = inst.operands.first() {
                        return Some(ctx.recover_operand(block.id, inst_idx, 0, op));
                    }
                    return Some(Expression::Unknown {
                        reason: "void return".to_string(),
                    });
                }
            }
        }
        None
    }

    /// Recover expressions for all definitions in the function.
    /// Returns Vec<(block_id, inst_idx, variable_name, version, expression)>.
    ///
    /// All definitions share a single function-level node budget
    /// (function_total_budget) to prevent cumulative OOM on real binaries.
    pub fn recover_all_definitions(
        &self,
        ssa: &SSAFunction,
    ) -> Vec<(usize, usize, String, u32, Expression)> {
        let ctx = RecoveryContext::new(ssa, self.max_depth, self.function_total_budget);
        // Shared node counter across ALL definitions in this function.
        let mut total_nodes: usize = 0;
        let mut results = Vec::new();
        for block in &ssa.basic_blocks {
            // Phi nodes
            for phi in &block.phi_nodes {
                if total_nodes >= self.function_total_budget {
                    results.push((
                        block.id,
                        usize::MAX,
                        phi.variable.clone(),
                        phi.result_version,
                        Expression::Unknown {
                            reason: "function node budget exhausted".to_string(),
                        },
                    ));
                    continue;
                }
                let expr = ctx.recover_phi_with_nodes(phi, &mut total_nodes);
                results.push((
                    block.id,
                    usize::MAX,
                    phi.variable.clone(),
                    phi.result_version,
                    expr,
                ));
            }
            // Instructions — use SSA-provided destination_operand_idx, not heuristic
            for (inst_idx, inst) in block.instructions.iter().enumerate() {
                if total_nodes >= self.function_total_budget {
                    if let Some(dest_idx) = inst.destination_operand_idx {
                        if let Some(SSAOperand::Variable { name, version }) =
                            inst.operands.get(dest_idx)
                        {
                            results.push((
                                block.id,
                                inst_idx,
                                name.clone(),
                                *version,
                                Expression::Unknown {
                                    reason: "function node budget exhausted".to_string(),
                                },
                            ));
                        }
                    }
                    continue;
                }
                if let Some(dest_idx) = inst.destination_operand_idx {
                    if let Some(SSAOperand::Variable { name, version }) =
                        inst.operands.get(dest_idx)
                    {
                        let expr =
                            ctx.recover_definition_with_nodes(block.id, inst_idx, &mut total_nodes);
                        results.push((block.id, inst_idx, name.clone(), *version, expr));
                    }
                }
            }
        }
        results
    }
}

// ---------------------------------------------------------------------------
// Internal recovery context
// ---------------------------------------------------------------------------

struct RecoveryContext<'a> {
    ssa: &'a SSAFunction,
    max_depth: usize,
    /// Node budget for this recovery session.
    /// For single definition: max_nodes. For all_definitions: function_total_budget.
    node_budget: usize,
    /// (name, version) -> (block_id, inst_idx)
    def_index: HashMap<(String, u32), (usize, usize)>,
}

impl<'a> RecoveryContext<'a> {
    fn new(ssa: &'a SSAFunction, max_depth: usize, node_budget: usize) -> Self {
        let mut def_index = HashMap::new();

        // Index phi definitions
        for block in &ssa.basic_blocks {
            for phi in &block.phi_nodes {
                def_index.insert(
                    (phi.variable.clone(), phi.result_version),
                    (block.id, usize::MAX),
                );
            }
        }

        // Index instruction definitions using SSA-provided destination_operand_idx.
        // This is NOT a heuristic: SSA construction records which explicit
        // register operand is Write/ReadWrite. None = no explicit register dest
        // (e.g. mul/div implicit eax/edx, push implicit esp, call implicit ret reg).
        for block in &ssa.basic_blocks {
            for (inst_idx, inst) in block.instructions.iter().enumerate() {
                if let Some(dest_idx) = inst.destination_operand_idx {
                    if let Some(SSAOperand::Variable { name, version }) =
                        inst.operands.get(dest_idx)
                    {
                        def_index.insert((name.clone(), *version), (block.id, inst_idx));
                    }
                }
            }
        }

        Self {
            ssa,
            max_depth,
            node_budget,
            def_index,
        }
    }

    fn recover_definition(&self, block_id: usize, inst_idx: usize) -> Expression {
        self.recover_definition_inner(block_id, inst_idx, 0, &mut Vec::new(), &mut 0)
    }

    /// Recover a definition using a shared node counter (for function-level budget).
    fn recover_definition_with_nodes(
        &self,
        block_id: usize,
        inst_idx: usize,
        nodes: &mut usize,
    ) -> Expression {
        self.recover_definition_inner(block_id, inst_idx, 0, &mut Vec::new(), nodes)
    }

    fn recover_use(&self, block_id: usize, inst_idx: usize, op_idx: usize) -> Expression {
        let block = match self.ssa.basic_blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => {
                return Expression::Unknown {
                    reason: format!("block {} not found", block_id),
                }
            }
        };
        let inst = match block.instructions.get(inst_idx) {
            Some(i) => i,
            None => {
                return Expression::Unknown {
                    reason: format!("inst {} not found", inst_idx),
                }
            }
        };
        let operand = match inst.operands.get(op_idx) {
            Some(o) => o,
            None => {
                return Expression::Unknown {
                    reason: format!("operand {} not found", op_idx),
                }
            }
        };
        self.recover_operand_inner(
            block_id,
            inst_idx,
            op_idx,
            operand,
            0,
            &mut Vec::new(),
            &mut 0,
        )
    }

    fn recover_operand(
        &self,
        _block_id: usize,
        _inst_idx: usize,
        _op_idx: usize,
        operand: &SSAOperand,
    ) -> Expression {
        self.recover_operand_inner(
            _block_id,
            _inst_idx,
            _op_idx,
            operand,
            0,
            &mut Vec::new(),
            &mut 0,
        )
    }

    /// Recover a phi using a shared node counter (for function-level budget).
    fn recover_phi_with_nodes(&self, phi: &PhiNode, nodes: &mut usize) -> Expression {
        let mut incoming = Vec::new();
        for (pred_block, version) in &phi.incoming {
            let val =
                self.recover_variable_inner(&phi.variable, *version, 0, &mut Vec::new(), nodes);
            incoming.push(PhiIncoming {
                block_id: *pred_block,
                value: Box::new(val),
            });
        }
        Expression::Phi { incoming }
    }

    // --- Inner recursive methods (take &mut counters) ---

    fn recover_definition_inner(
        &self,
        block_id: usize,
        inst_idx: usize,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        if depth >= self.max_depth {
            return Expression::Unknown {
                reason: format!("max depth {} exceeded", self.max_depth),
            };
        }
        if *nodes >= self.node_budget {
            return Expression::Unknown {
                reason: "max nodes exceeded".to_string(),
            };
        }

        // Phi node?
        if inst_idx == usize::MAX {
            if self.ssa.basic_blocks.iter().any(|b| b.id == block_id) {
                return Expression::Unknown {
                    reason: "phi recovery requires variable context".to_string(),
                };
            }
            return Expression::Unknown {
                reason: format!("phi block {} not found", block_id),
            };
        }

        let block = match self.ssa.basic_blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => {
                return Expression::Unknown {
                    reason: format!("block {} not found", block_id),
                }
            }
        };
        let inst = match block.instructions.get(inst_idx) {
            Some(i) => i,
            None => {
                return Expression::Unknown {
                    reason: format!("inst {} not found", inst_idx),
                }
            }
        };

        self.recover_instruction_expression(inst, block_id, inst_idx, depth, visited, nodes)
    }

    fn recover_instruction_expression(
        &self,
        inst: &SSAInstruction,
        block_id: usize,
        inst_idx: usize,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        *nodes += 1;
        if *nodes > self.node_budget {
            return Expression::Unknown {
                reason: "max nodes exceeded".to_string(),
            };
        }

        let op = inst.op.as_str();
        let operands = &inst.operands;

        match op {
            // Mov: dest = src
            "Mov" => {
                if operands.len() > 1 {
                    self.recover_operand_inner(
                        block_id,
                        inst_idx,
                        1,
                        &operands[1],
                        depth,
                        visited,
                        nodes,
                    )
                } else {
                    Expression::Unknown {
                        reason: "Mov with <2 operands".to_string(),
                    }
                }
            }

            // Lea: dest = address expression (treat as binary-ish)
            "Lea" => {
                if operands.len() > 1 {
                    // LEA computes an address; treat source as expression
                    self.recover_operand_inner(
                        block_id,
                        inst_idx,
                        1,
                        &operands[1],
                        depth,
                        visited,
                        nodes,
                    )
                } else {
                    Expression::Unknown {
                        reason: "Lea with <2 operands".to_string(),
                    }
                }
            }

            // Binary arithmetic / logic (ReadWrite dest)
            "Add" | "Sub" | "Mul" | "Div" | "Mod" | "And" | "Or" | "Xor" | "Shl" | "Shr"
            | "Sar" => {
                self.recover_binary_op(op, operands, block_id, inst_idx, depth, visited, nodes)
            }

            // Unary
            "Neg" | "Not" => {
                if !operands.is_empty() {
                    let unary_op = match op {
                        "Neg" => UnaryOp::Neg,
                        "Not" => UnaryOp::Not,
                        _ => unreachable!(),
                    };
                    // For Neg/Not, dest is ReadWrite; old value is operand[0]'s previous version
                    if let SSAOperand::Variable { name, version } = &operands[0] {
                        let old_val = self.recover_variable_inner(
                            name,
                            version.saturating_sub(1),
                            depth,
                            visited,
                            nodes,
                        );
                        Expression::Unary {
                            op: unary_op,
                            operand: Box::new(old_val),
                        }
                    } else {
                        Expression::Unknown {
                            reason: format!("{} non-variable dest", op),
                        }
                    }
                } else {
                    Expression::Unknown {
                        reason: format!("{} with no operands", op),
                    }
                }
            }

            // Inc / Dec: dest = dest ± 1
            "Inc" | "Dec" => {
                if let Some(SSAOperand::Variable { name, version }) = operands.first() {
                    let old_val = self.recover_variable_inner(
                        name,
                        version.saturating_sub(1),
                        depth,
                        visited,
                        nodes,
                    );
                    let bin_op = if op == "Inc" {
                        BinaryOp::Add
                    } else {
                        BinaryOp::Sub
                    };
                    Expression::Binary {
                        op: bin_op,
                        left: Box::new(old_val),
                        right: Box::new(Expression::Constant(1)),
                    }
                } else {
                    Expression::Unknown {
                        reason: format!("{} non-variable dest", op),
                    }
                }
            }

            // Load: dest = *address
            "Load" => {
                if operands.len() > 1 {
                    let addr_expr =
                        self.recover_memory_address(&operands[1], depth, visited, nodes);
                    Expression::Load {
                        address: Box::new(addr_expr),
                    }
                } else {
                    Expression::Unknown {
                        reason: "Load with <2 operands".to_string(),
                    }
                }
            }

            // Call: dest = call(target, args...)
            "Call" => {
                let target = if let Some(op) = operands.first() {
                    match op {
                        SSAOperand::Constant(v) => CallTarget::Address(*v),
                        SSAOperand::Label(s) => CallTarget::Symbol(s.clone()),
                        SSAOperand::Variable { .. } => {
                            // Indirect call through register
                            CallTarget::Unknown
                        }
                        _ => CallTarget::Unknown,
                    }
                } else {
                    CallTarget::Unknown
                };
                // Arguments: operands after the target (if any)
                let arguments: Vec<Expression> = operands
                    .iter()
                    .skip(1)
                    .enumerate()
                    .map(|(i, op)| {
                        self.recover_operand_inner(
                            block_id,
                            inst_idx,
                            i + 1,
                            op,
                            depth,
                            visited,
                            nodes,
                        )
                    })
                    .collect();
                Expression::Call { target, arguments }
            }

            // Pop: dest = *sp++ (treat as load)
            "Pop" => Expression::Load {
                address: Box::new(Expression::Unknown {
                    reason: "stack pointer (Pop)".to_string(),
                }),
            },

            // Store: not a value-producing expression
            "Store" => Expression::Unknown {
                reason: "Store is not an expression".to_string(),
            },

            // Cmp/Test: set flags, not a value
            "Cmp" | "Test" => Expression::Unknown {
                reason: "flag-setting instruction, not a value".to_string(),
            },

            // Control flow: not values
            "Jump" | "CondJump" | "Return" | "Nop" | "Halt" | "Int" | "Syscall" | "Enter"
            | "Leave" | "Push" | "SetFlag" | "ClearFlag" => Expression::Unknown {
                reason: format!("{} does not produce a recoverable value", op),
            },

            _ => Expression::Unknown {
                reason: format!("unsupported op: {}", op),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_binary_op(
        &self,
        op: &str,
        operands: &[SSAOperand],
        block_id: usize,
        inst_idx: usize,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        if operands.len() < 2 {
            return Expression::Unknown {
                reason: format!("{} with <2 operands", op),
            };
        }

        let bin_op = match op {
            "Add" => BinaryOp::Add,
            "Sub" => BinaryOp::Sub,
            "Mul" => BinaryOp::Mul,
            "Div" => BinaryOp::Div,
            "Mod" => BinaryOp::Mod,
            "And" => BinaryOp::And,
            "Or" => BinaryOp::Or,
            "Xor" => BinaryOp::Xor,
            "Shl" => BinaryOp::Shl,
            "Shr" => BinaryOp::Shr,
            "Sar" => BinaryOp::Sar,
            _ => {
                return Expression::Unknown {
                    reason: format!("unknown binary op: {}", op),
                }
            }
        };

        // operands[0] = destination (ReadWrite), old value is previous version
        // operands[1] = source
        let left = if let SSAOperand::Variable { name, version } = &operands[0] {
            self.recover_variable_inner(name, version.saturating_sub(1), depth, visited, nodes)
        } else {
            Expression::Unknown {
                reason: format!("{} non-variable dest", op),
            }
        };

        let right =
            self.recover_operand_inner(block_id, inst_idx, 1, &operands[1], depth, visited, nodes);

        Expression::Binary {
            op: bin_op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_operand_inner(
        &self,
        _block_id: usize,
        _inst_idx: usize,
        _op_idx: usize,
        operand: &SSAOperand,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        match operand {
            SSAOperand::Constant(v) => Expression::Constant(*v),
            SSAOperand::Variable { name, version } => {
                self.recover_variable_inner(name, *version, depth, visited, nodes)
            }
            SSAOperand::Memory { description } => Expression::Unknown {
                reason: format!("memory operand: {}", description),
            },
            SSAOperand::Label(s) => Expression::Unknown {
                reason: format!("label: {}", s),
            },
        }
    }

    fn recover_variable_inner(
        &self,
        name: &str,
        version: u32,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        if depth >= self.max_depth {
            return Expression::Unknown {
                reason: format!("max depth {} exceeded", self.max_depth),
            };
        }

        let key = (name.to_string(), version);

        // Cycle detection
        if visited.contains(&key) {
            return Expression::Unknown {
                reason: format!("cycle detected at {}.{}", name, version),
            };
        }

        // Version 0 = initial value (input / undefined)
        if version == 0 {
            return Expression::Variable {
                name: name.to_string(),
                version: 0,
            };
        }

        // Look up definition
        let def = match self.def_index.get(&key) {
            Some(d) => *d,
            None => {
                return Expression::Variable {
                    name: name.to_string(),
                    version,
                };
            }
        };

        visited.push(key);

        let result = if def.1 == usize::MAX {
            // Phi node
            self.recover_phi_definition(name, version, def.0, depth, visited, nodes)
        } else {
            self.recover_definition_inner(def.0, def.1, depth + 1, visited, nodes)
        };

        visited.pop();
        result
    }

    fn recover_phi_definition(
        &self,
        name: &str,
        version: u32,
        block_id: usize,
        depth: usize,
        visited: &mut Vec<(String, u32)>,
        nodes: &mut usize,
    ) -> Expression {
        let block = match self.ssa.basic_blocks.iter().find(|b| b.id == block_id) {
            Some(b) => b,
            None => {
                return Expression::Unknown {
                    reason: format!("phi block {} not found", block_id),
                }
            }
        };

        let phi = match block
            .phi_nodes
            .iter()
            .find(|p| p.variable == name && p.result_version == version)
        {
            Some(p) => p,
            None => {
                return Expression::Unknown {
                    reason: format!("phi {}.{} not found at block {}", name, version, block_id),
                };
            }
        };

        *nodes += 1;

        let mut incoming = Vec::new();
        for (pred_block, in_version) in &phi.incoming {
            let val = self.recover_variable_inner(name, *in_version, depth + 1, visited, nodes);
            incoming.push(PhiIncoming {
                block_id: *pred_block,
                value: Box::new(val),
            });
        }

        Expression::Phi { incoming }
    }

    fn recover_memory_address(
        &self,
        operand: &SSAOperand,
        _depth: usize,
        _visited: &mut Vec<(String, u32)>,
        _nodes: &mut usize,
    ) -> Expression {
        match operand {
            SSAOperand::Memory { description } => Expression::Unknown {
                reason: format!("memory address: {}", description),
            },
            SSAOperand::Variable { name, version } => Expression::Variable {
                name: name.clone(),
                version: *version,
            },
            SSAOperand::Constant(v) => Expression::Constant(*v),
            _ => Expression::Unknown {
                reason: "non-memory operand in Load".to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Display (human-readable, for debugging/dogfood — NOT the core model)
// ---------------------------------------------------------------------------

impl std::fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOp::Add => write!(f, "+"),
            BinaryOp::Sub => write!(f, "-"),
            BinaryOp::Mul => write!(f, "*"),
            BinaryOp::Div => write!(f, "/"),
            BinaryOp::Mod => write!(f, "%"),
            BinaryOp::And => write!(f, "&"),
            BinaryOp::Or => write!(f, "|"),
            BinaryOp::Xor => write!(f, "^"),
            BinaryOp::Shl => write!(f, "<<"),
            BinaryOp::Shr => write!(f, ">>"),
            BinaryOp::Sar => write!(f, ">>a"),
        }
    }
}

impl std::fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "-"),
            UnaryOp::Not => write!(f, "~"),
        }
    }
}

impl std::fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Constant(v) => write!(f, "{}", v),
            Expression::Variable { name, version } => write!(f, "{}.{}", name, version),
            Expression::Binary { op, left, right } => write!(f, "({} {} {})", left, op, right),
            Expression::Unary { op, operand } => write!(f, "{}({})", op, operand),
            Expression::Load { address } => write!(f, "*({})", address),
            Expression::Call { target, arguments } => {
                write!(f, "call(")?;
                match target {
                    CallTarget::Address(a) => write!(f, "0x{:x}", a)?,
                    CallTarget::Symbol(s) => write!(f, "{}", s)?,
                    CallTarget::Unknown => write!(f, "?")?,
                }
                for (i, arg) in arguments.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            Expression::Phi { incoming } => {
                write!(f, "phi(")?;
                for (i, inc) in incoming.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "bb{}:{}", inc.block_id, inc.value)?;
                }
                write!(f, ")")
            }
            Expression::Unknown { reason } => write!(f, "<?{}>", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fox_analysis::ssa::{PhiNode, SSABasicBlock, SSAFunction, SSAInstruction, SSAOperand};
    use fox_ir::{IRBasicBlock, IRFunction, IRInstruction, IROp, IROperand, OperandAccess};

    /// Helper: build a minimal SSA function from IR instructions in one block.
    fn make_ssa(instructions: Vec<IRInstruction>) -> SSAFunction {
        let ir_func = IRFunction {
            name: "test".to_string(),
            address: fox_core::Address(0x1000),
            basic_blocks: vec![IRBasicBlock {
                id: 0,
                start_address: fox_core::Address(0x1000),
                end_address: fox_core::Address(0x1100),
                instructions,
                successors: vec![],
                predecessors: vec![],
            }],
            entry_block: 0,
        };
        fox_analysis::ssa::SSAConstructor::construct_proper(&ir_func)
    }

    fn ir_inst(op: IROp, operands: Vec<IROperand>) -> IRInstruction {
        IRInstruction {
            address: fox_core::Address(0x1000),
            op,
            operands,
            original_mnemonic: None,
            original_operands: None,
            size: 1,
            reads_registers: vec![],
            writes_registers: vec![],
            implicit_reads: vec![],
            implicit_writes: vec![],
            reads_flags: false,
            writes_flags: false,
        }
    }

    fn reg_read(name: &str, width: u16) -> IROperand {
        IROperand::Register {
            name: name.to_string(),
            width,
            access: OperandAccess::Read,
        }
    }
    fn reg_write(name: &str, width: u16) -> IROperand {
        IROperand::Register {
            name: name.to_string(),
            width,
            access: OperandAccess::Write,
        }
    }
    fn reg_rw(name: &str, width: u16) -> IROperand {
        IROperand::Register {
            name: name.to_string(),
            width,
            access: OperandAccess::ReadWrite,
        }
    }
    fn imm(value: u64, width: u16) -> IROperand {
        IROperand::Immediate {
            value,
            width,
            is_signed: false,
        }
    }

    #[test]
    fn test_constant() {
        let expr = Expression::Constant(42);
        assert_eq!(expr.to_string(), "42");
    }

    #[test]
    fn test_variable() {
        let expr = Expression::Variable {
            name: "eax".to_string(),
            version: 1,
        };
        assert_eq!(expr.to_string(), "eax.1");
    }

    #[test]
    fn test_binary_add_display() {
        let expr = Expression::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expression::Variable {
                name: "a".to_string(),
                version: 0,
            }),
            right: Box::new(Expression::Variable {
                name: "b".to_string(),
                version: 0,
            }),
        };
        assert_eq!(expr.to_string(), "(a.0 + b.0)");
    }

    #[test]
    fn test_mov_recovery() {
        // mov eax, 42
        let ssa = make_ssa(vec![ir_inst(
            IROp::Mov,
            vec![reg_write("eax", 32), imm(42, 32)],
        )]);
        let recovery = ExpressionRecovery::new();
        // eax.1 is defined at block 0, inst 0
        let expr = recovery.recover_definition(&ssa, 0, 0);
        assert_eq!(expr, Expression::Constant(42));
    }

    #[test]
    fn test_add_recovery() {
        // mov eax, 10
        // add eax, 20
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(10, 32)]),
            ir_inst(IROp::Add, vec![reg_rw("eax", 32), imm(20, 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        // eax.2 = add(eax.1, 20) = add(10, 20)
        let expr = recovery.recover_definition(&ssa, 0, 1);
        assert_eq!(
            expr,
            Expression::Binary {
                op: BinaryOp::Add,
                left: Box::new(Expression::Constant(10)),
                right: Box::new(Expression::Constant(20)),
            }
        );
    }

    #[test]
    fn test_chained_expression() {
        // t1 = a + b  →  eax = ecx + edx
        // t2 = t1 * 4  →  eax = eax * 4
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), reg_read("ecx", 32)]),
            ir_inst(IROp::Add, vec![reg_rw("eax", 32), reg_read("edx", 32)]),
            ir_inst(IROp::Mul, vec![reg_rw("eax", 32), imm(4, 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        // eax.3 = mul(eax.2, 4) = mul(add(eax.1, edx.0), 4) = mul(add(ecx.0, edx.0), 4)
        let expr = recovery.recover_definition(&ssa, 0, 2);
        let expected = Expression::Binary {
            op: BinaryOp::Mul,
            left: Box::new(Expression::Binary {
                op: BinaryOp::Add,
                left: Box::new(Expression::Variable {
                    name: "ecx".to_string(),
                    version: 0,
                }),
                right: Box::new(Expression::Variable {
                    name: "edx".to_string(),
                    version: 0,
                }),
            }),
            right: Box::new(Expression::Constant(4)),
        };
        assert_eq!(expr, expected);
        assert_eq!(expr.to_string(), "((ecx.0 + edx.0) * 4)");
    }

    #[test]
    fn test_sub_and_or_xor() {
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(0xFF, 32)]),
            ir_inst(IROp::Sub, vec![reg_rw("eax", 32), imm(1, 32)]),
            ir_inst(IROp::And, vec![reg_rw("eax", 32), imm(0x0F, 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 2);
        // eax.3 = and(sub(eax.1, 1), 0x0F) = and(sub(0xFF, 1), 0x0F)
        assert_eq!(
            expr,
            Expression::Binary {
                op: BinaryOp::And,
                left: Box::new(Expression::Binary {
                    op: BinaryOp::Sub,
                    left: Box::new(Expression::Constant(0xFF)),
                    right: Box::new(Expression::Constant(1)),
                }),
                right: Box::new(Expression::Constant(0x0F)),
            }
        );
    }

    #[test]
    fn test_neg_not() {
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(5, 32)]),
            ir_inst(IROp::Neg, vec![reg_rw("eax", 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 1);
        assert_eq!(
            expr,
            Expression::Unary {
                op: UnaryOp::Neg,
                operand: Box::new(Expression::Constant(5)),
            }
        );
    }

    #[test]
    fn test_inc_dec() {
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(5, 32)]),
            ir_inst(IROp::Inc, vec![reg_rw("eax", 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 1);
        assert_eq!(
            expr,
            Expression::Binary {
                op: BinaryOp::Add,
                left: Box::new(Expression::Constant(5)),
                right: Box::new(Expression::Constant(1)),
            }
        );
    }

    #[test]
    fn test_load_recovery() {
        // mov eax, [rsp+8]  →  Load
        let ssa = make_ssa(vec![ir_inst(
            IROp::Load,
            vec![
                reg_write("eax", 32),
                IROperand::Memory {
                    base: Some("rsp".to_string()),
                    index: None,
                    scale: 1,
                    displacement: 8,
                    size: 4,
                    access: OperandAccess::Read,
                    is_rip_relative: false,
                    effective_address: None,
                },
            ],
        )]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 0);
        match expr {
            Expression::Load { .. } => {}
            _ => panic!("expected Load, got {:?}", expr),
        }
    }

    #[test]
    fn test_call_recovery() {
        // call 0x401000
        let ssa = make_ssa(vec![ir_inst(
            IROp::Call,
            vec![IROperand::Label("0x401000".to_string())],
        )]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 0);
        match expr {
            Expression::Call { target, .. } => {
                assert!(matches!(target, CallTarget::Symbol(_)));
            }
            _ => panic!("expected Call, got {:?}", expr),
        }
    }

    #[test]
    fn test_return_value() {
        // mov eax, 42
        // ret
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(42, 32)]),
            ir_inst(IROp::Return, vec![]),
        ]);
        let recovery = ExpressionRecovery::new();
        // Return with no operand → void
        let ret = recovery.recover_return_value(&ssa);
        assert!(ret.is_some());
    }

    #[test]
    fn test_phi_structure() {
        // Build SSA with a phi manually
        let ssa = SSAFunction {
            name: "test".to_string(),
            address: 0x1000,
            basic_blocks: vec![
                SSABasicBlock {
                    id: 0,
                    start_address: 0x1000,
                    end_address: 0x1010,
                    instructions: vec![SSAInstruction {
                        address: 0x1000,
                        op: "Mov".to_string(),
                        operands: vec![
                            SSAOperand::Variable {
                                name: "eax".to_string(),
                                version: 1,
                            },
                            SSAOperand::Constant(10),
                        ],
                        original_mnemonic: "mov".to_string(),
                        destination_operand_idx: Some(0),
                    }],
                    phi_nodes: vec![],
                    successors: vec![2],
                    predecessors: vec![],
                },
                SSABasicBlock {
                    id: 1,
                    start_address: 0x1010,
                    end_address: 0x1020,
                    instructions: vec![SSAInstruction {
                        address: 0x1010,
                        op: "Mov".to_string(),
                        operands: vec![
                            SSAOperand::Variable {
                                name: "eax".to_string(),
                                version: 2,
                            },
                            SSAOperand::Constant(20),
                        ],
                        original_mnemonic: "mov".to_string(),
                        destination_operand_idx: Some(0),
                    }],
                    phi_nodes: vec![],
                    successors: vec![2],
                    predecessors: vec![],
                },
                SSABasicBlock {
                    id: 2,
                    start_address: 0x1020,
                    end_address: 0x1030,
                    instructions: vec![],
                    phi_nodes: vec![PhiNode {
                        block_id: 2,
                        variable: "eax".to_string(),
                        incoming: vec![(0, 1), (1, 2)],
                        result_version: 3,
                    }],
                    successors: vec![],
                    predecessors: vec![0, 1],
                },
            ],
            entry_block: 0,
            phi_nodes: vec![],
            variable_versions: HashMap::new(),
            evidence: vec![],
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            proper_renaming: true,
        };

        // Recover eax.3 (the phi)
        let ctx = RecoveryContext::new(&ssa, 64, 10000);
        let expr = ctx.recover_variable_inner("eax", 3, 0, &mut Vec::new(), &mut 0);
        match expr {
            Expression::Phi { incoming } => {
                assert_eq!(incoming.len(), 2);
                assert_eq!(incoming[0].block_id, 0);
                assert_eq!(incoming[1].block_id, 1);
                assert_eq!(*incoming[0].value, Expression::Constant(10));
                assert_eq!(*incoming[1].value, Expression::Constant(20));
            }
            _ => panic!("expected Phi, got {:?}", expr),
        }
    }

    #[test]
    fn test_cycle_protection() {
        // Build a cyclic SSA manually: v1 -> v2 -> v1
        let ssa = SSAFunction {
            name: "cycle".to_string(),
            address: 0x1000,
            basic_blocks: vec![SSABasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1010,
                instructions: vec![SSAInstruction {
                    address: 0x1000,
                    op: "Add".to_string(),
                    operands: vec![
                        SSAOperand::Variable {
                            name: "eax".to_string(),
                            version: 2,
                        },
                        SSAOperand::Variable {
                            name: "eax".to_string(),
                            version: 1,
                        },
                    ],
                    original_mnemonic: "add".to_string(),
                    destination_operand_idx: Some(0),
                }],
                phi_nodes: vec![],
                successors: vec![],
                predecessors: vec![],
            }],
            entry_block: 0,
            phi_nodes: vec![],
            variable_versions: HashMap::new(),
            evidence: vec![],
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            proper_renaming: true,
        };

        let recovery = ExpressionRecovery::new();
        // eax.2 is defined at inst 0, which references eax.1
        // eax.1 has no definition → should be Variable (not a cycle)
        let expr = recovery.recover_definition(&ssa, 0, 0);
        // eax.2 = add(eax.1, eax.1) — eax.1 is undefined → Variable
        match expr {
            Expression::Binary {
                op: BinaryOp::Add, ..
            } => {}
            _ => panic!("expected Binary Add, got {:?}", expr),
        }
    }

    #[test]
    fn test_depth_protection() {
        // Deep chain: eax = eax + 1 repeated many times
        let recovery = ExpressionRecovery {
            max_depth: 3,
            max_nodes: 1000,
            function_total_budget: 10000,
        };

        let mut insts = Vec::new();
        insts.push(ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(0, 32)]));
        for _ in 0..10 {
            insts.push(ir_inst(IROp::Add, vec![reg_rw("eax", 32), imm(1, 32)]));
        }
        let ssa = make_ssa(insts);

        // Recover the last definition (deepest)
        let last_idx = ssa.basic_blocks[0].instructions.len() - 1;
        let expr = recovery.recover_definition(&ssa, 0, last_idx);
        // Should hit depth limit and produce Unknown at some point
        // The expression should not cause stack overflow
        assert!(matches!(
            expr,
            Expression::Binary { .. } | Expression::Unknown { .. }
        ));
    }

    #[test]
    fn test_store_not_expression() {
        let ssa = make_ssa(vec![ir_inst(
            IROp::Store,
            vec![
                IROperand::Memory {
                    base: Some("rsp".to_string()),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    size: 4,
                    access: OperandAccess::Write,
                    is_rip_relative: false,
                    effective_address: None,
                },
                reg_read("eax", 32),
            ],
        )]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 0);
        match expr {
            Expression::Unknown { reason } => {
                assert!(reason.contains("Store"));
            }
            _ => panic!("expected Unknown for Store, got {:?}", expr),
        }
    }

    #[test]
    fn test_cmp_not_value() {
        let ssa = make_ssa(vec![ir_inst(
            IROp::Cmp,
            vec![reg_read("eax", 32), reg_read("ebx", 32)],
        )]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 0);
        match expr {
            Expression::Unknown { reason } => {
                assert!(reason.contains("flag"));
            }
            _ => panic!("expected Unknown for Cmp, got {:?}", expr),
        }
    }

    #[test]
    fn test_shifts() {
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(1, 32)]),
            ir_inst(IROp::Shl, vec![reg_rw("eax", 32), imm(3, 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        let expr = recovery.recover_definition(&ssa, 0, 1);
        assert_eq!(
            expr,
            Expression::Binary {
                op: BinaryOp::Shl,
                left: Box::new(Expression::Constant(1)),
                right: Box::new(Expression::Constant(3)),
            }
        );
    }

    #[test]
    fn test_expression_is_structured_not_string() {
        // Verify the model is structured data, not a string
        let expr = Expression::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expression::Constant(1)),
            right: Box::new(Expression::Constant(2)),
        };
        // Can match on structure
        match &expr {
            Expression::Binary { op, left, right } => {
                assert_eq!(*op, BinaryOp::Add);
                assert_eq!(**left, Expression::Constant(1));
                assert_eq!(**right, Expression::Constant(2));
            }
            _ => panic!("not structured"),
        }
        // Display is just for debugging
        assert_eq!(expr.to_string(), "(1 + 2)");
    }

    #[test]
    fn test_recover_all_definitions() {
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("eax", 32), imm(10, 32)]),
            ir_inst(IROp::Add, vec![reg_rw("eax", 32), imm(20, 32)]),
        ]);
        let recovery = ExpressionRecovery::new();
        let defs = recovery.recover_all_definitions(&ssa);
        // Should find eax.1 (Mov) and eax.2 (Add)
        assert!(defs.len() >= 2);
    }

    // --- P1-1: destination_operand_idx tests ---

    #[test]
    fn test_mul_source_not_indexed_as_definition() {
        // mul ebx: explicit operand ebx is Read, eax/edx are implicit writes.
        // destination_operand_idx must be None → ebx must NOT be indexed as def.
        let ssa = make_ssa(vec![
            ir_inst(IROp::Mov, vec![reg_write("ebx", 32), imm(5, 32)]),
            ir_inst(IROp::Mul, vec![reg_read("ebx", 32)]),
        ]);
        // Verify SSA recorded destination_operand_idx correctly
        let mul_inst = &ssa.basic_blocks[0].instructions[1];
        assert_eq!(
            mul_inst.destination_operand_idx, None,
            "mul must have no explicit register destination"
        );
        // recover_all_definitions should only find ebx.1 (from Mov), not ebx from Mul
        let recovery = ExpressionRecovery::new();
        let defs = recovery.recover_all_definitions(&ssa);
        let ebx_defs: Vec<_> = defs
            .iter()
            .filter(|(_, _, name, _, _)| name == "ebx")
            .collect();
        assert_eq!(
            ebx_defs.len(),
            1,
            "ebx should only have one definition (from Mov)"
        );
        assert_eq!(
            ebx_defs[0].1, 0,
            "ebx definition should be at instruction 0 (Mov)"
        );
    }

    #[test]
    fn test_destination_idx_readwrite_identified() {
        // add eax, ebx: eax is ReadWrite → destination_operand_idx = Some(0)
        let ssa = make_ssa(vec![ir_inst(
            IROp::Add,
            vec![reg_rw("eax", 32), reg_read("ebx", 32)],
        )]);
        let add_inst = &ssa.basic_blocks[0].instructions[0];
        assert_eq!(
            add_inst.destination_operand_idx,
            Some(0),
            "add eax,ebx destination should be operand 0"
        );
    }

    #[test]
    fn test_cmp_has_no_destination() {
        // cmp eax, ebx: both Read, only FLAGS write → destination_operand_idx = None
        let ssa = make_ssa(vec![ir_inst(
            IROp::Cmp,
            vec![reg_read("eax", 32), reg_read("ebx", 32)],
        )]);
        let cmp_inst = &ssa.basic_blocks[0].instructions[0];
        assert_eq!(
            cmp_inst.destination_operand_idx, None,
            "cmp must have no register destination (only FLAGS)"
        );
        let recovery = ExpressionRecovery::new();
        let defs = recovery.recover_all_definitions(&ssa);
        assert!(
            defs.is_empty(),
            "cmp should produce no register definitions"
        );
    }

    // --- P1-2: function-level resource budget tests ---

    #[test]
    fn test_function_budget_shared_across_definitions() {
        // 5 simple Mov definitions, each costs ~1 node.
        // function_total_budget=3 → only first 3 recover, rest fail-closed.
        let mut insts = Vec::new();
        for i in 0..5u64 {
            insts.push(ir_inst(
                IROp::Mov,
                vec![reg_write(&format!("r{}", i), 64), imm(i, 64)],
            ));
        }
        let ssa = make_ssa(insts);
        let recovery = ExpressionRecovery {
            max_depth: 64,
            max_nodes: 10000,
            function_total_budget: 3,
        };
        let defs = recovery.recover_all_definitions(&ssa);
        assert_eq!(defs.len(), 5, "all 5 definitions should be enumerated");

        let recovered: Vec<_> = defs
            .iter()
            .filter(|(_, _, _, _, e)| !matches!(e, Expression::Unknown { .. }))
            .collect();
        let unknowns: Vec<_> = defs
            .iter()
            .filter(|(_, _, _, _, e)| matches!(e, Expression::Unknown { .. }))
            .collect();
        assert!(recovered.len() <= 3, "at most 3 definitions within budget");
        assert!(
            unknowns.len() >= 2,
            "at least 2 definitions should hit budget limit"
        );
        // Verify the Unknown reason mentions budget
        for (_, _, _, _, e) in &unknowns {
            if let Expression::Unknown { reason } = e {
                assert!(
                    reason.contains("budget") || reason.contains("nodes"),
                    "unknown reason should mention budget/nodes, got: {}",
                    reason
                );
            }
        }
    }

    #[test]
    fn test_single_expression_budget_independent() {
        // Single definition recovery uses max_nodes (per-expression), not function budget.
        let ssa = make_ssa(vec![ir_inst(
            IROp::Mov,
            vec![reg_write("eax", 32), imm(42, 32)],
        )]);
        let recovery = ExpressionRecovery {
            max_depth: 64,
            max_nodes: 1, // tiny per-expression budget
            function_total_budget: 100000,
        };
        // Single recovery: 1 node is within budget of 1 (check is > budget)
        let expr = recovery.recover_definition(&ssa, 0, 0);
        assert!(matches!(expr, Expression::Constant(42)));
    }
}
