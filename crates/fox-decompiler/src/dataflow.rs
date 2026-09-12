//! P0-11.3: Cross-Function Data Flow Evidence Engine.
//!
//! Builds on the P0-11.2.7 `DecompilerCallGraph` (caller -> callee facts) and
//! recovers the **data carried across those call edges**, purely from SSA facts:
//!
//! ```text
//! SSA CallStmt
//!   ├─ arguments[i]  ──► ArgumentFlow  (caller -> callee: what is passed)
//!   └─ behavior       ──► ReturnFlow   (callee -> caller: how return used)
//! ```
//!
//! This is an **Evidence Layer**: it only classifies already-recovered SSA
//! expressions. It does NOT guess function semantics, name functions, or
//! fabricate types. Unknowns are preserved verbatim.

use crate::callgraph::DecompilerCallGraph;
use crate::expression::{CallTarget, Expression};
use crate::structured_ir::{CallBehavior, DecompilerFunction, Statement};
use std::collections::HashMap;

/// Direction of a cross-function data edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// Caller passes a value INTO the callee as an argument (caller -> callee).
    ArgumentFlow,
    /// Callee's return value (eax) is consumed by the caller (callee -> caller).
    ReturnFlow,
}

/// Coarse origin class of an argument expression. Evidence only, not a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentSourceKind {
    /// The argument is an immediate constant (e.g. push 0).
    Constant,
    /// The argument is an SSA register/variable.
    Register,
    /// The argument is a memory load (e.g. push [global+x]).
    MemoryLoad,
    /// The argument is computed (binary/unary/phi).
    Computed,
    /// The argument could not be recovered.
    Unknown,
}

impl ArgumentSourceKind {
    /// Classify a recovered argument expression.
    fn of(expr: &Expression) -> ArgumentSourceKind {
        match expr {
            Expression::Constant(_) => ArgumentSourceKind::Constant,
            Expression::Variable { .. } => ArgumentSourceKind::Register,
            Expression::Load { .. } => ArgumentSourceKind::MemoryLoad,
            Expression::Binary { .. } | Expression::Unary { .. } => ArgumentSourceKind::Computed,
            // A nested call as argument means "computed by another call".
            Expression::Call { .. } => ArgumentSourceKind::Computed,
            Expression::Phi { .. } => ArgumentSourceKind::Computed,
            Expression::Unknown { .. } => ArgumentSourceKind::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ArgumentSourceKind::Constant => "constant",
            ArgumentSourceKind::Register => "register",
            ArgumentSourceKind::MemoryLoad => "mem_load",
            ArgumentSourceKind::Computed => "computed",
            ArgumentSourceKind::Unknown => "unknown",
        }
    }
}

/// How the callee's return value (eax) is consumed by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnConsumerKind {
    /// Return feeds a condition (call -> test/cmp eax -> jcc).
    Condition,
    /// Return feeds a non-branch instruction (mov/push/add ...).
    Instruction { op: String },
    /// Return has no consumer within the scan window.
    NoConsumer,
}

impl ReturnConsumerKind {
    pub fn label(&self) -> String {
        match self {
            ReturnConsumerKind::Condition => "condition".to_string(),
            ReturnConsumerKind::Instruction { op } => format!("instruction:{op}"),
            ReturnConsumerKind::NoConsumer => "no_consumer".to_string(),
        }
    }
}

/// Payload distinguishing argument vs return flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDetail {
    /// The Nth argument passed to the callee and its coarse origin.
    Argument {
        index: usize,
        source: ArgumentSourceKind,
    },
    /// The callee return value consumed by the caller.
    Return { consumer: ReturnConsumerKind },
}

/// A single cross-function data-flow edge (Evidence only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFlowEdge {
    /// Caller function address.
    pub caller: u64,
    /// Callee target (same target space as the call graph).
    pub callee: CallTarget,
    /// Source instruction address.
    pub callsite: u64,
    /// Whether data flows caller->callee (arg) or callee->caller (return).
    pub kind: FlowKind,
    /// Argument index/source or return consumer.
    pub detail: FlowDetail,
}

/// Cross-function data-flow graph built from SSA CallStmt facts.
#[derive(Clone)]
pub struct CrossFunctionDataFlowGraph {
    edges: Vec<DataFlowEdge>,
    /// caller -> edge indices (outgoing).
    outgoing: HashMap<u64, Vec<usize>>,
}

impl CrossFunctionDataFlowGraph {
    fn new() -> Self {
        Self {
            edges: Vec::new(),
            outgoing: HashMap::new(),
        }
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Edges belonging to a caller function (both argument and return).
    pub fn flows_of(&self, caller: u64) -> Vec<&DataFlowEdge> {
        match self.outgoing.get(&caller) {
            Some(idxs) => idxs.iter().map(|&i| &self.edges[i]).collect(),
            None => Vec::new(),
        }
    }

    /// Total argument-flow edges.
    pub fn argument_count(&self) -> usize {
        self.edges
            .iter()
            .filter(|e| e.kind == FlowKind::ArgumentFlow)
            .count()
    }

    /// Total return-flow edges.
    pub fn return_count(&self) -> usize {
        self.edges
            .iter()
            .filter(|e| e.kind == FlowKind::ReturnFlow)
            .count()
    }

    /// Counts of (constant, register, mem_load, computed, unknown) arguments.
    pub fn argument_source_counts(&self) -> (usize, usize, usize, usize, usize) {
        let (mut c, mut r, mut m, mut comp, mut u) = (0, 0, 0, 0, 0);
        for e in &self.edges {
            if let FlowDetail::Argument { source, .. } = e.detail {
                match source {
                    ArgumentSourceKind::Constant => c += 1,
                    ArgumentSourceKind::Register => r += 1,
                    ArgumentSourceKind::MemoryLoad => m += 1,
                    ArgumentSourceKind::Computed => comp += 1,
                    ArgumentSourceKind::Unknown => u += 1,
                }
            }
        }
        (c, r, m, comp, u)
    }

    /// Distinct callers that have at least one data-flow edge.
    pub fn caller_count(&self) -> usize {
        self.outgoing.len()
    }
}

/// Builder that turns SSA `CallStmt` arguments/behavior into data-flow edges.
pub struct CrossFunctionDataFlowBuilder;

impl CrossFunctionDataFlowBuilder {
    /// Build the data-flow graph. The `_call_graph` parameter documents that
    /// this layer consumes the P0-11.2.7 call graph (it does not re-derive
    /// caller-callee relationships); it only extracts the data carried by
    /// edges the call graph already established.
    pub fn build(
        functions: &[&DecompilerFunction],
        _call_graph: &DecompilerCallGraph,
    ) -> CrossFunctionDataFlowGraph {
        let mut graph = CrossFunctionDataFlowGraph::new();
        for func in functions {
            Self::collect(func.address, &func.statements, &mut graph.edges);
        }
        for (idx, edge) in graph.edges.iter().enumerate() {
            graph.outgoing.entry(edge.caller).or_default().push(idx);
        }
        graph
    }

    fn collect(caller: u64, stmts: &[Statement], out: &mut Vec<DataFlowEdge>) {
        for stmt in stmts {
            match stmt {
                Statement::CallStmt {
                    target,
                    arguments,
                    behavior,
                    evidence,
                    ..
                } => {
                    let callsite = evidence.instruction_addresses.first().copied().unwrap_or(0);
                    // Argument flow: caller -> callee (one edge per recovered arg).
                    for (i, arg) in arguments.iter().enumerate() {
                        out.push(DataFlowEdge {
                            caller,
                            callee: target.clone(),
                            callsite,
                            kind: FlowKind::ArgumentFlow,
                            detail: FlowDetail::Argument {
                                index: i,
                                source: ArgumentSourceKind::of(arg),
                            },
                        });
                    }
                    // Return flow: callee -> caller (one edge from behavior).
                    let consumer = match behavior {
                        Some(CallBehavior::ReturnUsedInCondition { .. }) => {
                            ReturnConsumerKind::Condition
                        }
                        Some(CallBehavior::ReturnUsedByInstruction { consumer_op, .. }) => {
                            ReturnConsumerKind::Instruction {
                                op: consumer_op.clone(),
                            }
                        }
                        Some(CallBehavior::NoConsumer) | None => ReturnConsumerKind::NoConsumer,
                    };
                    out.push(DataFlowEdge {
                        caller,
                        callee: target.clone(),
                        callsite,
                        kind: FlowKind::ReturnFlow,
                        detail: FlowDetail::Return { consumer },
                    });
                }
                Statement::If {
                    then_body,
                    else_body,
                    lifted_call,
                    ..
                } => {
                    Self::collect(caller, then_body, out);
                    Self::collect(caller, else_body, out);
                    // P0-7.3 lifted call carries its own recovered arguments.
                    if let Some(lc) = lifted_call {
                        Self::collect_lifted(caller, lc, out);
                    }
                }
                Statement::GuardClause {
                    body, lifted_call, ..
                } => {
                    Self::collect(caller, body, out);
                    if let Some(lc) = lifted_call {
                        Self::collect_lifted(caller, lc, out);
                    }
                }
                _ => {}
            }
        }
    }

    /// Emit argument edges for a lifted call (call -> test -> jcc merged).
    fn collect_lifted(
        caller: u64,
        lc: &crate::structured_ir::LiftedCall,
        out: &mut Vec<DataFlowEdge>,
    ) {
        let callsite = lc.call_address;
        for (i, arg) in lc.arguments.iter().enumerate() {
            out.push(DataFlowEdge {
                caller,
                callee: lc.target.clone(),
                callsite,
                kind: FlowKind::ArgumentFlow,
                detail: FlowDetail::Argument {
                    index: i,
                    source: ArgumentSourceKind::of(arg),
                },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::ConditionRecovery;
    use crate::structured_ir::{DecompilerFunction, FunctionEvidence, StatementEvidence};

    fn ev() -> StatementEvidence {
        StatementEvidence {
            instruction_addresses: vec![0x401000],
            block_ids: vec![0],
            reason: "test".into(),
        }
    }

    fn func(addr: u64, stmts: Vec<Statement>) -> DecompilerFunction {
        DecompilerFunction {
            address: addr,
            name: Some(format!("sub_{:X}", addr)),
            statements: stmts,
            evidence: FunctionEvidence {
                ssa_instructions: 0,
                cfg_blocks: 0,
                control_structures: 0,
                unknown_statements: 0,
                budget_exhausted: false,
            },
        }
    }

    #[test]
    fn test_argument_flow_from_constant() {
        let stmts = vec![Statement::CallStmt {
            target: CallTarget::Address(0x5000),
            arguments: vec![Expression::Constant(0)],
            arguments_complete: true,
            behavior: None,
            evidence: ev(),
        }];
        let f = func(0x4000, stmts);
        let cg = crate::DecompilerCallGraphBuilder::build(&[&f]);
        let df = CrossFunctionDataFlowBuilder::build(&[&f], &cg);
        assert_eq!(df.argument_count(), 1);
        assert_eq!(df.return_count(), 1);
        let flows = df.flows_of(0x4000);
        match flows[0].detail {
            FlowDetail::Argument {
                index: 0,
                source: ArgumentSourceKind::Constant,
            } => {}
            _ => panic!("expected constant argument"),
        }
    }

    #[test]
    fn test_argument_flow_from_memory_load() {
        let stmts = vec![Statement::CallStmt {
            target: CallTarget::Address(0x5000),
            arguments: vec![Expression::Load {
                address: Box::new(Expression::Variable {
                    name: "eax".into(),
                    version: 0,
                }),
            }],
            arguments_complete: true,
            behavior: None,
            evidence: ev(),
        }];
        let f = func(0x4000, stmts);
        let cg = crate::DecompilerCallGraphBuilder::build(&[&f]);
        let df = CrossFunctionDataFlowBuilder::build(&[&f], &cg);
        let flows = df.flows_of(0x4000);
        match flows[0].detail {
            FlowDetail::Argument {
                source: ArgumentSourceKind::MemoryLoad,
                ..
            } => {}
            _ => panic!("expected memory load argument"),
        }
    }

    #[test]
    fn test_return_flow_used_in_condition() {
        let stmts = vec![Statement::CallStmt {
            target: CallTarget::Address(0x5000),
            arguments: vec![],
            arguments_complete: true,
            behavior: Some(CallBehavior::ReturnUsedInCondition {
                condition: ConditionRecovery::NotConditionalJump,
                consumer_instruction: 0x401010,
                branch_instruction: 0x401013,
            }),
            evidence: ev(),
        }];
        let f = func(0x4000, stmts);
        let cg = crate::DecompilerCallGraphBuilder::build(&[&f]);
        let df = CrossFunctionDataFlowBuilder::build(&[&f], &cg);
        let returns: Vec<_> = df
            .edges
            .iter()
            .filter(|e| e.kind == FlowKind::ReturnFlow)
            .collect();
        assert_eq!(returns.len(), 1);
        match returns[0].detail {
            FlowDetail::Return {
                consumer: ReturnConsumerKind::Condition,
            } => {}
            _ => panic!("expected condition return consumer"),
        }
    }

    #[test]
    fn test_unknown_call_preserved_no_guess() {
        let stmts = vec![Statement::CallStmt {
            target: CallTarget::Unknown,
            arguments: vec![Expression::Unknown {
                reason: "opaque".into(),
            }],
            arguments_complete: false,
            behavior: Some(CallBehavior::NoConsumer),
            evidence: ev(),
        }];
        let f = func(0x4000, stmts);
        let cg = crate::DecompilerCallGraphBuilder::build(&[&f]);
        let df = CrossFunctionDataFlowBuilder::build(&[&f], &cg);
        // Unknown target still produces an edge (not dropped), but classified Unknown.
        assert_eq!(df.argument_count(), 1);
        match df.edges[0].detail {
            FlowDetail::Argument {
                source: ArgumentSourceKind::Unknown,
                ..
            } => {}
            _ => panic!("expected unknown argument preserved"),
        }
    }

    #[test]
    fn test_recursive_call_data_flow() {
        // Function calls itself: caller == callee address.
        let stmts = vec![Statement::CallStmt {
            target: CallTarget::Address(0x4000),
            arguments: vec![Expression::Variable {
                name: "ecx".into(),
                version: 1,
            }],
            arguments_complete: true,
            behavior: None,
            evidence: ev(),
        }];
        let f = func(0x4000, stmts);
        let cg = crate::DecompilerCallGraphBuilder::build(&[&f]);
        let df = CrossFunctionDataFlowBuilder::build(&[&f], &cg);
        // Self-edge: one argument edge + one return edge.
        assert_eq!(df.argument_count(), 1);
        assert_eq!(df.return_count(), 1);
        match df.edges[0].detail {
            FlowDetail::Argument {
                source: ArgumentSourceKind::Register,
                ..
            } => {}
            _ => panic!("expected register arg"),
        }
    }
}
