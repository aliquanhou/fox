//! P0-11.2.7: Real CallGraph built from SSA CallStmt.
//!
//! This is the decompiler-layer call relationship database. It consumes the
//! structured IR (`Statement::CallStmt`) produced by the analysis pipeline and
//! records real caller -> callee edges. It does NOT guess semantics, does NOT
//! name functions, and preserves Unknown targets honestly.
//!
//! Pipeline:
//! ```text
//! SSA CallStmt
//!   -> DecompilerCallGraphBuilder
//!   -> DecompilerCallEdge
//!   -> DecompilerCallGraph
//!   -> Query (callees_of / callers_of / edge_count)
//!   -> Emitter (display only)
//! ```

use crate::expression::CallTarget;
use crate::structured_ir::{DecompilerFunction, Statement};
use std::collections::HashMap;

/// Classification of a call edge based purely on the recovered CallTarget.
/// No business meaning is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompilerCallKind {
    /// Direct call to a resolved internal address (CallTarget::Address).
    Direct,
    /// Call to a recovered symbol (CallTarget::Symbol), e.g. an import.
    Symbol,
    /// Indirect / unresolved call (CallTarget::Unknown). Target is NOT guessed.
    Unknown,
}

impl DecompilerCallKind {
    pub fn label(self) -> &'static str {
        match self {
            DecompilerCallKind::Direct => "direct",
            DecompilerCallKind::Symbol => "symbol",
            DecompilerCallKind::Unknown => "unknown",
        }
    }
}

/// A single real call edge: one caller invoking one target at one callsite.
#[derive(Debug, Clone)]
pub struct DecompilerCallEdge {
    /// Address of the function containing the call instruction (caller).
    pub caller: u64,
    /// Resolved call target (Address / Symbol / Unknown).
    pub callee: CallTarget,
    /// Source instruction address (from StatementEvidence). 0 if unknown.
    pub callsite: u64,
    /// Edge kind derived from CallTarget variant.
    pub kind: DecompilerCallKind,
}

/// Real call graph for the decompiled program.
///
/// Stores every edge plus two lookup indexes:
/// - outgoing: caller address -> edge indices it originates
/// - incoming: callee address -> edge indices targeting it (only Address callees)
#[derive(Debug, Clone, Default)]
pub struct DecompilerCallGraph {
    pub edges: Vec<DecompilerCallEdge>,
    outgoing: HashMap<u64, Vec<usize>>,
    incoming: HashMap<u64, Vec<usize>>,
}

impl DecompilerCallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of recorded call edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Number of distinct functions that appear as callers.
    pub fn caller_count(&self) -> usize {
        self.outgoing.len()
    }

    /// Edges originating from `caller`.
    pub fn callees_of(&self, caller: u64) -> Vec<&DecompilerCallEdge> {
        match self.outgoing.get(&caller) {
            Some(idxs) => idxs.iter().map(|i| &self.edges[*i]).collect(),
            None => Vec::new(),
        }
    }

    /// Distinct caller addresses that call into `callee_addr`.
    ///
    /// Only meaningful for Address callees (internal functions). Symbol/Unknown
    /// targets are not indexed here because they have no canonical address.
    pub fn callers_of(&self, callee_addr: u64) -> Vec<u64> {
        match self.incoming.get(&callee_addr) {
            Some(idxs) => idxs.iter().map(|i| self.edges[*i].caller).collect(),
            None => Vec::new(),
        }
    }

    /// Counts by kind: (direct, symbol, unknown).
    pub fn kind_counts(&self) -> (usize, usize, usize) {
        let mut direct = 0usize;
        let mut symbol = 0usize;
        let mut unknown = 0usize;
        for e in &self.edges {
            match e.kind {
                DecompilerCallKind::Direct => direct += 1,
                DecompilerCallKind::Symbol => symbol += 1,
                DecompilerCallKind::Unknown => unknown += 1,
            }
        }
        (direct, symbol, unknown)
    }
}

/// Builds a `DecompilerCallGraph` from a set of decompiled functions.
///
/// This is the single entry point that turns SSA CallStmt facts into edges.
/// The emitter must never reconstruct edges itself; it only queries the built graph.
pub struct DecompilerCallGraphBuilder;

impl DecompilerCallGraphBuilder {
    /// Scan every function's statements (recursing into nested If/GuardClause
    /// bodies) and emit one edge per `Statement::CallStmt`.
    pub fn build(functions: &[&DecompilerFunction]) -> DecompilerCallGraph {
        let mut graph = DecompilerCallGraph::new();

        for func in functions {
            Self::collect_edges(func.address, &func.statements, &mut graph.edges);
        }

        // Build outgoing index.
        for (idx, edge) in graph.edges.iter().enumerate() {
            graph.outgoing.entry(edge.caller).or_default().push(idx);
            // Only address targets can be indexed as a callee node.
            if let CallTarget::Address(addr) = edge.callee {
                graph.incoming.entry(addr).or_default().push(idx);
            }
        }

        graph
    }

    fn collect_edges(caller: u64, stmts: &[Statement], out: &mut Vec<DecompilerCallEdge>) {
        for stmt in stmts {
            match stmt {
                Statement::CallStmt {
                    target, evidence, ..
                } => {
                    let callsite = evidence.instruction_addresses.first().copied().unwrap_or(0);
                    let kind = match target {
                        CallTarget::Address(_) => DecompilerCallKind::Direct,
                        CallTarget::Symbol(_) => DecompilerCallKind::Symbol,
                        CallTarget::Unknown => DecompilerCallKind::Unknown,
                    };
                    out.push(DecompilerCallEdge {
                        caller,
                        callee: target.clone(),
                        callsite,
                        kind,
                    });
                }
                Statement::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    Self::collect_edges(caller, then_body, out);
                    Self::collect_edges(caller, else_body, out);
                }
                Statement::GuardClause { body, .. } => {
                    Self::collect_edges(caller, body, out);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::ConditionRecovery;
    use crate::structured_ir::{
        DecompilerFunction, FunctionEvidence, Statement, StatementEvidence,
    };

    fn stmt_evidence() -> StatementEvidence {
        StatementEvidence {
            instruction_addresses: Vec::new(),
            block_ids: Vec::new(),
            reason: "test".to_string(),
        }
    }

    fn func_evidence() -> FunctionEvidence {
        FunctionEvidence {
            ssa_instructions: 0,
            cfg_blocks: 0,
            control_structures: 0,
            unknown_statements: 0,
            budget_exhausted: false,
        }
    }

    fn call_stmt(target: CallTarget) -> Statement {
        Statement::CallStmt {
            target,
            arguments: vec![],
            arguments_complete: true,
            behavior: None,
            evidence: stmt_evidence(),
        }
    }

    fn func(addr: u64, stmts: Vec<Statement>) -> DecompilerFunction {
        DecompilerFunction {
            address: addr,
            name: None,
            statements: stmts,
            evidence: func_evidence(),
        }
    }

    #[test]
    fn test_direct_call_edge() {
        let f_a = func(0x401000, vec![call_stmt(CallTarget::Address(0x402000))]);
        let graph = DecompilerCallGraphBuilder::build(&[&f_a]);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.kind_counts(), (1, 0, 0));
        // A calls B
        let callees = graph.callees_of(0x401000);
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].callee, CallTarget::Address(0x402000));
        // B is called by A
        let callers = graph.callers_of(0x402000);
        assert_eq!(callers, vec![0x401000]);
    }

    #[test]
    fn test_symbol_call_edge_not_indexed_as_callee() {
        let f_a = func(
            0x401000,
            vec![call_stmt(CallTarget::Symbol("printf".to_string()))],
        );
        let graph = DecompilerCallGraphBuilder::build(&[&f_a]);
        assert_eq!(graph.kind_counts(), (0, 1, 0));
        // Symbol has no address, so callers_of does not index it.
        assert!(graph.callers_of(0x0).is_empty());
        assert_eq!(graph.callees_of(0x401000).len(), 1);
    }

    #[test]
    fn test_unknown_call_edge_preserved() {
        let f_a = func(0x401000, vec![call_stmt(CallTarget::Unknown)]);
        let graph = DecompilerCallGraphBuilder::build(&[&f_a]);
        assert_eq!(graph.kind_counts(), (0, 0, 1));
        assert_eq!(graph.callees_of(0x401000).len(), 1);
    }

    #[test]
    fn test_query_callers_multi_caller() {
        // A and B both call C.
        let f_a = func(0x401000, vec![call_stmt(CallTarget::Address(0x403000))]);
        let f_b = func(0x402000, vec![call_stmt(CallTarget::Address(0x403000))]);
        let graph = DecompilerCallGraphBuilder::build(&[&f_a, &f_b]);
        let mut callers = graph.callers_of(0x403000);
        callers.sort();
        assert_eq!(callers, vec![0x401000, 0x402000]);
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn test_calls_inside_nested_if_are_collected() {
        // A calls B inside an If body.
        let f_a = func(
            0x401000,
            vec![Statement::If {
                condition: ConditionRecovery::NotConditionalJump,
                then_body: vec![call_stmt(CallTarget::Address(0x402000))],
                else_body: vec![],
                merge_block: None,
                lifted_call: None,
                evidence: stmt_evidence(),
            }],
        );
        let graph = DecompilerCallGraphBuilder::build(&[&f_a]);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.callees_of(0x401000).len(), 1);
    }
}
