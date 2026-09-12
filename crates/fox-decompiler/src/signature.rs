//! P0-12: Function Signature Recovery (Evidence Layer).
//!
//! Recovers the *interface facts* of a function purely by aggregating the
//! cross-function evidence already collected:
//!
//! ```text
//! For callee C:
//!   every caller's CallStmt.arguments[i]  ─► FunctionParameter #i
//!   every caller's CallBehavior          ─► ReturnEvidence
//! ```
//!
//! This does NOT guess function names, types, or business meaning. It only
//! reports: how many arguments are passed, what coarse source they come from,
//! and how the return value is consumed. Unknowns are preserved.

use crate::callgraph::DecompilerCallGraph;
use crate::dataflow::{ArgumentSourceKind, CrossFunctionDataFlowGraph, FlowDetail};
use crate::structured_ir::DecompilerFunction;
use std::collections::HashMap;

/// Where a parameter lives (coarse, evidence-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterLocation {
    /// Pushed on the stack (default x86 cdecl/stdcall slot).
    Stack,
    /// Delivered in a register (thiscall ecx / fastcall ecx+edx).
    Register,
    /// Location not determinable.
    Unknown,
}

impl ParameterLocation {
    pub fn label(self) -> &'static str {
        match self {
            ParameterLocation::Stack => "stack",
            ParameterLocation::Register => "register",
            ParameterLocation::Unknown => "unknown_loc",
        }
    }
}

/// One recovered parameter slot for a callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionParameter {
    /// 0-based argument index (push order, first pushed = lowest index recovered).
    pub index: usize,
    /// Coarse location.
    pub location: ParameterLocation,
    /// Most common source kind observed across all callers.
    pub source: ArgumentSourceKind,
    /// Number of call sites that pass this slot.
    pub call_sites: usize,
}

/// Evidence about how the callee's return value is consumed by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnEvidence {
    /// Return value feeds a condition somewhere.
    Condition,
    /// Return value is used as an ordinary value.
    Value,
    /// No return consumer observed.
    Unknown,
}

impl ReturnEvidence {
    pub fn label(&self) -> &'static str {
        match self {
            ReturnEvidence::Condition => "value", // bool-like consumer, but not asserted as bool
            ReturnEvidence::Value => "value",
            ReturnEvidence::Unknown => "unknown",
        }
    }
}

/// Confidence in the whole signature (evidence-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureConfidence {
    High,
    Medium,
    Low,
}

impl SignatureConfidence {
    pub fn label(self) -> &'static str {
        match self {
            SignatureConfidence::High => "HIGH",
            SignatureConfidence::Medium => "MEDIUM",
            SignatureConfidence::Low => "LOW",
        }
    }
}

/// Recovered signature for one callee function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    /// Callee function address.
    pub function: u64,
    /// Recovered parameter slots.
    pub parameters: Vec<FunctionParameter>,
    /// Return-value evidence.
    pub return_evidence: ReturnEvidence,
    /// Aggregate confidence.
    pub confidence: SignatureConfidence,
}

/// Aggregated signature map: callee address -> signature.
#[derive(Default, Clone)]
pub struct SignatureMap {
    signatures: HashMap<u64, FunctionSignature>,
}

impl SignatureMap {
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    pub fn get(&self, function: u64) -> Option<&FunctionSignature> {
        self.signatures.get(&function)
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Number of callees with at least N recovered parameters.
    pub fn with_param_count(&self, n: usize) -> usize {
        self.signatures
            .values()
            .filter(|s| s.parameters.len() >= n)
            .count()
    }
}

/// Builds signatures by aggregating caller argument/return evidence per callee.
pub struct FunctionSignatureBuilder;

impl FunctionSignatureBuilder {
    /// Aggregate the data-flow graph (and call graph) into per-callee signatures.
    ///
    /// Only `CallTarget::Address` callees get a signature (symbol/unknown callees
    /// have no canonical function node to attach to — preserved, not guessed).
    pub fn build(
        _functions: &[&DecompilerFunction],
        dataflow: &CrossFunctionDataFlowGraph,
        _call_graph: &DecompilerCallGraph,
    ) -> SignatureMap {
        // callee_addr -> param_index -> (source tally, call sites)
        let mut param_tallies: HashMap<u64, HashMap<usize, HashMap<ArgumentSourceKind, usize>>> =
            HashMap::new();
        // callee_addr -> (return observed, condition_seen)
        let mut return_seen: HashMap<u64, (bool, bool)> = HashMap::new();

        for flow in dataflow.edges() {
            // Only concrete internal callees get a signature node.
            let callee = match flow.callee {
                crate::CallTarget::Address(a) => a,
                _ => continue,
            };
            match &flow.detail {
                FlowDetail::Argument { index, source } => {
                    let entry = param_tallies.entry(callee).or_default();
                    let by_index = entry.entry(*index).or_default();
                    *by_index.entry(*source).or_insert(0) += 1;
                }
                FlowDetail::Return { consumer } => {
                    let e = return_seen.entry(callee).or_insert((false, false));
                    e.0 = true;
                    if matches!(consumer, crate::dataflow::ReturnConsumerKind::Condition) {
                        e.1 = true;
                    }
                }
            }
        }

        let mut map = SignatureMap::new();
        for (callee, by_index) in param_tallies {
            // Build sorted parameter list.
            let mut indices: Vec<usize> = by_index.keys().copied().collect();
            indices.sort_unstable();

            let mut parameters = Vec::new();
            let mut total_sites_for_0 = 0usize;
            for idx in &indices {
                let tally = &by_index[idx];
                let (&source, &sites) = tally
                    .iter()
                    .max_by_key(|(_, &n)| n)
                    .unwrap_or((&ArgumentSourceKind::Unknown, &0));
                if *idx == 0 {
                    total_sites_for_0 = sites;
                }
                // Heuristic: register source at index 0 with small stack args -> register slot.
                let location = if idx == &0
                    && matches!(source, ArgumentSourceKind::Register)
                    && indices.len() == 1
                {
                    ParameterLocation::Register
                } else {
                    ParameterLocation::Stack
                };
                parameters.push(FunctionParameter {
                    index: *idx,
                    location,
                    source,
                    call_sites: sites,
                });
            }

            // Confidence: parameters observed consistently across callers.
            let confidence = if total_sites_for_0 >= 3 && !indices.is_empty() {
                SignatureConfidence::Medium
            } else {
                SignatureConfidence::Low
            };

            let return_evidence = match return_seen.get(&callee) {
                Some((_, true)) => ReturnEvidence::Condition,
                Some((true, false)) => ReturnEvidence::Value,
                _ => ReturnEvidence::Unknown,
            };

            map.signatures.insert(
                callee,
                FunctionSignature {
                    function: callee,
                    parameters,
                    return_evidence,
                    confidence,
                },
            );
        }

        // Also emit a signature for callees seen ONLY via return flow (zero args).
        for (&callee, &(has_ret, cond)) in &return_seen {
            if map.signatures.contains_key(&callee) {
                continue;
            }
            let return_evidence = if cond {
                ReturnEvidence::Condition
            } else if has_ret {
                ReturnEvidence::Value
            } else {
                ReturnEvidence::Unknown
            };
            map.signatures.insert(
                callee,
                FunctionSignature {
                    function: callee,
                    parameters: Vec::new(),
                    return_evidence,
                    confidence: SignatureConfidence::Low,
                },
            );
        }

        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callgraph::DecompilerCallGraphBuilder;
    use crate::condition::ConditionRecovery;
    use crate::dataflow::CrossFunctionDataFlowBuilder;
    use crate::expression::{CallTarget, Expression};
    use crate::structured_ir::{
        CallBehavior, DecompilerFunction, FunctionEvidence, Statement, StatementEvidence,
    };

    fn ev() -> StatementEvidence {
        StatementEvidence {
            instruction_addresses: vec![0x401000],
            block_ids: vec![0],
            reason: "t".into(),
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

    fn build_map(funcs: &[&DecompilerFunction]) -> SignatureMap {
        let cg = DecompilerCallGraphBuilder::build(funcs);
        let df = CrossFunctionDataFlowBuilder::build(funcs, &cg);
        FunctionSignatureBuilder::build(funcs, &df, &cg)
    }

    #[test]
    fn test_no_arguments_no_signature() {
        // A leaf function that never calls anything has no callee signature.
        let f = func(
            0x4000,
            vec![Statement::Return {
                value: None,
                evidence: ev(),
            }],
        );
        let map = build_map(&[&f]);
        // 0x4000 itself receives no calls -> no signature.
        assert!(map.get(0x4000).is_none());
    }

    #[test]
    fn test_single_parameter_callee() {
        // Caller 0x4000 calls callee 0x5000 with one constant argument.
        let caller = func(
            0x4000,
            vec![Statement::CallStmt {
                target: CallTarget::Address(0x5000),
                arguments: vec![Expression::Constant(0)],
                arguments_complete: true,
                behavior: None,
                evidence: ev(),
            }],
        );
        let callee = func(
            0x5000,
            vec![Statement::Return {
                value: None,
                evidence: ev(),
            }],
        );
        let map = build_map(&[&caller, &callee]);
        let sig = map.get(0x5000).expect("callee should have a signature");
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].index, 0);
        assert_eq!(sig.parameters[0].source, ArgumentSourceKind::Constant);
    }

    #[test]
    fn test_multi_parameter_callee() {
        let caller = func(
            0x4000,
            vec![Statement::CallStmt {
                target: CallTarget::Address(0x6000),
                arguments: vec![
                    Expression::Constant(1),
                    Expression::Variable {
                        name: "ecx".into(),
                        version: 0,
                    },
                ],
                arguments_complete: true,
                behavior: None,
                evidence: ev(),
            }],
        );
        let callee = func(
            0x6000,
            vec![Statement::Return {
                value: None,
                evidence: ev(),
            }],
        );
        let map = build_map(&[&caller, &callee]);
        let sig = map.get(0x6000).unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].source, ArgumentSourceKind::Constant);
        assert_eq!(sig.parameters[1].source, ArgumentSourceKind::Register);
    }

    #[test]
    fn test_return_evidence_from_condition() {
        let caller = func(
            0x4000,
            vec![Statement::CallStmt {
                target: CallTarget::Address(0x7000),
                arguments: vec![],
                arguments_complete: true,
                behavior: Some(CallBehavior::ReturnUsedInCondition {
                    condition: ConditionRecovery::NotConditionalJump,
                    consumer_instruction: 0,
                    branch_instruction: 0,
                }),
                evidence: ev(),
            }],
        );
        let callee = func(
            0x7000,
            vec![Statement::Return {
                value: None,
                evidence: ev(),
            }],
        );
        let map = build_map(&[&caller, &callee]);
        let sig = map.get(0x7000).unwrap();
        assert_eq!(sig.return_evidence, ReturnEvidence::Condition);
    }

    #[test]
    fn test_unknown_call_has_no_signature() {
        // Indirect/unknown call target must NOT fabricate a signature.
        let caller = func(
            0x4000,
            vec![Statement::CallStmt {
                target: CallTarget::Unknown,
                arguments: vec![Expression::Constant(0)],
                arguments_complete: false,
                behavior: None,
                evidence: ev(),
            }],
        );
        let map = build_map(&[&caller]);
        assert!(
            map.is_empty(),
            "unknown target must not produce a signature"
        );
    }
}
