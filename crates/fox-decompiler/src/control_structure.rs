//! P0-6.4B: Control Structure Recovery (If/Else + Guard Clause / Early Return).
//!
//! Lifts existing CFG conditional branches into verifiable control structures
//! by reusing P0-6.3A ConditionRecovery.
//!
//! Detection methods (minimal, no Post-Dominator):
//! 1. If/Else — both branch targets share a common successor (merge).
//! 2. GuardClause — one branch path reaches a Return before the other;
//!    no common successor.
//! 3. Unknown — neither pattern applies; fail-closed.
//!
//! CFG remains Ground Truth. This module only adds a semantic interpretation
//! layer on top of existing CFG + SSA facts.

use fox_analysis::cfg::FunctionCfg;
use fox_analysis::ssa::SSAFunction;
use fox_core::EdgeKind;
use std::collections::HashSet;

use crate::condition::{recover_condition, ConditionRecovery};

// ---------------------------------------------------------------------------
// Data Model
// ---------------------------------------------------------------------------

/// A recovered control structure.
#[derive(Debug, Clone)]
pub enum ControlStructure {
    /// if/else with optional merge block.
    IfElse(IfElse),
    /// Guard clause / early return: one branch returns early.
    GuardClause(GuardClause),
    /// Conditional branch that could not be structured.
    Unknown(UnknownBranch),
}

/// if (condition) { then } else { else } [→ merge]
#[derive(Debug, Clone)]
pub struct IfElse {
    /// Recovered condition (from P0-6.3A).
    pub condition: ConditionRecovery,
    /// CFG block index of the conditional branch.
    pub branch_block: usize,
    /// CFG block index of the "then" path (ConditionalTrue / branch taken).
    pub then_block: usize,
    /// CFG block index of the "else" path (ConditionalFalse / fallthrough).
    pub else_block: usize,
    /// CFG block index of the merge point, if found.
    pub merge_block: Option<usize>,
    /// Evidence trace.
    pub evidence: StructureEvidence,
}

/// if (condition) { return ... };  // early return / guard clause
#[derive(Debug, Clone)]
pub struct GuardClause {
    /// Recovered condition (from P0-6.3A).
    pub condition: ConditionRecovery,
    /// CFG block index of the conditional branch.
    pub branch_block: usize,
    /// CFG block index of the normal continuation path.
    pub body_block: usize,
    /// CFG block index of the early-return path.
    pub return_block: usize,
    /// Whether the return path is the ConditionalTrue (taken) branch.
    pub return_is_taken_branch: bool,
    /// Evidence trace.
    pub evidence: StructureEvidence,
}

/// Conditional branch that could not be structured.
#[derive(Debug, Clone)]
pub struct UnknownBranch {
    /// CFG block index.
    pub branch_block: usize,
    /// Why it could not be structured.
    pub reason: String,
    /// Recovered condition (may be unresolved).
    pub condition: ConditionRecovery,
    /// Evidence trace.
    pub evidence: StructureEvidence,
}

/// Evidence explaining why a control structure exists.
///
/// Every field traces back to CFG or SSA facts.
#[derive(Debug, Clone)]
pub struct StructureEvidence {
    /// Address of the conditional jump instruction.
    pub branch_address: u64,
    /// Address of the ConditionalTrue (taken) target.
    pub true_target_address: u64,
    /// Address of the ConditionalFalse (fallthrough) target.
    pub false_target_address: u64,
    /// Address of the merge block (IfElse only).
    pub merge_address: Option<u64>,
    /// Whether a Return edge was detected in one branch.
    pub return_edge_detected: bool,
    /// Human-readable detection rationale.
    pub detection_reason: String,
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Recover control structures for a single function.
///
/// Inputs:
/// - `cfg`: the function CFG (Ground Truth for control flow).
/// - `ssa`: the function SSA (for ConditionRecovery via P0-6.3A).
///
/// Returns one `ControlStructure` per conditional branch block.
pub fn recover_control_structures(cfg: &FunctionCfg, ssa: &SSAFunction) -> Vec<ControlStructure> {
    let mut results = Vec::new();

    for (block_id, block) in cfg.blocks.iter().enumerate() {
        // Must have both ConditionalTrue and ConditionalFalse successors
        let cond_true: Vec<_> = block
            .successors
            .iter()
            .filter(|e| e.kind == EdgeKind::ConditionalTrue)
            .collect();
        let cond_false: Vec<_> = block
            .successors
            .iter()
            .filter(|e| e.kind == EdgeKind::ConditionalFalse)
            .collect();

        if cond_true.is_empty() || cond_false.is_empty() {
            continue;
        }

        let true_target = cond_true[0].target_block;
        let false_target = cond_false[0].target_block;

        // Find the CondJump instruction in SSA for this block
        let ssa_block = match ssa.basic_blocks.get(block_id) {
            Some(b) => b,
            None => continue,
        };
        let cond_jump_idx = match ssa_block
            .instructions
            .iter()
            .position(|i| i.op == "CondJump")
        {
            Some(idx) => idx,
            None => continue,
        };

        let branch_address = ssa_block.instructions[cond_jump_idx].address;

        // Reuse P0-6.3A ConditionRecovery (single source of truth)
        let condition = recover_condition(ssa, block_id, cond_jump_idx);

        let base_evidence = StructureEvidence {
            branch_address,
            true_target_address: cond_true[0].target_address.unwrap_or(0),
            false_target_address: cond_false[0].target_address.unwrap_or(0),
            merge_address: None,
            return_edge_detected: false,
            detection_reason: String::new(),
        };

        // Both targets must be known
        let (tt, ft) = match (true_target, false_target) {
            (Some(t), Some(f)) => (t, f),
            _ => {
                results.push(ControlStructure::Unknown(UnknownBranch {
                    branch_block: block_id,
                    reason: "one or both branch targets unresolved (indirect jump)".into(),
                    condition,
                    evidence: StructureEvidence {
                        detection_reason: "indirect or unresolved branch target".into(),
                        ..base_evidence
                    },
                }));
                continue;
            }
        };

        // --- Detection 1: If/Else with bounded common reachable merge ---
        // Uses BFS forward reachability (depth 8) to find a merge block
        // reachable from both branch paths. Excludes loop back-edges.
        const MERGE_BFS_DEPTH: usize = 8;
        if let Some(merge_block) =
            find_bounded_common_merge(cfg, tt, ft, block.start_address.0, MERGE_BFS_DEPTH)
        {
            let merge_address = cfg.blocks[merge_block].start_address.0;
            results.push(ControlStructure::IfElse(IfElse {
                condition,
                branch_block: block_id,
                then_block: tt,
                else_block: ft,
                merge_block: Some(merge_block),
                evidence: StructureEvidence {
                    merge_address: Some(merge_address),
                    detection_reason: format!(
                        "both branches share common successor block @ 0x{:X}",
                        merge_address
                    ),
                    ..base_evidence
                },
            }));
            continue;
        }

        // --- Detection 2: Guard Clause / Early Return (evidence-first) ---
        // One branch path has an immediate Return edge in CFG, and the
        // other path does NOT. Double-return (both immediate) → Unknown.
        if let Some((body_block, return_block, return_is_taken)) = detect_guard_clause(cfg, tt, ft)
        {
            results.push(ControlStructure::GuardClause(GuardClause {
                condition,
                branch_block: block_id,
                body_block,
                return_block,
                return_is_taken_branch: return_is_taken,
                evidence: StructureEvidence {
                    return_edge_detected: true,
                    detection_reason: format!(
                        "branch @ 0x{:X}: return path has immediate CFG Return edge; \
                         continuation path does not; early-return block @ 0x{:X}",
                        branch_address, cfg.blocks[return_block].start_address.0
                    ),
                    ..base_evidence
                },
            }));
            continue;
        }

        // --- Fail-closed: Unknown ---
        results.push(ControlStructure::Unknown(UnknownBranch {
            branch_block: block_id,
            reason: "no bounded merge and no evidence-first guard clause".into(),
            condition,
            evidence: StructureEvidence {
                detection_reason:
                    "unstructured conditional branch (no bounded merge, no evidence-first guard clause)"
                        .into(),
                ..base_evidence
            },
        }));
    }

    results
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Find a common reachable merge block of two branch paths.
///
/// Uses bounded BFS forward reachability from both `a` and `b`, and returns
/// the first block reachable from both within `max_depth` steps.
///
/// Loop / back-edge exclusion: a candidate merge block must have
/// `start_address >= branch_block_address`, which prevents loop headers
/// (located before the branch) from being falsely identified as merges.
///
/// Returns the first common reachable block index, or None.
fn find_bounded_common_merge(
    cfg: &FunctionCfg,
    a: usize,
    b: usize,
    branch_block_address: u64,
    max_depth: usize,
) -> Option<usize> {
    use std::collections::VecDeque;

    // BFS from `a`, collect all reachable block indices within max_depth.
    let mut a_reachable: HashSet<usize> = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((a, 0usize));
    a_reachable.insert(a);
    while let Some((bid, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for e in &cfg.blocks[bid].successors {
            if let Some(tid) = e.target_block {
                // Skip edges that go backward (loop back-edges)
                if cfg.blocks[tid].start_address.0 < branch_block_address {
                    continue;
                }
                if !a_reachable.contains(&tid) {
                    a_reachable.insert(tid);
                    queue.push_back((tid, depth + 1));
                }
            }
        }
    }

    // BFS from `b`, find first block also in `a_reachable`.
    let mut b_visited: HashSet<usize> = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((b, 0usize));
    b_visited.insert(b);
    while let Some((bid, depth)) = queue.pop_front() {
        // Check if this block is a common merge (excluding the start points a/b themselves)
        if bid != a && bid != b && a_reachable.contains(&bid) {
            return Some(bid);
        }
        if depth >= max_depth {
            continue;
        }
        for e in &cfg.blocks[bid].successors {
            if let Some(tid) = e.target_block {
                if cfg.blocks[tid].start_address.0 < branch_block_address {
                    continue;
                }
                if !b_visited.contains(&tid) {
                    b_visited.insert(tid);
                    queue.push_back((tid, depth + 1));
                }
            }
        }
    }

    None
}

/// Check whether a block is an "immediate return path".
///
/// An immediate return path is strong evidence for a guard clause / early
/// return: the branch target block **itself** has a Return edge in the CFG.
///
/// This is the most conservative, evidence-first definition. It requires the
/// Return edge to be present directly on the branch target block, not
/// inferred from distance comparison or reachability through intermediate
/// blocks.
///
/// Returns true if `start` itself has a Return successor edge.
fn is_immediate_return_path(cfg: &FunctionCfg, start: usize) -> bool {
    cfg.blocks[start]
        .successors
        .iter()
        .any(|e| e.kind == EdgeKind::Return)
}

/// Detect a guard clause / early return using evidence-first criteria.
///
/// A guard clause requires:
/// - One branch path is an **immediate return path** (has Return edge in CFG).
/// - The other branch path is **NOT** an immediate return path.
///
/// If both paths are immediate return (double return), or neither is, this
/// is NOT a guard clause — returns None.
///
/// This replaces the previous shortest-return-distance heuristic, which
/// produced massive false positives (89% of GuardClause had body also
/// reaching Return).
///
/// `true_target` = ConditionalTrue (taken branch), `false_target` = ConditionalFalse.
fn detect_guard_clause(
    cfg: &FunctionCfg,
    true_target: usize,
    false_target: usize,
) -> Option<(usize, usize, bool)> {
    let true_is_ret = is_immediate_return_path(cfg, true_target);
    let false_is_ret = is_immediate_return_path(cfg, false_target);

    match (true_is_ret, false_is_ret) {
        // Only true path is immediate return → guard clause, return=true path
        (true, false) => Some((false_target, true_target, true)),
        // Only false path is immediate return → guard clause, return=false path
        (false, true) => Some((true_target, false_target, false)),
        // Both immediate return (double return) → NOT a guard clause
        // Neither immediate return → NOT a guard clause
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Display for ControlStructure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlStructure::IfElse(ie) => write!(
                f,
                "IfElse @ 0x{:X}: then=block[{}] else=block[{}] merge={:?}",
                ie.evidence.branch_address, ie.then_block, ie.else_block, ie.merge_block
            ),
            ControlStructure::GuardClause(gc) => write!(
                f,
                "GuardClause @ 0x{:X}: body=block[{}] return=block[{}] (return is {} branch)",
                gc.evidence.branch_address,
                gc.body_block,
                gc.return_block,
                if gc.return_is_taken_branch {
                    "taken"
                } else {
                    "fallthrough"
                }
            ),
            ControlStructure::Unknown(ub) => write!(
                f,
                "Unknown @ 0x{:X}: {}",
                ub.evidence.branch_address, ub.reason
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use fox_analysis::basic_block::BasicBlock;
    use fox_core::{Address, CfgEdge, Evidence};

    /// Helper: build a minimal FunctionCfg with given blocks and edges.
    type TestBlockSpec = (usize, u64, Vec<(EdgeKind, Option<usize>, u64)>);

    fn make_cfg(blocks: Vec<TestBlockSpec>) -> FunctionCfg {
        let cfg_blocks: Vec<BasicBlock> = blocks
            .iter()
            .map(|(id, addr, succs)| {
                let mut bb = BasicBlock::new(*id, Address(*addr));
                bb.end_address = Address(*addr);
                for (kind, target, target_addr) in succs {
                    let mut edge = CfgEdge::new(*kind, *id, *addr);
                    if let Some(t) = target {
                        edge = edge.with_target(*t, *target_addr);
                    }
                    edge.evidence
                        .push(Evidence::new(fox_core::EvidenceKind::UnknownEdge));
                    bb.successors.push(edge);
                }
                bb
            })
            .collect();

        FunctionCfg {
            function_address: Address(0x1000),
            function_name: "test".into(),
            blocks: cfg_blocks,
            entry_block: 0,
            edge_count: 0,
            invalid_addresses: vec![],
        }
    }

    /// Helper: build a minimal SSA with a CondJump in a block.
    fn make_ssa_with_condjump(block_id: usize) -> SSAFunction {
        use fox_analysis::ssa::{SSABasicBlock, SSAInstruction, SSAOperand};
        use std::collections::HashMap;

        let mut block = SSABasicBlock {
            id: block_id,
            start_address: 0x1000,
            end_address: 0x1013,
            instructions: vec![
                SSAInstruction {
                    address: 0x1010,
                    op: "Test".into(),
                    operands: vec![
                        SSAOperand::Variable {
                            name: "eax".into(),
                            version: 1,
                        },
                        SSAOperand::Variable {
                            name: "eax".into(),
                            version: 1,
                        },
                        SSAOperand::Variable {
                            name: "FLAGS".into(),
                            version: 2,
                        },
                    ],
                    original_mnemonic: "test".into(),
                    destination_operand_idx: None,
                },
                SSAInstruction {
                    address: 0x1013,
                    op: "CondJump".into(),
                    operands: vec![
                        SSAOperand::Constant(0x1020),
                        SSAOperand::Variable {
                            name: "FLAGS".into(),
                            version: 2,
                        },
                    ],
                    original_mnemonic: "jz".into(),
                    destination_operand_idx: None,
                },
            ],
            phi_nodes: vec![],
            successors: vec![],
            predecessors: vec![],
        };

        let mut basic_blocks = Vec::new();
        for i in 0..block_id {
            basic_blocks.push(SSABasicBlock {
                id: i,
                start_address: 0,
                end_address: 0,
                instructions: vec![],
                phi_nodes: vec![],
                successors: vec![],
                predecessors: vec![],
            });
        }
        block.id = block_id;
        basic_blocks.push(block);

        SSAFunction {
            name: "test".into(),
            address: 0x1000,
            basic_blocks,
            entry_block: 0,
            phi_nodes: vec![],
            variable_versions: HashMap::new(),
            evidence: vec![],
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            proper_renaming: false,
        }
    }

    #[test]
    fn test_if_else_common_successor() {
        // B0: cond jump → B1 (true), B2 (false); B1→B3, B2→B3 (merge)
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (3, 0x1020, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::IfElse(ie) => {
                assert_eq!(ie.then_block, 1);
                assert_eq!(ie.else_block, 2);
                assert_eq!(ie.merge_block, Some(3));
                assert!(ie.evidence.merge_address.is_some());
            }
            other => panic!("expected IfElse, got {:?}", other),
        }
    }

    #[test]
    fn test_guard_clause_early_return() {
        // B0: cond jump → B1 (true, returns), B2 (false, continues)
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Return, None, 0)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (3, 0x1020, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::GuardClause(gc) => {
                assert_eq!(gc.body_block, 2);
                assert_eq!(gc.return_block, 1);
                assert!(gc.return_is_taken_branch);
                assert!(gc.evidence.return_edge_detected);
            }
            other => panic!("expected GuardClause, got {:?}", other),
        }
    }

    #[test]
    fn test_multi_block_if_else_bounded_merge() {
        // B0: cond → B1 (true), B2 (false); B1→B3→M, B2→B4→M
        // Old direct-successor logic would miss this (B1→{B3}, B2→{B4}, no intersection).
        // New bounded BFS finds M as common reachable merge.
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(4), 0x1025)]),
            (3, 0x1020, vec![(EdgeKind::Fallthrough, Some(5), 0x1030)]),
            (4, 0x1025, vec![(EdgeKind::Fallthrough, Some(5), 0x1030)]),
            (5, 0x1030, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::IfElse(ie) => {
                assert_eq!(ie.then_block, 1);
                assert_eq!(ie.else_block, 2);
                assert_eq!(ie.merge_block, Some(5));
            }
            other => panic!("expected IfElse (bounded merge), got {:?}", other),
        }
    }

    #[test]
    fn test_double_return_is_unknown_not_guard() {
        // B0: cond → B1 (true, immediate return), B2 (false, immediate return)
        // Both paths are immediate return → double return → NOT a guard clause → Unknown
        // This tests that the equal-distance tiebreaker has been removed.
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Return, None, 0)]),
            (2, 0x1015, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::Unknown(ub) => {
                assert!(ub.reason.contains("no bounded merge") || ub.reason.contains("guard"));
            }
            other => panic!("expected Unknown (double return), got {:?}", other),
        }
    }

    #[test]
    fn test_normal_if_else_both_eventually_return_is_ifelse() {
        // B0: cond → B1, B2; both paths do work then return, with common merge M.
        // Neither side is "immediate return" (both have multiple blocks before return).
        // This is a normal if/else, NOT a guard clause.
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(4), 0x1025)]),
            (3, 0x1020, vec![(EdgeKind::Fallthrough, Some(5), 0x1030)]),
            (4, 0x1025, vec![(EdgeKind::Fallthrough, Some(5), 0x1030)]),
            (5, 0x1030, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        // Bounded BFS finds M=block[5] as common merge → IfElse
        match &structures[0] {
            ControlStructure::IfElse(ie) => {
                assert_eq!(ie.merge_block, Some(5));
            }
            other => panic!(
                "expected IfElse (normal if/else with merge), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_guard_clause_immediate_return_vs_continuation() {
        // B0: cond → B1 (true, immediate return), B2 (false, continues to B3 then return)
        // B1 is immediate return, B2 is NOT → genuine guard clause.
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Return, None, 0)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (3, 0x1020, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::GuardClause(gc) => {
                assert_eq!(gc.body_block, 2);
                assert_eq!(gc.return_block, 1);
                assert!(gc.return_is_taken_branch);
                assert!(gc.evidence.return_edge_detected);
                // Evidence should mention "immediate CFG Return edge"
                assert!(gc
                    .evidence
                    .detection_reason
                    .contains("immediate CFG Return edge"));
            }
            other => panic!("expected GuardClause, got {:?}", other),
        }
    }

    #[test]
    fn test_genuinely_unstructured_unknown() {
        // B0: cond → B1, B2; paths diverge and never merge, neither immediate return.
        // B1→B3 (dead end), B2→B4 (dead end). No common merge, no guard → Unknown.
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(4), 0x1025)]),
            (3, 0x1020, vec![]),
            (4, 0x1025, vec![]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::Unknown(_) => {}
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn test_indirect_jump_unknown() {
        // B0: cond jump → B1 (true), IndirectJump (false, no target)
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, None, 0),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        match &structures[0] {
            ControlStructure::Unknown(ub) => {
                assert!(ub.reason.contains("unresolved"));
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn test_no_conditional_branch_no_structure() {
        // B0: just fallthrough, no conditional branch
        let cfg = make_cfg(vec![
            (0, 0x1000, vec![(EdgeKind::Fallthrough, Some(1), 0x1010)]),
            (1, 0x1010, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);
        assert!(structures.is_empty());
    }

    #[test]
    fn test_evidence_traceability() {
        let cfg = make_cfg(vec![
            (
                0,
                0x1000,
                vec![
                    (EdgeKind::ConditionalTrue, Some(1), 0x1010),
                    (EdgeKind::ConditionalFalse, Some(2), 0x1015),
                ],
            ),
            (1, 0x1010, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (2, 0x1015, vec![(EdgeKind::Fallthrough, Some(3), 0x1020)]),
            (3, 0x1020, vec![(EdgeKind::Return, None, 0)]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        if let ControlStructure::IfElse(ie) = &structures[0] {
            assert_eq!(ie.evidence.branch_address, 0x1013);
            assert_eq!(ie.evidence.true_target_address, 0x1010);
            assert_eq!(ie.evidence.false_target_address, 0x1015);
            assert_eq!(ie.evidence.merge_address, Some(0x1020));
            assert!(!ie.evidence.detection_reason.is_empty());
        }
    }
}
