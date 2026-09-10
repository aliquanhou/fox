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

        // --- Detection 1: If/Else with common successor (merge) ---
        if let Some(merge_block) = find_common_successor(cfg, tt, ft) {
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

        // --- Detection 2: Guard Clause / Early Return ---
        // One branch path reaches a Return block before the other.
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
                        "branch @ 0x{:X} reaches Return before other path; early-return block @ 0x{:X}",
                        branch_address,
                        cfg.blocks[return_block].start_address.0
                    ),
                    ..base_evidence
                },
            }));
            continue;
        }

        // --- Fail-closed: Unknown ---
        results.push(ControlStructure::Unknown(UnknownBranch {
            branch_block: block_id,
            reason: "no common successor and no detectable early-return path".into(),
            condition,
            evidence: StructureEvidence {
                detection_reason:
                    "unstructured conditional branch (no merge, no early return detected)".into(),
                ..base_evidence
            },
        }));
    }

    results
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Find a common successor block of two blocks (the merge point).
///
/// Returns the first common successor block index, or None.
fn find_common_successor(cfg: &FunctionCfg, a: usize, b: usize) -> Option<usize> {
    let a_succs: HashSet<usize> = cfg.blocks[a]
        .successors
        .iter()
        .filter_map(|e| e.target_block)
        .collect();
    let b_succs: HashSet<usize> = cfg.blocks[b]
        .successors
        .iter()
        .filter_map(|e| e.target_block)
        .collect();

    a_succs.intersection(&b_succs).next().copied()
}

/// Detect whether one branch path reaches a Return before the other.
///
/// Returns Some((body_block, return_block, return_is_taken_branch)) if a
/// guard clause pattern is detected, None otherwise.
///
/// Uses shortest-path distance to a Return block. If one branch reaches
/// Return in strictly fewer steps than the other (and they don't merge),
/// the shorter path is the early-return / guard clause path.
///
/// `true_target` = ConditionalTrue (taken branch), `false_target` = ConditionalFalse.
fn detect_guard_clause(
    cfg: &FunctionCfg,
    true_target: usize,
    false_target: usize,
) -> Option<(usize, usize, bool)> {
    const MAX_DEPTH: usize = 15;

    let true_dist = shortest_return_distance(cfg, true_target, MAX_DEPTH);
    let false_dist = shortest_return_distance(cfg, false_target, MAX_DEPTH);

    match (true_dist, false_dist) {
        (Some(t), Some(f)) if t < f => Some((false_target, true_target, true)),
        (Some(t), Some(f)) if f < t => Some((true_target, false_target, false)),
        // Equal distance: both paths reach return. In the common `jcc error_block`
        // pattern, the taken (ConditionalTrue) branch is the early-return path.
        // This is a convention-based tiebreaker, not a guess about semantics —
        // the structure is still a valid guard clause regardless of which side
        // is labeled "return".
        (Some(_), Some(_)) => Some((false_target, true_target, true)),
        (Some(_), None) => Some((false_target, true_target, true)),
        (None, Some(_)) => Some((true_target, false_target, false)),
        _ => None,
    }
}

/// BFS to find the shortest distance from `start` to a block with a Return edge.
///
/// Returns Some(distance) or None if no Return is reachable within max_depth.
/// Cycle-safe (tracks visited blocks).
fn shortest_return_distance(cfg: &FunctionCfg, start: usize, max_depth: usize) -> Option<usize> {
    use std::collections::VecDeque;

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back((start, 0usize));
    visited.insert(start);

    while let Some((block_id, depth)) = queue.pop_front() {
        let block = &cfg.blocks[block_id];

        // Check if this block has a Return successor
        if block.successors.iter().any(|e| e.kind == EdgeKind::Return) {
            return Some(depth);
        }

        if depth >= max_depth {
            continue;
        }

        // Continue BFS
        for succ in &block.successors {
            if let Some(tid) = succ.target_block {
                if !visited.contains(&tid) {
                    visited.insert(tid);
                    queue.push_back((tid, depth + 1));
                }
            }
        }
    }

    None
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
    fn test_unknown_ambiguous_branch() {
        // B0: cond jump → B1, B2; neither merges nor returns within depth
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
            (5, 0x1030, vec![]),
        ]);
        let ssa = make_ssa_with_condjump(0);
        let structures = recover_control_structures(&cfg, &ssa);

        assert_eq!(structures.len(), 1);
        // B3→B5 and B4→B5: B5 is a common successor of B3 and B4, but NOT of B1 and B2.
        // Wait — B1→B3, B2→B4. B3→B5, B4→B5. So B1's successor is B3, B2's successor is B4.
        // B3 and B4 don't share a successor directly. But B3→B5 and B4→B5 means B5 is a
        // common successor of B3 and B4, not B1 and B2.
        // find_common_successor checks B1 and B2's direct successors. B1→{B3}, B2→{B4}.
        // No common successor. Then guard clause check: B1 reaches return? B1→B3→B5(no return).
        // B2→B4→B5(no return). Neither reaches return within depth 12. So Unknown.
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
