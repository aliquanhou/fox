//! FOX Dominator Analysis
//!
//! P0-2.4: Dominator Tree, Immediate Dominator, Dominance Frontier.
//!
//! Based on the standard iterative data flow algorithm:
//!   Dom(n) = {n} ∪ (∩ Dom(p) for p in pred(n))
//!
//! Dominance Frontier:
//!   DF(n) = { w | n dominates a predecessor of w, but n does not strictly dominate w }

use fox_core::{Evidence, EvidenceKind};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Dominator analysis result for a single function CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominatorTree {
    /// Number of basic blocks
    pub block_count: usize,
    /// Entry block index
    pub entry_block: usize,
    /// Map: block index -> set of dominator block indices
    pub dominators: HashMap<usize, HashSet<usize>>,
    /// Map: block index -> immediate dominator block index (None for entry)
    pub immediate_dominators: HashMap<usize, Option<usize>>,
    /// Map: block index -> set of dominance frontier block indices
    pub dominance_frontier: HashMap<usize, HashSet<usize>>,
    /// Children in dominator tree: block -> list of immediately dominated blocks
    pub children: HashMap<usize, Vec<usize>>,
    /// Evidence for the analysis
    pub evidence: Vec<Evidence>,
}

impl DominatorTree {
    /// Compute dominator tree from CFG.
    ///
    /// `successors`: map block index -> list of successor block indices
    /// `predecessors`: map block index -> list of predecessor block indices
    /// `entry`: entry block index
    /// `block_count`: total number of blocks
    pub fn compute(
        _successors: &HashMap<usize, Vec<usize>>,
        predecessors: &HashMap<usize, Vec<usize>>,
        entry: usize,
        block_count: usize,
    ) -> Self {
        let all_blocks: HashSet<usize> = (0..block_count).collect();

        // Initialize: entry dominates only itself; all others dominate everything
        let mut dom: HashMap<usize, HashSet<usize>> = HashMap::new();
        for b in 0..block_count {
            if b == entry {
                dom.insert(b, [entry].iter().cloned().collect());
            } else {
                dom.insert(b, all_blocks.clone());
            }
        }

        // Iterative fixed-point computation
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 1000 {
            changed = false;
            iterations += 1;

            for b in 0..block_count {
                if b == entry {
                    continue;
                }

                let preds = predecessors.get(&b).cloned().unwrap_or_default();
                if preds.is_empty() {
                    continue;
                }

                // Intersect dominators of all predecessors
                let mut new_dom: Option<HashSet<usize>> = None;
                for p in &preds {
                    let p_dom = dom.get(p).cloned().unwrap_or_default();
                    new_dom = Some(match new_dom {
                        None => p_dom,
                        Some(acc) => acc.intersection(&p_dom).cloned().collect(),
                    });
                }

                let mut new_dom = new_dom.unwrap_or_default();
                new_dom.insert(b); // A block always dominates itself

                if new_dom != *dom.get(&b).unwrap() {
                    dom.insert(b, new_dom);
                    changed = true;
                }
            }
        }

        // Compute immediate dominators
        let mut idom: HashMap<usize, Option<usize>> = HashMap::new();
        for b in 0..block_count {
            if b == entry {
                idom.insert(b, None);
                continue;
            }
            let b_dom = dom.get(&b).cloned().unwrap_or_default();
            // Immediate dominator = the dominator (other than self) that is
            // dominated by all other dominators
            let mut idom_candidate: Option<usize> = None;
            for d in &b_dom {
                if *d == b {
                    continue;
                }
                // Check if d is dominated by all other dominators of b
                let d_dom = dom.get(d).cloned().unwrap_or_default();
                let is_idom = b_dom
                    .iter()
                    .filter(|&&x| x != b && x != *d)
                    .all(|x| d_dom.contains(x));
                if is_idom {
                    idom_candidate = Some(*d);
                    break;
                }
            }
            idom.insert(b, idom_candidate);
        }

        // Build dominator tree children
        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        for b in 0..block_count {
            if let Some(Some(parent)) = idom.get(&b) {
                children.entry(*parent).or_default().push(b);
            }
        }

        // Compute dominance frontier
        let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();
        for b in 0..block_count {
            df.insert(b, HashSet::new());
        }

        for b in 0..block_count {
            let preds = predecessors.get(&b).cloned().unwrap_or_default();
            if preds.len() >= 2 {
                // Join point: for each predecessor, walk up dominator tree
                for p in &preds {
                    let mut runner = *p;
                    let mut walked: HashSet<usize> = HashSet::new();
                    while Some(runner) != idom.get(&b).cloned().unwrap_or(None) {
                        if !walked.insert(runner) {
                            break; // GAP-RM-8.2: dominator chain broken/cycle, fail-safe
                        }
                        df.entry(runner).or_default().insert(b);
                        runner = idom.get(&runner).cloned().unwrap_or(None).unwrap_or(runner);
                        if runner == *p {
                            break; // prevent infinite loop
                        }
                    }
                }
            }
        }

        let mut evidence = Vec::new();
        evidence.push(Evidence::new(EvidenceKind::DominatorAnalysis).with_weight(0.9));
        evidence.push(
            Evidence::new(EvidenceKind::Heuristic {
                description: format!(
                    "Dominator tree: {} blocks, {} iterations",
                    block_count, iterations
                ),
            })
            .with_weight(0.7),
        );

        DominatorTree {
            block_count,
            entry_block: entry,
            dominators: dom,
            immediate_dominators: idom,
            dominance_frontier: df,
            children,
            evidence,
        }
    }

    /// Get the immediate dominator of a block.
    pub fn idom(&self, block: usize) -> Option<usize> {
        self.immediate_dominators
            .get(&block)
            .cloned()
            .unwrap_or(None)
    }

    /// Check if block A dominates block B.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        self.dominators
            .get(&b)
            .map(|d| d.contains(&a))
            .unwrap_or(false)
    }

    /// Get the dominance frontier of a block.
    pub fn frontier(&self, block: usize) -> &HashSet<usize> {
        self.dominance_frontier
            .get(&block)
            .unwrap_or_else(|| empty_set())
    }

    /// Get children in the dominator tree.
    pub fn children(&self, block: usize) -> &[usize] {
        self.children
            .get(&block)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

use std::sync::OnceLock;
static EMPTY_SET: OnceLock<HashSet<usize>> = OnceLock::new();
fn empty_set() -> &'static HashSet<usize> {
    EMPTY_SET.get_or_init(HashSet::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple_cfg() -> (HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
        // 0 -> 1, 0 -> 2
        // 1 -> 3
        // 2 -> 3
        // 3 -> 4
        let mut succ = HashMap::new();
        succ.insert(0, vec![1, 2]);
        succ.insert(1, vec![3]);
        succ.insert(2, vec![3]);
        succ.insert(3, vec![4]);
        succ.insert(4, vec![]);

        let mut pred = HashMap::new();
        pred.insert(0, vec![]);
        pred.insert(1, vec![0]);
        pred.insert(2, vec![0]);
        pred.insert(3, vec![1, 2]);
        pred.insert(4, vec![3]);

        (succ, pred)
    }

    #[test]
    fn test_dominator_basic() {
        let (succ, pred) = build_simple_cfg();
        let dt = DominatorTree::compute(&succ, &pred, 0, 5);

        // Entry dominates everything
        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.dominates(0, 3));
        assert!(dt.dominates(0, 4));

        // Block 1 does not dominate block 2
        assert!(!dt.dominates(1, 2));

        // Block 3 dominates block 4
        assert!(dt.dominates(3, 4));
    }

    #[test]
    fn test_immediate_dominator() {
        let (succ, pred) = build_simple_cfg();
        let dt = DominatorTree::compute(&succ, &pred, 0, 5);

        assert_eq!(dt.idom(0), None);
        assert_eq!(dt.idom(1), Some(0));
        assert_eq!(dt.idom(2), Some(0));
        assert_eq!(dt.idom(3), Some(0)); // join point, idom is entry
        assert_eq!(dt.idom(4), Some(3));
    }

    #[test]
    fn test_dominance_frontier() {
        let (succ, pred) = build_simple_cfg();
        let dt = DominatorTree::compute(&succ, &pred, 0, 5);

        // Block 1's frontier should include block 3 (join point)
        let df1 = dt.frontier(1);
        assert!(df1.contains(&3));

        // Block 2's frontier should include block 3
        let df2 = dt.frontier(2);
        assert!(df2.contains(&3));
    }

    #[test]
    fn test_dominator_tree_children() {
        let (succ, pred) = build_simple_cfg();
        let dt = DominatorTree::compute(&succ, &pred, 0, 5);

        // Entry's children: 1, 2, 3
        let children = dt.children(0);
        assert!(children.contains(&1));
        assert!(children.contains(&2));
        assert!(children.contains(&3));
    }
}
