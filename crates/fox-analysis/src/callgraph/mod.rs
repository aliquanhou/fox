//! FOX Call Graph
//!
//! P0-2.1: External Call Resolution via RIP-relative IAT lookup.
//!
//! Call edge types:
//! - DirectInternal: call to known internal function
//! - DirectExternal: call to imported function (resolved via IAT)
//! - IndirectResolved: indirect call with resolved target
//! - IndirectUnknown: indirect call, target unknown

use crate::Function;
use fox_binary::Binary;
use fox_core::{
    Address, CallEdgeKind, CallGraphEdge, Evidence, EvidenceKind, IndirectCallKind, WithEvidence,
};
use serde::{Deserialize, Serialize};

/// A node in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub address: Address,
    pub name: String,
    pub outgoing_calls: Vec<CallGraphEdge>,
    pub incoming_calls: Vec<u64>,
}

/// Call graph for the entire binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub direct_internal: usize,
    pub direct_external: usize,
    pub indirect_resolved: usize,
    pub indirect_unknown: usize,
}

impl CallGraph {
    pub fn new() -> Self {
        CallGraph {
            nodes: Vec::new(),
            direct_internal: 0,
            direct_external: 0,
            indirect_resolved: 0,
            indirect_unknown: 0,
        }
    }

    /// Build call graph from functions and their CFGs.
    ///
    /// P0-2.1: Resolves `call [rip+disp]` to IAT entries -> DirectExternal.
    pub fn build(
        binary: &Binary,
        functions: &[WithEvidence<Function>],
        function_cfgs: &[crate::cfg::FunctionCfg],
    ) -> Self {
        let mut graph = CallGraph::new();

        // Build address -> function name map
        let func_by_addr: std::collections::HashMap<u64, &String> = functions
            .iter()
            .map(|f| (f.value.address.0, &f.value.name))
            .collect();

        // Build IAT address -> (dll_name, func_name) map for External resolution
        let iat_map = Self::build_iat_map(binary);

        for func in functions {
            let mut node = CallGraphNode {
                address: func.value.address,
                name: func.value.name.clone(),
                outgoing_calls: Vec::new(),
                incoming_calls: Vec::new(),
            };

            if let Some(cfg) = function_cfgs
                .iter()
                .find(|c| c.function_address == func.value.address)
            {
                for block in &cfg.blocks {
                    for inst in &block.instructions {
                        if inst.is_call {
                            let edge = Self::classify_call(inst, &func_by_addr, &iat_map);
                            match edge.kind {
                                CallEdgeKind::Direct => {
                                    if edge.resolved_symbol.is_some() {
                                        graph.direct_external += 1;
                                    } else {
                                        graph.direct_internal += 1;
                                    }
                                }
                                CallEdgeKind::Indirect => {
                                    if edge.resolved_symbol.is_some() {
                                        graph.indirect_resolved += 1;
                                    } else {
                                        graph.indirect_unknown += 1;
                                    }
                                }
                                CallEdgeKind::External => graph.direct_external += 1,
                                CallEdgeKind::Unknown => graph.indirect_unknown += 1,
                            }
                            node.outgoing_calls.push(edge);
                        }
                    }
                }
            }

            graph.nodes.push(node);
        }

        // Build incoming calls
        let mut incoming: std::collections::HashMap<u64, Vec<u64>> =
            std::collections::HashMap::new();
        for node in &graph.nodes {
            for edge in &node.outgoing_calls {
                if let Some(callee) = edge.callee {
                    incoming.entry(callee).or_default().push(node.address.0);
                }
            }
        }
        for node in &mut graph.nodes {
            if let Some(callers) = incoming.get(&node.address.0) {
                node.incoming_calls = callers.clone();
            }
        }

        graph
    }

    /// Build IAT address -> (dll_name, func_name) map.
    fn build_iat_map(binary: &Binary) -> std::collections::HashMap<u64, (String, String)> {
        let mut map = std::collections::HashMap::new();
        for import in &binary.imports {
            for func in &import.functions {
                let iat_va = func.iat_address + binary.image_base;
                let name = func
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("ordinal_{}", func.ordinal.unwrap_or(0)));
                map.insert(iat_va, (import.dll_name.clone(), name));
            }
        }
        map
    }

    /// Classify a CALL instruction.
    ///
    /// P0-2.1: For indirect calls, checks if operand is RIP-relative memory
    /// pointing into IAT. If so, resolves to DirectExternal with symbol name.
    fn classify_call(
        inst: &fox_disasm::Instruction,
        func_by_addr: &std::collections::HashMap<u64, &String>,
        iat_map: &std::collections::HashMap<u64, (String, String)>,
    ) -> CallGraphEdge {
        let mut edge = CallGraphEdge {
            kind: CallEdgeKind::Unknown,
            caller: 0,
            callee: None,
            call_instruction: inst.address,
            resolved_symbol: None,
            indirect_kind: None,
            evidence: fox_core::EvidenceList::new(),
        };

        // Case 1: Direct call with known target
        if let Some(target) = inst.call_target {
            edge.callee = Some(target);

            if let Some((dll, func)) = iat_map.get(&target) {
                // Direct call to IAT entry (rare on x64, common on x86)
                edge.kind = CallEdgeKind::External;
                edge.resolved_symbol = Some(format!("{}!{}", dll, func));
                edge.evidence.push(
                    Evidence::new(EvidenceKind::ImportEntry)
                        .with_address(target)
                        .with_weight(0.95),
                );
            } else if func_by_addr.contains_key(&target) {
                edge.kind = CallEdgeKind::Direct;
                edge.evidence.push(
                    Evidence::new(EvidenceKind::CallReference { count: 1 })
                        .with_address(target)
                        .with_weight(0.9),
                );
            } else {
                edge.kind = CallEdgeKind::Direct;
                edge.evidence.push(
                    Evidence::new(EvidenceKind::Heuristic {
                        description: format!(
                            "Direct call to undiscovered function @ 0x{:X}",
                            target
                        ),
                    })
                    .with_weight(0.5),
                );
            }
            return edge;
        }

        // Case 2: Indirect call — check for RIP-relative IAT access
        for op in &inst.operands_structured {
            if let Some(ref mem) = op.memory {
                if mem.is_rip_relative {
                    if let Some(effective_addr) = mem.effective_address {
                        if let Some((dll, func)) = iat_map.get(&effective_addr) {
                            // Resolved external call via IAT
                            edge.kind = CallEdgeKind::External;
                            edge.callee = Some(effective_addr);
                            edge.resolved_symbol = Some(format!("{}!{}", dll, func));
                            edge.indirect_kind = Some(IndirectCallKind::Iat);
                            edge.evidence.push(
                                Evidence::new(EvidenceKind::ImportEntry)
                                    .with_address(effective_addr)
                                    .with_weight(0.95),
                            );
                            edge.evidence.push(
                                Evidence::new(EvidenceKind::IndirectCallEdge)
                                    .with_address(inst.address)
                                    .with_weight(0.8),
                            );
                            return edge;
                        }
                    }
                }
            }
        }

        // Case 3: Indirect call, unresolved — classify operand type
        edge.kind = CallEdgeKind::Indirect;
        for op in &inst.operands_structured {
            if op.register.is_some() {
                edge.indirect_kind = Some(IndirectCallKind::Register);
                break;
            }
            if let Some(ref mem) = op.memory {
                if mem.is_rip_relative {
                    // RIP-relative but not IAT — could be global function pointer
                    edge.indirect_kind = Some(IndirectCallKind::Memory);
                } else if mem.base.is_some() && mem.index.is_none() && mem.displacement != 0 {
                    // [reg+disp] pattern — vtable candidate
                    edge.indirect_kind = Some(IndirectCallKind::VtableCandidate);
                } else {
                    edge.indirect_kind = Some(IndirectCallKind::Memory);
                }
                break;
            }
        }
        if edge.indirect_kind.is_none() {
            edge.indirect_kind = Some(IndirectCallKind::Unknown);
        }
        edge.evidence.push(
            Evidence::new(EvidenceKind::IndirectCallEdge)
                .with_address(inst.address)
                .with_weight(0.4),
        );
        edge
    }

    /// Total edge count.
    pub fn total_edges(&self) -> usize {
        self.direct_internal + self.direct_external + self.indirect_resolved + self.indirect_unknown
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_edge_kind_display() {
        assert_eq!(CallEdgeKind::Direct.display_name(), "Direct");
        assert_eq!(CallEdgeKind::Indirect.display_name(), "Indirect");
        assert_eq!(CallEdgeKind::External.display_name(), "External");
        assert_eq!(CallEdgeKind::Unknown.display_name(), "Unknown");
    }
}
