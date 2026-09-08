//! FOX Control Flow Graph
//!
//! Each function has its own CFG containing BasicBlocks with typed edges.
//! Edge types: Fallthrough, ConditionalTrue, ConditionalFalse,
//!             UnconditionalJump, Call, Return, IndirectJump, IndirectCall, Unknown

use crate::basic_block::{BasicBlock, BasicBlockEngine};
use crate::Function;
use fox_binary::Binary;
use fox_core::{Address, CfgEdge, EdgeKind, WithEvidence};
use serde::{Deserialize, Serialize};

/// A function-level CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCfg {
    pub function_address: Address,
    pub function_name: String,
    pub blocks: Vec<BasicBlock>,
    pub entry_block: usize,
    pub edge_count: usize,
    pub invalid_addresses: Vec<u64>,
}

impl FunctionCfg {
    /// Build a CFG for a single function using recursive descent.
    pub fn build(
        binary: &Binary,
        function: &Function,
        disassembler: &dyn fox_disasm::Disassembler,
    ) -> Option<Self> {
        // Find the section containing this function
        let section = binary
            .sections
            .iter()
            .find(|s| s.contains_address(function.address.0 - binary.image_base))?;

        let section_data =
            &binary.raw_data[section.raw_offset..section.raw_offset + section.raw_size];
        let section_base = binary.image_base + section.virtual_address;

        let func_blocks = BasicBlockEngine::analyze_function(
            section_data,
            section_base,
            function.address.0,
            disassembler,
        );

        let edge_count = func_blocks.blocks.iter().map(|b| b.successors.len()).sum();

        Some(FunctionCfg {
            function_address: function.address,
            function_name: function.name.clone(),
            blocks: func_blocks.blocks,
            entry_block: func_blocks.entry_block,
            edge_count,
            invalid_addresses: func_blocks.invalid_addresses,
        })
    }

    /// Get all edges in this CFG.
    pub fn edges(&self) -> Vec<&CfgEdge> {
        self.blocks
            .iter()
            .flat_map(|b| b.successors.iter())
            .collect()
    }

    /// Count edges by type.
    pub fn edge_kind_counts(&self) -> std::collections::HashMap<EdgeKind, usize> {
        let mut counts = std::collections::HashMap::new();
        for edge in self.edges() {
            *counts.entry(edge.kind).or_insert(0) += 1;
        }
        counts
    }
}

/// Module-level CFG (collection of function CFGs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub function_cfgs: Vec<FunctionCfg>,
    pub total_blocks: usize,
    pub total_edges: usize,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        ControlFlowGraph {
            function_cfgs: Vec::new(),
            total_blocks: 0,
            total_edges: 0,
        }
    }

    /// Build CFGs for all functions.
    pub fn build(
        binary: &Binary,
        functions: &[WithEvidence<Function>],
        disassembler: &dyn fox_disasm::Disassembler,
    ) -> Self {
        let mut cfg = ControlFlowGraph::new();

        for func in functions {
            if let Some(func_cfg) = FunctionCfg::build(binary, &func.value, disassembler) {
                cfg.total_blocks += func_cfg.blocks.len();
                cfg.total_edges += func_cfg.edge_count;
                cfg.function_cfgs.push(func_cfg);
            }
        }

        cfg
    }

    /// Export CFG in DOT format for visualization.
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph FOX_CFG {\n");
        dot.push_str("  node [shape=box, fontname=\"monospace\"];\n");

        for func_cfg in &self.function_cfgs {
            dot.push_str(&format!(
                "  subgraph cluster_{:X} {{\n",
                func_cfg.function_address.0
            ));
            dot.push_str(&format!(
                "    label=\"{} @ {}\";\n",
                func_cfg.function_name, func_cfg.function_address
            ));

            for block in &func_cfg.blocks {
                let label = format!(
                    "BB#{}\\nstart=0x{:X}\\n{} instrs",
                    block.id,
                    block.start_address.0,
                    block.instruction_count()
                );
                dot.push_str(&format!(
                    "    \"{:X}_{}\" [label=\"{}\"];\n",
                    func_cfg.function_address.0, block.id, label
                ));
            }

            for block in &func_cfg.blocks {
                for edge in &block.successors {
                    if let Some(target_id) = edge.target_block {
                        let color = match edge.kind {
                            EdgeKind::Fallthrough => "black",
                            EdgeKind::ConditionalTrue => "green",
                            EdgeKind::ConditionalFalse => "red",
                            EdgeKind::UnconditionalJump => "blue",
                            EdgeKind::Call => "purple",
                            EdgeKind::Return => "gray",
                            EdgeKind::IndirectJump | EdgeKind::IndirectCall => "orange",
                            EdgeKind::Unknown => "brown",
                        };
                        dot.push_str(&format!(
                            "    \"{:X}_{}\" -> \"{:X}_{}\" [label=\"{}\", color={}];\n",
                            func_cfg.function_address.0,
                            block.id,
                            func_cfg.function_address.0,
                            target_id,
                            edge.kind,
                            color
                        ));
                    }
                }
            }
            dot.push_str("  }\n");
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_arch::Architecture;
    use fox_disasm::create_disassembler;

    #[test]
    fn test_cfg_edge_counts() {
        // Simple function with conditional branch
        // 0x1000: 31 C0       xor eax, eax
        // 0x1002: 85 C0       test eax, eax
        // 0x1004: 74 02       jz 0x1008 (0x1004+2+2)
        // 0x1006: 90          nop
        // 0x1007: 90          nop
        // 0x1008: C3          ret
        let code = [0x31, 0xC0, 0x85, 0xC0, 0x74, 0x02, 0x90, 0x90, 0xC3];
        let disasm = create_disassembler(Architecture::X64).unwrap();

        let func = Function {
            name: "test".to_string(),
            address: Address(0x1000),
            end_address: None,
            size: None,
            basic_blocks: vec![],
            calls: vec![],
            called_by: vec![],
            confidence_tier: crate::FunctionConfidence::Unknown,
            validation: crate::FunctionValidation::default(),
        };

        // Build a minimal binary for testing
        let binary = fox_binary::Binary {
            format: fox_binary::BinaryFormat::PE32Plus,
            architecture: Architecture::X64,
            entry_point: 0x1000,
            image_base: 0,
            size: code.len(),
            sections: vec![fox_binary::Section {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: code.len() as u32,
                raw_offset: 0,
                raw_size: code.len(),
                characteristics: 0x60000020,
            }],
            imports: vec![],
            exports: vec![],
            relocations: vec![],
            strings: vec![],
            raw_data: code.to_vec(),
        };

        let cfg = FunctionCfg::build(&binary, &func, disasm.as_ref()).unwrap();
        assert!(cfg.blocks.len() >= 2);
        assert!(cfg.edge_count >= 3); // true + false + return
    }
}
