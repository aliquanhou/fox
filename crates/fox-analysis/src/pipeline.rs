//! FOX Analysis Pipeline (P0-4.1)
//!
//! Unified per-function analysis pipeline that chains:
//! Function → CFG → IR → SSA → DataFlow → Evidence
//!
//! This solves the P0-4.0 audit finding: IR/SSA/DataFlow were isolated
//! modules only callable via CLI, not integrated into analyze_binary().
//!
//! P0-4.1 constraints: NO Memory SSA, NO new alias algorithms,
//! NO modification of existing SSA/DataFlow/CFG/FunctionDiscovery semantics.

#![allow(clippy::type_complexity)]

use fox_binary::Binary;
use fox_core::{Evidence, EvidenceKind, WithEvidence};
use fox_ir::{l1::IRTranslator, IRBasicBlock, IRFunction, IRInstruction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use crate::cfg::{ControlFlowGraph, FunctionCfg};
use crate::dataflow::CfgDataFlowResult;
use crate::ssa::SSAFunction;
use crate::{Function, FunctionConfidence};

/// Per-function unified analysis context.
///
/// This is the single source of truth for all analysis results of a function.
/// All downstream consumers (CLI, future Decompiler, GUI) must read from
/// this context rather than re-computing analysis independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysisContext {
    /// Function metadata (from FunctionDiscovery)
    pub function_address: u64,
    pub function_name: String,
    pub confidence_tier: FunctionConfidence,

    /// Disassembled instructions (flat, in address order)
    pub instructions: Vec<fox_disasm::Instruction>,

    /// IR function (built once from CFG blocks, shared by SSA and DataFlow)
    pub ir: IRFunction,

    /// Register SSA (existing algorithm, no changes)
    pub ssa: Option<SSAFunction>,

    /// CFG-aware register DataFlow (existing algorithm, no changes)
    pub dataflow: Option<CfgDataFlowResult>,

    /// Memory analysis (P0-4.2: semantic normalization via analyze_function_memory)
    pub memory: Option<fox_ir::memory::MemoryAnalysis>,

    /// Evidence collected during pipeline execution
    pub evidence: Vec<Evidence>,

    /// Pipeline timing (for performance baseline)
    pub timing: PipelineTiming,
}

/// Pipeline timing breakdown for a single function.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipelineTiming {
    pub ir_generation_ms: u128,
    pub ssa_construction_ms: u128,
    pub dataflow_ms: u128,
    pub memory_analysis_ms: u128,
    pub total_ms: u128,
}

/// Unified analysis pipeline result for an entire binary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipelineResult {
    /// Per-function analysis contexts, keyed by function address
    pub function_analysis: BTreeMap<u64, FunctionAnalysisContext>,
    /// Aggregate timing
    pub total_timing_ms: u128,
    /// Number of functions analyzed through the full pipeline
    pub functions_analyzed: usize,
    /// Number of functions skipped (e.g., no CFG, invalid)
    pub functions_skipped: usize,
}

/// The unified analysis pipeline.
///
/// Execution order (fixed, must not be reordered without architecture review):
/// 1. Function Discovery (done before pipeline, in analyze_binary)
/// 2. CFG Construction (done before pipeline, in analyze_binary)
/// 3. IR Generation (per function, from CFG blocks)
/// 4. SSA Construction (from IR)
/// 5. DataFlow Analysis (from IR + CFG)
/// 6. Memory Analysis mount (existing algorithm, no upgrade)
/// 7. Evidence Finalization
pub struct AnalysisPipeline;

impl AnalysisPipeline {
    /// Run the full per-function pipeline on all functions in the binary.
    ///
    /// Only functions with a valid CFG are processed through IR/SSA/DataFlow.
    /// Functions without CFG are recorded as skipped.
    pub fn run(
        binary: &Binary,
        functions: &[WithEvidence<Function>],
        cfg: &ControlFlowGraph,
    ) -> PipelineResult {
        let start = Instant::now();
        let mut result = PipelineResult::default();

        for func in functions {
            let addr = func.value.address.0;

            // Find the CFG for this function
            let func_cfg = match cfg
                .function_cfgs
                .iter()
                .find(|c| c.function_address.0 == addr)
            {
                Some(c) => c,
                None => {
                    result.functions_skipped += 1;
                    continue;
                }
            };

            // Skip functions with empty CFG (no blocks)
            if func_cfg.blocks.is_empty() {
                result.functions_skipped += 1;
                continue;
            }

            let context = Self::analyze_function(binary, func, func_cfg);
            result.function_analysis.insert(addr, context);
            result.functions_analyzed += 1;
        }

        result.total_timing_ms = start.elapsed().as_millis();
        result
    }

    /// Run the pipeline on a single function.
    fn analyze_function(
        _binary: &Binary,
        func: &WithEvidence<Function>,
        func_cfg: &FunctionCfg,
    ) -> FunctionAnalysisContext {
        let func_start = Instant::now();
        let mut evidence = Vec::new();

        // === Phase 3: IR Generation (from CFG blocks, single source of truth) ===
        let ir_start = Instant::now();
        let ir = Self::build_ir(func, func_cfg);
        let ir_ms = ir_start.elapsed().as_millis();

        evidence.push(
            Evidence::new(EvidenceKind::ValidInstructionDecoded)
                .with_address(func.value.address.0)
                .with_weight(0.9)
                .with_detail(format!(
                    "IR generated: {} blocks, {} instructions",
                    ir.basic_blocks.len(),
                    ir.basic_blocks
                        .iter()
                        .map(|b| b.instructions.len())
                        .sum::<usize>()
                )),
        );

        // === Thunk optimization: skip SSA/DataFlow for <=2 instruction functions ===
        // These are CRT/runtime thunks (JMP/CALL/RET) with no meaningful dataflow.
        // IR and Evidence are still recorded. This does not change any analysis result.
        let total_instructions: usize = ir.basic_blocks.iter().map(|b| b.instructions.len()).sum();

        if total_instructions <= 2 {
            let memory = Some(fox_ir::memory::analyze_function_memory(&ir));
            let instructions: Vec<fox_disasm::Instruction> = func_cfg
                .blocks
                .iter()
                .flat_map(|b| b.instructions.clone())
                .collect();
            evidence.push(
                Evidence::new(EvidenceKind::DataFlowAnalysis)
                    .with_address(func.value.address.0)
                    .with_weight(0.5)
                    .with_detail(format!(
                        "Thunk function ({} instructions): SSA/DataFlow skipped",
                        total_instructions
                    )),
            );
            return FunctionAnalysisContext {
                function_address: func.value.address.0,
                function_name: func.value.name.clone(),
                confidence_tier: func.value.confidence_tier,
                instructions,
                ir,
                ssa: None,
                dataflow: None,
                memory,
                evidence,
                timing: PipelineTiming {
                    ir_generation_ms: ir_ms,
                    ssa_construction_ms: 0,
                    dataflow_ms: 0,
                    memory_analysis_ms: 0,
                    total_ms: func_start.elapsed().as_millis(),
                },
            };
        }

        // === Phase 4: SSA Construction (existing register SSA, no changes) ===
        let ssa_start = Instant::now();
        let ssa = Some(crate::ssa::SSAConstructor::construct_proper(&ir));
        let ssa_ms = ssa_start.elapsed().as_millis();

        if let Some(ref s) = ssa {
            evidence.push(
                Evidence::new(EvidenceKind::DataFlowAnalysis)
                    .with_address(func.value.address.0)
                    .with_weight(0.85)
                    .with_detail(format!(
                        "SSA: {} phi nodes, {} variables versioned, proper_renaming={}",
                        s.phi_nodes.len(),
                        s.variable_versions.len(),
                        s.proper_renaming
                    )),
            );
        }

        // === Phase 5: DataFlow (existing CFG-aware register DataFlow, no changes) ===
        let df_start = Instant::now();
        let dataflow = Some(Self::build_dataflow(func.value.address.0, &ir, func_cfg));
        let df_ms = df_start.elapsed().as_millis();

        if let Some(ref df) = dataflow {
            evidence.push(
                Evidence::new(EvidenceKind::DataFlowAnalysis)
                    .with_address(func.value.address.0)
                    .with_weight(0.85)
                    .with_detail(format!(
                        "DataFlow: RD iterations={}, LV iterations={}, CP iterations={}",
                        df.reaching_definitions.iterations,
                        df.live_variables.iterations,
                        df.constant_propagation.iterations
                    )),
            );
        }

        // === Phase 6: Memory semantic analysis (P0-4.2: analyze_function_memory) ===
        let mem_start = Instant::now();
        let memory = Some(fox_ir::memory::analyze_function_memory(&ir));
        let mem_ms = mem_start.elapsed().as_millis();

        // === Collect flat instructions (for CLI compatibility) ===
        let instructions: Vec<fox_disasm::Instruction> = func_cfg
            .blocks
            .iter()
            .flat_map(|b| b.instructions.clone())
            .collect();

        let total_ms = func_start.elapsed().as_millis();

        FunctionAnalysisContext {
            function_address: func.value.address.0,
            function_name: func.value.name.clone(),
            confidence_tier: func.value.confidence_tier,
            instructions,
            ir,
            ssa,
            dataflow,
            memory,
            evidence,
            timing: PipelineTiming {
                ir_generation_ms: ir_ms,
                ssa_construction_ms: ssa_ms,
                dataflow_ms: df_ms,
                memory_analysis_ms: mem_ms,
                total_ms,
            },
        }
    }

    /// Build IRFunction from CFG blocks. This is the single IR generation point.
    /// CLI and all downstream consumers must use this IR, not rebuild their own.
    fn build_ir(func: &WithEvidence<Function>, func_cfg: &FunctionCfg) -> IRFunction {
        let ir_blocks: Vec<IRBasicBlock> = func_cfg
            .blocks
            .iter()
            .map(|bb| {
                let ir_insts: Vec<IRInstruction> = bb
                    .instructions
                    .iter()
                    .map(IRTranslator::translate)
                    .collect();
                IRBasicBlock {
                    id: bb.id,
                    start_address: bb.start_address,
                    end_address: bb.end_address,
                    instructions: ir_insts,
                    successors: bb
                        .successors
                        .iter()
                        .filter_map(|e| e.target_block)
                        .collect(),
                    predecessors: bb.predecessors.clone(),
                }
            })
            .collect();

        IRFunction {
            name: func.value.name.clone(),
            address: func.value.address,
            basic_blocks: ir_blocks,
            entry_block: func_cfg.entry_block,
        }
    }

    /// Build CFG-aware DataFlow from the shared IR + CFG.
    fn build_dataflow(
        function_address: u64,
        ir: &IRFunction,
        func_cfg: &FunctionCfg,
    ) -> CfgDataFlowResult {
        let block_data: Vec<(usize, Vec<IRInstruction>, Vec<usize>, Vec<usize>)> = ir
            .basic_blocks
            .iter()
            .map(|bb| {
                let succs: Vec<usize> = bb.successors.clone();
                (
                    bb.id,
                    bb.instructions.clone(),
                    bb.predecessors.clone(),
                    succs,
                )
            })
            .collect();

        let block_refs: Vec<(usize, &[IRInstruction], &[usize], &[usize])> = block_data
            .iter()
            .map(|(id, insts, preds, succs)| {
                (*id, insts.as_slice(), preds.as_slice(), succs.as_slice())
            })
            .collect();

        CfgDataFlowResult::analyze(function_address, &block_refs, func_cfg.entry_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_timing_default() {
        let t = PipelineTiming::default();
        assert_eq!(t.total_ms, 0);
        assert_eq!(t.ir_generation_ms, 0);
    }

    #[test]
    fn test_pipeline_result_default() {
        let r = PipelineResult::default();
        assert_eq!(r.functions_analyzed, 0);
        assert_eq!(r.functions_skipped, 0);
        assert!(r.function_analysis.is_empty());
    }
}
