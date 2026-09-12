//! P0-6.7: Batch decompilation of all NtcMach.exe functions.
//! Produces pseudocode for every function and computes real recoverability stats.
#![allow(warnings)]

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::expression::ExpressionRecovery;
use fox_decompiler::{
    emit_c_like, recover_control_structures, CLikeEmitter, EmitterConfig, StructuredIRBudget,
    StructuredIRBuilder,
};
use std::path::PathBuf;
use std::time::Instant;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NTCDLLV.DLL")
}

#[derive(Debug, Clone)]
struct FunctionResult {
    address: u64,
    name: String,
    cfg_blocks: usize,
    ssa_instrs: usize,
    control_structures: usize,
    if_count: usize,
    guard_count: usize,
    unknown_count: usize,
    statements: usize,
    output_chars: usize,
    output_lines: usize,
    output: String,
    has_return: bool,
    has_call: bool,
    has_assign: bool,
    budget_exhausted: bool,
    status: FunctionStatus,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FunctionStatus {
    /// Successfully produced readable pseudocode
    Ok,
    /// Produced output but with issues (empty, only unknown, etc.)
    Degraded,
    /// Failed to produce output
    Failed,
}

#[test]
fn reality_decompile_ntcdllv() {
    let start = Instant::now();
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    let total_functions = result.cfg.function_cfgs.len();
    println!("=== P0-6.7 Batch Decompilation: NtcMach.exe ===");
    println!("Total functions: {}", total_functions);
    println!("CallGraph: direct_internal={}, direct_external={}, indirect_resolved={}, indirect_unknown={}",
        result.call_graph.direct_internal, result.call_graph.direct_external,
        result.call_graph.indirect_resolved, result.call_graph.indirect_unknown);
    println!("");

    // P0-6.10: Build call target map from CallGraph (key = call instruction address)
    let call_targets: std::collections::HashMap<u64, fox_decompiler::CallTarget> = {
        let mut map = std::collections::HashMap::new();
        for node in &result.call_graph.nodes {
            for edge in &node.outgoing_calls {
                use fox_core::edge::CallEdgeKind;
                let target = match edge.kind {
                    CallEdgeKind::Direct | CallEdgeKind::External => {
                        if let Some(ref sym) = edge.resolved_symbol {
                            // External: "dll!func" -> use just func name
                            let func_name = sym.split('!').last().unwrap_or(sym);
                            fox_decompiler::CallTarget::Symbol(func_name.to_string())
                        } else if let Some(callee) = edge.callee {
                            fox_decompiler::CallTarget::Address(callee)
                        } else {
                            fox_decompiler::CallTarget::Unknown
                        }
                    }
                    CallEdgeKind::Indirect => {
                        if let Some(ref sym) = edge.resolved_symbol {
                            let func_name = sym.split('!').last().unwrap_or(sym);
                            fox_decompiler::CallTarget::Symbol(func_name.to_string())
                        } else if let Some(callee) = edge.callee {
                            fox_decompiler::CallTarget::Address(callee)
                        } else {
                            fox_decompiler::CallTarget::Unknown
                        }
                    }
                    CallEdgeKind::Unknown => fox_decompiler::CallTarget::Unknown,
                };
                map.insert(edge.call_instruction, target);
            }
        }
        map
    };
    println!(
        "P0-6.10: Resolved call targets from CallGraph: {}",
        call_targets.len()
    );
    println!("");

    let mut results: Vec<FunctionResult> = Vec::new();
    let mut ok_count = 0;
    let mut degraded_count = 0;
    let mut failed_count = 0;
    let mut total_output_chars = 0usize;
    let mut total_statements = 0usize;
    let mut functions_with_if = 0;
    let mut functions_with_guard = 0;
    let mut functions_with_unknown = 0;
    let mut functions_with_return = 0;
    let mut functions_with_call = 0;
    let mut functions_budget_exhausted = 0;
    let mut functions_empty_output = 0;

    // P0-11.2.7 Phase 1: Build ALL decompiled functions first (no emit),
    // so a real call graph can be constructed across the whole program.
    struct BuiltEntry {
        addr: u64,
        name: String,
        built: Result<BuiltFunction, FunctionResult>,
    }
    let mut built_entries: Vec<BuiltEntry> = Vec::new();
    for (idx, func_cfg) in result.cfg.function_cfgs.iter().enumerate() {
        let addr = func_cfg.function_address.0;
        let name = if func_cfg.function_name.is_empty() {
            format!("sub_{:X}", addr)
        } else {
            func_cfg.function_name.clone()
        };
        if idx % 50 == 0 {
            println!(
                "  Building function {}/{} (0x{:X})...",
                idx + 1,
                total_functions,
                addr
            );
        }
        let built = build_single_function(&result, addr, &name, &call_targets);
        built_entries.push(BuiltEntry { addr, name, built });
    }

    // P0-11.2.7: Build the REAL call graph from SSA CallStmt across all funcs.
    let all_funcs: Vec<&fox_decompiler::DecompilerFunction> = built_entries
        .iter()
        .filter_map(|e| match &e.built {
            Ok(b) => Some(&b.func),
            Err(_) => None,
        })
        .collect();
    let call_graph = fox_decompiler::DecompilerCallGraphBuilder::build(&all_funcs);
    let (cg_direct, cg_symbol, cg_unknown) = call_graph.kind_counts();
    println!(
        "P0-11.2.7 Real CallGraph: edges={} (direct={}, symbol={}, unknown={}), distinct callers={}",
        call_graph.edge_count(),
        cg_direct,
        cg_symbol,
        cg_unknown,
        call_graph.caller_count()
    );

    // P0-11.3: Build cross-function data-flow graph on top of the call graph.
    let data_flow = fox_decompiler::CrossFunctionDataFlowBuilder::build(&all_funcs, &call_graph);
    let (df_const, df_reg, df_mem, df_comp, df_unk) = data_flow.argument_source_counts();
    println!(
        "P0-11.3 CrossFunction DataFlow: edges={} (args={}, returns={}), arg sources: const={}, reg={}, mem={}, computed={}, unknown={}",
        data_flow.edge_count(),
        data_flow.argument_count(),
        data_flow.return_count(),
        df_const,
        df_reg,
        df_mem,
        df_comp,
        df_unk
    );

    // P0-12: Build per-callee function signatures on top of the dataflow graph.
    let sig_map =
        fox_decompiler::FunctionSignatureBuilder::build(&all_funcs, &data_flow, &call_graph);
    println!(
        "P0-12 Function Signatures: callees={} (with >=1 param: {}, >=2 params: {})",
        sig_map.len(),
        sig_map.with_param_count(1),
        sig_map.with_param_count(2)
    );

    // P0-13: Propagate type candidates from signatures (field facts empty this phase).
    let type_map = fox_decompiler::TypePropagationBuilder::build(&sig_map, &[]);
    println!(
        "P0-13 Type Candidates: keys={}, known={}, unknown={}",
        type_map.len(),
        type_map.known_count(),
        type_map.len() - type_map.known_count()
    );

    // P0-14: Build recovered variable candidates across all functions.
    let var_map = fox_decompiler::VariableRecoveryBuilder::build(&all_funcs);
    println!(
        "P0-14 Variables: total variables={}, functions={}",
        var_map.len(),
        var_map.function_count()
    );

    // GAP-RM-1: writable global regions from PE section table (portable).
    let regions = fox_decompiler::GlobalRegionMap::from_binary(&binary);
    println!(
        "GAP-RM-1 GlobalRegions: {} writable data sections (portable, no hard-coded range)",
        regions.len()
    );
    // P0-15: Build recovered object/field evidence across all functions.
    let obj_map = fox_decompiler::ObjectRecoveryBuilder::build(&all_funcs, &regions);
    println!(
        "P0-15 Objects: objects={}, fields={}, contiguous_structs={}",
        obj_map.object_count(),
        obj_map.total_fields(),
        obj_map.contiguous_struct_count()
    );
    println!("");

    // P0-11.2.7 Phase 2: Emit every built function, injecting the real graph.
    for entry in built_entries {
        let addr = entry.addr;
        let name = entry.name;
        let func_result = match entry.built {
            Ok(built) => emit_single_function(
                built,
                addr,
                &name,
                Some(&call_graph),
                Some(&data_flow),
                Some(&sig_map),
                Some(&type_map),
                Some(&var_map),
                Some(&obj_map),
            ),
            Err(fr) => fr,
        };

        match func_result.status {
            FunctionStatus::Ok => ok_count += 1,
            FunctionStatus::Degraded => degraded_count += 1,
            FunctionStatus::Failed => failed_count += 1,
        }

        total_output_chars += func_result.output_chars;
        total_statements += func_result.statements;
        if func_result.if_count > 0 {
            functions_with_if += 1;
        }
        if func_result.guard_count > 0 {
            functions_with_guard += 1;
        }
        if func_result.unknown_count > 0 {
            functions_with_unknown += 1;
        }
        if func_result.has_return {
            functions_with_return += 1;
        }
        if func_result.has_call {
            functions_with_call += 1;
        }
        if func_result.budget_exhausted {
            functions_budget_exhausted += 1;
        }
        if func_result.output_chars < 50 {
            functions_empty_output += 1;
        }

        results.push(func_result);
    }

    let elapsed = start.elapsed();
    println!("");
    println!("=== BATCH DECOMPILATION COMPLETE ===");
    println!("Total time: {:.2?}", elapsed);
    println!("");
    println!("--- Overall Status ---");
    println!("Total functions:    {}", total_functions);
    println!(
        "OK (readable):      {} ({:.1}%)",
        ok_count,
        ok_count as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Degraded:           {} ({:.1}%)",
        degraded_count,
        degraded_count as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Failed:             {} ({:.1}%)",
        failed_count,
        failed_count as f64 / total_functions as f64 * 100.0
    );
    println!("");
    println!("--- Output Volume ---");
    println!("Total statements:   {}", total_statements);
    println!("Total output chars: {}", total_output_chars);
    println!(
        "Avg statements/fn:  {:.1}",
        total_statements as f64 / total_functions as f64
    );
    println!(
        "Avg output chars/fn:{:.1}",
        total_output_chars as f64 / total_functions as f64
    );
    println!("");
    println!("--- Feature Coverage ---");
    println!(
        "Functions with if:        {} ({:.1}%)",
        functions_with_if,
        functions_with_if as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Functions with guard:     {} ({:.1}%)",
        functions_with_guard,
        functions_with_guard as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Functions with unknown:   {} ({:.1}%)",
        functions_with_unknown,
        functions_with_unknown as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Functions with return:    {} ({:.1}%)",
        functions_with_return,
        functions_with_return as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Functions with call:      {} ({:.1}%)",
        functions_with_call,
        functions_with_call as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Budget exhausted:         {} ({:.1}%)",
        functions_budget_exhausted,
        functions_budget_exhausted as f64 / total_functions as f64 * 100.0
    );
    println!(
        "Empty output (<50 chars): {} ({:.1}%)",
        functions_empty_output,
        functions_empty_output as f64 / total_functions as f64 * 100.0
    );
    println!("");

    // Top 10 largest functions by output
    println!("--- Top 10 Largest Functions by Output ---");
    let mut sorted: Vec<&FunctionResult> = results.iter().collect();
    sorted.sort_by(|a, b| b.output_chars.cmp(&a.output_chars));
    for (i, r) in sorted.iter().take(10).enumerate() {
        println!(
            "  {}. 0x{:X} {}: {} chars, {} stmts, {} blocks, {} if, {} guard, {} unknown",
            i + 1,
            r.address,
            r.name,
            r.output_chars,
            r.statements,
            r.cfg_blocks,
            r.if_count,
            r.guard_count,
            r.unknown_count
        );
    }
    println!("");

    // Functions with most unknown
    println!("--- Top 10 Functions by Unknown Count ---");
    let mut sorted_unknown: Vec<&FunctionResult> =
        results.iter().filter(|r| r.unknown_count > 0).collect();
    sorted_unknown.sort_by(|a, b| b.unknown_count.cmp(&a.unknown_count));
    for (i, r) in sorted_unknown.iter().take(10).enumerate() {
        println!(
            "  {}. 0x{:X} {}: {} unknown, {} if, {} guard, {} blocks",
            i + 1,
            r.address,
            r.name,
            r.unknown_count,
            r.if_count,
            r.guard_count,
            r.cfg_blocks
        );
    }
    println!("");

    // Failed functions
    if failed_count > 0 {
        println!("--- Failed Functions ---");
        for r in results
            .iter()
            .filter(|r| r.status == FunctionStatus::Failed)
        {
            println!(
                "  0x{:X} {}: {}",
                r.address,
                r.name,
                r.error.as_deref().unwrap_or("unknown")
            );
        }
        println!("");
    }

    // Degraded functions (empty or only unknown)
    println!("--- Degraded Functions Sample (first 10) ---");
    let mut degraded_shown = 0;
    for r in results
        .iter()
        .filter(|r| r.status == FunctionStatus::Degraded)
    {
        if degraded_shown >= 10 {
            break;
        }
        println!(
            "  0x{:X} {}: {} chars, {} stmts, {} unknown, blocks={}",
            r.address, r.name, r.output_chars, r.statements, r.unknown_count, r.cfg_blocks
        );
        degraded_shown += 1;
    }
    println!("");

    // Assertions
    assert!(ok_count > 0, "should have at least some OK functions");
    assert!(total_output_chars > 0, "should produce some output");

    // Write full decompilation output to file for human review
    let mut full_output = String::new();
    full_output.push_str(&format!(
        "// FOX Decompilation: NtcMach.exe\n// Generated: P0-6.9 (expression truncation)\n// Total: {} functions, {} OK, {} degraded, {} failed\n// Total output: {} chars\n\n",
        total_functions, ok_count, degraded_count, failed_count, total_output_chars
    ));
    for r in &results {
        if r.status == FunctionStatus::Ok {
            full_output.push_str(&r.output);
            full_output.push('\n');
        }
    }
    let out_path = std::env::temp_dir().join("ntcmach_decompilation_p0_6_9.c");
    std::fs::write(&out_path, &full_output).expect("write decompilation output");
    println!("Full output written to: {}", out_path.display());

    println!(
        "PASS: Batch decompilation completed for {} functions",
        total_functions
    );
}

/// P0-11.2.7: Built-but-not-emitted function, so a real call graph can be
/// constructed across ALL functions before any emitter reads it.
struct BuiltFunction {
    func: fox_decompiler::DecompilerFunction,
    func_cfg_blocks: usize,
    ssa_instrs: usize,
    cs_count: usize,
    if_count: usize,
    guard_count: usize,
    unknown_count: usize,
    has_return: bool,
    has_call: bool,
    has_assign: bool,
}

/// P0-11.2.7 Phase 1: SSA -> structured IR. Does NOT emit.
/// Returns Err(FunctionResult) when the function cannot be built.
fn build_single_function(
    result: &fox_analysis::AnalysisResult,
    addr: u64,
    name: &str,
    call_targets: &std::collections::HashMap<u64, fox_decompiler::CallTarget>,
) -> Result<BuiltFunction, FunctionResult> {
    let func_cfg = match result
        .cfg
        .function_cfgs
        .iter()
        .find(|f| f.function_address.0 == addr)
    {
        Some(f) => f,
        None => {
            return Err(FunctionResult {
                address: addr,
                name: name.to_string(),
                cfg_blocks: 0,
                ssa_instrs: 0,
                control_structures: 0,
                if_count: 0,
                guard_count: 0,
                unknown_count: 0,
                statements: 0,
                output_chars: 0,
                output_lines: 0,
                output: String::new(),
                has_return: false,
                has_call: false,
                has_assign: false,
                budget_exhausted: false,
                status: FunctionStatus::Failed,
                error: Some("CFG not found".to_string()),
            })
        }
    };

    let ctx = match result.pipeline.function_analysis.get(&addr) {
        Some(c) => c,
        None => {
            return Err(FunctionResult {
                address: addr,
                name: name.to_string(),
                cfg_blocks: func_cfg.blocks.len(),
                ssa_instrs: 0,
                control_structures: 0,
                if_count: 0,
                guard_count: 0,
                unknown_count: 0,
                statements: 0,
                output_chars: 0,
                output_lines: 0,
                output: String::new(),
                has_return: false,
                has_call: false,
                has_assign: false,
                budget_exhausted: false,
                status: FunctionStatus::Failed,
                error: Some("No SSA analysis".to_string()),
            })
        }
    };

    let ssa = match ctx.ssa.as_ref() {
        Some(s) => s,
        None => {
            return Err(FunctionResult {
                address: addr,
                name: name.to_string(),
                cfg_blocks: func_cfg.blocks.len(),
                ssa_instrs: 0,
                control_structures: 0,
                if_count: 0,
                guard_count: 0,
                unknown_count: 0,
                statements: 0,
                output_chars: 0,
                output_lines: 0,
                output: String::new(),
                has_return: false,
                has_call: false,
                has_assign: false,
                budget_exhausted: false,
                status: FunctionStatus::Failed,
                error: Some("SSA not available".to_string()),
            })
        }
    };

    let ssa_instrs: usize = ssa.basic_blocks.iter().map(|b| b.instructions.len()).sum();

    // Recover control structures
    let cs = recover_control_structures(func_cfg, ssa);
    let cs_count = cs.len();

    // Build structured IR with conservative budget
    let mut budget = StructuredIRBudget::default();
    budget.max_statements = 2000; // conservative for batch
    let mut builder = StructuredIRBuilder::new()
        .with_budget(budget)
        .with_call_targets(call_targets.clone());
    let func = builder.build(func_cfg, ssa, cs);

    // Count statement types
    let mut if_count = 0;
    let mut guard_count = 0;
    let mut unknown_count = 0;
    let mut has_return = false;
    let mut has_call = false;
    let mut has_assign = false;

    fn count_stmts(
        stmts: &[fox_decompiler::Statement],
        if_count: &mut usize,
        guard_count: &mut usize,
        unknown_count: &mut usize,
        has_return: &mut bool,
        has_call: &mut bool,
        has_assign: &mut bool,
    ) {
        for s in stmts {
            match s {
                fox_decompiler::Statement::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    *if_count += 1;
                    count_stmts(
                        then_body,
                        if_count,
                        guard_count,
                        unknown_count,
                        has_return,
                        has_call,
                        has_assign,
                    );
                    count_stmts(
                        else_body,
                        if_count,
                        guard_count,
                        unknown_count,
                        has_return,
                        has_call,
                        has_assign,
                    );
                }
                fox_decompiler::Statement::GuardClause { body, .. } => {
                    *guard_count += 1;
                    count_stmts(
                        body,
                        if_count,
                        guard_count,
                        unknown_count,
                        has_return,
                        has_call,
                        has_assign,
                    );
                }
                fox_decompiler::Statement::Unknown { .. } => {
                    *unknown_count += 1;
                }
                fox_decompiler::Statement::Return { .. } => {
                    *has_return = true;
                }
                fox_decompiler::Statement::CallStmt { .. } => {
                    *has_call = true;
                }
                fox_decompiler::Statement::Assign { .. } => {
                    *has_assign = true;
                }
                fox_decompiler::Statement::PhiAssign { .. } => {}
            }
        }
    }
    count_stmts(
        &func.statements,
        &mut if_count,
        &mut guard_count,
        &mut unknown_count,
        &mut has_return,
        &mut has_call,
        &mut has_assign,
    );

    Ok(BuiltFunction {
        func,
        func_cfg_blocks: func_cfg.blocks.len(),
        ssa_instrs,
        cs_count,
        if_count,
        guard_count,
        unknown_count,
        has_return,
        has_call,
        has_assign,
    })
}

/// P0-11.2.7 Phase 2: Emit a built function, consuming the real call graph.
fn emit_single_function(
    built: BuiltFunction,
    addr: u64,
    name: &str,
    callgraph: Option<&fox_decompiler::DecompilerCallGraph>,
    dataflow: Option<&fox_decompiler::CrossFunctionDataFlowGraph>,
    signatures: Option<&fox_decompiler::SignatureMap>,
    type_map: Option<&fox_decompiler::TypeMap>,
    var_map: Option<&fox_decompiler::VariableMap>,
    obj_map: Option<&fox_decompiler::ObjectMap>,
) -> FunctionResult {
    let BuiltFunction {
        func,
        func_cfg_blocks,
        ssa_instrs,
        cs_count,
        if_count,
        guard_count,
        unknown_count,
        has_return,
        has_call,
        has_assign,
    } = built;

    // Emit
    let emitter = CLikeEmitter::with_config(EmitterConfig {
        annotate_evidence: false, // clean output for batch stats
        show_phi: false,
        indent: "    ".to_string(),
        show_header: false,
        max_expression_chars: 400,
        max_expression_depth: 8,
    });
    // P0-11.2.7: Inject the REAL call graph so edges are displayed honestly.
    if let Some(g) = callgraph {
        emitter.set_callgraph(g.clone());
    }
    // P0-11.3: Inject cross-function data-flow graph (argument/return).
    if let Some(df) = dataflow {
        emitter.set_dataflow(df.clone());
    }
    // P0-12: Inject per-callee signature map.
    if let Some(sm) = signatures {
        emitter.set_signatures(sm.clone());
    }
    // P0-13: Inject propagated type candidates.
    if let Some(tm) = type_map {
        emitter.set_type_map(tm.clone());
    }
    // P0-14: Inject recovered variable candidates.
    if let Some(vm) = var_map {
        emitter.set_variable_map(vm.clone());
    }
    // P0-15: Inject recovered object/field evidence.
    if let Some(om) = obj_map {
        emitter.set_object_map(om.clone());
    }
    let output = emitter.emit(&func);
    let output_chars = output.len();
    let output_lines = output.lines().count();

    // Determine status
    let status = if output_chars < 20 {
        FunctionStatus::Failed
    } else if func.statements.is_empty()
        || (if_count == 0 && guard_count == 0 && !has_return && !has_call && !has_assign)
    {
        FunctionStatus::Degraded
    } else {
        FunctionStatus::Ok
    };

    FunctionResult {
        address: addr,
        name: name.to_string(),
        cfg_blocks: func_cfg_blocks,
        ssa_instrs,
        control_structures: cs_count,
        if_count,
        guard_count,
        unknown_count,
        statements: func.statements.len(),
        output_chars,
        output_lines,
        output,
        has_return,
        has_call,
        has_assign,
        budget_exhausted: func.evidence.budget_exhausted,
        status,
        error: None,
    }
}
