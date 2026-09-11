//! P0-7.1: Dynamic Plugin Call Resolution
//!
//! Resolves indirect calls via LoadLibraryA + GetProcAddress pattern.
//! Evidence-first: any broken chain → Unknown. No guessing.
#![allow(warnings)]

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use fox_decompiler::dynamic_plugin::{
    build_external_call_name_map, build_iat_map_from_imports, resolutions_to_call_targets,
    DynamicPluginResolver,
};
use fox_decompiler::expression::ExpressionRecovery;
use fox_decompiler::{
    recover_control_structures, CLikeEmitter, EmitterConfig, StructuredIRBudget,
    StructuredIRBuilder,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

fn ntcmach_path() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe")
}

/// Build string table from PE .rdata section: address → string content.
fn build_string_table(binary: &Binary) -> HashMap<u64, String> {
    let mut table = HashMap::new();
    for section in &binary.sections {
        if section.name != ".rdata" && section.name != ".data" {
            continue;
        }
        let data = match binary.section_data(&section.name) {
            Some(d) => d,
            None => continue,
        };
        let base = binary.image_base + section.virtual_address;
        let mut i = 0;
        while i < data.len() {
            // Find start of printable ASCII string (len >= 4)
            if data[i] >= 0x20 && data[i] <= 0x7E {
                let start = i;
                while i < data.len() && data[i] >= 0x20 && data[i] <= 0x7E {
                    i += 1;
                }
                let len = i - start;
                if len >= 4 && i < data.len() && data[i] == 0 {
                    if let Ok(s) = std::str::from_utf8(&data[start..start + len]) {
                        table.insert(base + start as u64, s.to_string());
                    }
                }
            } else {
                i += 1;
            }
        }
    }
    table
}

#[test]
fn p0_7_1_dynamic_plugin_resolution() {
    let start = Instant::now();
    let path = ntcmach_path();
    let data = std::fs::read(&path).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    println!("=== P0-7.1 Dynamic Plugin Call Resolution: NtcMach.exe ===");
    println!("Total functions: {}", result.cfg.function_cfgs.len());

    // Gate 1: Build string table
    let string_table = build_string_table(&binary);
    println!("String table: {} entries", string_table.len());

    // Gate 2: Build external call name maps
    let external_call_names = build_external_call_name_map(&result.call_graph);
    let iat_map = build_iat_map_from_imports(&binary);
    let loadlib_count = iat_map
        .values()
        .filter(|s| s.contains("LoadLibrary"))
        .count();
    let getproc_count = iat_map
        .values()
        .filter(|s| s.contains("GetProcAddress"))
        .count();
    println!(
        "IAT map: {} entries (LoadLibrary={}, GetProcAddress={})",
        iat_map.len(),
        loadlib_count,
        getproc_count
    );
    println!(
        "CallGraph external symbols: {} entries",
        external_call_names.len()
    );

    // Gate 3-5: Run DynamicPluginResolver on each function
    let expr_engine = ExpressionRecovery::new();

    // P0-7.1B: Two-pass approach
    // Pass 1: collect global function pointer slots (Store from GetProcAddress)
    let empty_slots: HashMap<u64, fox_decompiler::dynamic_plugin::TrackedValue> = HashMap::new();
    let empty_heap: HashMap<(u64, i64), fox_decompiler::dynamic_plugin::TrackedValue> =
        HashMap::new();
    let mut global_fp_slots: HashMap<u64, fox_decompiler::dynamic_plugin::TrackedValue> =
        HashMap::new();
    let mut global_heap_slots: HashMap<(u64, i64), fox_decompiler::dynamic_plugin::TrackedValue> =
        HashMap::new();

    for func_cfg in &result.cfg.function_cfgs {
        let addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let mut resolver = DynamicPluginResolver::new(
            &external_call_names,
            &iat_map,
            &string_table,
            &expr_engine,
            ctx.memory_ssa.as_ref(),
            &empty_slots,
            &empty_heap,
        );
        let _ = resolver.resolve(ssa);
        // Collect global slots stored by this function
        for (addr, val) in resolver.collected_global_slots() {
            global_fp_slots.insert(addr, val);
        }
        for (offset, val) in resolver.collected_heap_slots() {
            global_heap_slots.insert(offset, val);
        }
    }
    println!(
        "\n=== P0-7.1B Pass 1: Global FP Slots: {}, Heap Slots: {} ===",
        global_fp_slots.len(),
        global_heap_slots.len()
    );
    for ((global_addr, offset), val) in &global_heap_slots {
        println!(
            "  heap[base=0x{:x}+0x{:x}] → {:?}",
            global_addr, offset, val
        );
    }

    // Pass 2: resolve indirect calls using global slots
    let mut all_resolutions = Vec::new();
    let mut total_stats = fox_decompiler::dynamic_plugin::ResolverStats::default();

    for func_cfg in &result.cfg.function_cfgs {
        let addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let mut resolver = DynamicPluginResolver::new(
            &external_call_names,
            &iat_map,
            &string_table,
            &expr_engine,
            ctx.memory_ssa.as_ref(),
            &global_fp_slots,
            &global_heap_slots,
        );
        let resolutions = resolver.resolve(ssa);
        total_stats.load_library_calls += resolver.stats.load_library_calls;
        total_stats.load_library_resolved += resolver.stats.load_library_resolved;
        total_stats.get_proc_address_calls += resolver.stats.get_proc_address_calls;
        total_stats.get_proc_address_resolved += resolver.stats.get_proc_address_resolved;
        total_stats.indirect_calls_seen += resolver.stats.indirect_calls_seen;
        total_stats.indirect_calls_resolved += resolver.stats.indirect_calls_resolved;
        total_stats.propagation_mov += resolver.stats.propagation_mov;
        total_stats.broken_chains += resolver.stats.broken_chains;
        all_resolutions.extend(resolutions);
    }

    println!("\n=== Resolver Statistics ===");
    println!(
        "LoadLibraryA calls: {} (resolved: {})",
        total_stats.load_library_calls, total_stats.load_library_resolved
    );
    println!(
        "GetProcAddress calls: {} (resolved: {})",
        total_stats.get_proc_address_calls, total_stats.get_proc_address_resolved
    );
    println!("Indirect calls seen: {}", total_stats.indirect_calls_seen);
    println!(
        "Indirect calls RESOLVED: {}",
        total_stats.indirect_calls_resolved
    );
    println!("MOV propagation: {}", total_stats.propagation_mov);
    println!("Broken chains: {}", total_stats.broken_chains);
    println!("Total resolutions: {}", all_resolutions.len());

    // Show sample resolutions
    println!("\n=== Sample Resolved Dynamic Calls ===");
    let mut by_module: HashMap<String, usize> = HashMap::new();
    for r in &all_resolutions {
        *by_module.entry(r.module.clone()).or_insert(0) += 1;
    }
    for (module, count) in by_module.iter().take(15) {
        println!("  {}: {} calls", module, count);
    }
    for r in all_resolutions.iter().take(10) {
        println!("  @{:#010X} -> {}!{}", r.call_address, r.module, r.symbol);
    }

    // P0-7.1B-R1: Print full Evidence chain for every resolved call
    println!("\n=== Full Evidence Chain (P0-7.1B-R1) ===");
    for r in &all_resolutions {
        println!("  @{:#010X} -> {}!{}", r.call_address, r.module, r.symbol);
        println!(
            "    LoadLibraryA  @ {:#010X}  (module string @ {:#010X})",
            r.evidence.load_library_address, r.evidence.module_name_address
        );
        println!(
            "    GetProcAddress @ {:#010X}  (symbol string @ {:#010X})",
            r.evidence.get_proc_address_address, r.evidence.symbol_name_address
        );
        // Evidence must not be zero
        assert!(
            r.evidence.load_library_address != 0,
            "load_library_address must not be 0 for {}!{}",
            r.module,
            r.symbol
        );
        assert!(
            r.evidence.get_proc_address_address != 0,
            "get_proc_address_address must not be 0 for {}!{}",
            r.module,
            r.symbol
        );
        assert!(
            r.evidence.module_name_address != 0,
            "module_name_address must not be 0 for {}!{}",
            r.module,
            r.symbol
        );
        assert!(
            r.evidence.symbol_name_address != 0,
            "symbol_name_address must not be 0 for {}!{}",
            r.module,
            r.symbol
        );
    }

    // P0-7.1B-R1: Regression Gate — exactly these 7 real dynamic calls
    let expected: Vec<(u64, &str, &str)> = vec![
        (0x00421BD0, "NTCDLLC", "DCompiler_f19"),
        (0x0042F5C0, "NTCDLLG", "Dgraph_f00"),
        (0x0042F7E0, "NTCDLLM", "DMachine_f00"),
        (0x0042FE60, "NTCDLLC", "DCompiler_f00"),
        (0x004301C0, "NTCDLLV", "DAutoTape_f00"),
        (0x004303F0, "NTCDLLV", "DVtest_f00"),
        (0x0043065A, "NTCDLLV", "DFeed0_f00"),
    ];
    println!("\n=== P0-7.1B-R1 Regression Gate: 7 required results ===");
    for (call_addr, exp_module, exp_symbol) in &expected {
        let found = all_resolutions.iter().any(|r| {
            r.call_address == *call_addr && r.module == *exp_module && r.symbol == *exp_symbol
        });
        println!(
            "  @{:#010X} -> {}!{} : {}",
            call_addr,
            exp_module,
            exp_symbol,
            if found { "PASS" } else { "FAIL" }
        );
        assert!(
            found,
            "Regression Gate: expected @{:#010X} -> {}!{} but not found",
            call_addr, exp_module, exp_symbol
        );
    }
    assert_eq!(
        all_resolutions.len(),
        7,
        "Expected exactly 7 resolved indirect calls, got {}",
        all_resolutions.len()
    );

    // Gate 6: Merge resolutions into call_targets and re-decompile
    let dynamic_targets = resolutions_to_call_targets(&all_resolutions);

    // Build base call_targets from CallGraph (same as P0-6.10)
    let mut call_targets: HashMap<u64, fox_decompiler::CallTarget> = HashMap::new();
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            let target = if let Some(ref sym) = edge.resolved_symbol {
                let func_name = sym.split('!').last().unwrap_or(sym);
                fox_decompiler::CallTarget::Symbol(func_name.to_string())
            } else if let Some(callee) = edge.callee {
                fox_decompiler::CallTarget::Address(callee)
            } else {
                fox_decompiler::CallTarget::Unknown
            };
            call_targets.insert(edge.call_instruction, target);
        }
    }
    // Override with dynamic resolutions (these were previously Unknown indirect calls)
    let dynamic_override_count = dynamic_targets.len();
    for (addr, target) in dynamic_targets {
        call_targets.insert(addr, target);
    }
    println!(
        "\nCall targets: {} base + {} dynamic overrides",
        call_targets.len() - dynamic_override_count,
        dynamic_override_count
    );

    // Re-decompile all functions with enhanced call targets
    let budget = StructuredIRBudget::default();
    let emitter = CLikeEmitter::with_config(EmitterConfig {
        annotate_evidence: false,
        show_phi: false,
        indent: "    ".to_string(),
        show_header: true,
        max_expression_chars: 400,
        max_expression_depth: 8,
    });

    let mut total_output = String::new();
    let mut ok_count = 0;
    let mut call_unknown_after = 0;
    let mut call_with_symbol = 0;

    for (func_idx, func_cfg) in result.cfg.function_cfgs.iter().enumerate() {
        let addr = func_cfg.function_address.0;
        let ctx = match result.pipeline.function_analysis.get(&addr) {
            Some(c) => c,
            None => continue,
        };
        let ssa = match ctx.ssa.as_ref() {
            Some(s) => s,
            None => continue,
        };
        let cs = recover_control_structures(func_cfg, ssa);
        let mut builder = StructuredIRBuilder::new()
            .with_budget(budget.clone())
            .with_call_targets(call_targets.clone());
        let func = builder.build(func_cfg, ssa, cs);
        let output = emitter.emit(&func);
        ok_count += 1;

        // Count call_unknown in this function's output
        for line in output.lines() {
            if line.contains("call_unknown") {
                call_unknown_after += 1;
            }
            if line.contains("call_") && !line.contains("call_unknown") {
                call_with_symbol += 1;
            }
        }
        total_output.push_str(&output);
        total_output.push('\n');
    }

    println!("\n=== Re-decompilation Results ===");
    println!("Functions decompiled: {}", ok_count);
    println!("Total output: {} chars", total_output.len());
    println!("call_unknown (after): {}", call_unknown_after);
    println!("call with symbol (after): {}", call_with_symbol);
    println!("Elapsed: {:.2}s", start.elapsed().as_secs_f64());

    // Write output
    let out_path = r"C:\Users\Administrator\AppData\Local\Temp\ntcmach_decompilation_p0_7_1.c";
    std::fs::write(out_path, &total_output).expect("write output");
    println!("\nOutput written to: {}", out_path);

    // Assertions
    assert!(
        total_stats.load_library_calls > 0,
        "Should find LoadLibraryA calls"
    );
    assert!(
        total_stats.get_proc_address_calls > 0,
        "Should find GetProcAddress calls"
    );
    // P0-7.1B: Memory function pointer recovery established.
    // 7 real indirect dynamic calls resolved via Register→Store→Memory→Load→Register.
    assert!(
        total_stats.indirect_calls_resolved >= 7,
        "Should resolve at least 7 indirect dynamic calls (P0-7.1B)"
    );
    println!(
        "\n=== P0-7.1B Results ===\nLoadLibraryA: {}/{} resolved\nGetProcAddress: {}/{} resolved\nIndirect calls resolved: {}\nEvidence: all 4 addresses non-zero for every resolution\nHeap identity: GlobalBasePointer proven, fail-closed otherwise",
        total_stats.load_library_resolved, total_stats.load_library_calls,
        total_stats.get_proc_address_resolved, total_stats.get_proc_address_calls,
        total_stats.indirect_calls_resolved
    );
}
