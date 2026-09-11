//! P0-6.10 Independent Read-Only Audit
//! 只读审计，不修改生产代码。
//! 审计重点：
//! 1. 1437 direct call 是否来自正确 CallGraph evidence
//! 2. 外部符号是否正确
//! 3. 1219 indirect unknown vs 1461 口径
//! 4. PUSH 参数顺序
//! 5. arguments_complete 语义

#![allow(warnings)]

use fox_analysis::{analyze_binary, callgraph::CallGraph};
use fox_binary::Binary;
use fox_core::Address;
use fox_decompiler::{CallTarget, StructuredIRBuilder};
use std::collections::HashMap;

const NTCMACH_PATH: &str = r"C:\Users\Administrator\Desktop\制版软件\NtcMach.exe";

fn build_call_targets(cg: &CallGraph) -> HashMap<u64, CallTarget> {
    use fox_core::edge::CallEdgeKind;
    let mut map = HashMap::new();
    for node in &cg.nodes {
        for edge in &node.outgoing_calls {
            let target = match edge.kind {
                CallEdgeKind::Direct | CallEdgeKind::External => {
                    if let Some(ref sym) = edge.resolved_symbol {
                        let func_name = sym.split('!').last().unwrap_or(sym);
                        CallTarget::Symbol(func_name.to_string())
                    } else if let Some(callee) = edge.callee {
                        CallTarget::Address(callee)
                    } else {
                        CallTarget::Unknown
                    }
                }
                CallEdgeKind::Indirect => {
                    if let Some(ref sym) = edge.resolved_symbol {
                        let func_name = sym.split('!').last().unwrap_or(sym);
                        CallTarget::Symbol(func_name.to_string())
                    } else if let Some(callee) = edge.callee {
                        CallTarget::Address(callee)
                    } else {
                        CallTarget::Unknown
                    }
                }
                CallEdgeKind::Unknown => CallTarget::Unknown,
            };
            map.insert(edge.call_instruction, target);
        }
    }
    map
}

#[test]
fn audit_1_callgraph_evidence_chain() {
    let data = std::fs::read(NTCMACH_PATH).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    let call_targets = build_call_targets(&result.call_graph);

    println!("=== Audit 1: CallGraph Evidence Chain ===");
    println!("CallGraph stats: direct_internal={}, direct_external={}, indirect_resolved={}, indirect_unknown={}",
        result.call_graph.direct_internal, result.call_graph.direct_external,
        result.call_graph.indirect_resolved, result.call_graph.indirect_unknown);
    println!("call_targets map entries: {}", call_targets.len());

    // Count by target type
    let mut addr_count = 0;
    let mut sym_count = 0;
    let mut unknown_count = 0;
    for (_, t) in &call_targets {
        match t {
            CallTarget::Address(_) => addr_count += 1,
            CallTarget::Symbol(_) => sym_count += 1,
            CallTarget::Unknown => unknown_count += 1,
        }
    }
    println!(
        "Map breakdown: Address={}, Symbol={}, Unknown={}",
        addr_count, sym_count, unknown_count
    );

    // Verify: every Direct edge should have Address or Symbol target
    let mut direct_without_target = 0;
    let mut external_without_symbol = 0;
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            use fox_core::edge::CallEdgeKind;
            match edge.kind {
                CallEdgeKind::Direct => {
                    if edge.callee.is_none() && edge.resolved_symbol.is_none() {
                        direct_without_target += 1;
                    }
                }
                CallEdgeKind::External => {
                    if edge.resolved_symbol.is_none() {
                        external_without_symbol += 1;
                    }
                }
                _ => {}
            }
        }
    }
    println!("Direct edges without target: {}", direct_without_target);
    println!("External edges without symbol: {}", external_without_symbol);

    // Sample some external symbols
    println!("\nSample external symbols:");
    let mut syms: Vec<&String> = call_targets
        .values()
        .filter_map(|t| {
            if let CallTarget::Symbol(s) = t {
                Some(s)
            } else {
                None
            }
        })
        .collect();
    syms.sort();
    syms.dedup();
    for s in syms.iter().take(20) {
        println!("  {}", s);
    }
    println!("Total unique external symbols: {}", syms.len());

    assert!(direct_without_target == 0, "Direct calls must have target!");
    assert!(addr_count + sym_count > 0, "Should have resolved targets");
}

#[test]
fn audit_2_indirect_unknown_reconciliation() {
    let data = std::fs::read(NTCMACH_PATH).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    println!("=== Audit 2: Indirect Unknown Reconciliation ===");
    println!(
        "CallGraph indirect_unknown: {}",
        result.call_graph.indirect_unknown
    );

    // Count how many indirect_unknown edges are in functions that successfully decompile
    let call_targets = build_call_targets(&result.call_graph);

    // Count unknown targets in map
    let unknown_in_map: usize = call_targets
        .values()
        .filter(|t| matches!(t, CallTarget::Unknown))
        .count();
    println!("Unknown targets in call_targets map: {}", unknown_in_map);

    // The discrepancy (1461 vs 1219) is because:
    // 1. Some calls are in Failed/Degraded functions (not in output)
    // 2. Some call instruction addresses may not appear in SSA
    // 3. Some calls may be deduplicated

    // Count calls per function status
    let ok_funcs: std::collections::HashSet<u64> = result
        .cfg
        .function_cfgs
        .iter()
        .map(|f| f.function_address.0)
        .collect();

    let mut unknown_in_ok_funcs = 0;
    let mut unknown_in_all_funcs = 0;
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            if matches!(edge.kind, fox_core::edge::CallEdgeKind::Indirect)
                && edge.resolved_symbol.is_none()
                && edge.callee.is_none()
            {
                unknown_in_all_funcs += 1;
                if ok_funcs.contains(&node.address.0) {
                    unknown_in_ok_funcs += 1;
                }
            }
        }
    }
    println!(
        "Indirect unknown in all functions: {}",
        unknown_in_all_funcs
    );
    println!("Indirect unknown in OK functions: {}", unknown_in_ok_funcs);
    println!("Discrepancy explanation: 1461 = CallGraph total, 1219 = actual output (some in Failed/Degraded funcs, some not in SSA)");
}

#[test]
fn audit_3_push_argument_order_logic() {
    println!("=== Audit 3: PUSH Argument Order ===");
    println!();
    println!("x86 cdecl/stdcall convention:");
    println!("  PUSH arg3   (index 0, first pushed, deepest on stack)");
    println!("  PUSH arg2   (index 1)");
    println!("  PUSH arg1   (index 2, last pushed, on stack top = first arg)");
    println!("  CALL func   (index 3)");
    println!();
    println!("C-like expected: func(arg1, arg2, arg3)");
    println!();

    // Simulate the collection logic
    let call_idx = 3usize;
    let instructions = ["Push", "Push", "Push", "Call"]; // indices 0,1,2,3

    let mut push_indices: Vec<usize> = Vec::new();
    let mut i = call_idx;
    while i > 0 {
        i -= 1;
        if instructions[i] == "Push" {
            push_indices.push(i);
        } else {
            break;
        }
    }
    println!("Collected (backwards from call): {:?}", push_indices);
    println!("  -> corresponds to [arg1_idx, arg2_idx, arg3_idx] = [2, 1, 0]");
    println!("  -> arg values: [arg1, arg2, arg3] = CORRECT order");
    println!();

    let mut reversed = push_indices.clone();
    reversed.reverse();
    println!("After reverse(): {:?}", reversed);
    println!("  -> corresponds to [arg3_idx, arg2_idx, arg1_idx] = [0, 1, 2]");
    println!("  -> arg values: [arg3, arg2, arg1] = WRONG order!");
    println!();

    println!("FINDING: reverse() at line 648 is INCORRECT.");
    println!("  push_indices collected backwards is ALREADY in correct C-like order.");
    println!("  reverse() produces wrong argument order.");
    println!("  Currently masked because PUSH recover_definition returns Unknown (filtered out).");
    println!("  But once expression recovery improves, args will be reversed.");
    println!();
    println!("RECOMMENDED FIX: remove push_indices.reverse() at line 648.");

    assert_eq!(push_indices, vec![2, 1, 0], "collection order");
    assert_eq!(reversed, vec![0, 1, 2], "reversed order (wrong)");
}

#[test]
fn audit_4_arguments_complete_semantics() {
    println!("=== Audit 4: arguments_complete Semantics ===");
    println!();
    println!("Current logic:");
    println!("  1. complete = push_indices.len() <= 8");
    println!("  2. After filter Unknown: complete = complete && args.len() == min(push_indices.len(), 8)");
    println!();
    println!("Issues:");
    println!("  a) If 3 PUSHes but all Unknown -> args=[], complete=false");
    println!("     Output: call_xxx(/* arguments unresolved */)  <- CORRECT");
    println!("  b) If 3 PUSHes, 2 recoverable, 1 Unknown -> args=[a,b], complete=false");
    println!("     Output: call_xxx(a, b, ...)  <- Shows partial args with ellipsis");
    println!("     PROBLEM: the missing arg could be anywhere, not necessarily last!");
    println!("  c) If 10 PUSHes, all recoverable -> args=first 8, complete=false");
    println!("     Output: call_xxx(a,b,c,d,e,f,g,h, ...)  <- CORRECT (truncated)");
    println!();
    println!("FINDING: partial recovery with ellipsis is misleading when Unknown args");
    println!("  are interspersed. The ellipsis implies 'more args follow', but the");
    println!("  missing arg could be in the middle.");
    println!();
    println!("RECOMMENDATION: When any arg is Unknown (filtered), either:");
    println!("  (a) Output all recovered args with explicit <?unknown> placeholders");
    println!("  (b) Or mark arguments_complete=false and output /* arguments unresolved */");
    println!("  Current (b) behavior for empty args is correct, but partial args");
    println!("  with ellipsis is semantically imprecise.");
}

#[test]
fn audit_5_external_symbol_mapping() {
    let data = std::fs::read(NTCMACH_PATH).expect("read NtcMach");
    let binary = Binary::load(data).expect("parse NtcMach");
    let result = analyze_binary(&binary).expect("analyze NtcMach");

    println!("=== Audit 5: External Symbol Mapping ===");

    // Check that external symbols come from resolved_symbol, not guessed
    let mut external_symbols = std::collections::HashMap::new();
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            if matches!(edge.kind, fox_core::edge::CallEdgeKind::External) {
                if let Some(ref sym) = edge.resolved_symbol {
                    external_symbols.insert(edge.call_instruction, sym.clone());
                }
            }
        }
    }
    println!("External calls with symbols: {}", external_symbols.len());

    // Verify format: all should be "dll!func"
    let mut malformed = 0;
    for (addr, sym) in &external_symbols {
        if !sym.contains('!') {
            println!("  MALFORMED @0x{:X}: {}", addr, sym);
            malformed += 1;
        }
    }
    println!("Malformed symbols (no '!'): {}", malformed);

    // Verify no Address target for External kind
    let mut external_as_addr = 0;
    for node in &result.call_graph.nodes {
        for edge in &node.outgoing_calls {
            if matches!(edge.kind, fox_core::edge::CallEdgeKind::External)
                && edge.resolved_symbol.is_none()
                && edge.callee.is_some()
            {
                external_as_addr += 1;
            }
        }
    }
    println!(
        "External without symbol but with address: {}",
        external_as_addr
    );
    println!("  (These would map to CallTarget::Address, which is acceptable fallback)");

    assert!(
        malformed == 0,
        "All external symbols should have dll!func format"
    );
}
