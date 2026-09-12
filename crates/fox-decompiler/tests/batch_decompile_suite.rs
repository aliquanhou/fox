//! RM-8: Batch decompile all 14 PEs in 制版软件 suite.
use fox_decompiler::*;
use fox_binary::Binary;
use std::path::PathBuf;

fn pe_list() -> Vec<PathBuf> {
    let dir = PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件");
    let mut v = Vec::new();
    for f in ["NtcMach.exe","KeyTable.exe","NTCDLLA1.DLL","NTCDLLA2.DLL","NTCDLLA3.DLL","NTCDLLA4.DLL","NTCDLLA5.DLL","NTCDLLA6.DLL","NTCDLLC.DLL","NTCDLLG.DLL","NTCDLLM.DLL","NTCDLLV.DLL","NtcDLL_M3.DLL","NtcDLL_M4.DLL"] {
        v.push(dir.join(f));
    }
    v
}

#[test]
fn batch_decompile_all() {
    let out_dir = PathBuf::from(r"C:\Users\Administrator\Desktop\fox_decompiled");
    std::fs::create_dir_all(&out_dir).ok();
    let mut report = String::new();
    report.push_str("FOX Batch Decompile Report\n===========================\n\n");

    for path in pe_list() {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        eprintln!("\n=== {name} ===");
        let data = match std::fs::read(&path) { Ok(d)=>d, Err(e)=>{ report.push_str(&format!("{name}: read error {e}\n")); continue; } };
        let binary = match Binary::load(data) { Ok(b)=>b, Err(e)=>{ report.push_str(&format!("{name}: parse error {e}\n")); continue; } };
        let iat_map = fox_decompiler::iat_resolution::IatMap::from_binary(&binary);
        let result = match analyze_binary(&binary) { Ok(r)=>r, Err(e)=>{ report.push_str(&format!("{name}: analyze error {e}\n")); continue; } };
        let n_funcs = result.cfg.function_cfgs.len();

        let call_targets: std::collections::HashMap<u64, CallTarget> = {
            let mut map = std::collections::HashMap::new();
            for node in &result.call_graph.nodes {
                for edge in &node.outgoing_calls {
                    use fox_core::edge::CallEdgeKind;
                    let target = match edge.kind {
                        CallEdgeKind::Direct | CallEdgeKind::External | CallEdgeKind::Indirect => {
                            if let Some(ref sym) = edge.resolved_symbol {
                                let func_name = sym.split('!').last().unwrap_or(sym);
                                CallTarget::Symbol(func_name.to_string())
                            } else if let Some(callee) = edge.callee {
                                CallTarget::Address(callee)
                            } else { CallTarget::Unknown }
                        }
                        CallEdgeKind::Unknown => CallTarget::Unknown,
                    };
                    map.insert(edge.call_instruction, target);
                }
            }
            map
        };

        let mut cfuncs = Vec::new();
        let mut ok = 0usize;
        for func_cfg in &result.cfg.function_cfgs {
            let addr = func_cfg.function_address.0;
            let built = build_single_function(&result, addr, &format!("sub_{:X}", addr), &call_targets, &iat_map);
            match built {
                Ok(b) => { ok += 1; let mut t = c_ast::IrToC::new(); cfuncs.push(t.translate_function(&b.func)); }
                Err(_) => {}
            }
        }
        let src = c_ast::CRenderer::render(&cfuncs);
        std::fs::write(out_dir.join(format!("{name}.c")), &src).ok();

        report.push_str(&format!("{name}: funcs={} ok={} c_bytes={}\n", n_funcs, ok, src.len()));
        eprintln!("{name}: funcs={} ok={} c={}B", n_funcs, ok, src.len());
    }

    std::fs::write(out_dir.join("REPORT.txt"), &report).unwrap();
    println!("\n{report}");
}
