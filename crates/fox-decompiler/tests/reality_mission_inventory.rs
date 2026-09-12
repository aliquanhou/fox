//! FOX Reality Decompilation Mission — Phase 1: whole-artifact inventory.
//!
//! Walks 制版软件/ and runs Binary::load + analyze_binary on every PE
//! (exe + dll). Reports per-artifact function count and recoverability.
//! This is the first real-project stress test for FOX beyond NtcMach.exe.
#![allow(warnings)]

use fox_analysis::analyze_binary;
use fox_binary::Binary;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(r"C:\Users\Administrator\Desktop\制版软件")
}

#[test]
fn reality_mission_inventory() {
    let root = root();
    println!("=== FOX Reality Mission: artifact inventory ===");
    println!("root: {}", root.display());
    println!();

    let mut artifacts: Vec<PathBuf> = Vec::new();
    for ext in ["exe", "dll"] {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase() == ext)
                    .unwrap_or(false)
                {
                    artifacts.push(p);
                }
            }
        }
    }
    artifacts.sort();

    let mut total_funcs = 0usize;
    let mut loadable = 0usize;

    for p in &artifacts {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let data = match std::fs::read(p) {
            Ok(d) => d,
            Err(e) => {
                println!("{name:16} READ FAIL: {e}");
                continue;
            }
        };
        let bytes_kb = data.len() / 1024;
        let binary = match Binary::load(data) {
            Ok(b) => b,
            Err(e) => {
                println!("{name:16} LOAD FAIL ({bytes_kb}KB): {e}");
                continue;
            }
        };
        loadable += 1;
        let result = match analyze_binary(&binary) {
            Ok(r) => r,
            Err(e) => {
                println!("{name:16} ANALYZE FAIL ({bytes_kb}KB): {e}");
                continue;
            }
        };
        let n = result.cfg.function_cfgs.len();
        total_funcs += n;
        println!(
            "{name:16} {bytes_kb:>6}KB  functions={n:>5}  calls={}",
            result.call_graph.direct_internal
                + result.call_graph.direct_external
                + result.call_graph.indirect_resolved
                + result.call_graph.indirect_unknown
        );
    }

    println!();
    println!(
        "=== summary: {} artifacts, {} loadable, total functions={} ===",
        artifacts.len(),
        loadable,
        total_funcs
    );
}
