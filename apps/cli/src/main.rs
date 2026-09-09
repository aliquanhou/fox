//! FOX CLI - Command Line Interface
//!
#![allow(clippy::type_complexity)]
//! P0-1 commands:
//!   fox info <file>         - Binary header and metadata
//!   fox analyze <file>      - Full analysis pipeline
//!   fox functions <file>    - List discovered functions (with evidence + tiers)
//!   fox disasm <file>       - Disassemble (entry point or --address)
//!   fox blocks <file>       - Basic blocks per function
//!   fox cfg <file>          - CFG summary (--dot for Graphviz)
//!   fox callgraph <file>    - Call graph (Direct/Indirect/External/Unknown)
//!   fox ir <file>           - FOX IR L1 output
//!   fox evidence <file>     - Evidence chain detail
//!   fox imports <file>      - List imports
//!   fox exports <file>      - List exports
//!   fox strings <file>      - List extracted strings

use clap::{Parser, Subcommand};
use fox_analysis::{analyze_binary, FunctionConfidence};
use fox_binary::Binary;
use fox_ir::l1::IRTranslator;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "fox",
    version,
    about = "FOX - Binary Reverse Engineering & Decompilation Platform"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output as JSON
    #[arg(short, long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show binary information
    Info { file: PathBuf },
    /// Run full analysis pipeline
    Analyze { file: PathBuf },
    /// List discovered functions with evidence and confidence tiers
    Functions { file: PathBuf },
    /// Disassemble (entry point or --address)
    Disasm {
        file: PathBuf,
        /// Start address (hex, e.g. 0x140001000)
        #[arg(short, long)]
        address: Option<String>,
        /// Number of instructions
        #[arg(short, long, default_value = "50")]
        count: usize,
    },
    /// Show basic blocks per function
    Blocks { file: PathBuf },
    /// Show CFG summary (--dot for Graphviz output)
    Cfg {
        file: PathBuf,
        /// Output in DOT format
        #[arg(long)]
        dot: bool,
    },
    /// Show call graph with edge types
    Callgraph { file: PathBuf },
    /// Show FOX IR L1 output
    Ir {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// Show evidence chain detail
    Evidence {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// List imports
    Imports { file: PathBuf },
    /// List exports
    Exports { file: PathBuf },
    /// List extracted strings
    Strings {
        file: PathBuf,
        #[arg(short, long, default_value = "4")]
        min_length: usize,
    },
    /// Show call details (external/indirect resolution)
    Calls { file: PathBuf },
    /// Show data flow analysis (reaching defs, liveness, constants)
    Dataflow {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// Show dominator tree
    Dominators {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// Show SSA form
    Ssa {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
    /// Show recovered types
    Types {
        file: PathBuf,
        /// Function address (hex)
        #[arg(short, long)]
        address: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    let result = match &cli.command {
        Commands::Info { file } => cmd_info(file, cli.json),
        Commands::Analyze { file } => cmd_analyze(file, cli.json),
        Commands::Functions { file } => cmd_functions(file, cli.json),
        Commands::Disasm {
            file,
            address,
            count,
        } => cmd_disasm(file, address.as_deref(), *count, cli.json),
        Commands::Blocks { file } => cmd_blocks(file, cli.json),
        Commands::Cfg { file, dot } => cmd_cfg(file, *dot, cli.json),
        Commands::Callgraph { file } => cmd_callgraph(file, cli.json),
        Commands::Ir { file, address } => cmd_ir(file, address.as_deref(), cli.json),
        Commands::Evidence { file, address } => cmd_evidence(file, address.as_deref()),
        Commands::Imports { file } => cmd_imports(file, cli.json),
        Commands::Exports { file } => cmd_exports(file, cli.json),
        Commands::Strings { file, min_length } => cmd_strings(file, *min_length, cli.json),
        Commands::Calls { file } => cmd_calls(file, cli.json),
        Commands::Dataflow { file, address } => cmd_dataflow(file, address.as_deref(), cli.json),
        Commands::Dominators { file, address } => {
            cmd_dominators(file, address.as_deref(), cli.json)
        }
        Commands::Ssa { file, address } => cmd_ssa(file, address.as_deref(), cli.json),
        Commands::Types { file, address } => cmd_types(file, address.as_deref(), cli.json),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn load_binary(file: &PathBuf) -> Result<Binary, String> {
    let data = std::fs::read(file).map_err(|e| format!("Failed to read file: {}", e))?;
    Binary::load(data).map_err(|e| format!("Failed to parse binary: {}", e))
}

fn parse_hex_addr(s: &str) -> Result<u64, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("Invalid address: {}", e))
}

fn cmd_info(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;

    if json {
        let info = serde_json::json!({
            "format": binary.format.display_name(),
            "architecture": binary.architecture.display_name(),
            "execution_model": binary.execution_model.display_name(),
            "clr_present": binary.clr_present,
            "native_analysis": binary.execution_model.native_pipeline_applicable(),
            "reality_evidence": binary.reality_evidence,
            "entry_point": format!("0x{:016X}", binary.entry_point),
            "image_base": format!("0x{:016X}", binary.image_base),
            "size": binary.size,
            "sections": binary.sections.iter().map(|s| serde_json::json!({
                "name": s.name, "virtual_address": format!("0x{:X}", s.virtual_address),
                "virtual_size": s.virtual_size, "raw_size": s.raw_size,
                "executable": s.is_executable(), "readable": s.is_readable(), "writable": s.is_writable(),
            })).collect::<Vec<_>>(),
            "import_count": binary.imports.iter().map(|i| i.functions.len()).sum::<usize>(),
            "export_count": binary.exports.len(),
            "relocation_count": binary.relocations.len(),
            "string_count": binary.strings.len(),
        });
        println!("{}", serde_json::to_string_pretty(&info).unwrap());
    } else {
        println!("=== FOX Binary Info ===");
        println!("File:           {}", file.display());
        println!("Format:         {}", binary.format.display_name());
        println!("Architecture:   {}", binary.architecture);
        println!("Execution Model: {}", binary.execution_model.display_name());
        println!("CLR Present:    {}", binary.clr_present);
        println!(
            "Native Analysis: {}",
            if binary.execution_model.native_pipeline_applicable() {
                "applicable"
            } else {
                "NOT applicable"
            }
        );
        println!("Entry Point:    0x{:016X}", binary.entry_point);
        println!("Image Base:     0x{:016X}", binary.image_base);
        println!("File Size:      {} bytes", binary.size);
        if !binary.reality_evidence.is_empty() {
            println!();
            println!("--- Reality Evidence ---");
            for e in &binary.reality_evidence {
                println!("  - {}", e);
            }
        }
        println!();
        println!("--- Sections ({}) ---", binary.sections.len());
        println!(
            "{:<10} {:>12} {:>10} {:>10} {:>10} Flags",
            "Name", "VirtAddr", "VirtSize", "RawOff", "RawSize"
        );
        for s in &binary.sections {
            let mut flags = String::new();
            if s.is_executable() {
                flags.push('X');
            }
            if s.is_readable() {
                flags.push('R');
            }
            if s.is_writable() {
                flags.push('W');
            }
            println!(
                "{:<10} 0x{:>10X} {:>10} 0x{:>08X} {:>10} {}",
                s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size, flags
            );
        }
        println!();
        println!(
            "Imports:   {} functions from {} DLLs",
            binary
                .imports
                .iter()
                .map(|i| i.functions.len())
                .sum::<usize>(),
            binary.imports.len()
        );
        println!("Exports:   {} functions", binary.exports.len());
        println!("Relocs:    {} entries", binary.relocations.len());
        println!("Strings:   {} extracted", binary.strings.len());
    }
    Ok(())
}

fn cmd_analyze(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = analyze_binary(&binary).map_err(|e| e.to_string())?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else {
        println!("=== FOX Analysis Report ===");
        println!(
            "Functions discovered: {} (with confidence tiers)",
            result.functions.len()
        );
        let confirmed = result
            .functions
            .iter()
            .filter(|f| f.value.confidence_tier == FunctionConfidence::Confirmed)
            .count();
        let high = result
            .functions
            .iter()
            .filter(|f| f.value.confidence_tier == FunctionConfidence::High)
            .count();
        let probable = result
            .functions
            .iter()
            .filter(|f| f.value.confidence_tier == FunctionConfidence::Probable)
            .count();
        let unknown = result
            .functions
            .iter()
            .filter(|f| f.value.confidence_tier == FunctionConfidence::Unknown)
            .count();
        println!(
            "  Confirmed: {}, High: {}, Probable: {}, Unknown: {}",
            confirmed, high, probable, unknown
        );
        println!();
        println!(
            "CFG: {} function CFGs, {} total blocks, {} total edges",
            result.cfg.function_cfgs.len(),
            result.cfg.total_blocks,
            result.cfg.total_edges
        );
        println!("Call Graph: {} nodes, {} edges (DirectInt={}, DirectExt={}, IndirectRes={}, IndirectUnk={})",
            result.call_graph.nodes.len(), result.call_graph.total_edges(),
            result.call_graph.direct_internal, result.call_graph.direct_external,
            result.call_graph.indirect_resolved, result.call_graph.indirect_unknown);
    }
    Ok(())
}

fn cmd_functions(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;
    let functions = &result.functions;

    if json {
        println!("{}", serde_json::to_string_pretty(functions).unwrap());
    } else {
        println!("=== FOX Functions ({}) ===", functions.len());
        println!(
            "{:<20} {:>18} {:>10} {:>10}",
            "Name", "Address", "Conf", "Tier"
        );
        println!("{}", "-".repeat(62));
        for func in functions {
            println!(
                "{:<20} 0x{:>16X} {:>10} {:>10}",
                func.value.name, func.value.address.0, func.confidence, func.value.confidence_tier
            );
        }
        println!();
        println!("--- Evidence Detail (first 5) ---");
        for func in functions.iter().take(5) {
            println!(
                "\n{} (confidence: {}, tier: {})",
                func.value.name, func.confidence, func.value.confidence_tier
            );
            print!("{}", func.evidence);
        }
    }
    Ok(())
}

fn cmd_disasm(
    file: &PathBuf,
    address: Option<&str>,
    count: usize,
    json: bool,
) -> Result<(), String> {
    let binary = load_binary(file)?;

    // P0-4.5: Refuse disassembly for managed code (IL/metadata is not x86).
    if !binary.execution_model.native_pipeline_applicable() {
        return Err(format!(
            "Refused: execution model is {} (CLR={}). Native disassembly not applicable.",
            binary.execution_model.display_name(),
            binary.clr_present
        ));
    }

    let disasm = fox_disasm::create_disassembler(binary.architecture)
        .map_err(|e| format!("Failed to create disassembler: {}", e))?;

    let start_addr = match address {
        Some(a) => parse_hex_addr(a)?,
        None => binary.entry_point,
    };

    // Find section containing address
    let section = binary
        .sections
        .iter()
        .find(|s| s.contains_address(start_addr - binary.image_base))
        .ok_or_else(|| format!("Address 0x{:X} not in any section", start_addr))?;

    let rva = start_addr - binary.image_base;
    let offset = section.rva_to_offset(rva).ok_or("Invalid RVA")?;
    let data = &binary.raw_data[offset..(offset + count * 15).min(binary.raw_data.len())];

    let instructions = disasm
        .disassemble(data, start_addr)
        .map_err(|e| format!("Disassembly failed: {}", e))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&instructions.iter().take(count).collect::<Vec<_>>())
                .unwrap()
        );
    } else {
        println!(
            "=== FOX Disassembly @ 0x{:016X} ({} instructions) ===",
            start_addr,
            count.min(instructions.len())
        );
        for inst in instructions.iter().take(count) {
            let mut flags = String::new();
            if inst.is_call {
                flags.push('C');
            }
            if inst.is_ret {
                flags.push('R');
            }
            if inst.is_jump {
                flags.push('J');
            }
            if inst.is_conditional_jump {
                flags.push('c');
            }
            println!(
                "  0x{:016X}: {:<20} {:<8} {}",
                inst.address,
                inst.raw_bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<String>(),
                inst.mnemonic,
                inst.operands
            );
            let _ = flags;
        }
    }
    Ok(())
}

fn cmd_blocks(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = analyze_binary(&binary).map_err(|e| e.to_string())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result.cfg.function_cfgs).unwrap()
        );
    } else {
        println!("=== FOX Basic Blocks ===");
        for func_cfg in &result.cfg.function_cfgs {
            println!(
                "\n{} @ {} ({} blocks, {} edges)",
                func_cfg.function_name,
                func_cfg.function_address,
                func_cfg.blocks.len(),
                func_cfg.edge_count
            );
            for block in &func_cfg.blocks {
                let term = block
                    .terminator()
                    .map(|t| t.mnemonic.clone())
                    .unwrap_or_else(|| "fallthrough".to_string());
                println!(
                    "  BB#{:<4} 0x{:016X}-0x{:016X}  {:>3} instrs  term={}  succs={}",
                    block.id,
                    block.start_address.0,
                    block.end_address.0,
                    block.instruction_count(),
                    term,
                    block.successors.len()
                );
            }
            if !func_cfg.invalid_addresses.is_empty() {
                println!("  Invalid addresses: {:?}", func_cfg.invalid_addresses);
            }
        }
    }
    Ok(())
}

fn cmd_cfg(file: &PathBuf, dot: bool, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = analyze_binary(&binary).map_err(|e| e.to_string())?;

    if dot {
        print!("{}", result.cfg.to_dot());
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&result.cfg).unwrap());
    } else {
        println!("=== FOX CFG Summary ===");
        println!("Function CFGs: {}", result.cfg.function_cfgs.len());
        println!("Total blocks:   {}", result.cfg.total_blocks);
        println!("Total edges:    {}", result.cfg.total_edges);
        println!();

        for func_cfg in result.cfg.function_cfgs.iter().take(10) {
            println!(
                "{} @ {}: {} blocks, {} edges",
                func_cfg.function_name,
                func_cfg.function_address,
                func_cfg.blocks.len(),
                func_cfg.edge_count
            );

            // Edge type counts
            let counts = func_cfg.edge_kind_counts();
            let mut parts: Vec<String> =
                counts.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            parts.sort();
            println!("  Edge types: {}", parts.join(", "));
        }
        if result.cfg.function_cfgs.len() > 10 {
            println!(
                "... and {} more functions",
                result.cfg.function_cfgs.len() - 10
            );
        }
    }
    Ok(())
}

fn cmd_callgraph(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = analyze_binary(&binary).map_err(|e| e.to_string())?;
    let cg = &result.call_graph;

    if json {
        println!("{}", serde_json::to_string_pretty(cg).unwrap());
    } else {
        println!("=== FOX Call Graph ===");
        println!("Nodes:    {}", cg.nodes.len());
        println!("Edges:    {} (total)", cg.total_edges());
        println!("  DirectInternal:  {}", cg.direct_internal);
        println!("  DirectExternal:  {}", cg.direct_external);
        println!("  IndirectResolved: {}", cg.indirect_resolved);
        println!("  IndirectUnknown: {}", cg.indirect_unknown);
        println!();

        for node in cg
            .nodes
            .iter()
            .filter(|n| !n.outgoing_calls.is_empty())
            .take(15)
        {
            println!(
                "{} @ {} ({} outgoing calls)",
                node.name,
                node.address,
                node.outgoing_calls.len()
            );
            for edge in node.outgoing_calls.iter().take(5) {
                let callee = edge
                    .callee
                    .map(|a| format!("0x{:016X}", a))
                    .unwrap_or_else(|| "unknown".to_string());
                let symbol = edge.resolved_symbol.clone().unwrap_or_default();
                println!("  [{}] -> {} {}", edge.kind, callee, symbol);
            }
            if node.outgoing_calls.len() > 5 {
                println!("  ... and {} more", node.outgoing_calls.len() - 5);
            }
        }
    }
    Ok(())
}

fn cmd_ir(file: &PathBuf, address: Option<&str>, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let disasm = fox_disasm::create_disassembler(binary.architecture)
        .map_err(|e| format!("Failed to create disassembler: {}", e))?;

    let start_addr = match address {
        Some(a) => parse_hex_addr(a)?,
        None => binary.entry_point,
    };

    let section = binary
        .sections
        .iter()
        .find(|s| s.contains_address(start_addr - binary.image_base))
        .ok_or_else(|| format!("Address 0x{:X} not in any section", start_addr))?;

    let rva = start_addr - binary.image_base;
    let offset = section.rva_to_offset(rva).ok_or("Invalid RVA")?;
    let data = &binary.raw_data[offset..(offset + 200).min(binary.raw_data.len())];

    let instructions = disasm
        .disassemble(data, start_addr)
        .map_err(|e| format!("Disassembly failed: {}", e))?;

    let ir_instructions = IRTranslator::translate_all(&instructions);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&ir_instructions).unwrap()
        );
    } else {
        println!(
            "=== FOX IR L1 @ 0x{:016X} ({} instructions) ===",
            start_addr,
            ir_instructions.len()
        );
        for ir in &ir_instructions {
            let ops: Vec<String> = ir.operands.iter().map(|o| format!("{:?}", o)).collect();
            println!(
                "  0x{:016X}: {:<10} {}",
                ir.address.0,
                format!("{:?}", ir.op),
                ops.join(", ")
            );
        }
        let unknown_count = ir_instructions
            .iter()
            .filter(|i| matches!(i.op, fox_ir::IROp::Unknown(_)))
            .count();
        println!(
            "\nTranslation coverage: {}/{} mapped ({} unknown)",
            ir_instructions.len() - unknown_count,
            ir_instructions.len(),
            unknown_count
        );
    }
    Ok(())
}

fn cmd_evidence(file: &PathBuf, address: Option<&str>) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = analyze_binary(&binary).map_err(|e| e.to_string())?;

    if let Some(addr_str) = address {
        let addr = parse_hex_addr(addr_str)?;
        if let Some(func) = result.functions.iter().find(|f| f.value.address.0 == addr) {
            println!(
                "=== Evidence for {} @ {} ===",
                func.value.name, func.value.address
            );
            println!(
                "Confidence: {} ({})",
                func.confidence, func.value.confidence_tier
            );
            println!();
            println!("Evidence:");
            print!("{}", func.evidence);

            // Show CFG evidence if available
            if let Some(cfg) = result
                .cfg
                .function_cfgs
                .iter()
                .find(|c| c.function_address.0 == addr)
            {
                println!(
                    "\nCFG Evidence ({} blocks, {} edges):",
                    cfg.blocks.len(),
                    cfg.edge_count
                );
                for block in &cfg.blocks {
                    for edge in &block.successors {
                        if !edge.evidence.is_empty() {
                            println!("  BB#{} -> {:?}:", block.id, edge.kind);
                            print!("{}", edge.evidence);
                        }
                    }
                }
            }
        } else {
            println!("No function found at 0x{:016X}", addr);
        }
    } else {
        println!("=== FOX Evidence Summary ===");
        for func in result.functions.iter().take(10) {
            println!(
                "{} @ {}: conf={}, tier={}, evidence={}",
                func.value.name,
                func.value.address,
                func.confidence,
                func.value.confidence_tier,
                func.evidence.len()
            );
        }
    }
    Ok(())
}

fn cmd_imports(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&binary.imports).unwrap());
    } else {
        println!("=== FOX Imports ===");
        for import in &binary.imports {
            println!(
                "\n[{}] ({} functions)",
                import.dll_name,
                import.functions.len()
            );
            for func in &import.functions {
                match &func.name {
                    Some(name) => println!("  {:>6} {}", func.hint, name),
                    None => println!("  ordinal #{}", func.ordinal.unwrap_or(0)),
                }
            }
        }
        println!(
            "\nTotal: {} imports from {} DLLs",
            binary
                .imports
                .iter()
                .map(|i| i.functions.len())
                .sum::<usize>(),
            binary.imports.len()
        );
    }
    Ok(())
}

fn cmd_exports(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&binary.exports).unwrap());
    } else {
        println!("=== FOX Exports ({}) ===", binary.exports.len());
        println!("{:<8} {:>18} {:<40}", "Ordinal", "Address", "Name");
        println!("{}", "-".repeat(70));
        for export in &binary.exports {
            let name = export
                .name
                .clone()
                .unwrap_or_else(|| "(unnamed)".to_string());
            let fwd = if export.is_forwarded {
                format!(" -> {}", export.forward_name.clone().unwrap_or_default())
            } else {
                String::new()
            };
            println!(
                "{:<8} 0x{:>16X} {:<40}{}",
                export.ordinal, export.address, name, fwd
            );
        }
    }
    Ok(())
}

fn cmd_strings(file: &PathBuf, min_length: usize, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let filtered: Vec<_> = binary
        .strings
        .iter()
        .filter(|s| s.length >= min_length)
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
    } else {
        println!(
            "=== FOX Strings ({}, min length={}) ===",
            filtered.len(),
            min_length
        );
        for s in &filtered {
            println!("0x{:016X} (len={}): {}", s.address, s.length, s.value);
        }
    }
    Ok(())
}

// === P0-2 New Commands ===

fn cmd_calls(file: &PathBuf, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;

    if json {
        let external: Vec<_> = result
            .call_graph
            .nodes
            .iter()
            .flat_map(|n| n.outgoing_calls.iter())
            .filter(|e| e.resolved_symbol.is_some())
            .collect();
        println!("{}", serde_json::to_string_pretty(&external).unwrap());
    } else {
        println!("=== FOX Calls (External Resolution) ===");
        println!("DirectInternal:  {}", result.call_graph.direct_internal);
        println!("DirectExternal:  {}", result.call_graph.direct_external);
        println!("IndirectResolved: {}", result.call_graph.indirect_resolved);
        println!("IndirectUnknown: {}", result.call_graph.indirect_unknown);
        println!();
        println!("Resolved external calls:");
        let mut count = 0;
        for node in &result.call_graph.nodes {
            for edge in &node.outgoing_calls {
                if let Some(ref sym) = edge.resolved_symbol {
                    println!("  0x{:016X} -> {}", edge.call_instruction, sym);
                    count += 1;
                    if count >= 30 {
                        break;
                    }
                }
            }
            if count >= 30 {
                break;
            }
        }
    }
    Ok(())
}

fn select_function<'a>(
    result: &'a fox_analysis::AnalysisResult,
    address: Option<&str>,
) -> Option<(
    &'a fox_analysis::Function,
    &'a fox_analysis::cfg::FunctionCfg,
)> {
    if let Some(addr_str) = address {
        if let Ok(addr) = parse_hex_addr(addr_str) {
            let func = result
                .functions
                .iter()
                .find(|f| f.value.address.0 == addr)?;
            let cfg = result
                .cfg
                .function_cfgs
                .iter()
                .find(|c| c.function_address.0 == addr)?;
            return Some((&func.value, cfg));
        }
    }
    let func = result.functions.first()?;
    let cfg = result.cfg.function_cfgs.first()?;
    Some((&func.value, cfg))
}

fn collect_instructions(cfg: &fox_analysis::cfg::FunctionCfg) -> Vec<fox_disasm::Instruction> {
    let mut all = Vec::new();
    for block in &cfg.blocks {
        all.extend(block.instructions.iter().cloned());
    }
    all
}

fn cmd_dataflow(file: &PathBuf, address: Option<&str>, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;
    let (func, _cfg) = select_function(&result, address).ok_or("No function found")?;
    let addr = func.address.0;

    // P0-4.1: Use unified pipeline result (single source of truth)
    let ctx = result
        .pipeline
        .function_analysis
        .get(&addr)
        .ok_or_else(|| format!("Function 0x{:X} not in analysis pipeline (no CFG?)", addr))?;

    let df = ctx
        .dataflow
        .as_ref()
        .ok_or_else(|| format!("DataFlow not available for function 0x{:X}", addr))?;

    if json {
        println!("{}", serde_json::to_string_pretty(df).unwrap());
    } else {
        println!(
            "=== FOX Data Flow (CFG-aware, pipeline): {} @ {} ===",
            func.name, func.address
        );
        println!("RD iterations: {}", df.reaching_definitions.iterations);
        println!("LV iterations: {}", df.live_variables.iterations);
        println!("CP iterations: {}", df.constant_propagation.iterations);
        println!(
            "Constants propagated: {}",
            df.constant_propagation.propagated_count
        );
        let total_rd_in: usize = df
            .reaching_definitions
            .in_sets
            .values()
            .map(|v| v.len())
            .sum();
        let total_lv_in: usize = df.live_variables.in_sets.values().map(|v| v.len()).sum();
        println!("Total reaching defs (IN): {}", total_rd_in);
        println!("Total live vars (IN): {}", total_lv_in);
    }
    Ok(())
}

fn cmd_dominators(file: &PathBuf, address: Option<&str>, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;
    let (func, cfg) = select_function(&result, address).ok_or("No function found")?;

    let mut succ: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    let mut pred: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for block in &cfg.blocks {
        let targets: Vec<usize> = block
            .successors
            .iter()
            .filter_map(|e| e.target_block)
            .collect();
        succ.insert(block.id, targets);
        pred.insert(block.id, block.predecessors.clone());
    }

    let dt = fox_analysis::dominators::DominatorTree::compute(
        &succ,
        &pred,
        cfg.entry_block,
        cfg.blocks.len(),
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&dt).unwrap());
    } else {
        println!("=== FOX Dominators: {} @ {} ===", func.name, func.address);
        println!("Blocks: {}", dt.block_count);
        println!("Entry:  block {}", dt.entry_block);
        println!();
        for b in 0..dt.block_count.min(15) {
            let idom = dt
                .idom(b)
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".to_string());
            let frontier: Vec<_> = dt.frontier(b).iter().collect();
            println!("  block {}: idom={}, frontier={:?}", b, idom, frontier);
        }
    }
    Ok(())
}

fn cmd_ssa(file: &PathBuf, address: Option<&str>, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;
    let (func, _cfg) = select_function(&result, address).ok_or("No function found")?;
    let addr = func.address.0;

    // P0-4.1: Use unified pipeline result (single source of truth)
    let ctx = result
        .pipeline
        .function_analysis
        .get(&addr)
        .ok_or_else(|| format!("Function 0x{:X} not in analysis pipeline (no CFG?)", addr))?;

    let ssa = ctx
        .ssa
        .as_ref()
        .ok_or_else(|| format!("SSA not available for function 0x{:X}", addr))?;

    if json {
        println!("{}", serde_json::to_string_pretty(ssa).unwrap());
    } else {
        println!(
            "=== FOX SSA: {} @ {} (pipeline) ===",
            func.name, func.address
        );
        println!("Phi nodes: {}", ssa.phi_nodes.len());
        println!("Variables versioned: {}", ssa.variable_versions.len());
        println!("Proper renaming: {}", ssa.proper_renaming);
        for (var, ver) in ssa.variable_versions.iter().take(10) {
            println!("  {}: v{}", var, ver);
        }
    }
    Ok(())
}

fn cmd_types(file: &PathBuf, address: Option<&str>, json: bool) -> Result<(), String> {
    let binary = load_binary(file)?;
    let result = fox_analysis::analyze_binary(&binary).map_err(|e| e.to_string())?;
    let (func, cfg) = select_function(&result, address).ok_or("No function found")?;

    let insts = collect_instructions(cfg);
    let ir_insts: Vec<_> = insts
        .iter()
        .map(fox_ir::l1::IRTranslator::translate)
        .collect();
    let types = fox_analysis::type_recovery::TypeRecovery::analyze(func.address.0, &ir_insts);

    if json {
        println!("{}", serde_json::to_string_pretty(&types).unwrap());
    } else {
        println!("=== FOX Types: {} @ {} ===", func.name, func.address);
        println!("Inferences: {}", types.inferences.len());
        println!();
        println!("{:<12} {:<10} {:>10}", "Variable", "Type", "Confidence");
        println!("{}", "-".repeat(35));
        for inf in types.inferences.iter().take(20) {
            println!(
                "{:<12} {:<10} {:>9.2}",
                inf.variable,
                inf.inferred_type.display_name(),
                inf.confidence
            );
        }
    }
    Ok(())
}
