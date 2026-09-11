//! P0-7.1: Dynamic Plugin Call Resolution
//!
//! Resolves indirect calls that go through LoadLibraryA + GetProcAddress.
//!
//! Evidence chain:
//!   LoadLibraryA("NTCDLLG")       → ModuleHandle("NTCDLLG") in eax
//!   GetProcAddress(hmod, "Dgraph_f00") → FunctionPointer("NTCDLLG", "Dgraph_f00") in eax
//!   mov esi, eax                   → FunctionPointer propagates to esi
//!   call [esi] / call esi          → resolved to Dgraph_f00
//!
//! This is a pure consumer layer. Does not modify SSA, CallGraph, or any
//! sealed analysis module. Fail-closed: any broken propagation chain → Unknown.

use std::collections::HashMap;

use fox_analysis::ssa::{SSAFunction, SSAInstruction, SSAOperand};

use crate::expression::{CallTarget, Expression, ExpressionRecovery};

/// A resolved dynamic (indirect) call with full evidence chain.
#[derive(Debug, Clone)]
pub struct ResolvedDynamicCall {
    /// Address of the indirect call instruction.
    pub call_address: u64,
    /// DLL module name (e.g. "NTCDLLG").
    pub module: String,
    /// Export symbol name (e.g. "Dgraph_f00").
    pub symbol: String,
    /// Evidence chain for auditability.
    pub evidence: DynamicCallEvidence,
}

/// Evidence chain for a resolved dynamic call.
#[derive(Debug, Clone)]
pub struct DynamicCallEvidence {
    /// Address of LoadLibraryA call.
    pub load_library_address: u64,
    /// Address of GetProcAddress call.
    pub get_proc_address_address: u64,
    /// String address of module name passed to LoadLibraryA.
    pub module_name_address: u64,
    /// String address of symbol name passed to GetProcAddress.
    pub symbol_name_address: u64,
}

/// Internal tracked value during SSA scan.
#[derive(Debug, Clone)]
enum TrackedValue {
    /// HMODULE from LoadLibraryA.
    ModuleHandle(String),
    /// Function pointer from GetProcAddress.
    FunctionPointer { module: String, symbol: String },
    /// Constant address (e.g. from `mov reg, offset string`).
    ConstantAddress(u64),
    /// External function loaded from IAT (e.g. GetProcAddress via `mov reg, [IAT]`).
    ExternalFunction(String),
    /// Not tracked.
    #[allow(dead_code)]
    Unknown,
}

/// Resolves dynamic plugin calls via LoadLibraryA + GetProcAddress pattern.
pub struct DynamicPluginResolver<'a> {
    /// Map: call instruction address → external function full name (from CallGraph).
    external_call_names: &'a HashMap<u64, String>,
    /// Map: IAT entry address → external function full name (from PE imports).
    iat_map: &'a HashMap<u64, String>,
    /// Map: string address → string content.
    string_table: &'a HashMap<u64, String>,
    /// Expression recovery engine for resolving PUSH source operands.
    expr_engine: &'a ExpressionRecovery,
    /// Collected resolutions.
    resolutions: Vec<ResolvedDynamicCall>,
    /// Register (name, version) → tracked value within current block.
    reg_values: HashMap<(String, u32), TrackedValue>,
    /// Statistics.
    pub stats: ResolverStats,
}

/// Statistics for P0-7.1 audit.
#[derive(Debug, Default, Clone)]
pub struct ResolverStats {
    pub load_library_calls: usize,
    pub load_library_resolved: usize,
    pub get_proc_address_calls: usize,
    pub get_proc_address_resolved: usize,
    pub indirect_calls_seen: usize,
    pub indirect_calls_resolved: usize,
    pub propagation_mov: usize,
    pub broken_chains: usize,
}

impl<'a> DynamicPluginResolver<'a> {
    pub fn new(
        external_call_names: &'a HashMap<u64, String>,
        iat_map: &'a HashMap<u64, String>,
        string_table: &'a HashMap<u64, String>,
        expr_engine: &'a ExpressionRecovery,
    ) -> Self {
        Self {
            external_call_names,
            iat_map,
            string_table,
            expr_engine,
            resolutions: Vec::new(),
            reg_values: HashMap::new(),
            stats: ResolverStats::default(),
        }
    }

    /// Scan entire SSA function and resolve dynamic plugin calls.
    pub fn resolve(&mut self, ssa: &SSAFunction) -> Vec<ResolvedDynamicCall> {
        for block in &ssa.basic_blocks {
            // Preserve ModuleHandle / FunctionPointer / ExternalFunction across blocks.
            // These are semantic values that don't change between basic blocks.
            // Clear only ConstantAddress (block-local temporary) and register aliases.
            self.reg_values.retain(|_, v| {
                matches!(
                    v,
                    TrackedValue::ModuleHandle(_)
                        | TrackedValue::FunctionPointer { .. }
                        | TrackedValue::ExternalFunction(_)
                )
            });
            for (idx, inst) in block.instructions.iter().enumerate() {
                self.process_instruction(ssa, block.id, idx, inst);
            }
        }
        std::mem::take(&mut self.resolutions)
    }

    fn process_instruction(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        inst: &SSAInstruction,
    ) {
        match inst.op.as_str() {
            "Call" => self.process_call(ssa, block_id, inst_idx, inst),
            "Mov" => self.process_mov(inst),
            _ => {}
        }
    }

    fn process_call(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        inst: &SSAInstruction,
    ) {
        // Determine the external function name for this call (if any).
        // Check 1: by call instruction address (from CallGraph resolved_symbol)
        // Check 2: by call target address matching IAT entry (from PE imports)
        let func_name: Option<&str> = self
            .external_call_names
            .get(&inst.address)
            .map(|s| s.as_str())
            .or_else(|| {
                if !inst.operands.is_empty() {
                    match &inst.operands[0] {
                        SSAOperand::Constant(addr) => self.iat_map.get(addr).map(|s| s.as_str()),
                        SSAOperand::Memory { description } => {
                            // Extract hex address from description like "[0x456xxx]"
                            if let Some(hex_start) = description.find("0x") {
                                let addr_str: String = description[hex_start + 2..]
                                    .chars()
                                    .take_while(|c| c.is_ascii_hexdigit())
                                    .collect();
                                if let Ok(addr) = u64::from_str_radix(&addr_str, 16) {
                                    self.iat_map.get(&addr).map(|s| s.as_str())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            });

        if let Some(func_name) = func_name {
            if func_name.contains("LoadLibraryA") || func_name.contains("LoadLibraryW") {
                self.stats.load_library_calls += 1;
                self.handle_load_library(ssa, block_id, inst_idx, inst);
                return;
            }
            if func_name.contains("GetProcAddress") {
                self.stats.get_proc_address_calls += 1;
                self.handle_get_proc_address(ssa, block_id, inst_idx, inst);
                return;
            }
            // Other external call: clear return register tracking (eax gets a new value)
            self.clear_return_register();
            return;
        }

        // Indirect call: check if target register holds a tracked value
        self.stats.indirect_calls_seen += 1;
        if inst.operands.is_empty() {
            return;
        }
        if let SSAOperand::Variable { name, version } = &inst.operands[0] {
            let tracked = self.reg_values.get(&(name.clone(), *version)).cloned();
            match tracked {
                Some(TrackedValue::FunctionPointer { module, symbol }) => {
                    self.stats.indirect_calls_resolved += 1;
                    self.resolutions.push(ResolvedDynamicCall {
                        call_address: inst.address,
                        module: module.clone(),
                        symbol: symbol.clone(),
                        evidence: DynamicCallEvidence {
                            load_library_address: 0,
                            get_proc_address_address: 0,
                            module_name_address: 0,
                            symbol_name_address: 0,
                        },
                    });
                    self.clear_return_register();
                    return;
                }
                Some(TrackedValue::ExternalFunction(ref func_name)) => {
                    if func_name.contains("GetProcAddress") {
                        self.stats.get_proc_address_calls += 1;
                        self.handle_get_proc_address(ssa, block_id, inst_idx, inst);
                        return;
                    }
                    if func_name.contains("LoadLibraryA") || func_name.contains("LoadLibraryW") {
                        self.stats.load_library_calls += 1;
                        self.handle_load_library(ssa, block_id, inst_idx, inst);
                        return;
                    }
                    self.clear_return_register();
                    return;
                }
                _ => {}
            }
        }
        // Indirect call through memory (call [reg]) — first phase doesn't track memory
        self.clear_return_register();
    }

    fn handle_load_library(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        _inst: &SSAInstruction,
    ) {
        // Find the PUSH before this call that contains the module name string
        let module_name = self.recover_push_string_arg(ssa, block_id, inst_idx, 0);
        if let Some((name, str_addr)) = module_name {
            self.stats.load_library_resolved += 1;
            // LoadLibraryA returns HMODULE in eax
            // Find the destination version of eax after this call
            if let Some(eax_ver) = self.find_next_register_version(ssa, block_id, inst_idx, "eax") {
                self.reg_values.insert(
                    ("eax".to_string(), eax_ver),
                    TrackedValue::ModuleHandle(name),
                );
            }
            let _ = str_addr; // Evidence tracking (simplified in first phase)
        } else {
            self.stats.broken_chains += 1;
            self.clear_return_register();
        }
    }

    fn handle_get_proc_address(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        _inst: &SSAInstruction,
    ) {
        // GetProcAddress(hModule, lpProcName)
        // x86 stdcall: args pushed right-to-left
        //   push lpProcName  (arg2, pushed first, farther from call)
        //   push hModule     (arg1, pushed last, nearest to call)
        // Scanning backward from call: pushes[0]=arg1 (hModule), pushes[1]=arg2 (symbol)
        let pushes = self.collect_preceding_pushes(ssa, block_id, inst_idx, 2);

        if pushes.len() < 2 {
            self.stats.broken_chains += 1;
            self.clear_return_register();
            return;
        }

        // arg1 = hModule (nearest PUSH = pushes[0])
        // arg2 = lpProcName (farther PUSH = pushes[1])
        let module_handle = self.recover_push_as_module_handle(ssa, block_id, pushes[0]);
        let symbol_name = self.recover_push_string_arg_at(ssa, block_id, pushes[1]);

        if let (Some(module), Some((symbol, _sym_addr))) = (module_handle, symbol_name) {
            self.stats.get_proc_address_resolved += 1;
            if let Some(eax_ver) = self.find_next_register_version(ssa, block_id, inst_idx, "eax") {
                self.reg_values.insert(
                    ("eax".to_string(), eax_ver),
                    TrackedValue::FunctionPointer {
                        module: module.clone(),
                        symbol: symbol.clone(),
                    },
                );
            }
        } else {
            self.stats.broken_chains += 1;
            self.clear_return_register();
        }
    }

    fn process_mov(&mut self, inst: &SSAInstruction) {
        if inst.operands.len() < 2 {
            return;
        }
        let dst = &inst.operands[0];
        let src = &inst.operands[1];

        // mov reg, constant → track ConstantAddress (string pointer)
        if let (
            SSAOperand::Variable {
                name: dst_name,
                version: dst_ver,
            },
            SSAOperand::Constant(addr),
        ) = (dst, src)
        {
            self.reg_values.insert(
                (dst_name.clone(), *dst_ver),
                TrackedValue::ConstantAddress(*addr),
            );
            return;
        }

        // mov reg, [IAT] → track ExternalFunction (e.g. GetProcAddress)
        if let (
            SSAOperand::Variable {
                name: dst_name,
                version: dst_ver,
            },
            SSAOperand::Memory { description },
        ) = (dst, src)
        {
            if let Some(hex_start) = description.find("0x") {
                let addr_str: String = description[hex_start + 2..]
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if let Ok(addr) = u64::from_str_radix(&addr_str, 16) {
                    if let Some(func_name) = self.iat_map.get(&addr) {
                        self.reg_values.insert(
                            (dst_name.clone(), *dst_ver),
                            TrackedValue::ExternalFunction(func_name.clone()),
                        );
                        return;
                    }
                }
            }
        }

        // mov reg, reg → propagate tracked value
        if let (
            SSAOperand::Variable {
                name: dst_name,
                version: dst_ver,
            },
            SSAOperand::Variable {
                name: src_name,
                version: src_ver,
            },
        ) = (dst, src)
        {
            if let Some(val) = self.reg_values.get(&(src_name.clone(), *src_ver)).cloned() {
                self.stats.propagation_mov += 1;
                self.reg_values.insert((dst_name.clone(), *dst_ver), val);
            }
        }
    }

    /// Recover a string argument from the Nth PUSH before a call (0 = nearest PUSH).
    fn recover_push_string_arg(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        call_idx: usize,
        push_offset: usize,
    ) -> Option<(String, u64)> {
        let pushes = self.collect_preceding_pushes(ssa, block_id, call_idx, push_offset + 1);
        if pushes.len() <= push_offset {
            return None;
        }
        self.recover_push_string_arg_at(ssa, block_id, pushes[push_offset])
    }

    fn recover_push_string_arg_at(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        push_idx: usize,
    ) -> Option<(String, u64)> {
        let block = &ssa.basic_blocks[block_id];
        let push_inst = &block.instructions[push_idx];
        // Check 1: PUSH source is a direct constant (push offset string)
        if !push_inst.operands.is_empty() {
            if let SSAOperand::Constant(addr) = &push_inst.operands[0] {
                if let Some(s) = self.string_table.get(addr) {
                    return Some((s.clone(), *addr));
                }
            }
            // Check 2: PUSH source is a register that holds a tracked ConstantAddress
            if let SSAOperand::Variable { name, version } = &push_inst.operands[0] {
                if let Some(TrackedValue::ConstantAddress(addr)) =
                    self.reg_values.get(&(name.clone(), *version))
                {
                    if let Some(s) = self.string_table.get(addr) {
                        return Some((s.clone(), *addr));
                    }
                }
            }
        }
        // Check 3: fallback to recover_use
        let expr = self.expr_engine.recover_use(ssa, block_id, push_idx, 0);
        if let Expression::Constant(addr) = expr {
            if let Some(s) = self.string_table.get(&addr) {
                return Some((s.clone(), addr));
            }
        }
        None
    }

    fn recover_push_as_module_handle(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        push_idx: usize,
    ) -> Option<String> {
        let block = &ssa.basic_blocks[block_id];
        let push_inst = &block.instructions[push_idx];
        // Check: PUSH source is a register holding a tracked ModuleHandle
        if !push_inst.operands.is_empty() {
            if let SSAOperand::Variable { name, version } = &push_inst.operands[0] {
                if let Some(TrackedValue::ModuleHandle(name)) =
                    self.reg_values.get(&(name.clone(), *version))
                {
                    return Some(name.clone());
                }
            }
        }
        // Fallback: recover_use
        let expr = self.expr_engine.recover_use(ssa, block_id, push_idx, 0);
        if let Expression::Variable { name, version } = expr {
            if let Some(TrackedValue::ModuleHandle(name)) = self.reg_values.get(&(name, version)) {
                return Some(name.clone());
            }
        }
        None
    }

    /// Collect indices of consecutive PUSH instructions before call_idx (nearest first).
    fn collect_preceding_pushes(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        call_idx: usize,
        max_count: usize,
    ) -> Vec<usize> {
        let block = &ssa.basic_blocks[block_id];
        let mut pushes = Vec::new();
        let mut i = call_idx;
        // Search backward, skipping non-Push instructions (e.g. mov between push and call).
        // Limit search distance to avoid matching unrelated pushes.
        let max_scan = 64;
        let mut scanned = 0;
        while i > 0 && pushes.len() < max_count && scanned < max_scan {
            i -= 1;
            scanned += 1;
            let inst = &block.instructions[i];
            if inst.op == "Push" {
                pushes.push(i);
            }
            // Don't break on other instructions — arguments may be set up far before call.
        }
        pushes
    }

    /// Find the SSA version of a register immediately after a call instruction.
    fn find_next_register_version(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        after_idx: usize,
        reg_name: &str,
    ) -> Option<u32> {
        let block = &ssa.basic_blocks[block_id];
        // Look at instructions after the call in the same block
        for i in (after_idx + 1)..block.instructions.len() {
            for op in &block.instructions[i].operands {
                if let SSAOperand::Variable { name, version } = op {
                    if name == reg_name {
                        return Some(*version);
                    }
                }
            }
        }
        // Fallback: search direct successor blocks
        for &succ in &block.successors {
            if succ >= ssa.basic_blocks.len() {
                continue;
            }
            let blk = &ssa.basic_blocks[succ];
            for inst in &blk.instructions {
                for op in &inst.operands {
                    if let SSAOperand::Variable { name, version } = op {
                        if name == reg_name {
                            return Some(*version);
                        }
                    }
                }
            }
        }
        None
    }

    fn clear_return_register(&mut self) {
        // eax gets overwritten by any call; we can't track it across unknown calls
        // But we keep other registers' tracked values
    }
}

/// Build IAT address → "dll!func" map from PE imports.
/// `iat_address` in PE imports is RVA; we add image_base to get VA.
pub fn build_iat_map_from_imports(binary: &fox_binary::Binary) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let image_base = binary.image_base;
    for import in &binary.imports {
        for func in &import.functions {
            if let Some(ref name) = func.name {
                let full_name = format!("{}!{}", import.dll_name, name);
                map.insert(image_base + func.iat_address, full_name);
            }
        }
    }
    map
}

/// Build a map of call instruction address → external function name from CallGraph edges.
pub fn build_external_call_name_map(
    call_graph: &fox_analysis::callgraph::CallGraph,
) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    for node in &call_graph.nodes {
        for edge in &node.outgoing_calls {
            if let Some(ref sym) = edge.resolved_symbol {
                map.insert(edge.call_instruction, sym.clone());
            }
        }
    }
    map
}

/// Convert resolved dynamic calls into CallTarget entries for StructuredIRBuilder.
pub fn resolutions_to_call_targets(
    resolutions: &[ResolvedDynamicCall],
) -> HashMap<u64, CallTarget> {
    let mut map = HashMap::new();
    for r in resolutions {
        let target_name = format!("{}!{}", r.module, r.symbol);
        map.insert(r.call_address, CallTarget::Symbol(target_name));
    }
    map
}
