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

use fox_analysis::memory_ssa::{MemorySSAFunction, MemoryVariable};
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
/// All semantic values carry their full evidence chain (P0-7.1B-R1).
#[derive(Debug, Clone)]
pub enum TrackedValue {
    /// HMODULE from LoadLibraryA, with evidence.
    ModuleHandle {
        module: String,
        load_library_address: u64,
        module_name_address: u64,
    },
    /// Function pointer from GetProcAddress, with full evidence chain.
    FunctionPointer {
        module: String,
        symbol: String,
        load_library_address: u64,
        module_name_address: u64,
        get_proc_address_address: u64,
        symbol_name_address: u64,
    },
    /// Constant address (e.g. from `mov reg, offset string`).
    ConstantAddress(u64),
    /// External function loaded from IAT (e.g. GetProcAddress via `mov reg, [IAT]`).
    ExternalFunction(String),
    /// Global base pointer: register loaded from [global_addr].
    /// Used to prove heap Store/Load refer to the same structural object.
    GlobalBasePointer(u64),
    /// Not tracked.
    #[allow(dead_code)]
    Unknown,
}

/// Heap slot identity: must prove same base object, not just same offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HeapBaseIdentity {
    /// Base register loaded from a specific global address (e.g. mov ecx, [0x46E920]).
    /// Store and Load with same (global_addr, offset) refer to same object slot.
    Global(u64),
    /// Base cannot be proven — fail-closed, do not resolve.
    Unknown,
}

/// Module handle info with full evidence chain (P0-7.1B-R1).
struct ModuleHandleInfo {
    module: String,
    load_library_address: u64,
    module_name_address: u64,
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
    /// Memory SSA for Store→Load function pointer propagation (P0-7.1B).
    memory_ssa: Option<&'a MemorySSAFunction>,
    /// MemoryVariable → tracked value (only Global addresses, exact identity).
    memory_values: HashMap<MemoryVariable, TrackedValue>,
    /// Heap slot → tracked value. Key is (base_identity, offset) — must prove
    /// same structural object, not just same offset (P0-7.1B-R1 heap alias hardening).
    heap_offset_values: HashMap<(HeapBaseIdentity, i64), TrackedValue>,
    /// External global function pointer slots (cross-function, from first pass).
    /// Map: global address → tracked value (FunctionPointer/ModuleHandle).
    global_fp_slots: &'a HashMap<u64, TrackedValue>,
    /// External heap-offset function pointer slots (cross-function, from first pass).
    /// Key: (global_base_addr, offset) — only Global base identity is cross-function safe.
    global_heap_slots: &'a HashMap<(u64, i64), TrackedValue>,
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
        memory_ssa: Option<&'a MemorySSAFunction>,
        global_fp_slots: &'a HashMap<u64, TrackedValue>,
        global_heap_slots: &'a HashMap<(u64, i64), TrackedValue>,
    ) -> Self {
        Self {
            external_call_names,
            iat_map,
            string_table,
            expr_engine,
            resolutions: Vec::new(),
            reg_values: HashMap::new(),
            memory_ssa,
            memory_values: HashMap::new(),
            heap_offset_values: HashMap::new(),
            global_fp_slots,
            global_heap_slots,
            stats: ResolverStats::default(),
        }
    }

    /// Collect global function pointer slots stored in this function.
    /// Used in first pass to build cross-function global slot map.
    /// Returns (global_address → value) and (heap_offset → value).
    pub fn collected_global_slots(&self) -> HashMap<u64, TrackedValue> {
        let mut out = HashMap::new();
        for (var, val) in &self.memory_values {
            if let MemoryVariable::Global { address } = var {
                out.insert(*address, val.clone());
            }
        }
        out
    }

    /// Collect heap-offset function pointer slots (cross-function).
    /// Only returns slots with Global base identity (proven same object).
    pub fn collected_heap_slots(&self) -> HashMap<(u64, i64), TrackedValue> {
        let mut out = HashMap::new();
        for ((base, offset), val) in &self.heap_offset_values {
            if let HeapBaseIdentity::Global(global_addr) = base {
                out.insert((*global_addr, *offset), val.clone());
            }
        }
        out
    }

    /// Resolve heap base identity from a Memory description like "[ecx+0xdbcb04]".
    /// Returns (base_identity, offset). If base register is a GlobalBasePointer,
    /// we can prove same-object identity; otherwise Unknown (fail-closed).
    fn resolve_heap_base(&self, description: &str) -> (HeapBaseIdentity, Option<i64>) {
        let offset = Self::extract_heap_offset(description);
        // Extract base register name from "[ecx+0x...]" or "[eax]"
        let base_name: Option<String> = if description.starts_with('[') {
            let inner = description.strip_prefix('[').unwrap_or(description);
            let reg_end = inner
                .find(|c: char| ['+', '-', ']'].contains(&c))
                .unwrap_or(inner.len());
            let reg = inner[..reg_end].trim().to_string();
            if reg.is_empty() {
                None
            } else {
                Some(reg)
            }
        } else {
            None
        };
        let base_identity = match base_name {
            Some(reg) => {
                // Find latest version of this register holding a GlobalBasePointer
                // We search reg_values for any version of this register that is GlobalBasePointer
                let mut found: Option<u64> = None;
                for ((name, _ver), val) in &self.reg_values {
                    if name == &reg {
                        if let TrackedValue::GlobalBasePointer(addr) = val {
                            found = Some(*addr);
                            break;
                        }
                    }
                }
                match found {
                    Some(addr) => HeapBaseIdentity::Global(addr),
                    None => HeapBaseIdentity::Unknown,
                }
            }
            None => HeapBaseIdentity::Unknown,
        };
        (base_identity, offset)
    }

    /// Extract numeric displacement from a Memory description like "[ecx+0xdbcb04]".
    /// Returns None if no displacement found (e.g. "[ecx]" or "[0x46A180]").
    fn extract_heap_offset(description: &str) -> Option<i64> {
        // Look for +0xHEX or -0xHEX pattern after a register name
        let sign_pos = description.find('+').or_else(|| description.find('-'))?;
        let after_sign = &description[sign_pos + 1..];
        // Skip optional "0x" prefix
        let hex_start = if after_sign.starts_with("0x") || after_sign.starts_with("0X") {
            2
        } else {
            0
        };
        let num_str: String = after_sign[hex_start..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if num_str.is_empty() {
            return None;
        }
        let val = i64::from_str_radix(&num_str, 16).ok()?;
        if description.as_bytes()[sign_pos] == b'-' {
            Some(-val)
        } else {
            Some(val)
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
                    TrackedValue::ModuleHandle { .. }
                        | TrackedValue::FunctionPointer { .. }
                        | TrackedValue::ExternalFunction(_)
                        | TrackedValue::GlobalBasePointer(_)
                )
            });
            // Preserve memory_values across blocks (Global function pointer slots).
            // Only Global addresses are tracked (exact identity, no alias risk).
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
            "Mov" => self.process_mov(ssa, block_id, inst_idx, inst),
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
                Some(TrackedValue::FunctionPointer {
                    module,
                    symbol,
                    load_library_address,
                    module_name_address,
                    get_proc_address_address,
                    symbol_name_address,
                }) => {
                    self.stats.indirect_calls_resolved += 1;
                    self.resolutions.push(ResolvedDynamicCall {
                        call_address: inst.address,
                        module: module.clone(),
                        symbol: symbol.clone(),
                        evidence: DynamicCallEvidence {
                            load_library_address,
                            get_proc_address_address,
                            module_name_address,
                            symbol_name_address,
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
        inst: &SSAInstruction,
    ) {
        // Find the PUSH before this call that contains the module name string
        let module_name = self.recover_push_string_arg(ssa, block_id, inst_idx, 0);
        if let Some((name, str_addr)) = module_name {
            self.stats.load_library_resolved += 1;
            // LoadLibraryA returns HMODULE in eax
            if let Some(eax_ver) = self.find_next_register_version(ssa, block_id, inst_idx, "eax") {
                self.reg_values.insert(
                    ("eax".to_string(), eax_ver),
                    TrackedValue::ModuleHandle {
                        module: name,
                        load_library_address: inst.address,
                        module_name_address: str_addr,
                    },
                );
            }
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
        inst: &SSAInstruction,
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

        if let (Some(module_info), Some((symbol, sym_addr))) = (module_handle, symbol_name) {
            self.stats.get_proc_address_resolved += 1;
            if let Some(eax_ver) = self.find_next_register_version(ssa, block_id, inst_idx, "eax") {
                self.reg_values.insert(
                    ("eax".to_string(), eax_ver),
                    TrackedValue::FunctionPointer {
                        module: module_info.module,
                        symbol,
                        load_library_address: module_info.load_library_address,
                        module_name_address: module_info.module_name_address,
                        get_proc_address_address: inst.address,
                        symbol_name_address: sym_addr,
                    },
                );
            }
        } else {
            self.stats.broken_chains += 1;
            self.clear_return_register();
        }
    }

    fn process_mov(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        inst: &SSAInstruction,
    ) {
        // Note: Store instructions may have only 1 operand (Memory dst) in SSA,
        // because the source register is dropped. We recover it via Memory SSA.
        if inst.operands.is_empty() {
            return;
        }
        let dst = &inst.operands[0];

        // Single-operand Store (e.g. mov [0x46A180], eax): only handle Store logic.
        if inst.operands.len() == 1 {
            self.process_store(ssa, block_id, inst_idx, inst, dst, None);
            return;
        }
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
            // First: check IAT map (external function thunk)
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
            // P0-7.1B: Load from memory that holds a function pointer
            // mov reg, [global_addr] where global_addr was previously stored
            // with a FunctionPointer from GetProcAddress.
            if let Some(mem_var) = self.lookup_memory_use(block_id, inst_idx) {
                // First check function-local memory_values
                if let Some(val) = self.memory_values.get(&mem_var).cloned() {
                    self.stats.propagation_mov += 1;
                    self.reg_values.insert((dst_name.clone(), *dst_ver), val);
                    return;
                }
                // Then check cross-function global slots
                if let MemoryVariable::Global { address } = &mem_var {
                    if let Some(val) = self.global_fp_slots.get(address).cloned() {
                        self.stats.propagation_mov += 1;
                        self.reg_values.insert((dst_name.clone(), *dst_ver), val);
                        return;
                    }
                    // P0-7.1B-R1: Track global base pointer for heap identity proof.
                    // mov ecx, [0x46E920] → GlobalBasePointer(0x46E920)
                    // This lets us prove later heap Store/Load refer to same object.
                    if let Some(hex_start) = description.find("0x") {
                        let addr_str: String = description[hex_start + 2..]
                            .chars()
                            .take_while(|c| c.is_ascii_hexdigit())
                            .collect();
                        if let Ok(global_addr) = u64::from_str_radix(&addr_str, 16) {
                            self.reg_values.insert(
                                (dst_name.clone(), *dst_ver),
                                TrackedValue::GlobalBasePointer(global_addr),
                            );
                            return;
                        }
                    }
                }
                // P0-7.1B-R1: Load from heap slot — must prove same base object.
                // mov reg, [ecx+offset] where (base_identity, offset) was previously
                // stored with a FunctionPointer. Fail-closed if base unknown.
                if let MemoryVariable::Heap = &mem_var {
                    let (base_identity, offset_opt) = self.resolve_heap_base(description);
                    if let (HeapBaseIdentity::Global(global_addr), Some(offset)) =
                        (&base_identity, offset_opt)
                    {
                        let key = (base_identity.clone(), offset);
                        // First check function-local
                        if let Some(val) = self.heap_offset_values.get(&key).cloned() {
                            self.stats.propagation_mov += 1;
                            self.reg_values.insert((dst_name.clone(), *dst_ver), val);
                            return;
                        }
                        // Then check cross-function heap slots (keyed by global_addr, offset)
                        let cross_key = (*global_addr, offset);
                        if let Some(val) = self.global_heap_slots.get(&cross_key).cloned() {
                            self.stats.propagation_mov += 1;
                            self.reg_values.insert((dst_name.clone(), *dst_ver), val);
                            return;
                        }
                    }
                    // base_identity == Unknown → fail-closed, do not resolve
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

        // P0-7.1B: Store a tracked function pointer to memory (two-operand form)
        if let SSAOperand::Memory { .. } = dst {
            self.process_store(ssa, block_id, inst_idx, inst, dst, Some(src));
        }
    }

    /// Handle Store instruction: track function pointers / module handles written to memory.
    ///
    /// Two cases:
    /// 1. SSA has both operands: dst=Memory, src=Variable (e.g. mov [ecx+off], eax)
    /// 2. SSA has only Memory operand (e.g. mov [0x46A180], eax) — source register
    ///    is dropped by SSA construction, recover it from MemoryDef.source_register
    fn process_store(
        &mut self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        _inst: &SSAInstruction,
        dst: &SSAOperand,
        src: Option<&SSAOperand>,
    ) {
        let store_src_reg: Option<(String, u32)> = match (dst, src) {
            (SSAOperand::Memory { .. }, Some(SSAOperand::Variable { name, version })) => {
                Some((name.clone(), *version))
            }
            (SSAOperand::Memory { .. }, _) => {
                // Single-operand store: recover source register.
                // Two sub-cases:
                // a) Memory SSA has source_register → use it
                // b) Memory SSA source_register is None → this is x86 A3 encoding
                //    `mov [disp32], eax`, where source is implicitly eax.
                //    This is guaranteed by x86 instruction encoding (A3 is the
                //    only opcode that produces a single-operand Store in SSA).
                if let Some(mem_def) = self.lookup_memory_def_full(block_id, inst_idx) {
                    let src_name = mem_def
                        .source_register
                        .clone()
                        .unwrap_or_else(|| "eax".to_string());
                    // Fall back to version 0 if no explicit definition found
                    // (e.g. call return value not versioned by SSA).
                    let version = self
                        .find_latest_register_version(ssa, block_id, inst_idx, &src_name)
                        .unwrap_or(0);
                    Some((src_name, version))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some((src_name, src_ver)) = store_src_reg {
            if let Some(val) = self.reg_values.get(&(src_name, src_ver)).cloned() {
                if let Some(mem_var) = self.lookup_memory_def(block_id, inst_idx) {
                    match mem_var {
                        MemoryVariable::Global { .. } => {
                            self.memory_values.insert(mem_var, val);
                        }
                        MemoryVariable::Heap => {
                            // P0-7.1B-R1: Track heap slots by (base_identity, offset).
                            // Must prove same structural object, not just same offset.
                            if let SSAOperand::Memory { description } = dst {
                                let (base_identity, offset_opt) =
                                    self.resolve_heap_base(description);
                                if let Some(offset) = offset_opt {
                                    self.heap_offset_values.insert((base_identity, offset), val);
                                }
                            }
                        }
                        _ => {} // Stack/Unknown: too aliasing-prone to track
                    }
                }
            }
        }
    }

    /// Look up the MemoryVariable for a Store instruction via Memory SSA.
    fn lookup_memory_def(&self, block_id: usize, inst_idx: usize) -> Option<MemoryVariable> {
        let mssa = self.memory_ssa?;
        mssa.definitions
            .iter()
            .find(|d| d.block_id == block_id && d.inst_index == inst_idx)
            .map(|d| d.variable.clone())
    }

    /// Look up the full MemoryDef for a Store instruction via Memory SSA.
    fn lookup_memory_def_full(
        &self,
        block_id: usize,
        inst_idx: usize,
    ) -> Option<&fox_analysis::memory_ssa::MemoryDef> {
        let mssa = self.memory_ssa?;
        mssa.definitions
            .iter()
            .find(|d| d.block_id == block_id && d.inst_index == inst_idx)
    }

    /// Find the latest SSA version of a register before a given instruction in a block.
    fn find_latest_register_version(
        &self,
        ssa: &SSAFunction,
        block_id: usize,
        inst_idx: usize,
        reg_name: &str,
    ) -> Option<u32> {
        let block = ssa.basic_blocks.get(block_id)?;
        let mut latest: Option<u32> = None;
        for (i, inst) in block.instructions.iter().enumerate() {
            if i >= inst_idx {
                break;
            }
            if let Some(dst_idx) = inst.destination_operand_idx {
                if let Some(SSAOperand::Variable { name, version }) = inst.operands.get(dst_idx) {
                    if name == reg_name {
                        latest = Some(*version);
                    }
                }
            }
        }
        // Also check phi nodes at block entry (function-level phi list)
        for phi in &ssa.phi_nodes {
            if phi.block_id == block_id && phi.variable == reg_name {
                latest = Some(latest.map_or(phi.result_version, |v| v.max(phi.result_version)));
            }
        }
        latest
    }

    /// Look up the MemoryVariable for a Load instruction via Memory SSA.
    fn lookup_memory_use(&self, block_id: usize, inst_idx: usize) -> Option<MemoryVariable> {
        let mssa = self.memory_ssa?;
        mssa.uses
            .iter()
            .find(|u| u.block_id == block_id && u.inst_index == inst_idx)
            .map(|u| u.variable.clone())
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
    ) -> Option<ModuleHandleInfo> {
        let block = &ssa.basic_blocks[block_id];
        let push_inst = &block.instructions[push_idx];
        // Check: PUSH source is a register holding a tracked ModuleHandle
        if !push_inst.operands.is_empty() {
            if let SSAOperand::Variable { name, version } = &push_inst.operands[0] {
                if let Some(TrackedValue::ModuleHandle {
                    module,
                    load_library_address,
                    module_name_address,
                }) = self.reg_values.get(&(name.clone(), *version))
                {
                    return Some(ModuleHandleInfo {
                        module: module.clone(),
                        load_library_address: *load_library_address,
                        module_name_address: *module_name_address,
                    });
                }
            }
        }
        // Fallback: recover_use
        let expr = self.expr_engine.recover_use(ssa, block_id, push_idx, 0);
        if let Expression::Variable { name, version } = expr {
            if let Some(TrackedValue::ModuleHandle {
                module,
                load_library_address,
                module_name_address,
            }) = self.reg_values.get(&(name, version))
            {
                return Some(ModuleHandleInfo {
                    module: module.clone(),
                    load_library_address: *load_library_address,
                    module_name_address: *module_name_address,
                });
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
