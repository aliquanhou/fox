//! FOX Tools - Tool Calling interface for AI investigation
//!
//! Provides structured tools that DeepSeek can call to investigate
//! binary evidence without needing manual data extraction.

use std::collections::HashMap;

/// A tool call request from the LLM
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub tool_name: String,
    pub arguments: HashMap<String, String>,
    pub call_id: String,
}

/// A tool result returned to the LLM
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub success: bool,
    pub data: String,
    pub evidence_ids: Vec<String>,
}

/// FOX Tools - the evidence bus for LLM investigation
pub struct FoxTools {
    decompiled_c: HashMap<String, String>,  // module -> C source
    function_index: HashMap<String, FunctionInfo>,
    string_xrefs: HashMap<String, Vec<XrefRef>>,
    investigation_memory: Vec<InvestigationRecord>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub line_count: usize,
    pub api_calls: Vec<String>,
    pub calls: Vec<String>,
    pub called_by: Vec<String>,
    pub module: String,
}

#[derive(Debug, Clone)]
pub struct XrefRef {
    pub source_address: u64,
    pub function: String,
    pub module: String,
}

#[derive(Debug, Clone)]
pub struct InvestigationRecord {
    pub query: String,
    pub tool_calls: Vec<String>,
    pub result_summary: String,
    pub confidence: String,
}

impl FoxTools {
    pub fn new() -> Self {
        Self {
            decompiled_c: HashMap::new(),
            function_index: HashMap::new(),
            string_xrefs: HashMap::new(),
            investigation_memory: Vec::new(),
        }
    }

    /// Load decompiled C source for a module
    pub fn load_module(&mut self, module_name: &str, c_source: &str) {
        self.decompiled_c.insert(module_name.to_string(), c_source.to_string());
        self.index_functions(module_name, c_source);
    }

    /// Index all functions in a module
    fn index_functions(&mut self, module: &str, source: &str) {
        let lines: Vec<&str> = source.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.contains("static uint32_t fn_") {
                if let Some(name) = extract_fn_name(line) {
                    let start = i;
                    let mut depth = line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    let mut j = i + 1;
                    while j < lines.len() && depth > 0 {
                        depth += lines[j].matches('{').count() as i32;
                        depth -= lines[j].matches('}').count() as i32;
                        j += 1;
                    }
                    let body: String = lines[start..j].join("\n");
                    let apis = extract_apis(&body);
                    let calls = extract_fn_calls(&body);

                    let info = FunctionInfo {
                        name: name.clone(),
                        address: parse_addr(&name),
                        line_count: j - start,
                        api_calls: apis,
                        calls: calls.clone(),
                        called_by: Vec::new(),
                        module: module.to_string(),
                    };

                    // Update called_by
                    for callee in &calls {
                        if let Some(callee_info) = self.function_index.get_mut(callee) {
                            callee_info.called_by.push(name.clone());
                        }
                    }

                    self.function_index.insert(name, info);
                    i = j;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    // === TOOL 1: get_function ===
    /// Get basic info about a function
    pub fn get_function(&self, name: &str) -> Option<&FunctionInfo> {
        self.function_index.get(name)
    }

    // === TOOL 2: get_function_evidence ===
    /// Get full evidence for a function (body + APIs + calls)
    pub fn get_function_evidence(&self, name: &str) -> Option<String> {
        let info = self.function_index.get(name)?;
        let source = self.decompiled_c.get(&info.module)?;

        // Extract function body from source
        let lines: Vec<&str> = source.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].contains(&format!("static uint32_t {}", name)) {
                let start = i;
                let mut depth = lines[i].matches('{').count() as i32 - lines[i].matches('}').count() as i32;
                let mut j = i + 1;
                while j < lines.len() && depth > 0 {
                    depth += lines[j].matches('{').count() as i32;
                    depth -= lines[j].matches('}').count() as i32;
                    j += 1;
                }
                return Some(lines[start..j].join("\n"));
            }
            i += 1;
        }
        None
    }

    // === TOOL 3: get_callers ===
    /// Get all functions that call this function
    pub fn get_callers(&self, name: &str) -> Vec<&FunctionInfo> {
        self.function_index
            .values()
            .filter(|f| f.calls.contains(&name.to_string()))
            .collect()
    }

    // === TOOL 4: get_callees ===
    /// Get all functions called by this function
    pub fn get_callees(&self, name: &str) -> Vec<&FunctionInfo> {
        self.function_index
            .values()
            .filter(|f| self.function_index.get(name)
                .map(|info| info.calls.contains(&f.name))
                .unwrap_or(false))
            .collect()
    }

    // === TOOL 5: find_string_refs ===
    /// Find all functions that reference a string
    pub fn find_string_refs(&self, pattern: &str) -> Vec<&FunctionInfo> {
        self.function_index
            .values()
            .filter(|f| {
                self.get_function_evidence(&f.name)
                    .map(|body| body.contains(pattern))
                    .unwrap_or(false)
            })
            .collect()
    }

    // === TOOL 6: trace_call_chain ===
    /// Trace call chain from a function up to entry points
    pub fn trace_call_chain(&self, name: &str, depth: usize) -> Vec<Vec<String>> {
        let mut chains = Vec::new();
        self.trace_up(name, depth, vec![name.to_string()], &mut chains);
        chains
    }

    fn trace_up(&self, func: &str, remaining: usize, mut path: Vec<String>, chains: &mut Vec<Vec<String>>) {
        if remaining == 0 {
            chains.push(path);
            return;
        }
        let callers = self.get_callers(func);
        if callers.is_empty() {
            chains.push(path);
            return;
        }
        for caller in callers {
            let mut new_path = path.clone();
            new_path.push(caller.name.clone());
            self.trace_up(&caller.name, remaining - 1, new_path, chains);
        }
    }

    // === TOOL 7: verify_hypothesis ===
    /// Verify a hypothesis about a function
    pub fn verify_hypothesis(&self, func_name: &str, hypothesis: &str) -> bool {
        // Simple verification: check if evidence supports the hypothesis
        // TODO: implement more sophisticated verification
        match hypothesis {
            "window_class" => {
                // Verify: calls LoadString/LoadIcon/LoadCursor
                self.function_index.get(func_name)
                    .map(|f| f.api_calls.iter().any(|a| a.contains("Load")))
                    .unwrap_or(false)
            }
            "file_io" => {
                self.function_index.get(func_name)
                    .map(|f| f.api_calls.iter().any(|a|
                        a.contains("CreateFile") || a.contains("ReadFile") || a.contains("WriteFile")))
                    .unwrap_or(false)
            }
            "device_io" => {
                self.function_index.get(func_name)
                    .map(|f| f.api_calls.iter().any(|a| a.contains("DeviceIoControl")))
                    .unwrap_or(false)
            }
            "ui_handler" => {
                self.function_index.get(func_name)
                    .map(|f| f.api_calls.iter().any(|a| a.contains("SendMessage") || a.contains("MessageBox")))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// Record investigation for memory
    pub fn record_investigation(&mut self, query: &str, tools: Vec<String>, result: &str, confidence: &str) {
        self.investigation_memory.push(InvestigationRecord {
            query: query.to_string(),
            tool_calls: tools,
            result_summary: result.to_string(),
            confidence: confidence.to_string(),
        });
    }

    /// Get investigation memory
    pub fn get_investigation_memory(&self) -> &[InvestigationRecord] {
        &self.investigation_memory
    }

    /// Get all functions summary
    pub fn all_functions_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("Total functions: {}\n", self.function_index.len()));
        summary.push_str("\nTop 10 largest:\n");
        let mut funcs: Vec<_> = self.function_index.values().collect();
        funcs.sort_by(|a, b| b.line_count.cmp(&a.line_count));
        for f in funcs.iter().take(10) {
            summary.push_str(&format!(
                "  {} ({} lines, APIs: {})\n",
                f.name, f.line_count, f.api_calls.join(", ")
            ));
        }
        summary
    }
}

fn extract_fn_name(line: &str) -> Option<String> {
    if line.contains("static uint32_t fn_") {
        let start = line.find("fn_")?;
        let rest = &line[start..];
        let end = rest.find('(')?;
        Some(rest[..end].to_string())
    } else {
        None
    }
}

fn extract_apis(body: &str) -> Vec<String> {
    let apis = ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "DeviceIoControl",
        "LoadStringA", "LoadIconA", "LoadCursorA", "SendMessageA", "SetWindowTextA",
        "CreateServiceA", "OpenServiceA", "StartServiceA", "ControlService",
        "DeleteService", "CloseServiceHandle", "MessageBoxA", "Shell_NotifyIconA",
        "SetFilePointer", "FlushFileBuffers", "FindWindowA", "EnterCriticalSection",
        "LeaveCriticalSection", "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree"];
    let mut found = Vec::new();
    for api in &apis {
        if body.contains(api) {
            found.push(api.to_string());
        }
    }
    found
}

fn extract_fn_calls(body: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut search = body;
    while let Some(idx) = search.find("fn_") {
        let rest = &search[idx..];
        if let Some(end) = rest.find('(') {
            let name = &rest[..end];
            if name.starts_with("fn_") && !calls.contains(&name.to_string()) {
                calls.push(name.to_string());
            }
        }
        search = &search[idx + 3..];
    }
    calls
}

fn parse_addr(name: &str) -> u64 {
    let hex = &name[3..];
    u64::from_str_radix(hex, 16).unwrap_or(0)
}
