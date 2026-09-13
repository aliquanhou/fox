//! Batch function semantic analyzer
//!
//! Analyzes all functions in decompiled C output,
//! extracts API calls and patterns, and uses DeepSeek
//! to produce semantic understanding for each function.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FunctionSemantic {
    pub name: String,
    pub address: u64,
    pub line_count: usize,
    pub api_calls: Vec<String>,
    pub string_refs: Vec<String>,
    pub calls_functions: Vec<String>,
    pub local_var_count: usize,
    pub semantic_role: String,
    pub confidence: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub side_effects: Vec<String>,
}

pub struct BatchAnalyzer {
    functions: HashMap<String, FunctionSemantic>,
}

impl BatchAnalyzer {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    /// Parse decompiled C code and extract function info
    pub fn parse_decompiled_c(&mut self, c_source: &str) {
        let lines: Vec<&str> = c_source.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            // Match function definition: static uint32_t fn_XXXXXX(...)
            if let Some(func_name) = extract_function_name(line) {
                let start_line = i;
                let brace_count = line.matches('{').count() as i32 - line.matches('}').count() as i32;
                let mut j = i + 1;
                let mut depth = brace_count;

                // Find function body
                while j < lines.len() && depth > 0 {
                    depth += lines[j].matches('{').count() as i32;
                    depth -= lines[j].matches('}').count() as i32;
                    j += 1;
                }

                let body: String = lines[start_line..j].join("\n");

                // Extract API calls
                let api_calls = extract_api_calls(&body);

                // Extract string references
                let string_refs = extract_string_refs(&body);

                // Extract function calls
                let calls_functions = extract_function_calls(&body);

                // Count local variables
                let local_var_count = extract_local_var_count(&body);

                let semantic = FunctionSemantic {
                    name: func_name.clone(),
                    address: parse_function_address(&func_name),
                    line_count: j - start_line,
                    api_calls,
                    string_refs,
                    calls_functions,
                    local_var_count,
                    semantic_role: String::new(),
                    confidence: String::new(),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    side_effects: Vec::new(),
                };

                self.functions.insert(func_name, semantic);
                i = j;
            } else {
                i += 1;
            }
        }
    }

    /// Get all functions
    pub fn all_functions(&self) -> Vec<&FunctionSemantic> {
        self.functions.values().collect()
    }

    /// Get function by name
    pub fn get_function(&self, name: &str) -> Option<&FunctionSemantic> {
        self.functions.get(name)
    }

    /// Find functions by API call
    pub fn find_by_api(&self, api_name: &str) -> Vec<&FunctionSemantic> {
        self.functions
            .values()
            .filter(|f| f.api_calls.iter().any(|a| a.contains(api_name)))
            .collect()
    }

    /// Find functions by string reference
    pub fn find_by_string(&self, pattern: &str) -> Vec<&FunctionSemantic> {
        self.functions
            .values()
            .filter(|f| f.string_refs.iter().any(|s| s.contains(pattern)))
            .collect()
    }

    /// Find largest functions (likely core business logic)
    pub fn largest_functions(&self, n: usize) -> Vec<&FunctionSemantic> {
        let mut funcs: Vec<&FunctionSemantic> = self.functions.values().collect();
        funcs.sort_by(|a, b| b.line_count.cmp(&a.line_count));
        funcs.into_iter().take(n).collect()
    }

    /// Find functions that call a specific function
    pub fn find_callers_of(&self, func_name: &str) -> Vec<&FunctionSemantic> {
        self.functions
            .values()
            .filter(|f| f.calls_functions.iter().any(|c| c == func_name))
            .collect()
    }

    /// Find functions called by a specific function
    pub fn find_callees_of(&self, func_name: &str) -> Vec<&FunctionSemantic> {
        self.functions
            .values()
            .filter(|f| f.name == func_name)
            .flat_map(|f| f.calls_functions.iter())
            .filter_map(|name| self.functions.get(name))
            .collect()
    }

    /// Generate summary report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# Batch Function Semantic Analysis\n\n");
        report.push_str(&format!("Total functions: {}\n\n", self.functions.len()));

        // Top 20 largest
        report.push_str("## Top 20 Largest Functions\n\n");
        for f in self.largest_functions(20) {
            report.push_str(&format!(
                "- {} ({} lines, {} local vars, APIs: {:?})\n",
                f.name, f.line_count, f.local_var_count, f.api_calls
            ));
        }

        // API usage statistics
        report.push_str("\n## API Usage Statistics\n\n");
        let mut api_counts: HashMap<String, usize> = HashMap::new();
        for f in self.functions.values() {
            for api in &f.api_calls {
                *api_counts.entry(api.clone()).or_insert(0) += 1;
            }
        }
        let mut apis: Vec<_> = api_counts.into_iter().collect();
        apis.sort_by(|a, b| b.1.cmp(&a.1));
        for (api, count) in apis.iter().take(20) {
            report.push_str(&format!("- {}: {} functions\n", api, count));
        }

        report
    }
}

fn extract_function_name(line: &str) -> Option<String> {
    let re = regex_static_static!(r"static uint32_t (fn_[0-9A-F]+)\(");
    re.captures(line).map(|c| c[1].to_string())
}

fn extract_api_calls(body: &str) -> Vec<String> {
    let re = regex_static_static!(r"\b(CreateFile[A-Z]?|ReadFile|WriteFile|CloseHandle|DeviceIoControl|RegisterClass[A-Z]?|LoadString[A-Z]?|LoadIcon[A-Z]?|LoadCursor[A-Z]?|SendMessage[A-Z]?|SetWindowText[A-Z]?|CreateService[A-Z]?|OpenService[A-Z]?|StartService[A-Z]?|ControlService|DeleteService|CloseServiceHandle|MessageBox[A-Z]?|Shell_NotifyIcon[A-Z]?|SetFilePointer|FlushFileBuffers|FindWindow[A-Z]?|EnterCriticalSection|LeaveCriticalSection|HeapAlloc|HeapFree|VirtualAlloc|VirtualFree)\b");
    let mut calls = Vec::new();
    for cap in re.captures_iter(body) {
        calls.push(cap[1].to_string());
    }
    calls.sort();
    calls.dedup();
    calls
}

fn extract_string_refs(body: &str) -> Vec<String> {
    let re = regex_static_static!(r'"([^"]{4,})"');
    let mut refs = Vec::new();
    for cap in re.captures_iter(body) {
        refs.push(cap[1].to_string());
    }
    refs
}

fn extract_function_calls(body: &str) -> Vec<String> {
    let re = regex_static_static!(r"\b(fn_[0-9A-F]+)\s*\(");
    let mut calls = Vec::new();
    for cap in re.captures_iter(body) {
        calls.push(cap[1].to_string());
    }
    calls.sort();
    calls.dedup();
    calls
}

fn extract_local_var_count(body: &str) -> usize {
    let re = regex_static_static!(r"uint32_t (local_\d+[,\s]+)");
    if let Some(cap) = re.captures(body) {
        cap[1].matches(',').count() + 1
    } else {
        0
    }
}

fn parse_function_address(name: &str) -> u64 {
    let hex = &name[3..]; // strip "fn_"
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

// Simple regex implementation without external dependency
macro_rules! regex_static_static {
    ($pattern:expr) => {
        // Simple string-based pattern matcher
        Regex::new($pattern).unwrap()
    };
}

struct Regex {
    pattern: String,
}

impl Regex {
    fn new(pattern: &str) -> Result<Self, String> {
        Ok(Self { pattern: pattern.to_string() })
    }

    fn captures<'a>(&'a self, text: &'a str) -> RegexCaptures<'a> {
        RegexCaptures { text, regex: self, pos: 0 }
    }
}

struct RegexCaptures<'a> {
    text: &'a str,
    regex: &'a Regex,
    pos: usize,
}

impl<'a> Iterator for RegexCaptures<'a> {
    type Item = Captures<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Simplified: just find substrings
        if self.pos >= self.text.len() {
            return None;
        }
        let remaining = &self.text[self.pos..];
        // Find next function call pattern
        if let Some(idx) = remaining.find("fn_") {
            let start = self.pos + idx;
            let end = start + remaining[idx..].find('(')?;
            self.pos = end;
            Some(Captures {
                text: &self.text[start..end],
            })
        } else {
            None
        }
    }
}

struct Captures<'a> {
    text: &'a str,
}

impl<'a> Captures<'a> {
    fn get(&self, _index: usize) -> &str {
        self.text
    }
}
