//! FOX Tool Calling Engine
//!
//! DeepSeek ↔ FOX Tools ↔ Evidence loop

use crate::fox_tools::{FoxTools, ToolCall, ToolResult};
use std::collections::HashMap;

/// Evidence ID generator
pub struct EvidenceIdGen {
    counter: u32,
}

impl EvidenceIdGen {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn next(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("E-{}-{:04}", prefix, self.counter)
    }
}

/// Tool Dispatcher
pub struct ToolDispatcher {
    tools: FoxTools,
    evidence_gen: EvidenceIdGen,
}

impl ToolDispatcher {
    pub fn new(tools: FoxTools) -> Self {
        Self {
            tools,
            evidence_gen: EvidenceIdGen::new(),
        }
    }

    pub fn dispatch(&mut self, call: &ToolCall) -> ToolResult {
        let mut evidence_ids = Vec::new();

        let data = match call.tool_name.as_str() {
            "get_function" => {
                let name = call.arguments.get("name").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("FUNC");
                evidence_ids.push(eid);
                match self.tools.get_function(&name) {
                    Some(info) => format!(
                        "Function {}: addr=0x{:x}, lines={}, apis={:?}, calls={:?}",
                        info.name, info.address, info.line_count, info.api_calls, info.calls
                    ),
                    None => format!("Function {} not found", name),
                }
            }
            "get_function_evidence" => {
                let name = call.arguments.get("name").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("BODY");
                evidence_ids.push(eid);
                match self.tools.get_function_evidence(&name) {
                    Some(body) => format!("Function body ({} chars):\n{}", body.len(),
                        &body[..body.len().min(2000)]),
                    None => format!("Function {} not found", name),
                }
            }
            "get_callers" => {
                let name = call.arguments.get("name").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("CALLERS");
                evidence_ids.push(eid);
                let callers = self.tools.get_callers(&name);
                format!("Callers of {}: {} functions\n{}",
                    name, callers.len(),
                    callers.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(", "))
            }
            "get_callees" => {
                let name = call.arguments.get("name").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("CALLEES");
                evidence_ids.push(eid);
                let callees = self.tools.get_callees(&name);
                format!("Callees of {}: {} functions\n{}",
                    name, callees.len(),
                    callees.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(", "))
            }
            "find_string_refs" => {
                let pattern = call.arguments.get("pattern").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("XREF");
                evidence_ids.push(eid);
                let refs = self.tools.find_string_refs(&pattern);
                format!("Functions referencing '{}': {} functions\n{}",
                    pattern, refs.len(),
                    refs.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(", "))
            }
            "trace_call_chain" => {
                let name = call.arguments.get("name").cloned().unwrap_or_default();
                let depth: usize = call.arguments.get("depth")
                    .and_then(|d| d.parse().ok()).unwrap_or(3);
                let eid = self.evidence_gen.next("TRACE");
                evidence_ids.push(eid);
                let chains = self.tools.trace_call_chain(&name, depth);
                format!("Call chains from {}: {} chains\n{}",
                    name, chains.len(),
                    chains.iter().map(|c| c.join(" → ")).collect::<Vec<_>>().join("\n"))
            }
            "verify_hypothesis" => {
                let func = call.arguments.get("function").cloned().unwrap_or_default();
                let hyp = call.arguments.get("hypothesis").cloned().unwrap_or_default();
                let eid = self.evidence_gen.next("VERIFY");
                evidence_ids.push(eid);
                let result = self.tools.verify_hypothesis(&func, &hyp);
                format!("Verification of '{}' for {}: {}",
                    hyp, func,
                    if result { "SUPPORTED" } else { "NOT_SUPPORTED" })
            }
            _ => format!("Unknown tool: {}", call.tool_name),
        };

        ToolResult {
            call_id: call.call_id.clone(),
            tool_name: call.tool_name.clone(),
            success: true,
            data,
            evidence_ids,
        }
    }

    pub fn tools(&self) -> &FoxTools { &self.tools }
    pub fn tools_mut(&mut self) -> &mut FoxTools { &mut self.tools }
}

/// Investigation result
#[derive(Debug, Clone)]
pub struct InvestigationResult {
    pub conclusion: String,
    pub confidence: String,
    pub evidence_ids: Vec<String>,
    pub tool_calls_made: Vec<String>,
    pub iterations: usize,
}

/// LLM chat function type
pub type ChatFn = fn(&[HashMap<String, String>]) -> Result<String, String>;

/// Autonomous Investigation Loop
pub struct InvestigationLoop {
    dispatcher: ToolDispatcher,
    chat_fn: ChatFn,
    max_iterations: usize,
}

impl InvestigationLoop {
    pub fn new(dispatcher: ToolDispatcher, chat_fn: ChatFn) -> Self {
        Self {
            dispatcher,
            chat_fn,
            max_iterations: 10,
        }
    }

    pub fn investigate(&mut self, question: &str) -> InvestigationResult {
        let mut messages: Vec<HashMap<String, String>> = vec![
            HashMap::from([
                ("role".to_string(), "system".to_string()),
                ("content".to_string(), SYSTEM_PROMPT.to_string()),
            ]),
            HashMap::from([
                ("role".to_string(), "user".to_string()),
                ("content".to_string(), question.to_string()),
            ]),
        ];

        let mut tool_calls_made = Vec::new();
        let mut all_evidence = Vec::new();

        for iteration in 0..self.max_iterations {
            println!("Investigation iteration {}/{}", iteration + 1, self.max_iterations);

            let response = match (self.chat_fn)(&messages) {
                Ok(r) => r,
                Err(e) => {
                    return InvestigationResult {
                        conclusion: format!("LLM error: {}", e),
                        confidence: "error".to_string(),
                        evidence_ids: all_evidence,
                        tool_calls_made,
                        iterations: iteration,
                    };
                }
            };

            if let Some(tool_calls) = parse_tool_calls(&response) {
                for tc in tool_calls {
                    println!("  Tool call: {} args={:?}", tc.tool_name, tc.arguments);
                    tool_calls_made.push(format!("{}({:?})", tc.tool_name, tc.arguments));
                    let result = self.dispatcher.dispatch(&tc);
                    all_evidence.extend(result.evidence_ids);
                    messages.push(HashMap::from([
                        ("role".to_string(), "assistant".to_string()),
                        ("content".to_string(), format!("Called {}", tc.tool_name)),
                    ]));
                    messages.push(HashMap::from([
                        ("role".to_string(), "tool".to_string()),
                        ("content".to_string(), result.data),
                    ]));
                }
            } else {
                return InvestigationResult {
                    conclusion: response,
                    confidence: "medium".to_string(),
                    evidence_ids: all_evidence,
                    tool_calls_made,
                    iterations: iteration,
                };
            }
        }

        InvestigationResult {
            conclusion: "Max iterations reached".to_string(),
            confidence: "low".to_string(),
            evidence_ids: all_evidence,
            tool_calls_made,
            iterations: self.max_iterations,
        }
    }
}

const SYSTEM_PROMPT: &str = r#"You are FOX Semantic Analyst, investigating a binary reverse engineering task.

Available tools:
- get_function: {"name": "fn_XXXXXX"}
- get_function_evidence: {"name": "fn_XXXXXX"}
- get_callers: {"name": "fn_XXXXXX"}
- get_callees: {"name": "fn_XXXXXX"}
- find_string_refs: {"pattern": "string"}
- trace_call_chain: {"name": "fn_XXXXXX", "depth": 3}
- verify_hypothesis: {"function": "fn_XXXXXX", "hypothesis": "window_class|file_io|device_io|ui_handler"}

To call a tool, respond with JSON:
{"tool_calls": [{"name": "tool_name", "arguments": {"key": "value"}}]}

When you have enough evidence, respond with analysis as plain text,
classifying findings as FACT, HYPOTHESIS, or UNKNOWN.

Rules:
- Every claim must reference evidence
- If evidence is insufficient, say UNKNOWN
- Do not guess"#;

fn parse_tool_calls(response: &str) -> Option<Vec<ToolCall>> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
        if let Some(tool_calls) = json.get("tool_calls") {
            if let Some(arr) = tool_calls.as_array() {
                let mut calls = Vec::new();
                for (i, tc) in arr.iter().enumerate() {
                    let name = tc.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let args: HashMap<String, String> = tc.get("arguments")
                        .and_then(|a| a.as_object())
                        .map(|obj| obj.iter().map(|(k, v)| (k.clone(),
                            v.as_str().unwrap_or("").to_string())).collect())
                        .unwrap_or_default();
                    calls.push(ToolCall {
                        tool_name: name,
                        arguments: args,
                        call_id: format!("call_{}", i),
                    });
                }
                return Some(calls);
            }
        }
    }
    None
}
