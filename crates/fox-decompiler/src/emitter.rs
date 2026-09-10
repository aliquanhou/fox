//! P0-6.6B: C-like Emitter
//!
//! Converts Structured IR (DecompilerFunction -> Vec<Statement>) into
//! human-readable C-like pseudocode.
//!
//! This is NOT a C compiler. It does NOT recover types, variables, or
//! arguments. It emits honest pseudocode with UNKNOWN/goto where evidence
//! is insufficient.
//!
//! Key principles:
//! - Unknown is preserved (goto or comment), never fabricated
//! - Evidence is traceable (annotated mode shows @address)
//! - No type/variable/argument recovery
//! - No fixing P0-6.6A nesting gap (flat if/else is OK for now)

use crate::condition::ConditionRecovery;
use crate::expression::CallTarget;
use crate::structured_ir::{AssignTarget, DecompilerFunction, Statement, StatementEvidence};

/// Emitter configuration.
#[derive(Debug, Clone)]
pub struct EmitterConfig {
    /// Show evidence annotations (/* @0x401234 */) after each statement.
    pub annotate_evidence: bool,
    /// Show SSA phi assignments (usually elided in clean output).
    pub show_phi: bool,
    /// Indentation string.
    pub indent: String,
    /// Show function header comment with metadata.
    pub show_header: bool,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            annotate_evidence: true,
            show_phi: false,
            indent: "    ".to_string(),
            show_header: true,
        }
    }
}

impl EmitterConfig {
    /// Clean output: no evidence annotations, no phi.
    pub fn clean() -> Self {
        Self {
            annotate_evidence: false,
            show_phi: false,
            indent: "    ".to_string(),
            show_header: false,
        }
    }

    /// Annotated output: show evidence addresses.
    pub fn annotated() -> Self {
        Self {
            annotate_evidence: true,
            show_phi: false,
            indent: "    ".to_string(),
            show_header: true,
        }
    }
}

/// C-like pseudocode emitter.
pub struct CLikeEmitter {
    config: EmitterConfig,
}

impl Default for CLikeEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl CLikeEmitter {
    pub fn new() -> Self {
        Self {
            config: EmitterConfig::default(),
        }
    }

    pub fn with_config(config: EmitterConfig) -> Self {
        Self { config }
    }

    /// Emit a DecompilerFunction as C-like pseudocode string.
    pub fn emit(&self, func: &DecompilerFunction) -> String {
        let mut out = String::new();
        self.emit_function(func, &mut out);
        out
    }

    fn emit_function(&self, func: &DecompilerFunction, out: &mut String) {
        if self.config.show_header {
            let name = func.name.as_deref().unwrap_or("unknown");
            out.push_str(&format!("// Function @ 0x{:X} ({})\n", func.address, name));
            out.push_str(&format!(
                "// SSA instrs: {}, CFG blocks: {}, CS: {}, Unknown: {}, Budget: {}\n",
                func.evidence.ssa_instructions,
                func.evidence.cfg_blocks,
                func.evidence.control_structures,
                func.evidence.unknown_statements,
                if func.evidence.budget_exhausted {
                    "EXHAUSTED"
                } else {
                    "ok"
                }
            ));
        }

        out.push_str(&format!("void func_{:X}() {{\n", func.address));

        for stmt in &func.statements {
            self.emit_statement(stmt, 1, out);
        }

        out.push_str("}\n");
    }

    fn emit_statement(&self, stmt: &Statement, depth: usize, out: &mut String) {
        let indent = self.config.indent.repeat(depth);

        match stmt {
            Statement::Assign { lhs, rhs, evidence } => {
                let ev = self.fmt_evidence(evidence);
                out.push_str(&format!(
                    "{}{} = {};{}\n",
                    indent,
                    self.fmt_target(lhs),
                    rhs,
                    ev
                ));
            }

            Statement::If {
                condition,
                then_body,
                else_body,
                evidence,
                ..
            } => {
                let ev = self.fmt_evidence(evidence);
                out.push_str(&format!(
                    "{}if ({}) {{{}\n",
                    indent,
                    self.fmt_condition(condition),
                    ev
                ));

                for s in then_body {
                    self.emit_statement(s, depth + 1, out);
                }

                if !else_body.is_empty() {
                    out.push_str(&format!("{}}} else {{\n", indent));
                    for s in else_body {
                        self.emit_statement(s, depth + 1, out);
                    }
                }

                out.push_str(&format!("{}}}\n", indent));
            }

            Statement::GuardClause {
                condition,
                body,
                return_value,
                evidence,
            } => {
                let ev = self.fmt_evidence(evidence);
                out.push_str(&format!(
                    "{}if ({}) {{{}\n",
                    indent,
                    self.fmt_condition(condition),
                    ev
                ));

                for s in body {
                    self.emit_statement(s, depth + 1, out);
                }

                let inner_indent = self.config.indent.repeat(depth + 1);
                if let Some(val) = return_value {
                    out.push_str(&format!("{}return {};\n", inner_indent, val));
                } else {
                    out.push_str(&format!("{}return;\n", inner_indent));
                }

                out.push_str(&format!("{}}}\n", indent));
            }

            Statement::Return { value, evidence } => {
                let ev = self.fmt_evidence(evidence);
                if let Some(val) = value {
                    out.push_str(&format!("{}return {};{}\n", indent, val, ev));
                } else {
                    out.push_str(&format!("{}return;{}\n", indent, ev));
                }
            }

            Statement::CallStmt {
                target,
                arguments_unresolved,
                evidence,
            } => {
                let ev = self.fmt_evidence(evidence);
                let args = if *arguments_unresolved {
                    "/* arguments unresolved */"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "{}{}({});{}\n",
                    indent,
                    self.fmt_call_target(target),
                    args,
                    ev
                ));
            }

            Statement::Unknown {
                reason,
                goto_target,
                evidence,
                ..
            } => {
                let ev = self.fmt_evidence(evidence);
                if let Some(addr) = goto_target {
                    out.push_str(&format!(
                        "{}/* UNKNOWN: {} */ goto loc_{:X};{}\n",
                        indent, reason, addr, ev
                    ));
                } else {
                    out.push_str(&format!("{}/* UNKNOWN: {} */{}\n", indent, reason, ev));
                }
            }

            Statement::PhiAssign {
                lhs,
                incoming,
                evidence,
            } => {
                if !self.config.show_phi {
                    return; // elide phi in clean output
                }
                let ev = self.fmt_evidence(evidence);
                let inc: Vec<String> = incoming
                    .iter()
                    .map(|p| format!("{}@blk{}", p.value, p.block_id))
                    .collect();
                out.push_str(&format!(
                    "{}{} = phi({}); /* SSA phi */{}\n",
                    indent,
                    self.fmt_target(lhs),
                    inc.join(", "),
                    ev
                ));
            }
        }
    }

    fn fmt_target(&self, t: &AssignTarget) -> String {
        match t {
            AssignTarget::Variable { name, version, .. } => {
                format!("{}_{}", name, version)
            }
            AssignTarget::Memory { address } => format!("*({})", address),
            AssignTarget::Unknown => "/* unknown */".to_string(),
        }
    }

    fn fmt_call_target(&self, t: &CallTarget) -> String {
        match t {
            CallTarget::Address(addr) => format!("call_{:X}", addr),
            CallTarget::Symbol(name) => name.clone(),
            CallTarget::Unknown => "call_unknown".to_string(),
        }
    }

    fn fmt_condition(&self, c: &ConditionRecovery) -> String {
        match c {
            ConditionRecovery::Resolved(cond) => format!("{}", cond),
            ConditionRecovery::ProducerNotCmpTest { producer_op, .. } => {
                format!("/* condition from {} (not CMP/TEST) */", producer_op)
            }
            ConditionRecovery::ProducerNotFound { .. } => {
                "/* condition: FLAGS producer not found */".to_string()
            }
            ConditionRecovery::NotConditionalJump => "/* not a conditional jump */".to_string(),
        }
    }

    fn fmt_evidence(&self, ev: &StatementEvidence) -> String {
        if !self.config.annotate_evidence {
            return String::new();
        }
        if ev.instruction_addresses.is_empty() {
            return String::new();
        }
        let addrs: Vec<String> = ev
            .instruction_addresses
            .iter()
            .map(|a| format!("0x{:X}", a))
            .collect();
        format!(" /* @{} */", addrs.join(", "))
    }
}

/// Convenience: emit a function with default (annotated) config.
pub fn emit_c_like(func: &DecompilerFunction) -> String {
    CLikeEmitter::new().emit(func)
}

/// Convenience: emit a function with clean config (no annotations).
pub fn emit_c_like_clean(func: &DecompilerFunction) -> String {
    CLikeEmitter::with_config(EmitterConfig::clean()).emit(func)
}
