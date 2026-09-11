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
use crate::expression::{CallTarget, Expression};
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
    /// Maximum characters per expression before truncation (P0-6.9).
    pub max_expression_chars: usize,
    /// Maximum recursion depth for expression formatting (P0-6.9).
    pub max_expression_depth: usize,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            annotate_evidence: true,
            show_phi: false,
            indent: "    ".to_string(),
            show_header: true,
            max_expression_chars: 400,
            max_expression_depth: 8,
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
            max_expression_chars: 400,
            max_expression_depth: 8,
        }
    }

    /// Annotated output: show evidence addresses.
    pub fn annotated() -> Self {
        Self {
            annotate_evidence: true,
            show_phi: false,
            indent: "    ".to_string(),
            show_header: true,
            max_expression_chars: 400,
            max_expression_depth: 8,
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
                    self.format_expr(rhs),
                    ev
                ));
            }

            Statement::If {
                condition,
                then_body,
                else_body,
                lifted_call,
                evidence,
                ..
            } => {
                let ev = self.fmt_evidence(evidence);
                let cond_str = if let Some(lc) = lifted_call {
                    self.fmt_lifted_condition(condition, lc)
                } else {
                    self.fmt_condition(condition)
                };
                out.push_str(&format!("{}if ({}) {{{}\n", indent, cond_str, ev));

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
                lifted_call,
                evidence,
            } => {
                let ev = self.fmt_evidence(evidence);
                let cond_str = if let Some(lc) = lifted_call {
                    self.fmt_lifted_condition(condition, lc)
                } else {
                    self.fmt_condition(condition)
                };
                out.push_str(&format!("{}if ({}) {{{}\n", indent, cond_str, ev));

                for s in body {
                    self.emit_statement(s, depth + 1, out);
                }

                let inner_indent = self.config.indent.repeat(depth + 1);
                if let Some(val) = return_value {
                    out.push_str(&format!(
                        "{}return {};\n",
                        inner_indent,
                        self.format_expr(val)
                    ));
                } else {
                    out.push_str(&format!("{}return;\n", inner_indent));
                }

                out.push_str(&format!("{}}}\n", indent));
            }

            Statement::Return { value, evidence } => {
                let ev = self.fmt_evidence(evidence);
                if let Some(val) = value {
                    out.push_str(&format!(
                        "{}return {};{}\n",
                        indent,
                        self.format_expr(val),
                        ev
                    ));
                } else {
                    out.push_str(&format!("{}return;{}\n", indent, ev));
                }
            }

            Statement::CallStmt {
                target,
                arguments,
                arguments_complete,
                behavior,
                evidence,
            } => {
                let ev = self.fmt_evidence(evidence);
                let args_str: Vec<String> = arguments.iter().map(|a| self.format_expr(a)).collect();
                let args_display = if arguments.is_empty() {
                    if *arguments_complete {
                        "".to_string()
                    } else {
                        "/* arguments unresolved */".to_string()
                    }
                } else if *arguments_complete {
                    args_str.join(", ")
                } else {
                    format!("{}, ...", args_str.join(", "))
                };
                let behavior_comment = match behavior {
                    Some(crate::structured_ir::CallBehavior::ReturnUsedInCondition { .. }) => {
                        " /* return used in condition */"
                    }
                    Some(crate::structured_ir::CallBehavior::ReturnUsedByInstruction {
                        consumer_op,
                        ..
                    }) => &format!(" /* return consumed by {} */", consumer_op),
                    Some(crate::structured_ir::CallBehavior::NoConsumer) => " /* return unused */",
                    None => "",
                };
                out.push_str(&format!(
                    "{}{}({});{}{}\n",
                    indent,
                    self.fmt_call_target(target),
                    args_display,
                    behavior_comment,
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
                    .map(|p| format!("{}@blk{}", self.format_expr(&p.value), p.block_id))
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
            AssignTarget::Memory { address } => format!("*({})", self.format_expr(address)),
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

    /// P0-7.3: Format condition with lifted call expression.
    fn fmt_lifted_condition(
        &self,
        c: &ConditionRecovery,
        lc: &crate::structured_ir::LiftedCall,
    ) -> String {
        let call_str = {
            let args: Vec<String> = lc.arguments.iter().map(|a| self.format_expr(a)).collect();
            let args_display = if args.is_empty() {
                "".to_string()
            } else {
                args.join(", ")
            };
            format!("{}({})", self.fmt_call_target(&lc.target), args_display)
        };

        match c {
            ConditionRecovery::Resolved(cond) => {
                let op_str = match cond.operator {
                    fox_ir::JumpCondition::Equal => "==",
                    fox_ir::JumpCondition::NotEqual => "!=",
                    fox_ir::JumpCondition::SignedLess => "<",
                    fox_ir::JumpCondition::SignedLessEqual => "<=",
                    fox_ir::JumpCondition::SignedGreater => ">",
                    fox_ir::JumpCondition::SignedGreaterEqual => ">=",
                    fox_ir::JumpCondition::UnsignedLess => "<",
                    fox_ir::JumpCondition::UnsignedLessEqual => "<=",
                    fox_ir::JumpCondition::UnsignedGreater => ">",
                    fox_ir::JumpCondition::UnsignedGreaterEqual => ">=",
                    _ => return self.fmt_condition(c),
                };
                if cond.is_test {
                    format!("{} {} 0", call_str, op_str)
                } else {
                    let right_str = match &cond.right {
                        crate::condition::ConditionOperand::Constant(v) => {
                            format!("0x{:X}", v)
                        }
                        crate::condition::ConditionOperand::Register { name, version } => {
                            format!("{}.v{}", name, version)
                        }
                        other => format!("{}", other),
                    };
                    format!("{} {} {}", call_str, op_str, right_str)
                }
            }
            _ => self.fmt_condition(c),
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

    // --- P0-6.9: Expression truncation to prevent output explosion ---

    /// Format an Expression with length/depth truncation.
    /// Prevents 100KB+ expressions from making output unreadable.
    fn format_expr(&self, expr: &Expression) -> String {
        let mut buf = String::new();
        let mut truncated = false;
        self.fmt_expr_truncated(
            expr,
            &mut buf,
            &mut truncated,
            self.config.max_expression_chars,
            self.config.max_expression_depth,
            0,
        );
        if truncated {
            format!("{} /* expr truncated */", buf)
        } else {
            buf
        }
    }

    fn fmt_expr_truncated(
        &self,
        expr: &Expression,
        buf: &mut String,
        truncated: &mut bool,
        max_chars: usize,
        max_depth: usize,
        depth: usize,
    ) {
        if *truncated {
            return;
        }
        if buf.len() >= max_chars {
            *truncated = true;
            return;
        }
        if depth >= max_depth {
            buf.push_str("...");
            *truncated = true;
            return;
        }

        match expr {
            Expression::Constant(v) => {
                buf.push_str(&v.to_string());
            }
            Expression::Variable { name, version } => {
                buf.push_str(&format!("{}_{}", name, version));
            }
            Expression::Binary { op, left, right } => {
                buf.push('(');
                self.fmt_expr_truncated(left, buf, truncated, max_chars, max_depth, depth + 1);
                buf.push_str(&format!(" {} ", op));
                self.fmt_expr_truncated(right, buf, truncated, max_chars, max_depth, depth + 1);
                buf.push(')');
            }
            Expression::Unary { op, operand } => {
                buf.push_str(&format!("{}(", op));
                self.fmt_expr_truncated(operand, buf, truncated, max_chars, max_depth, depth + 1);
                buf.push(')');
            }
            Expression::Load { address } => {
                buf.push_str("*(");
                self.fmt_expr_truncated(address, buf, truncated, max_chars, max_depth, depth + 1);
                buf.push(')');
            }
            Expression::Call { target, arguments } => {
                buf.push_str("call(");
                match target {
                    CallTarget::Address(a) => buf.push_str(&format!("0x{:x}", a)),
                    CallTarget::Symbol(s) => buf.push_str(s),
                    CallTarget::Unknown => buf.push('?'),
                }
                for (i, arg) in arguments.iter().take(4).enumerate() {
                    if i > 0 {
                        buf.push_str(", ");
                    }
                    self.fmt_expr_truncated(arg, buf, truncated, max_chars, max_depth, depth + 1);
                }
                if arguments.len() > 4 {
                    buf.push_str(&format!(", ...{} more", arguments.len() - 4));
                }
                buf.push(')');
            }
            Expression::Phi { incoming } => {
                // Phi is the #1 source of expression explosion.
                // Show at most 3 incoming, and don't recurse deeply into phi values.
                if incoming.len() > 3 {
                    buf.push_str(&format!("phi({}incoming:", incoming.len()));
                } else {
                    buf.push_str("phi(");
                }
                for (i, inc) in incoming.iter().take(3).enumerate() {
                    if i > 0 {
                        buf.push_str(", ");
                    }
                    buf.push_str(&format!("bb{}:", inc.block_id));
                    // Only shallow-format phi values (depth limit prevents recursion)
                    self.fmt_expr_truncated(
                        &inc.value,
                        buf,
                        truncated,
                        max_chars,
                        max_depth.min(2),
                        depth + 1,
                    );
                }
                if incoming.len() > 3 {
                    buf.push_str(&format!(", ...{} more", incoming.len() - 3));
                }
                buf.push(')');
            }
            Expression::Unknown { reason } => {
                buf.push_str(&format!("<?{}>", reason));
            }
        }
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
