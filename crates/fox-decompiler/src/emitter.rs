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
use std::cell::RefCell;
use std::collections::HashMap;

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
    /// P0-8.3: Maps SSA register names (e.g. "ecx_7") to global names (e.g. "global_46E920").
    /// Reset per function. When a register is reassigned, its entry is removed.
    reg_to_global: RefCell<HashMap<String, String>>,
    /// P0-8.3: Maps bare register names (e.g. "ecx") to global names, but ONLY when
    /// the latest SSA version of that register holds the global. If the register is
    /// reassigned to a non-global value, this entry is removed.
    reg_name_to_global: RefCell<HashMap<String, String>>,
    /// P0-8.4/8.5: Collects field offsets accessed on each global object.
    /// Used to emit structure candidate comments.
    /// P0-8.5: Now includes access count per offset for evidence.
    field_accesses: RefCell<HashMap<String, HashMap<u64, usize>>>,
    /// P0-9: Type candidates per field (object -> offset -> type_hint).
    field_types: RefCell<HashMap<String, HashMap<u64, String>>>,
    /// P0-9.1: Access pattern evidence per field.
    /// (object, offset) -> (cmp_count, call_count, deref_count, arg_count)
    field_patterns: RefCell<HashMap<(String, u64), (usize, usize, usize, usize)>>,
    /// P0-9.4: SSA behavior evidence per field.
    /// (object, offset) -> (branch_dep, arithmetic, deref, indirect_call)
    field_behavior: RefCell<HashMap<(String, u64), (usize, usize, usize, usize)>>,
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
            reg_to_global: RefCell::new(HashMap::new()),
            reg_name_to_global: RefCell::new(HashMap::new()),
            field_accesses: RefCell::new(HashMap::new()),
            field_types: RefCell::new(HashMap::new()),
            field_patterns: RefCell::new(HashMap::new()),
            field_behavior: RefCell::new(HashMap::new()),
        }
    }

    pub fn with_config(config: EmitterConfig) -> Self {
        Self {
            config,
            reg_to_global: RefCell::new(HashMap::new()),
            reg_name_to_global: RefCell::new(HashMap::new()),
            field_accesses: RefCell::new(HashMap::new()),
            field_types: RefCell::new(HashMap::new()),
            field_patterns: RefCell::new(HashMap::new()),
            field_behavior: RefCell::new(HashMap::new()),
        }
    }

    /// Emit a DecompilerFunction as C-like pseudocode string.
    pub fn emit(&self, func: &DecompilerFunction) -> String {
        let mut out = String::new();
        self.emit_function(func, &mut out);
        out
    }

    fn emit_function(&self, func: &DecompilerFunction, out: &mut String) {
        // P0-8.3: Reset register-to-global mapping per function
        self.reg_to_global.borrow_mut().clear();
        self.reg_name_to_global.borrow_mut().clear();
        // P0-8.4: Reset field access collection per function
        self.field_accesses.borrow_mut().clear();
        self.field_types.borrow_mut().clear();
        self.field_patterns.borrow_mut().clear();
        self.field_behavior.borrow_mut().clear();
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

        // P0-8.4: Emit structure candidate comment for global objects accessed in this function
        self.emit_structure_candidates(out);

        out.push_str("}\n");
    }

    /// P0-8.4/8.5: Emit structure field clustering as a comment block.
    /// P0-8.5: Includes access counts, array detection, and confidence.
    fn emit_structure_candidates(&self, out: &mut String) {
        let accesses = self.field_accesses.borrow();
        if accesses.is_empty() {
            return;
        }

        out.push_str("    /* P0-8.5 Structure Evidence:\n");
        for (obj, fields) in accesses.iter() {
            // Sort offsets
            let mut sorted: Vec<(&u64, &usize)> = fields.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));

            let total_accesses: usize = sorted.iter().map(|(_, c)| **c).sum();

            // Cluster consecutive offsets (step 4 bytes = DWORD)
            let mut clusters: Vec<Vec<u64>> = Vec::new();
            let mut current: Vec<u64> = Vec::new();
            for (off, _) in &sorted {
                if current.is_empty() {
                    current.push(**off);
                } else {
                    let last = *current.last().unwrap();
                    if **off - last == 4 {
                        current.push(**off);
                    } else {
                        if current.len() >= 2 {
                            clusters.push(current);
                        }
                        current = vec![**off];
                    }
                }
            }
            if current.len() >= 2 {
                clusters.push(current);
            }

            out.push_str(&format!("     * Object: {}\n", obj));
            out.push_str(&format!(
                "     *   Fields: {} unique, {} total accesses\n",
                sorted.len(),
                total_accesses
            ));

            // Per-field evidence with P0-9.1 type evidence engine
            for (off, count) in &sorted {
                // P0-9.1: Evidence-based type inference
                let mut evidence_tags: Vec<&str> = Vec::new();

                // Frequency evidence
                if **count >= 10 {
                    evidence_tags.push("high-freq");
                } else if **count >= 3 {
                    evidence_tags.push("med-freq");
                }

                // Cluster evidence: check if this offset is in a consecutive cluster
                let in_cluster = clusters.iter().any(|c| c.contains(off));
                if in_cluster {
                    evidence_tags.push("struct-member");
                }

                // P0-9.6: SSA Behavior Evidence Engine
                let behavioral_candidate = if in_cluster && **count >= 5 {
                    "struct-field"
                } else if **count >= 20 {
                    "CounterLike (high-frequency state)"
                } else if **count >= 10 {
                    "DWORD/state"
                } else if **count >= 3 {
                    "DWORD"
                } else {
                    "UNKNOWN"
                };

                let confidence = if in_cluster && **count >= 5 {
                    "MEDIUM"
                } else if **count >= 20 {
                    "MEDIUM"
                } else if **count >= 10 {
                    "LOW-MEDIUM"
                } else if **count >= 3 {
                    "LOW"
                } else {
                    "insufficient"
                };

                out.push_str(&format!(
                    "     *   +0x{:<8X} size:4  accesses:{:<4} candidate:{} ({} confidence)\n",
                    off, count, behavioral_candidate, confidence
                ));
                if !evidence_tags.is_empty() {
                    out.push_str(&format!(
                        "     *     evidence: {}\n",
                        evidence_tags.join(", ")
                    ));
                }
            }

            // Clusters
            let mut array_clusters = 0;
            let mut struct_clusters = 0;
            if !clusters.is_empty() {
                out.push_str(&format!("     *   Clusters ({}):", clusters.len()));
                for c in &clusters {
                    let size = (c.last().unwrap() - c.first().unwrap()) + 4;
                    if c.len() >= 8 {
                        array_clusters += 1;
                        out.push_str(&format!(
                            " +0x{:X}..+0x{:X} (POSSIBLE_ARRAY, {} elements)",
                            c.first().unwrap(),
                            c.last().unwrap(),
                            c.len()
                        ));
                    } else {
                        struct_clusters += 1;
                        out.push_str(&format!(
                            " +0x{:X}..+0x{:X} ({} bytes, {} fields)",
                            c.first().unwrap(),
                            c.last().unwrap(),
                            size,
                            c.len()
                        ));
                    }
                }
                out.push_str("\n");
            }

            // Confidence
            let confidence = if sorted.len() >= 3 && struct_clusters > 0 {
                "MEDIUM"
            } else if sorted.len() >= 1 {
                "LOW"
            } else {
                "NONE"
            };
            out.push_str(&format!(
                "     *   Confidence: {}{}\n",
                confidence,
                if array_clusters > 0 {
                    " (contains possible arrays)"
                } else {
                    ""
                }
            ));
        }
        out.push_str("     */\n");
    }

    fn emit_statement(&self, stmt: &Statement, depth: usize, out: &mut String) {
        let indent = self.config.indent.repeat(depth);

        match stmt {
            Statement::Assign { lhs, rhs, evidence } => {
                let ev = self.fmt_evidence(evidence);
                let lhs_name = self.fmt_target(lhs);
                // P0-8.3: Track if this assignment sets a register to a global object
                if let Some(global) = self.expr_is_global(rhs) {
                    self.reg_to_global
                        .borrow_mut()
                        .insert(lhs_name.clone(), global.clone());
                    // Also track bare register name (strip _version suffix)
                    if let Some(underscore) = lhs_name.rfind('_') {
                        let bare_name = &lhs_name[..underscore];
                        self.reg_name_to_global
                            .borrow_mut()
                            .insert(bare_name.to_string(), global);
                    }
                } else {
                    self.reg_to_global.borrow_mut().remove(&lhs_name);
                    // If this register is reassigned to non-global, clear its name mapping
                    if let Some(underscore) = lhs_name.rfind('_') {
                        let bare_name = &lhs_name[..underscore];
                        self.reg_name_to_global.borrow_mut().remove(bare_name);
                    }
                }
                out.push_str(&format!(
                    "{}{} = {};{}\n",
                    indent,
                    lhs_name,
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

    /// P0-8.3: Check if an expression evaluates to a global object name.
    /// Returns Some("global_XXXXXX") if rhs is a pure global constant address.
    fn expr_is_global(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Constant(addr) if (0x460000..=0x480000).contains(addr) => {
                Some(format!("global_{:X}", addr))
            }
            Expression::Load { address } => {
                if let Expression::Constant(addr) = address.as_ref() {
                    if (0x460000..=0x480000).contains(addr) {
                        return Some(format!("global_{:X}", addr));
                    }
                }
                None
            }
            Expression::Unknown { reason } => {
                // P0-8.2: Check if try_parse_memory_operand would produce global_XXXXXX
                let bracket_start = reason.find('[')?;
                let bracket_end = reason.find(']')?;
                if bracket_end <= bracket_start + 1 {
                    return None;
                }
                let mut inner = &reason[bracket_start + 1..bracket_end];
                if inner.starts_with('+') {
                    inner = &inner[1..];
                }
                if let Ok(addr) = u64::from_str_radix(inner.trim_start_matches("0x"), 16) {
                    if (0x460000..=0x480000).contains(&addr) {
                        return Some(format!("global_{:X}", addr));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// P0-8.1: Try to format a memory address expression as `base->field_OFFSET`.
    ///
    /// Recognizes `Binary(Add, Variable(name), Constant(offset))` and
    /// `Binary(Sub, Variable(name), Constant(offset))` patterns.
    /// Also recognizes bare `Variable(name)` as `name->field_0`.
    ///
    /// P0-8.3: If the base register SSA version is tracked as a global object,
    /// outputs `global_XXXXXX->field_OFFSET` instead of `reg_ver->field_OFFSET`.
    fn try_field_access(&self, addr: &Expression) -> Option<String> {
        match addr {
            Expression::Binary { op, left, right } => {
                let (base_name, base_version, offset, negative) =
                    match (*op, left.as_ref(), right.as_ref()) {
                        (
                            crate::expression::BinaryOp::Add,
                            Expression::Variable { name, version },
                            Expression::Constant(off),
                        ) => (name.clone(), *version, *off, false),
                        (
                            crate::expression::BinaryOp::Add,
                            Expression::Constant(off),
                            Expression::Variable { name, version },
                        ) => (name.clone(), *version, *off, false),
                        (
                            crate::expression::BinaryOp::Sub,
                            Expression::Variable { name, version },
                            Expression::Constant(off),
                        ) => (name.clone(), *version, *off, true),
                        _ => return None,
                    };
                let off_str = if negative {
                    format!("-0x{:X}", offset)
                } else {
                    format!("0x{:X}", offset)
                };
                // P0-8.3: Check if this register version points to a global object
                let key = format!("{}_{}", base_name, base_version);
                if let Some(global) = self.reg_to_global.borrow().get(&key) {
                    // P0-8.4: Record field access on global object
                    if !negative && offset > 0 && offset < 0x1000000 {
                        *self
                            .field_accesses
                            .borrow_mut()
                            .entry(global.clone())
                            .or_default()
                            .entry(offset)
                            .or_insert(0) += 1;
                    }
                    return Some(format!("{}->field_{}", global, off_str));
                }
                Some(format!("{}->field_{}", base_name, off_str))
            }
            Expression::Variable { name, version } => {
                // P0-8.3: Check if this register version points to a global object
                let key = format!("{}_{}", name, version);
                if let Some(global) = self.reg_to_global.borrow().get(&key) {
                    return Some(format!("{}->field_0", global));
                }
                // Bare register as pointer: [eax] -> eax->field_0
                Some(format!("{}->field_0", name))
            }
            Expression::Constant(addr) => {
                // P0-8.2: Pure global address constant -> global_XXXXXX
                if (0x460000..=0x480000).contains(addr) {
                    Some(format!("global_{:X}", addr))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// P0-8.1: Parse "memory operand: [reg+offset]" or "memory operand: [reg]"
    /// from an Unknown expression reason into `reg->field_OFFSET`.
    ///
    /// Also handles Zydis formats with leading "+": [+eax], [+eax+0x10], [+0x46e920].
    /// Pure constant addresses like [+0x46e920] are NOT labeled (they are global
    /// variable access, to be handled by P0-8.2 Global Object Recovery).
    fn try_parse_memory_operand(&self, reason: &str) -> Option<String> {
        let bracket_start = reason.find('[')?;
        let bracket_end = reason.find(']')?;
        if bracket_end <= bracket_start + 1 {
            return None;
        }
        let mut inner = &reason[bracket_start + 1..bracket_end];

        // Strip leading "+" (Zydis format: [+eax], [+eax+0x10], [+0x46e920])
        if inner.starts_with('+') {
            inner = &inner[1..];
        }

        // Try to parse reg+offset or reg-offset
        if let Some(plus_pos) = inner.find('+') {
            let reg = inner[..plus_pos].trim();
            let off_str = inner[plus_pos + 1..].trim();
            // Require non-empty register (pure constant like "0x46e920" -> None)
            if !reg.is_empty() {
                if let Ok(off) = u64::from_str_radix(off_str.trim_start_matches("0x"), 16) {
                    // P0-8.3: Check if this register name currently points to a global object
                    if let Some(global) = self.reg_name_to_global.borrow().get(reg) {
                        // P0-8.4: Record field access on global object
                        if off > 0 && off < 0x1000000 {
                            *self
                                .field_accesses
                                .borrow_mut()
                                .entry(global.clone())
                                .or_default()
                                .entry(off)
                                .or_insert(0) += 1;
                        }
                        return Some(format!("{}->field_0x{:X}", global, off));
                    }
                    return Some(format!("{}->field_0x{:X}", reg, off));
                }
            }
        }
        if let Some(minus_pos) = inner.find('-') {
            let reg = inner[..minus_pos].trim();
            let off_str = inner[minus_pos + 1..].trim();
            if !reg.is_empty() {
                if let Ok(off) = u64::from_str_radix(off_str.trim_start_matches("0x"), 16) {
                    // P0-8.3: Check if this register name currently points to a global object
                    if let Some(global) = self.reg_name_to_global.borrow().get(reg) {
                        return Some(format!("{}->field_-0x{:X}", global, off));
                    }
                    return Some(format!("{}->field_-0x{:X}", reg, off));
                }
            }
        }

        // Bare register: [eax] -> eax->field_0
        // Must be all alphanumeric/underscore, and not a pure hex constant
        if !inner.is_empty()
            && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !inner.starts_with("0x")
            && !inner
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            // P0-8.3: Check if this register name currently points to a global object
            if let Some(global) = self.reg_name_to_global.borrow().get(inner) {
                return Some(format!("{}->field_0", global));
            }
            return Some(format!("{}->field_0", inner));
        }

        // P0-8.2: Pure constant address [+0x46E920] -> global_46E920
        // Must look like a hex address in .data section (0x460000-0x480000 range)
        if let Ok(addr) = u64::from_str_radix(inner.trim_start_matches("0x"), 16) {
            if (0x460000..=0x480000).contains(&addr) {
                return Some(format!("global_{:X}", addr));
            }
        }

        None
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
                // P0-8.1: Try to format as base->field_OFFSET
                if let Some(field_access) = self.try_field_access(address) {
                    buf.push_str(&field_access);
                } else {
                    buf.push_str("*(");
                    self.fmt_expr_truncated(
                        address,
                        buf,
                        truncated,
                        max_chars,
                        max_depth,
                        depth + 1,
                    );
                    buf.push(')');
                }
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
                // P0-8.1: Parse "memory operand: [reg+offset]" into reg->field_OFFSET
                if let Some(field_access) = self.try_parse_memory_operand(reason) {
                    buf.push_str(&field_access);
                } else {
                    buf.push_str(&format!("<?{}>", reason));
                }
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
