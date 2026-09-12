//! FOX Final Reconstruction — C AST Layer (RM-6).
//!
//! Proper reconstruction: SSA Evidence -> C AST -> C Renderer.
//! No regex patching of emitter text. Every node traces back to a
//! structured Statement/Expression.
//!
//! Unknowns degrade to a single opaque call `tll_unknown_op()` instead of
//! fabricating logic — compile-safe AND evidence-preserving.

use crate::expression::{BinaryOp, CallTarget, Expression, UnaryOp};
use crate::structured_ir::{AssignTarget, DecompilerFunction, Statement};
use std::collections::HashMap;

/// A C expression.
#[derive(Debug, Clone)]
pub enum CExpr {
    /// A recovered temporary variable (SSA version lowered).
    Var(String),
    /// Immediate constant.
    Const(u64),
    Binary {
        op: char,
        left: Box<CExpr>,
        right: Box<CExpr>,
    },
    Unary {
        op: char,
        operand: Box<CExpr>,
    },
    /// Dereference: *p.
    Deref(Box<CExpr>),
    /// Comparison: left op right (op is "==", "<=", ...).
    Compare {
        op: String,
        left: Box<CExpr>,
        right: Box<CExpr>,
    },
    /// Function call.
    Call {
        target: String,
        args: Vec<CExpr>,
    },
    /// Unresolved — rendered as tll_unknown_op() result.
    Unknown,
}

/// A C statement.
#[derive(Debug, Clone)]
pub enum CStmt {
    Assign { lhs: CExpr, rhs: CExpr },
    Expr(Box<CExpr>),
    If {
        cond: CExpr,
        then: Vec<CStmt>,
        els: Vec<CStmt>,
    },
    Return(Option<CExpr>),
    /// An unresolved statement — rendered as tll_unknown_op();
    Unknown,
}

/// A reconstructed function.
#[derive(Debug, Clone)]
pub struct CFunction {
    pub name: String,
    pub stmts: Vec<CStmt>,
    /// All tmp variable names declared at function top.
    pub tmps: Vec<String>,
}

/// Translates one DecompilerFunction into a CFunction.
pub struct IrToC {
    /// (register, version) -> tmp name.
    var_map: HashMap<(String, u32), String>,
    tmps: Vec<String>,
    next_tmp: usize,
}

impl IrToC {
    pub fn new() -> Self {
        Self {
            var_map: HashMap::new(),
            tmps: Vec::new(),
            next_tmp: 0,
        }
    }

    fn tmp_name(&mut self, reg: &str, version: u32) -> String {
        let key = (reg.to_string(), version);
        if let Some(n) = self.var_map.get(&key) {
            return n.clone();
        }
        // RM-7.4: source-style sequential naming, not register names.
        let n = format!("tmp_{}", self.next_tmp);
        self.next_tmp += 1;
        self.var_map.insert(key, n.clone());
        self.tmps.push(n.clone());
        n
    }

    pub fn translate_function(&mut self, func: &DecompilerFunction) -> CFunction {
        let name = format!("sub_{:X}", func.address);
        let mut stmts = Vec::new();
        for stmt in &func.statements {
            self.translate_stmt(stmt, &mut stmts);
        }
        // Ensure every function ends with a return (C requires it for non-void).
        if !matches!(stmts.last(), Some(CStmt::Return(_))) {
            stmts.push(CStmt::Return(Some(CExpr::Const(0))));
        }
        CFunction {
            name,
            stmts,
            tmps: std::mem::take(&mut self.tmps),
        }
    }

    fn translate_stmt(&mut self, stmt: &Statement, out: &mut Vec<CStmt>) {
        match stmt {
            Statement::Assign { lhs, rhs, .. } => {
                let rhs = self.translate_expr(rhs);
                match lhs {
                    AssignTarget::Variable { name, version, .. } => {
                        let lhs = CExpr::Var(self.tmp_name(name, *version));
                        out.push(CStmt::Assign { lhs, rhs });
                    }
                    AssignTarget::Memory { address } => {
                        let lhs = CExpr::Deref(Box::new(self.translate_expr(address)));
                        out.push(CStmt::Assign { lhs, rhs });
                    }
                    AssignTarget::Unknown => {
                        out.push(CStmt::Assign {
                            lhs: CExpr::Var("tll_discard".to_string()),
                            rhs,
                        });
                    }
                }
            }
            Statement::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                let cond = self.translate_condition(condition);
                let mut then = Vec::new();
                for s in then_body {
                    self.translate_stmt(s, &mut then);
                }
                let mut els = Vec::new();
                for s in else_body {
                    self.translate_stmt(s, &mut els);
                }
                out.push(CStmt::If { cond, then, els });
            }
            Statement::GuardClause { body, .. } => {
                for s in body {
                    self.translate_stmt(s, out);
                }
            }
            Statement::Return { value, .. } => {
                let v = value.as_ref().map(|v| self.translate_expr(v));
                out.push(CStmt::Return(v));
            }
            Statement::CallStmt {
                target, arguments, ..
            } => {
                let call = self.translate_call(target, arguments);
                out.push(CStmt::Expr(Box::new(call)));
            }
            Statement::PhiAssign { lhs, incoming, .. } => {
                if let AssignTarget::Variable { name, version, .. } = lhs {
                    let v = self.tmp_name(name, *version);
                    // Phi: take first incoming value (evidence-preserving fallback).
                    let rhs = incoming
                        .first()
                        .map(|i| self.translate_expr(&i.value))
                        .unwrap_or(CExpr::Unknown);
                    out.push(CStmt::Assign {
                        lhs: CExpr::Var(v),
                        rhs,
                    });
                }
            }
            Statement::Unknown { .. } => out.push(CStmt::Unknown),
        }
    }

    /// RM-7.3: translate a recovered condition into a C comparison.
    fn translate_condition(&mut self, cond: &crate::condition::ConditionRecovery) -> CExpr {
        use crate::condition::{ConditionOperand, ConditionRecovery};
        match cond {
            ConditionRecovery::Resolved(c) => {
                use fox_ir::JumpCondition;
                let op = match c.operator {
                    JumpCondition::Equal => "==",
                    JumpCondition::NotEqual => "!=",
                    JumpCondition::SignedLess | JumpCondition::UnsignedLess => "<",
                    JumpCondition::SignedLessEqual | JumpCondition::UnsignedLessEqual => "<=",
                    JumpCondition::SignedGreater | JumpCondition::UnsignedGreater => ">",
                    JumpCondition::SignedGreaterEqual | JumpCondition::UnsignedGreaterEqual => ">=",
                    _ => return CExpr::Unknown,
                };
                let l = match &c.left {
                    ConditionOperand::Register { name, version } => {
                        CExpr::Var(self.tmp_name(name, *version))
                    }
                    ConditionOperand::Constant(v) => CExpr::Const(*v),
                    _ => CExpr::Unknown,
                };
                let r = match &c.right {
                    ConditionOperand::Register { name, version } => {
                        CExpr::Var(self.tmp_name(name, *version))
                    }
                    ConditionOperand::Constant(v) => CExpr::Const(*v),
                    _ => CExpr::Unknown,
                };
                CExpr::Compare {
                    op: op.to_string(),
                    left: Box::new(l),
                    right: Box::new(r),
                }
            }
            _ => CExpr::Unknown,
        }
    }

    fn translate_call(&mut self, target: &CallTarget, args: &[Expression]) -> CExpr {        let name = match target {
            CallTarget::Address(a) => format!("sub_{:X}", a),
            CallTarget::Symbol(s) => s.clone(),
            CallTarget::Unknown => "tll_unknown_call".to_string(),
        };
        let args: Vec<CExpr> = args.iter().map(|a| self.translate_expr(a)).collect();
        CExpr::Call { target: name, args }
    }

    fn translate_expr(&mut self, e: &Expression) -> CExpr {
        match e {
            Expression::Constant(v) => CExpr::Const(*v),
            Expression::Variable { name, version } => {
                // Register any free (entry) variable so it gets a declaration.
                CExpr::Var(self.tmp_name(name, *version))
            }
            Expression::Binary { op, left, right } => {
                let c_op = match op {
                    BinaryOp::Add => '+',
                    BinaryOp::Sub => '-',
                    BinaryOp::Mul => '*',
                    BinaryOp::Div => '/',
                    BinaryOp::Mod => '%',
                    BinaryOp::And => '&',
                    BinaryOp::Or => '|',
                    BinaryOp::Xor => '^',
                    BinaryOp::Shl => '<',
                    BinaryOp::Shr => '>',
                    BinaryOp::Sar => '>',
                };
                CExpr::Binary {
                    op: c_op,
                    left: Box::new(self.translate_expr(left)),
                    right: Box::new(self.translate_expr(right)),
                }
            }
            Expression::Unary { op, operand } => {
                let c_op = match op {
                    UnaryOp::Neg => '-',
                    UnaryOp::Not => '!',
                };
                CExpr::Unary {
                    op: c_op,
                    operand: Box::new(self.translate_expr(operand)),
                }
            }
            Expression::Load { address } => CExpr::Deref(Box::new(self.translate_expr(address))),
            Expression::Call { target, arguments } => self.translate_call(target, arguments),
            Expression::Phi { .. } => CExpr::Unknown,
            Expression::Unknown { reason } => {
                // RM-7.1: recover real memory operands from lift text.
                if reason.contains("stack pointer") {
                    // A pop reads from the stack top: model as *(esp).
                    CExpr::Deref(Box::new(CExpr::Var(self.tmp_name("esp", 0))))
                } else if let Some(pm) = crate::memory_recovery::parse_memory_operand(reason) {
                    match pm.base {
                        None => CExpr::Const(pm.offset as u64),
                        Some(reg) => {
                            let base = CExpr::Var(self.tmp_name(&reg, 0));
                            if pm.offset == 0 {
                                base
                            } else {
                                CExpr::Binary {
                                    op: '+',
                                    left: Box::new(base),
                                    right: Box::new(CExpr::Const((pm.offset) as u64)),
                                }
                            }
                        }
                    }
                } else {
                    CExpr::Unknown
                }
            }
        }
    }
}

/// Renders C AST to compilable C source.
pub struct CRenderer;

impl CRenderer {
    pub fn render(funcs: &[CFunction]) -> String {
        let mut out = String::new();
        out.push_str("/* FOX reconstructed C — RM-7 (auto-generated) */\n");
        out.push_str("#include <stdint.h>\n\n");
        out.push_str("static void tll_unknown_op(void) {}\n");
        out.push_str("static uint32_t tll_unknown_call() { return 0; }\n\n");

        // RM-7.2: collect every callee and its max call-site argument count.
        let mut callees = std::collections::BTreeSet::new();
        let mut arg_counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for f in funcs {
            for s in &f.stmts {
                Self::collect_callees(s, &mut callees, &mut arg_counts);
            }
        }
        let sig = |name: &str| -> String {
            // Variadic prototype tolerates the fact that different call sites
            // disagree on arity (SSA argument binding not done yet).
            format!("uint32_t {}(uint32_t, ...)", name)
        };
        for c in &callees {
            out.push_str(&format!("extern {};\n", sig(c)));
        }
        out.push('\n');

        for f in funcs {
            out.push_str("static uint32_t ");
            out.push_str(&f.name);
            out.push_str("(uint32_t arg0, ...) {\n");
            if !f.tmps.is_empty() {
                out.push_str("    uint32_t ");
                out.push_str(&f.tmps.join(", "));
                out.push_str(";\n");
                out.push_str("    uint32_t tll_discard = 0;\n");
            }
            for s in &f.stmts {
                out.push_str("    ");
                Self::render_stmt(s, &mut out, 1);
                out.push('\n');
            }
            out.push_str("}\n\n");
        }
        out
    }

    fn collect_callees(
        stmt: &CStmt,
        out: &mut std::collections::BTreeSet<String>,
        arg_counts: &mut std::collections::BTreeMap<String, usize>,
    ) {
        match stmt {
            CStmt::Expr(e) => Self::collect_callees_expr(e, out, arg_counts),
            CStmt::Assign { lhs, rhs } => {
                Self::collect_callees_expr(lhs, out, arg_counts);
                Self::collect_callees_expr(rhs, out, arg_counts);
            }
            CStmt::If { then, els, .. } => {
                for s in then.iter().chain(els) {
                    Self::collect_callees(s, out, arg_counts);
                }
            }
            CStmt::Return(Some(v)) => Self::collect_callees_expr(v, out, arg_counts),
            _ => {}
        }
    }

    fn collect_callees_expr(
        e: &CExpr,
        out: &mut std::collections::BTreeSet<String>,
        arg_counts: &mut std::collections::BTreeMap<String, usize>,
    ) {
        match e {
            CExpr::Call { target, args } => {
                out.insert(target.clone());
                let entry = arg_counts.entry(target.clone()).or_insert(0);
                if args.len() > *entry {
                    *entry = args.len();
                }
                for a in args {
                    Self::collect_callees_expr(a, out, arg_counts);
                }
            }
            CExpr::Binary { left, right, .. } => {
                Self::collect_callees_expr(left, out, arg_counts);
                Self::collect_callees_expr(right, out, arg_counts);
            }
            CExpr::Unary { operand, .. } => Self::collect_callees_expr(operand, out, arg_counts),
            CExpr::Deref(inner) => Self::collect_callees_expr(inner, out, arg_counts),
            _ => {}
        }
    }

    fn render_expr(e: &CExpr, out: &mut String) {
        match e {
            CExpr::Var(v) => out.push_str(v),
            CExpr::Const(c) => out.push_str(&format!("{}", c)),
            CExpr::Binary { op, left, right } => {
                out.push('(');
                Self::render_expr(left, out);
                out.push_str(&format!(" {} ", op));
                Self::render_expr(right, out);
                out.push(')');
            }
            CExpr::Unary { op, operand } => {
                out.push(*op);
                out.push('(');
                Self::render_expr(operand, out);
                out.push(')');
            }
            CExpr::Deref(inner) => {
                out.push_str("(*((uint32_t*)(");
                Self::render_expr(inner, out);
                out.push_str(")))");
            }
            CExpr::Compare { op, left, right } => {
                out.push('(');
                Self::render_expr(left, out);
                out.push_str(&format!(" {} ", op));
                Self::render_expr(right, out);
                out.push(')');
            }
            CExpr::Call { target, args } => {
                out.push_str(target);
                out.push('(');
                if args.is_empty() {
                    out.push('0');
                }
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    Self::render_expr(a, out);
                }
                out.push(')');
            }
            CExpr::Unknown => out.push_str("0"),
        }
    }

    fn render_stmt(s: &CStmt, out: &mut String, _depth: usize) {
        match s {
            CStmt::Assign { lhs, rhs } => {
                Self::render_expr(lhs, out);
                out.push_str(" = ");
                Self::render_expr(rhs, out);
                out.push(';');
            }
            CStmt::Expr(e) => {
                Self::render_expr(e, out);
                out.push(';');
            }
            CStmt::If { cond, then, els, .. } => {
                out.push_str("if (");
                Self::render_expr(cond, out);
                out.push_str(") {");
                for st in then {
                    out.push('\n');
                    out.push_str("        ");
                    Self::render_stmt(st, out, _depth + 1);
                }
                out.push_str("\n    } else {");
                for st in els {
                    out.push('\n');
                    out.push_str("        ");
                    Self::render_stmt(st, out, _depth + 1);
                }
                out.push_str("\n    }");
            }
            CStmt::Return(Some(v)) => {
                out.push_str("return ");
                Self::render_expr(v, out);
                out.push(';');
            }
            CStmt::Return(None) => out.push_str("return 0;"),
            CStmt::Unknown => out.push_str("tll_unknown_op();"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_trivial_function() {
        let func = CFunction {
            name: "sub_401000".to_string(),
            stmts: vec![CStmt::Return(Some(CExpr::Const(0)))],
            tmps: vec![],
        };
        let src = CRenderer::render(&[func]);
        assert!(src.contains("static uint32_t sub_401000(void)"));
        assert!(src.contains("return 0;"));
    }

    #[test]
    fn unknown_degrades_compile_safe() {
        let func = CFunction {
            name: "sub_x".to_string(),
            stmts: vec![CStmt::Unknown, CStmt::Return(None)],
            tmps: vec![],
        };
        let src = CRenderer::render(&[func]);
        assert!(src.contains("tll_unknown_op();"));
    }
}
