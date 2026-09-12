//! P0-14: Variable Recovery Engine (Evidence Layer).
//!
//! Groups SSA values (register.name.version) into logical *variable candidates*.
//! One logical variable = all SSA versions of the same register name within a
//! function (the SSA renaming already split reads/writes into versions; this
//! collapses them back to a "this is one C-like variable" fact).
//!
//! Naming discipline: we emit `variable-candidate` / register name; NEVER
//! `int x`, `count`, `player_name`. No guesses about variable purpose.

use crate::expression::Expression;
use crate::structured_ir::{AssignTarget, DecompilerFunction, Statement};
use std::collections::BTreeMap;

/// One recovered logical variable (a register's SSA versions coalesced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Stable ordinal within the function (variable_0, variable_1, ...).
    pub index: usize,
    /// Register name this variable lives in (e.g. "eax").
    pub register: String,
    /// SSA versions defined for this register in the function.
    pub def_versions: Vec<u32>,
    /// Whether this variable has a phi merge.
    pub has_phi: bool,
    /// Whether this variable has memory (stack) assignments.
    pub has_memory_store: bool,
}

impl Variable {
    pub fn version_count(&self) -> usize {
        self.def_versions.len()
    }

    /// Evidence label: always "variable-candidate", never a guessed name.
    pub fn kind_label(&self) -> &'static str {
        "variable-candidate"
    }
}

/// Map: function address -> its recovered variables, ordered by first appearance.
#[derive(Default, Clone)]
pub struct VariableMap {
    per_function: BTreeMap<u64, Vec<Variable>>,
}

impl VariableMap {
    pub fn new() -> Self {
        Self {
            per_function: BTreeMap::new(),
        }
    }

    pub fn variables_of_function(&self, function: u64) -> &[Variable] {
        self.per_function
            .get(&function)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Find the variable for a register name inside a function.
    pub fn variable_of_register(&self, function: u64, register: &str) -> Option<&Variable> {
        self.per_function
            .get(&function)?
            .iter()
            .find(|v| v.register == register)
    }

    pub fn len(&self) -> usize {
        self.per_function.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.per_function.is_empty()
    }

    /// How many functions have at least one recovered variable.
    pub fn function_count(&self) -> usize {
        self.per_function.len()
    }
}

/// Builds the VariableMap by walking each function's structured statements.
pub struct VariableRecoveryBuilder;

/// Internal per-function accumulator.
struct FuncAcc {
    /// register name -> ordered versions defined
    defs: BTreeMap<String, Vec<u32>>,
    phi: Vec<String>,
    mem: Vec<String>,
}

impl FuncAcc {
    fn new() -> Self {
        Self {
            defs: BTreeMap::new(),
            phi: Vec::new(),
            mem: Vec::new(),
        }
    }

    fn add_def(&mut self, name: &str, version: u32) {
        let e = self.defs.entry(name.to_string()).or_default();
        if !e.contains(&version) {
            e.push(version);
        }
    }

    fn add_phi(&mut self, name: &str) {
        if !self.phi.contains(&name.to_string()) {
            self.phi.push(name.to_string());
        }
    }

    fn add_memory(&mut self, name: &str) {
        if !self.mem.contains(&name.to_string()) {
            self.mem.push(name.to_string());
        }
    }
}

impl VariableRecoveryBuilder {
    /// Build from all decompiled functions. Pure read; no IR/SSA mutation.
    pub fn build(funcs: &[&DecompilerFunction]) -> VariableMap {
        let mut map = VariableMap::new();
        for func in funcs {
            let mut acc = FuncAcc::new();
            for stmt in &func.statements {
                Self::walk_stmt(stmt, &mut acc);
            }
            if acc.defs.is_empty() {
                continue; // leaf / no recovered values: stay silent
            }
            let mut vars = Vec::new();
            for (register, mut versions) in acc.defs {
                versions.sort_unstable();
                vars.push(Variable {
                    index: vars.len(),
                    has_phi: acc.phi.contains(&register),
                    has_memory_store: acc.mem.contains(&register),
                    register,
                    def_versions: versions,
                });
            }
            map.per_function.insert(func.address, vars);
        }
        map
    }

    fn walk_stmt(stmt: &Statement, acc: &mut FuncAcc) {
        match stmt {
            Statement::Assign { lhs, rhs, .. } => {
                Self::record_lhs(lhs, acc);
                Self::walk_expr(rhs, acc);
            }
            Statement::PhiAssign { lhs, incoming, .. } => {
                if let AssignTarget::Variable { name, version, .. } = lhs {
                    acc.add_def(name, *version);
                    acc.add_phi(name);
                }
                for inc in incoming {
                    Self::walk_expr(&inc.value, acc);
                }
            }
            Statement::Return { value, .. } => {
                if let Some(v) = value {
                    Self::walk_expr(v, acc);
                }
            }
            Statement::CallStmt { arguments, .. } => {
                for a in arguments {
                    Self::walk_expr(a, acc);
                }
            }
            Statement::If {
                then_body,
                else_body,
                ..
            } => {
                for s in then_body {
                    Self::walk_stmt(s, acc);
                }
                for s in else_body {
                    Self::walk_stmt(s, acc);
                }
            }
            Statement::GuardClause {
                body, return_value, ..
            } => {
                for s in body {
                    Self::walk_stmt(s, acc);
                }
                if let Some(v) = return_value {
                    Self::walk_expr(v, acc);
                }
            }
            Statement::Unknown { .. } => {}
        }
    }

    fn record_lhs(lhs: &AssignTarget, acc: &mut FuncAcc) {
        match lhs {
            AssignTarget::Variable { name, version, .. } => {
                acc.add_def(name, *version);
            }
            AssignTarget::Memory { .. } => {
                // A memory/stack store: note it as a memory-assignment site.
                acc.add_memory("(stack)");
            }
            AssignTarget::Unknown => {}
        }
    }

    /// Walk an expression tree and collect variable *uses* as defs too (so a
    /// register that is only used-but-never-defined-in-structured-IR still shows up).
    fn walk_expr(expr: &Expression, acc: &mut FuncAcc) {
        match expr {
            Expression::Variable { name, version } => {
                // A use of a value. We record it so the variable appears even if
                // its definition lived in an un-lifted place; versions are the
                // truth, grouped by register name.
                acc.add_def(name, *version);
            }
            Expression::Binary { left, right, .. } => {
                Self::walk_expr(left, acc);
                Self::walk_expr(right, acc);
            }
            Expression::Unary { operand, .. } => Self::walk_expr(operand, acc),
            Expression::Load { address } => Self::walk_expr(address, acc),
            Expression::Call { arguments, .. } => {
                for a in arguments {
                    Self::walk_expr(a, acc);
                }
            }
            Expression::Phi { incoming } => {
                for inc in incoming {
                    Self::walk_expr(&inc.value, acc);
                }
            }
            Expression::Constant(_) | Expression::Unknown { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expression::{BinaryOp, Expression};
    use crate::structured_ir::{
        AssignTarget, DecompilerFunction, FunctionEvidence, Statement, StatementEvidence,
        VariableOrigin,
    };

    fn ev() -> StatementEvidence {
        StatementEvidence {
            instruction_addresses: vec![],
            block_ids: vec![],
            reason: String::new(),
        }
    }

    fn stmt_assign(name: &str, version: u32, rhs: Expression) -> Statement {
        Statement::Assign {
            lhs: AssignTarget::Variable {
                name: name.to_string(),
                version,
                origin: VariableOrigin::SSAPlaceholder,
            },
            rhs,
            evidence: ev(),
        }
    }

    fn func_with(statements: Vec<Statement>) -> DecompilerFunction {
        DecompilerFunction {
            address: 0x5000,
            name: None,
            statements,
            evidence: FunctionEvidence {
                ssa_instructions: 0,
                cfg_blocks: 0,
                control_structures: 0,
                unknown_statements: 0,
                budget_exhausted: false,
            },
        }
    }

    #[test]
    fn test_same_register_chain_becomes_one_variable() {
        // eax.1 = const; eax.2 = eax.1 + 1  -> one variable "eax"
        let stmts = vec![
            stmt_assign("eax", 1, Expression::Constant(100)),
            stmt_assign(
                "eax",
                2,
                Expression::Binary {
                    op: BinaryOp::Add,
                    left: Box::new(Expression::Variable {
                        name: "eax".to_string(),
                        version: 1,
                    }),
                    right: Box::new(Expression::Constant(1)),
                },
            ),
        ];
        let map = VariableRecoveryBuilder::build(&[&func_with(stmts)]);
        let vars = map.variables_of_function(0x5000);
        assert_eq!(vars.len(), 1, "same register coalesces to one variable");
        assert_eq!(vars[0].register, "eax");
        assert_eq!(vars[0].def_versions, vec![1, 2]);
    }

    #[test]
    fn test_phi_marks_variable() {
        let phi = Statement::PhiAssign {
            lhs: AssignTarget::Variable {
                name: "eax".to_string(),
                version: 3,
                origin: VariableOrigin::SSAPlaceholder,
            },
            incoming: vec![],
            evidence: ev(),
        };
        let map = VariableRecoveryBuilder::build(&[&func_with(vec![phi])]);
        let vars = map.variables_of_function(0x5000);
        assert_eq!(vars.len(), 1);
        assert!(vars[0].has_phi, "phi should be marked");
    }

    #[test]
    fn test_two_registers_two_variables() {
        let stmts = vec![
            stmt_assign("eax", 1, Expression::Constant(1)),
            stmt_assign("ebx", 1, Expression::Constant(2)),
        ];
        let map = VariableRecoveryBuilder::build(&[&func_with(stmts)]);
        assert_eq!(map.variables_of_function(0x5000).len(), 2);
        assert!(map.variable_of_register(0x5000, "ebx").is_some());
    }

    #[test]
    fn test_memory_store_is_stack_candidate() {
        let stmts = vec![Statement::Assign {
            lhs: AssignTarget::Memory {
                address: Box::new(Expression::Constant(0x100)),
            },
            rhs: Expression::Constant(0),
            evidence: ev(),
        }];
        // Memory target produces a memory-store site but no register variable.
        // The register side remains empty; memory is tracked separately.
        let func = func_with(stmts);
        let map = VariableRecoveryBuilder::build(&[&func]);
        // No register defs -> function stays silent (fail-closed).
        assert_eq!(map.variables_of_function(0x5000).len(), 0);
    }

    #[test]
    fn test_leaf_function_has_no_variables_block() {
        // A function with no structured statements yields nothing.
        let func = func_with(vec![]);
        let map = VariableRecoveryBuilder::build(&[&func]);
        assert!(map.variables_of_function(0x5000).is_empty());
    }
}
