//! P0-15: Struct / Object Recovery Engine.
//!
//! Promotes `*(global_base + offset)` memory accesses into:
//!
//! ```text
//! ObjectCandidate {
//!     base: global_46E920,
//!     fields: [ field_0 @0x10, field_1 @0x14, ... ]
//! }
//! ```
//!
//! Principles (Evidence-First, fail-closed):
//! - A global object is recognized ONLY from a pure constant address in the
//!   loader range, or from a register that was assigned such a constant.
//! - A field is ONLY recorded when a `base + offset` access is observed on a
//!   known object base.
//! - Field names stay `field_N`; business names (`player.health`) are NEVER invented.
//! - Type integration is via `FieldTypeFact` (P0-13); absent facts -> no type.

use crate::expression::{BinaryOp, Expression};
use crate::structured_ir::{AssignTarget, DecompilerFunction, Statement};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Loader data range that FOX treats as writable global objects (matches P0-8.2).
const GLOBAL_BASE_MIN: u64 = 0x460000;
const GLOBAL_BASE_MAX: u64 = 0x480000;
/// Max positive offset before we stop treating it as a struct field.
const MAX_FIELD_OFFSET: u64 = 0x1_000_000;

/// One recovered field inside an object.
#[derive(Debug, Clone)]
pub struct FieldCandidate {
    /// Byte offset from the object base.
    pub offset: u64,
    /// How many times this field was accessed.
    pub accesses: usize,
    /// Optional type label from P0-13 (None when no evidence).
    pub type_label: Option<String>,
    /// Which functions touch this field.
    pub touched_by: BTreeSet<u64>,
}

/// One recovered object (global base + its fields).
#[derive(Debug, Clone)]
pub struct ObjectCandidate {
    /// Ordinal id, `object_N`.
    pub id: usize,
    /// Numeric base address.
    pub base: u64,
    /// Pretty name, `global_46E920`.
    pub name: String,
    /// Offsets -> fields, sorted.
    pub fields: BTreeMap<u64, FieldCandidate>,
    /// Functions that touch this object at all.
    pub functions: BTreeSet<u64>,
}

/// The recovered object map, consumed read-only by the emitter.
#[derive(Debug, Clone, Default)]
pub struct ObjectMap {
    objects: Vec<ObjectCandidate>,
    by_base: HashMap<u64, usize>,
}

impl ObjectMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn objects(&self) -> &[ObjectCandidate] {
        &self.objects
    }

    pub fn object_of_address(&self, base: u64) -> Option<&ObjectCandidate> {
        self.by_base.get(&base).map(|&i| &self.objects[i])
    }

    pub fn fields_of_object(&self, base: u64) -> Option<&BTreeMap<u64, FieldCandidate>> {
        self.object_of_address(base).map(|o| &o.fields)
    }

    pub fn field_at_offset(&self, base: u64, offset: u64) -> Option<&FieldCandidate> {
        self.fields_of_object(base)?.get(&offset)
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn total_fields(&self) -> usize {
        self.objects.iter().map(|o| o.fields.len()).sum()
    }
}

/// Accumulator used while walking one function.
struct FuncScan {
    /// `reg_version` -> global base it currently points to (P0-8.3 style).
    reg_to_base: HashMap<String, u64>,
    /// (object base, offset) -> access count, aggregated across functions.
    access: HashMap<(u64, u64), usize>,
    /// (object base) -> functions touching it.
    obj_funcs: HashMap<u64, BTreeSet<u64>>,
    /// (object base, offset) -> functions touching the field.
    field_funcs: HashMap<(u64, u64), BTreeSet<u64>>,
    /// Pure global constants that stand alone as objects.
    pure_globals: BTreeSet<u64>,
}

impl FuncScan {
    fn new() -> Self {
        Self {
            reg_to_base: HashMap::new(),
            access: HashMap::new(),
            obj_funcs: HashMap::new(),
            field_funcs: HashMap::new(),
            pure_globals: BTreeSet::new(),
        }
    }

    fn record(&mut self, obj: u64, offset: u64, func: u64) {
        if offset >= MAX_FIELD_OFFSET {
            return;
        }
        *self.access.entry((obj, offset)).or_insert(0) += 1;
        self.obj_funcs.entry(obj).or_default().insert(func);
        self.field_funcs
            .entry((obj, offset))
            .or_default()
            .insert(func);
    }

    /// If `e` is `base_reg + offset` / `offset + base_reg` / `base_reg - offset`
    /// and `base_reg` points to a global, record a field access.
    fn consider(&mut self, e: &Expression, func: u64) {
        match e {
            Expression::Binary { op, left, right } => {
                let (name, version, off, neg) = match (*op, left.as_ref(), right.as_ref()) {
                    (
                        BinaryOp::Add,
                        Expression::Variable { name, version },
                        Expression::Constant(o),
                    ) => (name.clone(), *version, *o, false),
                    (
                        BinaryOp::Add,
                        Expression::Constant(o),
                        Expression::Variable { name, version },
                    ) => (name.clone(), *version, *o, false),
                    (
                        BinaryOp::Sub,
                        Expression::Variable { name, version },
                        Expression::Constant(o),
                    ) => (name.clone(), *version, *o, true),
                    _ => return,
                };
                let key = format!("{}_{}", name, version);
                if let Some(&base) = self.reg_to_base.get(&key) {
                    if !neg && off > 0 {
                        self.record(base, off, func);
                    }
                }
            }
            // A bare register that points to a global -> field_0.
            Expression::Variable { name, version } => {
                let key = format!("{}_{}", name, version);
                if let Some(&base) = self.reg_to_base.get(&key) {
                    self.record(base, 0, func);
                }
            }
            // Pure global constant address -> object itself.
            Expression::Constant(addr)
                if (GLOBAL_BASE_MIN..=GLOBAL_BASE_MAX).contains(addr) =>
            {
                self.pure_globals.insert(*addr);
            }
            _ => {}
        }
    }

    fn walk_expr(&mut self, e: &Expression, func: u64) {
        self.consider(e, func);
        match e {
            Expression::Binary { left, right, .. } => {
                self.walk_expr(left, func);
                self.walk_expr(right, func);
            }
            Expression::Unary { operand, .. } => self.walk_expr(operand, func),
            Expression::Load { address } => self.walk_expr(address, func),
            Expression::Call { arguments, .. } => {
                for a in arguments {
                    self.walk_expr(a, func);
                }
            }
            Expression::Phi { incoming } => {
                for inc in incoming {
                    self.walk_expr(&inc.value, func);
                }
            }
            Expression::Variable { .. } | Expression::Constant(_) | Expression::Unknown { .. } => {}
        }
    }

    #[allow(clippy::collapsible_match)] // inner guards also walk the rest of rhs/lhs
    fn walk_stmt(&mut self, stmt: &Statement, func: u64) {
        match stmt {
            Statement::Assign { lhs, rhs, .. } => {
                // P0-8.3: if rhs is a pure global constant, remember lhs reg points to it.
                if let Expression::Constant(addr) = rhs {
                    if (GLOBAL_BASE_MIN..=GLOBAL_BASE_MAX).contains(addr) {
                        if let AssignTarget::Variable { name, version, .. } = lhs {
                            self.reg_to_base
                                .insert(format!("{}_{}", name, version), *addr);
                        }
                    }
                }
                self.walk_expr(rhs, func);
                if let AssignTarget::Memory { address } = lhs {
                    self.consider(address, func);
                }
            }
            Statement::If {
                then_body,
                else_body,
                ..
            } => {
                // condition is ConditionRecovery; walk structured bodies.
                for s in then_body {
                    self.walk_stmt(s, func);
                }
                for s in else_body {
                    self.walk_stmt(s, func);
                }
            }
            Statement::GuardClause { body, .. } => {
                for s in body {
                    self.walk_stmt(s, func);
                }
            }
            Statement::Return { value, .. } => {
                if let Some(v) = value {
                    self.walk_expr(v, func);
                }
            }
            Statement::CallStmt { arguments, .. } => {
                for a in arguments {
                    self.walk_expr(a, func);
                }
            }
            Statement::PhiAssign {
                lhs:
                    AssignTarget::Variable { name, version, .. },
                incoming,
                ..
            } => {
                for inc in incoming {
                    self.walk_expr(&inc.value, func);
                }
                let key = format!("{}_{}", name, version);
                let _ = key;
            }
            Statement::PhiAssign { .. } => {}
            Statement::Unknown { .. } => {}
        }
    }
}

/// Builds the ObjectMap from all decompiled functions.
pub struct ObjectRecoveryBuilder;

impl ObjectRecoveryBuilder {
    pub fn build(funcs: &[&DecompilerFunction]) -> ObjectMap {
        let mut scan = FuncScan::new();
        for func in funcs {
            for stmt in &func.statements {
                scan.walk_stmt(stmt, func.address);
            }
        }

        // Objects = every base that has at least one field access or pure global ref.
        let mut bases: BTreeSet<u64> = BTreeSet::new();
        for (base, _off) in scan.access.keys() {
            bases.insert(*base);
        }
        for g in &scan.pure_globals {
            bases.insert(*g);
        }

        let mut objects = Vec::new();
        let mut by_base = HashMap::new();
        for (id, base) in bases.into_iter().enumerate() {
            let mut fields: BTreeMap<u64, FieldCandidate> = BTreeMap::new();
            for ((b, off), cnt) in &scan.access {
                if *b == base {
                    fields.insert(
                        *off,
                        FieldCandidate {
                            offset: *off,
                            accesses: *cnt,
                            type_label: None,
                            touched_by: scan
                                .field_funcs
                                .get(&(*b, *off))
                                .cloned()
                                .unwrap_or_default(),
                        },
                    );
                }
            }
            by_base.insert(base, id);
            objects.push(ObjectCandidate {
                id,
                base,
                name: format!("global_{:X}", base),
                fields,
                functions: scan.obj_funcs.get(&base).cloned().unwrap_or_default(),
            });
        }

        ObjectMap { objects, by_base }
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

    fn assign(lhs: AssignTarget, rhs: Expression) -> Statement {
        Statement::Assign {
            lhs,
            rhs,
            evidence: ev(),
        }
    }

    fn func(stmts: Vec<Statement>) -> DecompilerFunction {
        DecompilerFunction {
            address: 0x5000,
            name: None,
            statements: stmts,
            evidence: FunctionEvidence {
                ssa_instructions: 0,
                cfg_blocks: 0,
                control_structures: 0,
                unknown_statements: 0,
                budget_exhausted: false,
            },
        }
    }

    /// Helper: `mov regN, global_46E920` then `[regN + off]`.
    fn load_then_access(reg: &str, ver: u32, off: u64) -> Vec<Statement> {
        vec![
            assign(
                AssignTarget::Variable {
                    name: reg.to_string(),
                    version: ver,
                    origin: VariableOrigin::SSAPlaceholder,
                },
                Expression::Constant(0x46E920),
            ),
            assign(
                AssignTarget::Memory {
                    address: Box::new(Expression::Binary {
                        op: BinaryOp::Add,
                        left: Box::new(Expression::Variable {
                            name: reg.to_string(),
                            version: ver,
                        }),
                        right: Box::new(Expression::Constant(off)),
                    }),
                },
                Expression::Constant(0),
            ),
        ]
    }

    #[test]
    fn test_same_base_offsets_merge_one_object() {
        let f = func(load_then_access("ecx", 1, 0x10));
        let more = load_then_access("ecx", 2, 0x14);
        let f = func([f.statements, more].concat());
        let map = ObjectRecoveryBuilder::build(&[&f]);
        assert_eq!(map.object_count(), 1, "one base -> one object");
        assert_eq!(
            map.fields_of_object(0x46E920).unwrap().len(),
            2,
            "two offsets -> two fields"
        );
    }

    #[test]
    fn test_two_bases_two_objects() {
        let f1 = func(load_then_access("ecx", 1, 0x10));
        // Second object base 0x470000.
        let mut stmts = load_then_access("ecx", 3, 0x20);
        if let Statement::Assign { rhs, .. } = &mut stmts[0] {
            *rhs = Expression::Constant(0x470000);
        }
        let f2 = func(stmts);
        let map = ObjectRecoveryBuilder::build(&[&f1, &f2]);
        assert_eq!(map.object_count(), 2);
    }

    #[test]
    fn test_field_access_count_aggregates() {
        // Same offset accessed twice.
        let mut stmts = load_then_access("ecx", 1, 0x10);
        stmts.extend(load_then_access("ecx", 4, 0x10));
        let f = func(stmts);
        let map = ObjectRecoveryBuilder::build(&[&f]);
        let field = map.field_at_offset(0x46E920, 0x10).unwrap();
        assert_eq!(field.accesses, 2);
    }

    #[test]
    fn test_no_memory_access_no_object() {
        let f = func(vec![assign(
            AssignTarget::Variable {
                name: "eax".into(),
                version: 1,
                origin: VariableOrigin::SSAPlaceholder,
            },
            Expression::Constant(0x1234),
        )]);
        let map = ObjectRecoveryBuilder::build(&[&f]);
        assert_eq!(map.object_count(), 0, "fail-closed: unrelated constant");
    }

    #[test]
    fn test_pure_global_constant_becomes_object() {
        // A direct reference to the global address with no register load.
        let f = func(vec![assign(
            AssignTarget::Memory {
                address: Box::new(Expression::Constant(0x46E920)),
            },
            Expression::Constant(0),
        )]);
        let map = ObjectRecoveryBuilder::build(&[&f]);
        assert!(map.object_of_address(0x46E920).is_some());
    }
}
