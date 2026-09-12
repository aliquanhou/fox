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
use fox_binary::Binary;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Max positive offset before we stop treating it as a struct field.
const MAX_FIELD_OFFSET: u64 = 0x1_000_000;

/// One writable data section (.data/.bss) that can hold global objects.
#[derive(Debug, Clone)]
pub struct GlobalRegion {
    pub name: String,
    pub va_start: u64,
    pub va_end: u64,
}

/// GAP-RM-1: writable global regions derived from the PE section table,
/// NOT hard-coded addresses. This makes Object Recovery portable across
/// any PE (different ImageBase / .data layout).
#[derive(Debug, Clone, Default)]
pub struct GlobalRegionMap {
    regions: Vec<GlobalRegion>,
}

impl GlobalRegionMap {
    /// Build from a parsed binary: writable, non-executable sections
    /// (.data, .bss, writable .rdata) whose VA = image_base + RVA.
    pub fn from_binary(bin: &Binary) -> Self {
        let regions = bin
            .sections
            .iter()
            .filter(|s| s.is_writable() && !s.is_executable())
            .map(|s| GlobalRegion {
                name: s.name.clone(),
                va_start: bin.image_base + s.virtual_address,
                va_end: bin.image_base + s.virtual_address + s.virtual_size as u64,
            })
            .collect();
        Self { regions }
    }

    /// Build from explicit ranges (tests).
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            regions: ranges
                .into_iter()
                .enumerate()
                .map(|(i, (a, b))| GlobalRegion {
                    name: format!("region_{}", i),
                    va_start: a,
                    va_end: b,
                })
                .collect(),
        }
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| addr >= r.va_start && addr < r.va_end)
    }

    pub fn len(&self) -> usize {
        self.regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

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

/// Layout shape of a recovered struct candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructLayoutKind {
    /// Fields tile contiguous slots (e.g. 0x0,0x4,0x8) — struct-like.
    Contiguous,
    /// Fields are scattered — sparse global, weak struct evidence.
    Sparse,
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
    /// GAP-RM-3: inferred struct size = max observed offset + slot width (4).
    pub size_candidate: u64,
    /// GAP-RM-3: contiguous vs sparse layout shape.
    pub layout: StructLayoutKind,
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

    /// GAP-RM-3: count objects whose fields tile a contiguous struct layout.
    pub fn contiguous_struct_count(&self) -> usize {
        self.objects
            .iter()
            .filter(|o| o.layout == StructLayoutKind::Contiguous)
            .count()
    }
}

/// Accumulator used while walking one function.
struct FuncScan {
    /// Writable global regions (from PE section table).
    regions: GlobalRegionMap,
    /// `reg_version` -> global base it currently points to (P0-8.3 style).
    reg_to_base: HashMap<String, u64>,
    /// GAP-RM-2: bare register name -> global base (lift text uses no version).
    reg_name_to_base: HashMap<String, u64>,
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
    fn new(regions: GlobalRegionMap) -> Self {
        Self {
            regions,
            reg_to_base: HashMap::new(),
            reg_name_to_base: HashMap::new(),
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
            Expression::Constant(addr) if self.regions.contains(*addr) => {
                self.pure_globals.insert(*addr);
            }
            // GAP-RM-2: lift memory operand text "[ecx+0x24]" inside Unknown reason.
            Expression::Unknown { reason } => {
                if let Some(p) = crate::memory_recovery::parse_memory_operand(reason) {
                    match p.base {
                        Some(reg) => {
                            if let Some(&base) = self.reg_name_to_base.get(&reg) {
                                if p.offset > 0 {
                                    self.record(base, p.offset as u64, func);
                                } else if p.offset == 0 {
                                    self.record(base, 0, func);
                                }
                            }
                        }
                        None => {
                            if p.offset > 0 && self.regions.contains(p.offset as u64) {
                                self.pure_globals.insert(p.offset as u64);
                            }
                        }
                    }
                }
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
                    if self.regions.contains(*addr) {
                        if let AssignTarget::Variable { name, version, .. } = lhs {
                            self.reg_to_base
                                .insert(format!("{}_{}", name, version), *addr);
                            // GAP-RM-2: also record bare name for lift-text parsing.
                            self.reg_name_to_base.insert(name.clone(), *addr);
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
                lhs: AssignTarget::Variable { name, version, .. },
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

/// GAP-RM-3: decide whether fields tile a contiguous struct or are scattered.
fn infer_layout(fields: &BTreeMap<u64, FieldCandidate>) -> StructLayoutKind {
    let offsets: Vec<u64> = fields.keys().copied().collect();
    if offsets.len() < 2 {
        return StructLayoutKind::Sparse;
    }
    let contiguous_gaps = offsets.windows(2).filter(|w| w[1] - w[0] <= 8).count();
    let total_gaps = offsets.len() - 1;
    if contiguous_gaps * 3 >= total_gaps * 2 {
        StructLayoutKind::Contiguous
    } else {
        StructLayoutKind::Sparse
    }
}

/// Builds the ObjectMap from all decompiled functions.
pub struct ObjectRecoveryBuilder;

impl ObjectRecoveryBuilder {
    pub fn build(funcs: &[&DecompilerFunction], regions: &GlobalRegionMap) -> ObjectMap {
        let mut scan = FuncScan::new(regions.clone());
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
            // GAP-RM-3: infer struct size + layout shape from observed offsets.
            let size_candidate = fields.last_key_value().map(|(off, _)| off + 4).unwrap_or(0);
            let layout = infer_layout(&fields);
            by_base.insert(base, id);
            objects.push(ObjectCandidate {
                id,
                base,
                name: format!("global_{:X}", base),
                fields,
                functions: scan.obj_funcs.get(&base).cloned().unwrap_or_default(),
                size_candidate,
                layout,
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

    /// Writable region covering the test constants (0x460000-0x480000).
    fn test_regions() -> GlobalRegionMap {
        GlobalRegionMap::from_ranges(vec![(0x460000, 0x480000)])
    }

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
        let map = ObjectRecoveryBuilder::build(&[&f], &test_regions());
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
        let map = ObjectRecoveryBuilder::build(&[&f1, &f2], &test_regions());
        assert_eq!(map.object_count(), 2);
    }

    #[test]
    fn test_field_access_count_aggregates() {
        // Same offset accessed twice.
        let mut stmts = load_then_access("ecx", 1, 0x10);
        stmts.extend(load_then_access("ecx", 4, 0x10));
        let f = func(stmts);
        let map = ObjectRecoveryBuilder::build(&[&f], &test_regions());
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
        let map = ObjectRecoveryBuilder::build(&[&f], &test_regions());
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
        let map = ObjectRecoveryBuilder::build(&[&f], &test_regions());
        assert!(map.object_of_address(0x46E920).is_some());
    }
}
