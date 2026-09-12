//! P0-13: Type Propagation Engine (Evidence Layer).
//!
//! Turns the already-recovered evidence into *candidate* types — never named
//! types. Every candidate carries a confidence and an evidence trail.
//!
//! ```text
//! ArgumentSourceKind (P0-12)  ─► Integer/Pointer candidate (arg slots)
//! ReturnEvidence     (P0-12)  ─► Boolean/Value candidate   (return)
//! field (object,offset,deref)  ─► Integer/Pointer candidate (fields)
//! ```
//!
//! Naming discipline: we emit `integer-candidate`, `pointer-candidate`, ...
//! NEVER `int`, `char*`, `bool`, or a struct name. Conflicting evidence on the
//! same key collapses to Unknown (never a forced guess).

use crate::dataflow::ArgumentSourceKind;
use crate::signature::{ReturnEvidence, SignatureMap};
use std::collections::HashMap;

/// Coarse candidate type. Evidence-only, NOT a C type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeKind {
    /// No / insufficient evidence.
    Unknown,
    /// Integer of some bit width.
    Integer { bits: u32 },
    /// A pointer (target unknown unless proven).
    Pointer { target: Option<u64> },
    /// A struct/aggregate bound to a global object id.
    Struct { object: String },
    /// Boolean-like (feeds a zero test / branch).
    Boolean,
    /// A function pointer.
    FunctionPointer,
}

impl TypeKind {
    /// Human label for evidence output. Never a C type keyword.
    pub fn label(&self) -> String {
        match self {
            TypeKind::Unknown => "unknown".to_string(),
            TypeKind::Integer { bits } => format!("integer-candidate({}b)", bits),
            TypeKind::Pointer { target: None } => "pointer-candidate".to_string(),
            TypeKind::Pointer { target: Some(t) } => format!("pointer-candidate->0x{:X}", t),
            TypeKind::Struct { object } => format!("struct-candidate({})", object),
            TypeKind::Boolean => "boolean-candidate".to_string(),
            TypeKind::FunctionPointer => "function-pointer-candidate".to_string(),
        }
    }
}

/// Confidence in a type candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeConfidence {
    None,
    Low,
    Medium,
}

impl TypeConfidence {
    pub fn label(self) -> &'static str {
        match self {
            TypeConfidence::None => "NONE",
            TypeConfidence::Low => "LOW",
            TypeConfidence::Medium => "MEDIUM",
        }
    }
}

/// A candidate type for one typed key (arg slot / return / field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeCandidate {
    pub kind: TypeKind,
    pub confidence: TypeConfidence,
    /// Short evidence strings (machine facts, not guesses).
    pub evidence: Vec<String>,
}

impl Default for TypeCandidate {
    fn default() -> Self {
        Self {
            kind: TypeKind::Unknown,
            confidence: TypeConfidence::None,
            evidence: Vec::new(),
        }
    }
}

/// Stable key identifying a typed location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeKey {
    /// A callee's argument slot: (callee, arg index).
    Param(u64, usize),
    /// A callee's return value.
    Return(u64),
    /// A global object field: (object id, offset).
    Field(String, u64),
}

/// Propagated type map: key -> candidate.
#[derive(Default, Clone)]
pub struct TypeMap {
    candidates: HashMap<TypeKey, TypeCandidate>,
}

impl TypeMap {
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
        }
    }

    pub fn get(&self, key: &TypeKey) -> Option<&TypeCandidate> {
        self.candidates.get(key)
    }

    pub fn param_type(&self, callee: u64, index: usize) -> Option<&TypeCandidate> {
        self.candidates.get(&TypeKey::Param(callee, index))
    }

    pub fn return_type(&self, callee: u64) -> Option<&TypeCandidate> {
        self.candidates.get(&TypeKey::Return(callee))
    }

    pub fn field_type(&self, object: &str, offset: u64) -> Option<&TypeCandidate> {
        self.candidates
            .get(&TypeKey::Field(object.to_string(), offset))
    }

    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Count keys whose kind is NOT Unknown (for the Unknown>50% discipline).
    pub fn known_count(&self) -> usize {
        self.candidates
            .values()
            .filter(|c| !matches!(c.kind, TypeKind::Unknown))
            .count()
    }
}

/// One field fact fed in from the object layer (P0-8/P0-9 evidence).
pub struct FieldTypeFact {
    pub object: String,
    pub offset: u64,
    /// Times the field was dereferenced as a memory base.
    pub deref_count: usize,
    /// Times the field fed an arithmetic operation.
    pub arith_count: usize,
}

/// Builds the TypeMap by joining evidence across callers.
pub struct TypePropagationBuilder;

impl TypePropagationBuilder {
    /// Build from the P0-12 signature map plus optional field facts.
    pub fn build(sig_map: &SignatureMap, field_facts: &[FieldTypeFact]) -> TypeMap {
        let mut map = TypeMap::new();

        // --- Parameter types: majority vote across callers per (callee, arg) ---
        // The signature map already collapsed caller arguments into a source kind
        // per parameter slot; we translate that source kind into a TypeKind.
        for (_callee, sig) in sig_map.iter() {
            for p in &sig.parameters {
                let (kind, ev) = match p.source {
                    ArgumentSourceKind::Constant => (
                        TypeKind::Integer { bits: 32 },
                        format!("arg source=constant ({} call sites)", p.call_sites),
                    ),
                    ArgumentSourceKind::Computed => (
                        TypeKind::Integer { bits: 32 },
                        format!("arg source=computed ({} call sites)", p.call_sites),
                    ),
                    ArgumentSourceKind::MemoryLoad => (
                        TypeKind::Pointer { target: None },
                        format!("arg source=mem_load ({} call sites)", p.call_sites),
                    ),
                    ArgumentSourceKind::Register => (
                        TypeKind::Unknown,
                        format!("arg source=register ({} call sites)", p.call_sites),
                    ),
                    ArgumentSourceKind::Unknown => {
                        (TypeKind::Unknown, "arg source=unknown".to_string())
                    }
                };
                let confidence = if matches!(kind, TypeKind::Unknown) {
                    TypeConfidence::None
                } else if p.call_sites >= 3 {
                    TypeConfidence::Medium
                } else {
                    TypeConfidence::Low
                };
                map.candidates.insert(
                    TypeKey::Param(sig.function, p.index),
                    TypeCandidate {
                        kind,
                        confidence,
                        evidence: vec![ev],
                    },
                );
            }

            // --- Return type from ReturnEvidence ---
            let (ret_kind, ret_conf, ret_ev) = match sig.return_evidence {
                ReturnEvidence::Condition => (
                    TypeKind::Boolean,
                    TypeConfidence::Low,
                    "return feeds a zero test/branch".to_string(),
                ),
                ReturnEvidence::Value => (
                    TypeKind::Unknown,
                    TypeConfidence::None,
                    "return used as ordinary value".to_string(),
                ),
                ReturnEvidence::Unknown => (
                    TypeKind::Unknown,
                    TypeConfidence::None,
                    "no return evidence".to_string(),
                ),
            };
            map.candidates.insert(
                TypeKey::Return(sig.function),
                TypeCandidate {
                    kind: ret_kind,
                    confidence: ret_conf,
                    evidence: vec![ret_ev],
                },
            );
        }

        // --- Field types from deref/arith facts ---
        for fact in field_facts {
            let (kind, conf) = if fact.deref_count > 0 {
                (TypeKind::Pointer { target: None }, TypeConfidence::Low)
            } else if fact.arith_count > 0 {
                (TypeKind::Integer { bits: 32 }, TypeConfidence::Low)
            } else {
                (TypeKind::Unknown, TypeConfidence::None)
            };
            map.candidates.insert(
                TypeKey::Field(fact.object.clone(), fact.offset),
                TypeCandidate {
                    kind,
                    confidence: conf,
                    evidence: vec![format!(
                        "deref={}, arith={}",
                        fact.deref_count, fact.arith_count
                    )],
                },
            );
        }

        map
    }

    /// Join two candidates that arrived at the same key (TypeJoin).
    /// Consensus wins; conflict collapses to Unknown (fail-closed).
    pub fn join(a: &TypeCandidate, b: &TypeCandidate) -> TypeCandidate {
        if a.kind == b.kind {
            let evidence: Vec<String> = a
                .evidence
                .iter()
                .chain(b.evidence.iter())
                .cloned()
                .collect();
            TypeCandidate {
                kind: a.kind.clone(),
                confidence: std::cmp::max(a.confidence, b.confidence),
                evidence,
            }
        } else {
            TypeCandidate {
                kind: TypeKind::Unknown,
                confidence: TypeConfidence::None,
                evidence: vec![format!(
                    "conflict: {} vs {}",
                    a.kind.label(),
                    b.kind.label()
                )],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataflow::ArgumentSourceKind;
    use crate::signature::{
        FunctionParameter, FunctionSignature, ParameterLocation, ReturnEvidence,
        SignatureConfidence, SignatureMap,
    };

    fn sig_with_args(
        callee: u64,
        params: Vec<FunctionParameter>,
        ret: ReturnEvidence,
    ) -> FunctionSignature {
        FunctionSignature {
            function: callee,
            parameters: params,
            return_evidence: ret,
            confidence: SignatureConfidence::Low,
        }
    }

    fn map_for(sig: FunctionSignature) -> TypeMap {
        let mut sm = SignatureMap::new();
        sm.insert(sig);
        TypePropagationBuilder::build(&sm, &[])
    }

    #[test]
    fn test_constant_argument_is_integer_candidate() {
        let sig = sig_with_args(
            0x5000,
            vec![FunctionParameter {
                index: 0,
                location: ParameterLocation::Stack,
                source: ArgumentSourceKind::Constant,
                call_sites: 3,
            }],
            ReturnEvidence::Unknown,
        );
        let tm = map_for(sig);
        let t = tm.param_type(0x5000, 0).unwrap();
        assert_eq!(t.kind, TypeKind::Integer { bits: 32 });
        assert_eq!(t.confidence, TypeConfidence::Medium);
    }

    #[test]
    fn test_memory_load_argument_is_pointer_candidate() {
        let sig = sig_with_args(
            0x5000,
            vec![FunctionParameter {
                index: 0,
                location: ParameterLocation::Stack,
                source: ArgumentSourceKind::MemoryLoad,
                call_sites: 1,
            }],
            ReturnEvidence::Unknown,
        );
        let tm = map_for(sig);
        assert_eq!(
            tm.param_type(0x5000, 0).unwrap().kind,
            TypeKind::Pointer { target: None }
        );
    }

    #[test]
    fn test_return_condition_is_boolean_candidate() {
        let sig = sig_with_args(0x5000, vec![], ReturnEvidence::Condition);
        let tm = map_for(sig);
        assert_eq!(tm.return_type(0x5000).unwrap().kind, TypeKind::Boolean);
    }

    #[test]
    fn test_join_conflict_collapses_to_unknown() {
        let a = TypeCandidate {
            kind: TypeKind::Integer { bits: 32 },
            confidence: TypeConfidence::Medium,
            evidence: vec!["int".into()],
        };
        let b = TypeCandidate {
            kind: TypeKind::Pointer { target: None },
            confidence: TypeConfidence::Medium,
            evidence: vec!["ptr".into()],
        };
        let joined = TypePropagationBuilder::join(&a, &b);
        assert_eq!(joined.kind, TypeKind::Unknown);
        assert_eq!(joined.confidence, TypeConfidence::None);
    }

    #[test]
    fn test_field_fact_with_deref_is_pointer() {
        let facts = vec![FieldTypeFact {
            object: "global_x".into(),
            offset: 8,
            deref_count: 2,
            arith_count: 0,
        }];
        let sm = SignatureMap::new();
        let tm = TypePropagationBuilder::build(&sm, &facts);
        assert_eq!(
            tm.field_type("global_x", 8).unwrap().kind,
            TypeKind::Pointer { target: None }
        );
    }
}
