//! FOX Decompiler
//!
//! P0-6.1: Expression Recovery (SSA → Expression Tree).
//! P0-6.3A: Condition Recovery (CMP/TEST + Jcc → structured condition).
//! P0-6.4B: Control Structure Recovery (If/Else + Guard Clause / Early Return).
//! P0-6.6A: Structured IR (aggregate analysis → DecompilerFunction → Statements).
//! P0-6.6B: C-like Emitter (Structured IR → human-readable pseudocode).

pub mod callgraph;
pub mod condition;
pub mod control_structure;
pub mod dataflow;
pub mod dynamic_plugin;
pub mod emitter;
pub mod expression;
pub mod structured_ir;

pub use callgraph::{
    DecompilerCallEdge, DecompilerCallGraph, DecompilerCallGraphBuilder, DecompilerCallKind,
};
pub use condition::{
    recover_all_conditions, recover_condition, Condition, ConditionOperand, ConditionRecovery,
};
pub use control_structure::{
    recover_control_structures, ControlStructure, GuardClause, IfElse, StructureEvidence,
    UnknownBranch,
};
pub use dataflow::{
    ArgumentSourceKind, CrossFunctionDataFlowBuilder, CrossFunctionDataFlowGraph, DataFlowEdge,
    FlowDetail, FlowKind, ReturnConsumerKind,
};
pub use dynamic_plugin::{
    build_external_call_name_map, build_iat_map_from_imports, resolutions_to_call_targets,
    DynamicCallEvidence, DynamicPluginResolver, ResolvedDynamicCall, ResolverStats, TrackedValue,
};
pub use emitter::{emit_c_like, emit_c_like_clean, CLikeEmitter, EmitterConfig};
pub use expression::{BinaryOp, CallTarget, Expression, ExpressionRecovery, PhiIncoming, UnaryOp};
pub use structured_ir::{
    AssignTarget, CallBehavior, DecompilerFunction, FunctionEvidence, Statement, StatementEvidence,
    StructuredIRBudget, StructuredIRBuilder, VariableOrigin,
};

pub struct Decompiler;

impl Decompiler {
    pub fn new() -> Self {
        Decompiler
    }
}

impl Default for Decompiler {
    fn default() -> Self {
        Self::new()
    }
}
