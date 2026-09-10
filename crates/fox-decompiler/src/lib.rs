//! FOX Decompiler
//!
//! P0-6.1: Expression Recovery (SSA → Expression Tree).
//! P0-6.3A: Condition Recovery (CMP/TEST + Jcc → structured condition).
//! P0: placeholder for full decompiler.

pub mod condition;
pub mod expression;

pub use condition::{
    recover_all_conditions, recover_condition, Condition, ConditionOperand, ConditionRecovery,
};
pub use expression::{BinaryOp, CallTarget, Expression, ExpressionRecovery, PhiIncoming, UnaryOp};

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
