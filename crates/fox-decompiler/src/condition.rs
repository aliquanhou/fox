//! P0-6.3A: Condition recovery from SSA + CondJump.
//!
//! Given a conditional branch instruction (Jcc) in SSA form, trace the
//! FLAGS use-def chain back to its producer (CMP/TEST) and reconstruct
//! a structured condition with operands.
//!
//! This is the first real "machine code → C-like condition" link in FOX.
//! It does NOT produce AST or C source — only a structured internal result
//! with full evidence traceability.

use fox_analysis::ssa::{SSAFunction, SSAOperand};
use fox_ir::JumpCondition;

/// A recovered condition from CMP/TEST + Jcc.
///
/// Evidence chain:
///   Condition ← FLAGS producer (CMP/TEST) ← FLAGS version ← Jcc
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// The jump condition (Equal, NotEqual, SignedLess, ...).
    pub operator: JumpCondition,
    /// Left operand expression (register name or constant).
    pub left: ConditionOperand,
    /// Right operand expression.
    pub right: ConditionOperand,
    /// Address of the FLAGS-producing instruction (CMP/TEST).
    pub flags_producer_address: u64,
    /// Address of the conditional jump instruction.
    pub branch_address: u64,
    /// Whether the producer was TEST (bitwise AND) rather than CMP (subtract).
    pub is_test: bool,
}

/// An operand in a recovered condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOperand {
    /// Register variable (name, SSA version).
    Register { name: String, version: u32 },
    /// Constant value.
    Constant(u64),
    /// Memory reference (description string).
    Memory(String),
    /// Unknown / not recoverable.
    Unknown,
}

impl ConditionOperand {
    fn from_ssa_operand(op: &SSAOperand) -> Self {
        match op {
            SSAOperand::Variable { name, version } => {
                if name == "FLAGS" {
                    ConditionOperand::Unknown
                } else {
                    ConditionOperand::Register {
                        name: name.clone(),
                        version: *version,
                    }
                }
            }
            SSAOperand::Constant(v) => ConditionOperand::Constant(*v),
            SSAOperand::Memory { description } => ConditionOperand::Memory(description.clone()),
            SSAOperand::Label(_) => ConditionOperand::Unknown,
        }
    }
}

impl std::fmt::Display for ConditionOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConditionOperand::Register { name, version } => {
                write!(f, "{}.v{}", name, version)
            }
            ConditionOperand::Constant(v) => write!(f, "0x{:X}", v),
            ConditionOperand::Memory(desc) => write!(f, "[{}]", desc),
            ConditionOperand::Unknown => write!(f, "?"),
        }
    }
}

impl std::fmt::Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op_str = match self.operator {
            JumpCondition::Equal => "==",
            JumpCondition::NotEqual => "!=",
            JumpCondition::SignedLess => "<",
            JumpCondition::SignedLessEqual => "<=",
            JumpCondition::SignedGreater => ">",
            JumpCondition::SignedGreaterEqual => ">=",
            JumpCondition::UnsignedLess => "<",
            JumpCondition::UnsignedLessEqual => "<=",
            JumpCondition::UnsignedGreater => ">",
            JumpCondition::UnsignedGreaterEqual => ">=",
            JumpCondition::Overflow => "overflow",
            JumpCondition::NoOverflow => "!overflow",
            JumpCondition::Sign => "<0",
            JumpCondition::NoSign => ">=0",
            JumpCondition::Parity => "parity",
            JumpCondition::NoParity => "!parity",
        };
        if self.is_test {
            // TEST a, b + Jcc → (a & b) condition
            write!(f, "({} & {}) {} 0", self.left, self.right, op_str)
        } else {
            write!(f, "{} {} {}", self.left, op_str, self.right)
        }
    }
}

/// Result of condition recovery for a single CondJump instruction.
#[derive(Debug, Clone)]
pub enum ConditionRecovery {
    /// Successfully recovered a condition.
    Resolved(Condition),
    /// FLAGS producer found but not CMP/TEST (e.g., arithmetic FLAGS).
    ProducerNotCmpTest {
        producer_address: u64,
        producer_op: String,
        branch_address: u64,
        operator: JumpCondition,
    },
    /// FLAGS producer not found via use-def (may be phi or external).
    ProducerNotFound {
        branch_address: u64,
        operator: JumpCondition,
    },
    /// Instruction is not a CondJump.
    NotConditionalJump,
}

/// Recover the condition for a CondJump instruction in SSA form.
///
/// Traces the FLAGS operand's use-def chain to find the producer,
/// then extracts operands from CMP/TEST instructions.
pub fn recover_condition(ssa: &SSAFunction, block_id: usize, inst_idx: usize) -> ConditionRecovery {
    let block = match ssa.basic_blocks.get(block_id) {
        Some(b) => b,
        None => return ConditionRecovery::NotConditionalJump,
    };
    let inst = match block.instructions.get(inst_idx) {
        Some(i) => i,
        None => return ConditionRecovery::NotConditionalJump,
    };

    // Must be CondJump
    if inst.op != "CondJump" {
        return ConditionRecovery::NotConditionalJump;
    }

    // Extract condition from original mnemonic (JNZ → NotEqual, etc.)
    let operator = match mnemonic_to_condition(&inst.original_mnemonic) {
        Some(c) => c,
        None => return ConditionRecovery::NotConditionalJump,
    };

    // Find FLAGS operand index
    let flags_op_idx = inst
        .operands
        .iter()
        .position(|op| matches!(op, SSAOperand::Variable { name, .. } if name == "FLAGS"));

    let flags_op_idx = match flags_op_idx {
        Some(idx) => idx,
        None => {
            return ConditionRecovery::ProducerNotFound {
                branch_address: inst.address,
                operator,
            }
        }
    };

    // Trace use-def to find FLAGS producer
    let def_key = (block_id, inst_idx, flags_op_idx);
    let (def_block, def_inst, _version) = match ssa.use_def_chains.get(&def_key) {
        Some(&(b, i, v)) => (b, i, v),
        None => {
            return ConditionRecovery::ProducerNotFound {
                branch_address: inst.address,
                operator,
            }
        }
    };

    if def_block == usize::MAX || def_inst == usize::MAX {
        return ConditionRecovery::ProducerNotFound {
            branch_address: inst.address,
            operator,
        };
    }

    let producer = match ssa
        .basic_blocks
        .get(def_block)
        .and_then(|b| b.instructions.get(def_inst))
    {
        Some(p) => p,
        None => {
            return ConditionRecovery::ProducerNotFound {
                branch_address: inst.address,
                operator,
            }
        }
    };

    // Check if producer is CMP or TEST
    let is_test = producer.op == "Test";
    if producer.op != "Cmp" && !is_test {
        return ConditionRecovery::ProducerNotCmpTest {
            producer_address: producer.address,
            producer_op: producer.op.clone(),
            branch_address: inst.address,
            operator,
        };
    }

    // Extract operands (skip FLAGS operand)
    let data_operands: Vec<&SSAOperand> = producer
        .operands
        .iter()
        .filter(|op| !matches!(op, SSAOperand::Variable { name, .. } if name == "FLAGS"))
        .collect();

    let left = data_operands
        .first()
        .map(|op| ConditionOperand::from_ssa_operand(op))
        .unwrap_or(ConditionOperand::Unknown);
    let right = data_operands
        .get(1)
        .map(|op| ConditionOperand::from_ssa_operand(op))
        .unwrap_or(ConditionOperand::Unknown);

    ConditionRecovery::Resolved(Condition {
        operator,
        left,
        right,
        flags_producer_address: producer.address,
        branch_address: inst.address,
        is_test,
    })
}

/// Recover all conditions in a function (one per CondJump).
pub fn recover_all_conditions(ssa: &SSAFunction) -> Vec<ConditionRecovery> {
    let mut results = Vec::new();
    for (block_id, block) in ssa.basic_blocks.iter().enumerate() {
        for (inst_idx, inst) in block.instructions.iter().enumerate() {
            if inst.op == "CondJump" {
                results.push(recover_condition(ssa, block_id, inst_idx));
            }
        }
    }
    results
}

/// Map original Jcc mnemonic to JumpCondition.
fn mnemonic_to_condition(mnemonic: &str) -> Option<JumpCondition> {
    use JumpCondition::*;
    Some(match mnemonic {
        "je" | "jz" => Equal,
        "jne" | "jnz" => NotEqual,
        "jl" | "jnge" => SignedLess,
        "jle" | "jng" => SignedLessEqual,
        "jg" | "jnle" => SignedGreater,
        "jge" | "jnl" => SignedGreaterEqual,
        "jb" | "jnae" | "jc" => UnsignedLess,
        "jbe" | "jna" => UnsignedLessEqual,
        "ja" | "jnbe" => UnsignedGreater,
        "jae" | "jnb" | "jnc" => UnsignedGreaterEqual,
        "jo" => Overflow,
        "jno" => NoOverflow,
        "js" => Sign,
        "jns" => NoSign,
        "jp" | "jpe" => Parity,
        "jnp" | "jpo" => NoParity,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_display_cmp() {
        let cond = Condition {
            operator: JumpCondition::SignedLess,
            left: ConditionOperand::Register {
                name: "eax".into(),
                version: 3,
            },
            right: ConditionOperand::Constant(5),
            flags_producer_address: 0x1000,
            branch_address: 0x1003,
            is_test: false,
        };
        assert_eq!(format!("{}", cond), "eax.v3 < 0x5");
    }

    #[test]
    fn test_condition_display_test() {
        let cond = Condition {
            operator: JumpCondition::NotEqual,
            left: ConditionOperand::Register {
                name: "ecx".into(),
                version: 1,
            },
            right: ConditionOperand::Register {
                name: "ecx".into(),
                version: 1,
            },
            flags_producer_address: 0x4013B3,
            branch_address: 0x4013B5,
            is_test: true,
        };
        assert_eq!(format!("{}", cond), "(ecx.v1 & ecx.v1) != 0");
    }

    #[test]
    fn test_mnemonic_to_condition() {
        assert_eq!(mnemonic_to_condition("jnz"), Some(JumpCondition::NotEqual));
        assert_eq!(mnemonic_to_condition("jz"), Some(JumpCondition::Equal));
        assert_eq!(mnemonic_to_condition("jl"), Some(JumpCondition::SignedLess));
        assert_eq!(
            mnemonic_to_condition("jb"),
            Some(JumpCondition::UnsignedLess)
        );
        assert_eq!(mnemonic_to_condition("jmp"), None);
    }

    #[test]
    fn test_condition_operand_from_ssa() {
        let reg = SSAOperand::Variable {
            name: "eax".into(),
            version: 5,
        };
        assert!(matches!(
            ConditionOperand::from_ssa_operand(&reg),
            ConditionOperand::Register { name, version: 5 } if name == "eax"
        ));

        let flags = SSAOperand::Variable {
            name: "FLAGS".into(),
            version: 1,
        };
        assert!(matches!(
            ConditionOperand::from_ssa_operand(&flags),
            ConditionOperand::Unknown
        ));

        let c = SSAOperand::Constant(42);
        assert!(matches!(
            ConditionOperand::from_ssa_operand(&c),
            ConditionOperand::Constant(42)
        ));
    }
}
