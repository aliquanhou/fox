//! FOX Basic Type Recovery
//!
//! P0-2.6: Infer basic types from instruction semantics.
//!
//! Supported types:
//! - u8, u16, u32, u64 (unsigned integers)
//! - i8, i16, i32, i64 (signed integers)
//! - pointer (64-bit address on x64)
//! - unknown
//!
//! Evidence sources:
//! - Memory access width (mov eax, [x] → u32)
//! - Arithmetic operations (add/sub → integer)
//! - Pointer arithmetic (lea with base+index → pointer)
//! - API signature (passed to CreateFileW → pointer)
//! - Register usage conventions (rax return value, rdi/rsi string ops)

use fox_core::{Evidence, EvidenceKind};
use fox_ir::{IRInstruction, IROperand, OperandAccess};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A recovered type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoxType {
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int8,
    Int16,
    Int32,
    Int64,
    Pointer,
    Float32,
    Float64,
    Unknown,
}

impl FoxType {
    pub fn display_name(&self) -> &'static str {
        match self {
            FoxType::UInt8 => "u8",
            FoxType::UInt16 => "u16",
            FoxType::UInt32 => "u32",
            FoxType::UInt64 => "u64",
            FoxType::Int8 => "i8",
            FoxType::Int16 => "i16",
            FoxType::Int32 => "i32",
            FoxType::Int64 => "i64",
            FoxType::Pointer => "pointer",
            FoxType::Float32 => "f32",
            FoxType::Float64 => "f64",
            FoxType::Unknown => "unknown",
        }
    }

    /// Width in bits.
    pub fn width(&self) -> u16 {
        match self {
            FoxType::UInt8 | FoxType::Int8 => 8,
            FoxType::UInt16 | FoxType::Int16 => 16,
            FoxType::UInt32 | FoxType::Int32 | FoxType::Float32 => 32,
            FoxType::UInt64 | FoxType::Int64 | FoxType::Pointer | FoxType::Float64 => 64,
            FoxType::Unknown => 0,
        }
    }
}

/// A type inference result with evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInference {
    pub variable: String,
    pub inferred_type: FoxType,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}

/// Type recovery result for a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRecoveryResult {
    pub function_address: u64,
    pub inferences: Vec<TypeInference>,
    pub evidence: Vec<Evidence>,
}

/// Basic type recovery engine.
pub struct TypeRecovery;

impl TypeRecovery {
    /// Analyze a function's instructions and infer types.
    pub fn analyze(function_address: u64, instructions: &[IRInstruction]) -> TypeRecoveryResult {
        let mut inferences: HashMap<String, TypeInference> = HashMap::new();

        for inst in instructions {
            // Infer types from memory access width
            Self::infer_from_memory_access(inst, &mut inferences);

            // Infer types from arithmetic
            Self::infer_from_arithmetic(inst, &mut inferences);

            // Infer pointer from LEA
            Self::infer_pointer_from_lea(inst, &mut inferences);

            // Infer from register conventions
            Self::infer_from_conventions(inst, &mut inferences);
        }

        let inference_count = inferences.len();
        let result = TypeRecoveryResult {
            function_address,
            inferences: inferences.into_values().collect(),
            evidence: vec![
                Evidence::new(EvidenceKind::TypeInference).with_weight(0.8),
                Evidence::new(EvidenceKind::Heuristic {
                    description: format!("Type recovery: {} variables inferred", inference_count),
                })
                .with_weight(0.7),
            ],
        };

        result
    }

    /// Infer type from memory operand access width.
    fn infer_from_memory_access(
        inst: &IRInstruction,
        inferences: &mut HashMap<String, TypeInference>,
    ) {
        for op in &inst.operands {
            if let IROperand::Memory { size, access, .. } = op {
                let ty = match size {
                    1 => FoxType::UInt8,
                    2 => FoxType::UInt16,
                    4 => FoxType::UInt32,
                    8 => FoxType::UInt64,
                    _ => continue,
                };

                // The destination register of a load gets the type
                if matches!(access, OperandAccess::Read) {
                    if let Some(dst_reg) = inst.writes_registers.first() {
                        Self::add_inference(
                            inferences,
                            dst_reg,
                            ty.clone(),
                            0.85,
                            Evidence::new(EvidenceKind::TypeUsagePattern)
                                .with_address(inst.address.0)
                                .with_weight(0.85),
                        );
                    }
                }
            }
        }
    }

    /// Infer integer type from arithmetic operations.
    fn infer_from_arithmetic(
        inst: &IRInstruction,
        inferences: &mut HashMap<String, TypeInference>,
    ) {
        match inst.op {
            fox_ir::IROp::Add
            | fox_ir::IROp::Sub
            | fox_ir::IROp::Mul
            | fox_ir::IROp::Div
            | fox_ir::IROp::And
            | fox_ir::IROp::Or
            | fox_ir::IROp::Xor
            | fox_ir::IROp::Shl
            | fox_ir::IROp::Shr
            | fox_ir::IROp::Sar
            | fox_ir::IROp::Cmp
            | fox_ir::IROp::Test => {
                // Operands are integers; infer from width
                for op in &inst.operands {
                    if let IROperand::Register {
                        name,
                        width,
                        access,
                    } = op
                    {
                        if matches!(access, OperandAccess::Read | OperandAccess::ReadWrite) {
                            let ty = match width {
                                8 => FoxType::UInt8,
                                16 => FoxType::UInt16,
                                32 => FoxType::UInt32,
                                64 => FoxType::UInt64,
                                _ => continue,
                            };
                            Self::add_inference(
                                inferences,
                                name,
                                ty,
                                0.7,
                                Evidence::new(EvidenceKind::TypeUsagePattern)
                                    .with_address(inst.address.0)
                                    .with_weight(0.7),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Infer pointer type from LEA (load effective address).
    fn infer_pointer_from_lea(
        inst: &IRInstruction,
        inferences: &mut HashMap<String, TypeInference>,
    ) {
        if inst.op == fox_ir::IROp::Lea {
            // LEA dst, [mem] → dst is a pointer
            if let Some(dst_reg) = inst.writes_registers.first() {
                Self::add_inference(
                    inferences,
                    dst_reg,
                    FoxType::Pointer,
                    0.95,
                    Evidence::new(EvidenceKind::TypeUsagePattern)
                        .with_address(inst.address.0)
                        .with_weight(0.95),
                );
            }
        }
    }

    /// Infer types from register usage conventions (x64 System V / Microsoft x64).
    fn infer_from_conventions(
        _inst: &IRInstruction,
        inferences: &mut HashMap<String, TypeInference>,
    ) {
        // Stack pointer is always a pointer
        for reg in &["rsp".to_string(), "esp".to_string(), "sp".to_string()] {
            Self::add_inference(
                inferences,
                reg,
                FoxType::Pointer,
                1.0,
                Evidence::new(EvidenceKind::CallingConvention).with_weight(1.0),
            );
        }

        // Instruction pointer is a pointer
        for reg in &["rip".to_string(), "eip".to_string()] {
            Self::add_inference(
                inferences,
                reg,
                FoxType::Pointer,
                1.0,
                Evidence::new(EvidenceKind::CallingConvention).with_weight(1.0),
            );
        }
    }

    /// Add or merge a type inference.
    fn add_inference(
        inferences: &mut HashMap<String, TypeInference>,
        variable: &str,
        ty: FoxType,
        confidence: f32,
        evidence: Evidence,
    ) {
        if let Some(existing) = inferences.get_mut(variable) {
            // Merge: higher confidence wins, but if types differ, downgrade
            if existing.inferred_type == ty {
                existing.confidence = existing.confidence.max(confidence);
                existing.evidence.push(evidence);
            } else if confidence > existing.confidence {
                existing.inferred_type = ty;
                existing.confidence = confidence;
                existing.evidence.push(evidence);
            } else {
                existing.evidence.push(evidence);
            }
        } else {
            inferences.insert(
                variable.to_string(),
                TypeInference {
                    variable: variable.to_string(),
                    inferred_type: ty,
                    confidence,
                    evidence: vec![evidence],
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fox_core::Address;
    use fox_ir::{IRInstruction, IROp, IROperand, OperandAccess};

    fn make_inst(
        address: u64,
        op: IROp,
        operands: Vec<IROperand>,
        reads: Vec<&str>,
        writes: Vec<&str>,
    ) -> IRInstruction {
        IRInstruction {
            address: Address(address),
            op,
            operands,
            original_mnemonic: None,
            original_operands: None,
            size: 0,
            reads_registers: reads.into_iter().map(String::from).collect(),
            writes_registers: writes.into_iter().map(String::from).collect(),
            implicit_reads: vec![],
            implicit_writes: vec![],
            reads_flags: false,
            writes_flags: false,
        }
    }

    #[test]
    fn test_pointer_from_lea() {
        let insts = vec![make_inst(
            0x1000,
            IROp::Lea,
            vec![
                IROperand::Register {
                    name: "rax".into(),
                    width: 64,
                    access: OperandAccess::Write,
                },
                IROperand::Memory {
                    base: Some("rcx".into()),
                    index: None,
                    scale: 1,
                    displacement: 0x10,
                    size: 8,
                    access: OperandAccess::Read,
                    is_rip_relative: false,
                    effective_address: None,
                },
            ],
            vec![],
            vec!["rax"],
        )];
        let result = TypeRecovery::analyze(0x1000, &insts);
        let rax = result
            .inferences
            .iter()
            .find(|i| i.variable == "rax")
            .unwrap();
        assert_eq!(rax.inferred_type, FoxType::Pointer);
        assert!(rax.confidence >= 0.9);
    }

    #[test]
    fn test_uint_from_memory_load() {
        let insts = vec![make_inst(
            0x1000,
            IROp::Mov,
            vec![
                IROperand::Register {
                    name: "eax".into(),
                    width: 32,
                    access: OperandAccess::Write,
                },
                IROperand::Memory {
                    base: Some("rbx".into()),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    size: 4,
                    access: OperandAccess::Read,
                    is_rip_relative: false,
                    effective_address: None,
                },
            ],
            vec![],
            vec!["eax"],
        )];
        let result = TypeRecovery::analyze(0x1000, &insts);
        let eax = result
            .inferences
            .iter()
            .find(|i| i.variable == "eax")
            .unwrap();
        assert_eq!(eax.inferred_type, FoxType::UInt32);
    }

    #[test]
    fn test_rsp_is_pointer() {
        let insts = vec![make_inst(
            0x1000,
            IROp::Push,
            vec![IROperand::Register {
                name: "rax".into(),
                width: 64,
                access: OperandAccess::Read,
            }],
            vec!["rax", "rsp"],
            vec!["rsp"],
        )];
        let result = TypeRecovery::analyze(0x1000, &insts);
        let rsp = result
            .inferences
            .iter()
            .find(|i| i.variable == "rsp")
            .unwrap();
        assert_eq!(rsp.inferred_type, FoxType::Pointer);
        assert_eq!(rsp.confidence, 1.0);
    }

    #[test]
    fn test_type_display_names() {
        assert_eq!(FoxType::UInt32.display_name(), "u32");
        assert_eq!(FoxType::Pointer.display_name(), "pointer");
        assert_eq!(FoxType::Int64.display_name(), "i64");
    }
}
