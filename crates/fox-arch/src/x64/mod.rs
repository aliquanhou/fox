//! x64 (x86-64) architecture specifics

use crate::{CallingConvention, StackDirection};

/// Microsoft x64 calling convention (Windows).
pub fn calling_convention_ms_x64() -> CallingConvention {
    CallingConvention {
        name: "ms_x64".to_string(),
        argument_registers: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
        return_register: "rax".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec![
            "rbx".into(),
            "rbp".into(),
            "rsi".into(),
            "rdi".into(),
            "r12".into(),
            "r13".into(),
            "r14".into(),
            "r15".into(),
        ],
        caller_saved_registers: vec![
            "rax".into(),
            "rcx".into(),
            "rdx".into(),
            "r8".into(),
            "r9".into(),
            "r10".into(),
            "r11".into(),
        ],
    }
}

/// System V AMD64 calling convention (Linux/macOS).
pub fn calling_convention_system_v_amd64() -> CallingConvention {
    CallingConvention {
        name: "system_v_amd64".to_string(),
        argument_registers: vec![
            "rdi".into(),
            "rsi".into(),
            "rdx".into(),
            "rcx".into(),
            "r8".into(),
            "r9".into(),
        ],
        return_register: "rax".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec![
            "rbx".into(),
            "rbp".into(),
            "r12".into(),
            "r13".into(),
            "r14".into(),
            "r15".into(),
        ],
        caller_saved_registers: vec![
            "rax".into(),
            "rcx".into(),
            "rdx".into(),
            "rsi".into(),
            "rdi".into(),
            "r8".into(),
            "r9".into(),
            "r10".into(),
            "r11".into(),
        ],
    }
}

/// Common x64 function prologue patterns.
pub const FUNCTION_PROLOGUES: &[&[u8]] = &[
    &[0x48, 0x89, 0x4C, 0x24, 0x08], // mov [rsp+8], rcx (MS x64 shadow space)
    &[0x48, 0x83, 0xEC, 0x20],       // sub rsp, 0x20
    &[0x55, 0x48, 0x8B, 0xEC],       // push rbp; mov rbp, rsp
    &[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20], // push rbx; sub rsp, 0x20
];

/// x64 RET instruction opcodes.
pub const RET_OPCODES: &[u8] = &[0xC3, 0xC2];
