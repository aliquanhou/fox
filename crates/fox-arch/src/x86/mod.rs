//! x86 (32-bit) architecture specifics

use crate::{CallingConvention, StackDirection};

pub fn calling_convention_cdecl() -> CallingConvention {
    CallingConvention {
        name: "cdecl".to_string(),
        argument_registers: vec![], // all args on stack
        return_register: "eax".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec!["esi".into(), "edi".into(), "ebx".into(), "ebp".into()],
        caller_saved_registers: vec!["eax".into(), "ecx".into(), "edx".into()],
    }
}

pub fn calling_convention_stdcall() -> CallingConvention {
    CallingConvention {
        name: "stdcall".to_string(),
        argument_registers: vec![],
        return_register: "eax".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec!["esi".into(), "edi".into(), "ebx".into(), "ebp".into()],
        caller_saved_registers: vec!["eax".into(), "ecx".into(), "edx".into()],
    }
}

pub fn calling_convention_thiscall() -> CallingConvention {
    CallingConvention {
        name: "thiscall".to_string(),
        argument_registers: vec!["ecx".into()], // this pointer in ECX
        return_register: "eax".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec!["esi".into(), "edi".into(), "ebx".into(), "ebp".into()],
        caller_saved_registers: vec!["eax".into(), "edx".into()],
    }
}

/// Common x86 function prologue patterns (byte sequences).
pub const FUNCTION_PROLOGUES: &[&[u8]] = &[
    &[0x55, 0x8B, 0xEC],             // push ebp; mov ebp, esp
    &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp (alt encoding)
    &[0x8B, 0xFF, 0x55, 0x8B, 0xEC], // mov edi, edi; push ebp; mov ebp, esp (hotpatch)
];

/// x86 RET instruction opcodes.
pub const RET_OPCODES: &[u8] = &[0xC3, 0xC2, 0xCB, 0xCA];
