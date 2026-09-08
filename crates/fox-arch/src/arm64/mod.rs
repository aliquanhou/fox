//! ARM64 (AArch64) architecture specifics
//!
//! P0: placeholder. Full implementation in P0-2+.

use crate::{CallingConvention, StackDirection};

pub fn calling_convention_aapcs64() -> CallingConvention {
    CallingConvention {
        name: "aapcs64".to_string(),
        argument_registers: vec![
            "x0".into(),
            "x1".into(),
            "x2".into(),
            "x3".into(),
            "x4".into(),
            "x5".into(),
            "x6".into(),
            "x7".into(),
        ],
        return_register: "x0".to_string(),
        stack_direction: StackDirection::GrowsDown,
        callee_saved_registers: vec![
            "x19".into(),
            "x20".into(),
            "x21".into(),
            "x22".into(),
            "x23".into(),
            "x24".into(),
            "x25".into(),
            "x26".into(),
            "x27".into(),
            "x28".into(),
            "x29".into(),
            "x30".into(),
        ],
        caller_saved_registers: vec![
            "x0".into(),
            "x1".into(),
            "x2".into(),
            "x3".into(),
            "x4".into(),
            "x5".into(),
            "x6".into(),
            "x7".into(),
            "x8".into(),
            "x9".into(),
            "x10".into(),
            "x11".into(),
            "x12".into(),
            "x13".into(),
            "x14".into(),
            "x15".into(),
            "x16".into(),
            "x17".into(),
            "x18".into(),
        ],
    }
}
