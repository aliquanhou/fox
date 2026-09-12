//! GAP-RM-2: Memory Operand Recovery.
//!
//! Many `[ecx+0x24]` / `mov [esi+0x18],edx` accesses never become a structured
//! `Binary{reg,const}` Expression in the IR. They survive as the lift-produced
//! description carried in `Expression::Unknown{ reason: "memory operand: [ecx+0x24]" }`.
//!
//! This module parses that lift-original text (NOT emitter C output) into a
//! `ParsedMemory` fact, so Object Recovery can see the same fields the emitter
//! already displays via try_parse_memory_operand.

/// A parsed memory operand from lift text like `[ecx+0x24]`, `[0x46e920]`,
/// `[esi-0x18]`, or `[ecx]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMemory {
    /// Base register name when present (e.g. "ecx"); None for `[0x...]`.
    pub base: Option<String>,
    /// Displacement (signed).
    pub offset: i64,
}

/// Parse a lift memory description. Tolerates Zydis leading "+" and scale forms.
pub fn parse_memory_operand(reason: &str) -> Option<ParsedMemory> {
    // Find bracketed content, e.g. "memory operand: [ecx+0x24]" -> "ecx+0x24"
    let open = reason.find('[')?;
    let close = reason.find(']')?;
    if close <= open {
        return None;
    }
    let mut inner = &reason[open + 1..close];
    if inner.starts_with('+') {
        inner = &inner[1..];
    }
    let inner = inner.trim();
    if inner.is_empty() {
        return None;
    }

    // Pure constant: [0x46e920]
    if let Some(off) = parse_int(inner) {
        return Some(ParsedMemory {
            base: None,
            offset: off,
        });
    }

    // reg+off / reg-off: split on the last + or -.
    // Find an operator that separates a register name from an offset.
    let bytes = inner.as_bytes();
    let mut split_pos: Option<usize> = None;
    for i in 1..bytes.len() {
        if bytes[i] == b'+' || bytes[i] == b'-' {
            // The part before must look like a register (alnum, no digits after start).
            let lhs = &inner[..i];
            if is_reg_name(lhs) {
                split_pos = Some(i);
                break;
            }
        }
    }

    match split_pos {
        Some(i) => {
            let reg = inner[..i].trim().to_string();
            let off_str = inner[i..].trim();
            let off = parse_int(off_str)?;
            Some(ParsedMemory {
                base: Some(reg),
                offset: off,
            })
        }
        None => {
            // Bare register: [ecx]
            if is_reg_name(inner) {
                Some(ParsedMemory {
                    base: Some(inner.to_string()),
                    offset: 0,
                })
            } else {
                None
            }
        }
    }
}

fn is_reg_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
}

fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim().trim_start_matches('+');
    let negative = s.starts_with('-');
    let digits = s.trim_start_matches('-');
    let digits = digits.trim_start_matches("0x").trim_start_matches("0X");
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let v = i64::from_str_radix(digits, 16).ok()?;
    Some(if negative { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reg_plus_offset() {
        let p = parse_memory_operand("memory operand: [ecx+0x24]").unwrap();
        assert_eq!(p.base.as_deref(), Some("ecx"));
        assert_eq!(p.offset, 0x24);
    }

    #[test]
    fn parse_reg_minus_offset() {
        let p = parse_memory_operand("[esi-0x18]").unwrap();
        assert_eq!(p.base.as_deref(), Some("esi"));
        assert_eq!(p.offset, -0x18);
    }

    #[test]
    fn parse_pure_constant() {
        let p = parse_memory_operand("memory address: [0x46e920]").unwrap();
        assert_eq!(p.base, None);
        assert_eq!(p.offset, 0x46E920);
    }

    #[test]
    fn parse_bare_register() {
        let p = parse_memory_operand("[eax]").unwrap();
        assert_eq!(p.base.as_deref(), Some("eax"));
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn parse_leading_plus_zydis() {
        let p = parse_memory_operand("[+ecx+0x100]").unwrap();
        assert_eq!(p.base.as_deref(), Some("ecx"));
        assert_eq!(p.offset, 0x100);
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_memory_operand("no brackets").is_none());
        assert!(parse_memory_operand("[esp*4]").is_none());
    }
}
