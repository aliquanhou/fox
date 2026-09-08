// 13_switch: Switch statement / jump table.
#[no_mangle]
pub extern "C" fn sample_13_switch(op: i32, a: i32, b: i32) -> i32 {
    match op {
        0 => a + b,
        1 => a - b,
        2 => a * b,
        3 => if b != 0 { a / b } else { 0 },
        4 => a & b,
        5 => a | b,
        6 => a ^ b,
        _ => -1,
    }
}

fn main() {}
