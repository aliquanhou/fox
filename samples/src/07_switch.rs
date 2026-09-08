// 07_switch: Switch statement (jump table or branch chain)
// Expected: 1 function, multiple basic blocks, multiple conditional/unconditional edges

#[no_mangle]
pub extern "C" fn switch_dispatch(op: i32, a: i32, b: i32) -> i32 {
    match op {
        0 => a + b,
        1 => a - b,
        2 => a * b,
        3 => if b != 0 { a / b } else { 0 },
        4 => a % b,
        _ => -1,
    }
}

fn main() {
    let result = switch_dispatch(2, 6, 7);
    println!("{}", result);
}
