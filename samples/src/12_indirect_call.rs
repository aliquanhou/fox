// 12_indirect_call: Function pointer / indirect call.
fn add(a: i32, b: i32) -> i32 { a + b }
fn sub(a: i32, b: i32) -> i32 { a - b }

type BinOp = fn(i32, i32) -> i32;

#[no_mangle]
pub extern "C" fn sample_12_indirect_call(use_add: bool, x: i32, y: i32) -> i32 {
    let op: BinOp = if use_add { add } else { sub };
    op(x, y)
}

fn main() {}
