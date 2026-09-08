// 09_function_pointer: Indirect call via function pointer
// Expected: indirect call edge (CallEdgeKind::Indirect)

type BinOp = extern "C" fn(i32, i32) -> i32;

#[no_mangle]
pub extern "C" fn add_op(a: i32, b: i32) -> i32 { a + b }

#[no_mangle]
pub extern "C" fn mul_op(a: i32, b: i32) -> i32 { a * b }

#[no_mangle]
pub extern "C" fn apply_op(op: BinOp, a: i32, b: i32) -> i32 {
    op(a, b)
}

fn main() {
    let result = apply_op(add_op, 3, 4);
    println!("{}", result);
}
