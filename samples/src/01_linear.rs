// 01_linear: Linear function with no branches
// Expected: 1 function, 1 basic block, 0 CFG edges (except return), 0 calls

#[no_mangle]
pub extern "C" fn linear_add(a: i32, b: i32) -> i32 {
    let c = a + b;
    let d = c * 2;
    d - 1
}

fn main() {
    let result = linear_add(3, 4);
    println!("{}", result);
}
