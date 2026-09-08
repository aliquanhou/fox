// 05_call: Function with direct calls
// Expected: >=2 functions, direct call edges

#[no_mangle]
pub extern "C" fn helper(x: i32) -> i32 {
    x * 2
}

#[no_mangle]
pub extern "C" fn caller(a: i32, b: i32) -> i32 {
    let x = helper(a);
    let y = helper(b);
    x + y
}

fn main() {
    let result = caller(3, 4);
    println!("{}", result);
}
