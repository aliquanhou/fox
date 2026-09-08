// 19_constant_propagation: Constant folding and propagation.
#[no_mangle]
pub extern "C" fn sample_19_constant_math() -> i32 {
    let a = 10;
    let b = 20;
    let c = a + b;       // 30
    let d = c * 2;       // 60
    let e = d - 5;       // 55
    e
}

#[no_mangle]
pub extern "C" fn sample_19_constant_branch(x: i32) -> i32 {
    let base = 100;
    if x > 0 {
        base + 10        // 110
    } else {
        base - 10        // 90
    }
}

fn main() {}
