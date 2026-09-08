// 20_dataflow: Complex data flow with multiple definitions and uses.
#[no_mangle]
pub extern "C" fn sample_20_dataflow(x: i32, y: i32) -> i32 {
    let mut a = x;
    let mut b = y;
    a = a + 1;
    b = b * 2;
    let c = a + b;
    a = c - 3;
    b = a & 0xFF;
    a + b + c
}

#[no_mangle]
pub extern "C" fn sample_20_liveness(flag: bool, x: i32) -> i32 {
    let a = x + 1;
    let b = x * 2;
    if flag {
        a
    } else {
        b
    }
}

fn main() {}
