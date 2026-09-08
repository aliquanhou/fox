// 17_loop_phi: Loop with phi node at loop header.
#[no_mangle]
pub extern "C" fn sample_17_loop_phi(n: i32) -> i32 {
    let mut sum = 0;
    let mut i = 0;
    while i < n {
        sum += i;
        i += 1;
    }
    sum
}

#[no_mangle]
pub extern "C" fn sample_17_factorial(n: u64) -> u64 {
    let mut result = 1u64;
    let mut i = 1u64;
    while i <= n {
        result *= i;
        i += 1;
    }
    result
}

fn main() {}
