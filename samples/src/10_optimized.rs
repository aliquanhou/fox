// 10_optimized: Same as 02_branch but with optimization
// Compiled with opt-level=3 to test optimized code handling
// Expected: same semantic structure, possibly fewer blocks due to optimization

#[no_mangle]
pub extern "C" fn optimized_max(a: i32, b: i32) -> i32 {
    if a > b { a } else { b }
}

#[no_mangle]
pub extern "C" fn optimized_loop(n: i32) -> i32 {
    let mut sum = 0;
    for i in 0..n {
        sum += i * 2;
    }
    sum
}

fn main() {
    println!("{}", optimized_max(10, 20));
    println!("{}", optimized_loop(50));
}
