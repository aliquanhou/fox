// 03_loop: Simple loop with conditional branch
// Expected: 1 function, >=3 basic blocks, loop back edge, 0 calls

#[no_mangle]
pub extern "C" fn loop_sum(n: i32) -> i32 {
    let mut sum = 0;
    for i in 0..n {
        sum += i;
    }
    sum
}

fn main() {
    let result = loop_sum(100);
    println!("{}", result);
}
