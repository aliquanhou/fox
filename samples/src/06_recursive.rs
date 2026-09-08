// 06_recursive: Recursive function
// Expected: 1 function with self-call, recursive call edge

#[no_mangle]
pub extern "C" fn factorial(n: i32) -> i32 {
    if n <= 1 {
        1
    } else {
        n * factorial(n - 1)
    }
}

fn main() {
    let result = factorial(10);
    println!("{}", result);
}
