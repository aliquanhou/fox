// 04_nested_branch: Nested if/else
// Expected: 1 function, >=5 basic blocks, multiple conditional edges

#[no_mangle]
pub extern "C" fn nested_classify(a: i32, b: i32) -> i32 {
    if a > 0 {
        if b > 0 {
            1
        } else {
            2
        }
    } else {
        if b > 0 {
            3
        } else {
            4
        }
    }
}

fn main() {
    let result = nested_classify(1, -1);
    println!("{}", result);
}
