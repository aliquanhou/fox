// 02_branch: Simple if/else conditional branch
// Expected: 1 function, >=3 basic blocks, >=2 CFG edges (cond true/false), 0 calls

#[no_mangle]
pub extern "C" fn branch_max(a: i32, b: i32) -> i32 {
    if a > b {
        a
    } else {
        b
    }
}

fn main() {
    let result = branch_max(10, 20);
    println!("{}", result);
}
