// 08_pointer: Pointer operations and memory access
// Expected: 1 function, LOAD/STORE IR operations

#[no_mangle]
pub extern "C" fn pointer_sum(arr: *const i32, len: usize) -> i32 {
    let mut sum = 0;
    unsafe {
        for i in 0..len {
            sum += *arr.add(i);
        }
    }
    sum
}

fn main() {
    let arr = [1, 2, 3, 4, 5];
    let result = pointer_sum(arr.as_ptr(), arr.len());
    println!("{}", result);
}
