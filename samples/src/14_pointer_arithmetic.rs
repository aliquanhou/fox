// 14_pointer_arithmetic: Pointer arithmetic and array access.
#[no_mangle]
pub extern "C" fn sample_14_pointer_arithmetic(arr: *mut i32, len: usize, idx: usize) -> i32 {
    if idx >= len {
        return -1;
    }
    unsafe {
        let ptr = arr.add(idx);
        *ptr = *ptr * 2;
        *ptr
    }
}

#[no_mangle]
pub extern "C" fn sample_14_sum(arr: *const i32, len: usize) -> i64 {
    let mut sum: i64 = 0;
    unsafe {
        for i in 0..len {
            sum += *arr.add(i) as i64;
        }
    }
    sum
}

fn main() {}
