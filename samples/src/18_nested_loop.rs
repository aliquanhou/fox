// 18_nested_loop: Nested loops (matrix sum).
#[no_mangle]
pub extern "C" fn sample_18_nested_loop(matrix: *const i32, rows: usize, cols: usize) -> i64 {
    let mut sum: i64 = 0;
    unsafe {
        for i in 0..rows {
            for j in 0..cols {
                sum += *matrix.add(i * cols + j) as i64;
            }
        }
    }
    sum
}

#[no_mangle]
pub extern "C" fn sample_18_bubble_sort(arr: *mut i32, n: usize) {
    unsafe {
        for i in 0..n {
            for j in 0..(n - i - 1) {
                if *arr.add(j) > *arr.add(j + 1) {
                    let tmp = *arr.add(j);
                    *arr.add(j) = *arr.add(j + 1);
                    *arr.add(j + 1) = tmp;
                }
            }
        }
    }
}

fn main() {}
