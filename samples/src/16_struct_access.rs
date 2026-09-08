// 16_struct_access: Struct field access (memory layout).
#[repr(C)]
pub struct Point {
    x: i32,
    y: i32,
}

#[repr(C)]
pub struct Rectangle {
    top_left: Point,
    bottom_right: Point,
    width: u32,
    height: u32,
}

#[no_mangle]
pub extern "C" fn sample_16_struct_area(r: *const Rectangle) -> u64 {
    unsafe {
        let w = (*r).width as u64;
        let h = (*r).height as u64;
        w * h
    }
}

#[no_mangle]
pub extern "C" fn sample_16_struct_move(p: *mut Point, dx: i32, dy: i32) {
    unsafe {
        (*p).x += dx;
        (*p).y += dy;
    }
}

fn main() {}
