// 15_global_variable: Global variable access (RIP-relative).
static mut GLOBAL_COUNTER: u64 = 0;
static GLOBAL_CONST: u32 = 42;

#[no_mangle]
pub extern "C" fn sample_15_global_increment() -> u64 {
    unsafe {
        GLOBAL_COUNTER += 1;
        GLOBAL_COUNTER
    }
}

#[no_mangle]
pub extern "C" fn sample_15_global_read() -> u32 {
    GLOBAL_CONST
}

#[no_mangle]
pub extern "C" fn sample_15_global_reset() {
    unsafe {
        GLOBAL_COUNTER = 0;
    }
}

fn main() {}
