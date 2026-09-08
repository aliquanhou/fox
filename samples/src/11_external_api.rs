// 11_external_api: Calls Windows API functions to test IAT resolution.
#[link(name = "kernel32")]
extern "system" {
    fn GetTickCount() -> u32;
    fn Sleep(ms: u32);
}

#[no_mangle]
pub extern "C" fn sample_11_external_api() -> u32 {
    unsafe {
        let start = GetTickCount();
        Sleep(10);
        let end = GetTickCount();
        end - start
    }
}

fn main() {}
