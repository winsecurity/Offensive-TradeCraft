use winapi::ctypes::*;
use winapi::shared::sddl::*;
use winapi::shared::*;
use winapi::um::memoryapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::*;

pub fn ConvertbytestoStringSID(mut sidbytes: Vec<u8>) -> String {
    unsafe {
        let mut temppointer = 0 as *mut i8;

        let res = ConvertSidToStringSidA(sidbytes.as_mut_ptr() as *mut c_void, &mut temppointer);
        //println!("temppointer: {}",temppointer as u64);

        let sid = ReadStringFromMemory(GetCurrentProcess(), temppointer as *mut c_void);

        return sid;
    }
}

pub fn ReadStringFromMemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut i: isize = 0;
        let mut s = String::new();
        loop {
            let mut a: [u8; 1] = [0];
            ReadProcessMemory(
                prochandle,
                (base as isize + i) as *const c_void,
                a.as_mut_ptr() as *mut c_void,
                1,
                std::ptr::null_mut(),
            );

            if a[0] == 0 || i == 50 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}
