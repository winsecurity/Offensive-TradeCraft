use ntapi::ntpebteb::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winnt::{TOKEN_INFORMATION_CLASS, TOKEN_USER};
use winapi::um::ntlsa::*;
use ntapi::ntexapi::*;
use winapi::um::synchapi::*;
use winapi::um::tlhelp32::*;
use winapi::shared::winerror::*;
pub fn getprocessbaseaddress(prochandle: *mut c_void) -> usize{
    unsafe{
        let mut bytesneeded = 1024 as u32;
        let mut buffer = loop{

            let mut buffer2 = vec![0u8;bytesneeded as usize];
            let ntstatus = NtQueryInformationProcess(prochandle, 
                0, 
                buffer2.as_mut_ptr() as *mut c_void, 
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                 &mut bytesneeded);
            if NT_SUCCESS(ntstatus){
                break buffer2;
            }
        };

        

        let pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);
        let peb = RemoteParse::<PEB>(prochandle, pbi.PebBaseAddress as *const c_void).unwrap();
        return peb.ImageBaseAddress as usize;
        
    }
}
