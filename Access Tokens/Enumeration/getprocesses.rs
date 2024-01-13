pub fn getprocesses(){
    unsafe{
        let mut bytesneeded = 0u32;
        let mut ntstatus = 0i32;
        let mut buffer = loop {
            let mut buffer = vec![0u8;bytesneeded as usize];
            ntstatus = NtQuerySystemInformation(5, 
                buffer.as_mut_ptr() as *mut c_void, 
                bytesneeded, 
                &mut bytesneeded);

            if NT_SUCCESS(ntstatus){
                break buffer;
            }

        };

        let mut nextbase = buffer.as_mut_ptr();
        loop{
           
            let procinfo = *(nextbase as *mut SYSTEM_PROCESS_INFORMATION);
            println!("processname: {} \t pid: {}",
            unicodetostring(&procinfo.ImageName, GetCurrentProcess()),procinfo.UniqueProcessId as usize);
            let nextoffset = std::ptr::read(nextbase as *const u32);
            if nextoffset == 0{
                break;
            }
            nextbase = (nextbase as usize+ nextoffset as usize) as *mut u8;
            
        }

        
    }
}

