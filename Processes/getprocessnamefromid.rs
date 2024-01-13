
pub fn getprocessnamefromid(pid: usize) -> Result<String,String>{
    unsafe{
        let res = getprocesses();
        if res.is_err(){
            return Err(format!("process not found"));
        }
        if res.is_ok(){
            for (k,v) in res.unwrap(){
                if v==pid{
                    return Ok(format!("{}",k));
                }
            }
        }

        return Err(format!("process not found"));
    }
}








pub fn getprocesses() -> Result<HashMap<String,usize>,String>{
    unsafe{
        let mut allprocs:HashMap<String,usize> = HashMap::new(); 
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
            
            allprocs.insert(unicodetostring(&procinfo.ImageName, GetCurrentProcess())
            .trim_end_matches("\0").to_string(), procinfo.UniqueProcessId as usize);
            let nextoffset = std::ptr::read(nextbase as *const u32);
            if nextoffset == 0{
                break;
            }
            nextbase = (nextbase as usize+ nextoffset as usize) as *mut u8;
            
        }

        return Ok(allprocs);
        
    }
}
