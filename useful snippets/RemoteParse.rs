pub fn RemoteParse<T>(prochandle:*mut c_void, baseaddress:*const c_void)
 -> Result<T, String> where T:Copy,{
    unsafe{
        let mut t1 = std::mem::zeroed::<T>();
        let ssize = std::mem::size_of::<T>();
        let mut buffer = vec![0u8;ssize];
        let mut bytesread = 0;
        let res = ReadProcessMemory(prochandle, baseaddress,
             buffer.as_mut_ptr() as *mut c_void, 
             buffer.len(), 
            &mut bytesread);
        if res==0{
            return Err(format!("readprocessmemory failed: {}",GetLastError()));
        }
        return Ok(*(buffer.as_mut_ptr() as *mut T));
    }
}
