pub fn getallprochandles() -> Result<HashMap<u32,*mut c_void>,String>{
    unsafe{

        let snaphandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut prochandles:HashMap<u32,*mut c_void> = HashMap::new();

        if snaphandle == INVALID_HANDLE_VALUE{
            return Err(format!("createtoolhelp32snapshot failed: {}", GetLastError()));
            
        }

        let mut procentry = std::mem::zeroed::<PROCESSENTRY32>();
        procentry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        
        Process32First(snaphandle, &mut procentry);

        let phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, procentry.th32ProcessID);
        if !phandle.is_null(){
            prochandles.insert(procentry.th32ProcessID, phandle);
        }

        loop{

            let res = Process32Next(snaphandle, &mut procentry);
            if res==0 || res==ERROR_NO_MORE_FILES as i32{
                break;
            }

            let phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, procentry.th32ProcessID);
            if !phandle.is_null(){
                prochandles.insert(procentry.th32ProcessID, phandle);
            }

        }

        return Ok(prochandles);

    }
}

