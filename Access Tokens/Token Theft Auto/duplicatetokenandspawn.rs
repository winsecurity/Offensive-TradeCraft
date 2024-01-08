pub fn duplicatetokenandspawn(tokenhandle: *mut c_void){
    unsafe{

        let mut newtoken = 0 as *mut c_void;
        let res = DuplicateTokenEx(tokenhandle, 
            0, 
            std::ptr::null_mut(), 
            3, 
            1, 
            &mut newtoken);

        if res==0{
            println!("duplicatetokenex failed: {}",GetLastError());
            return();
        }


        let mut sinfo = std::mem::zeroed::<STARTUPINFOW>();
        sinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();

        let res = CreateProcessWithTokenW(
            newtoken, 
            1,
            "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16, 
            std::ptr::null_mut(), 
            0,
            std::ptr::null_mut()
             , std::ptr::null_mut(), 
             
              
             &mut sinfo, &mut pinfo);

        if res==0{
            println!("createprocessasuserw failed: {}",GetLastError());
            return()
        }

        //WaitForSingleObject(pinfo.hProcess, 0xFFFFFFFF);


    }
}
