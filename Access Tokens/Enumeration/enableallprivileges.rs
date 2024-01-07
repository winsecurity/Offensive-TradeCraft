pub fn enableallprivileges(tokenhandle: *mut c_void){
    unsafe{
        let privileges = gettokenprivilegeinfo(tokenhandle);
        let privileges = match privileges{
            Ok(p) => p,
            Err(e) => {
                println!("{}",e.to_string());
                return ();
            }
        };
        println!("{:?}",privileges);
        let mut tokenprivs = std::mem::zeroed::<MY_TOKEN_PRIVILEGES>();
        tokenprivs.PrivilegeCount = privileges.len() as u32;
        let mut luids = vec![std::mem::zeroed::<LUID_AND_ATTRIBUTES>();privileges.len()];


        for i in 0..privileges.len(){
            let mut luid1 = std::mem::zeroed::<LUID>();
            let res = LookupPrivilegeValueA(std::ptr::null_mut(), 
                privileges[i].as_bytes().as_ptr() as *const i8, 
                &mut luid1);
            if res==0{
                println!("LookupPrivilegeValueA failed: {}",GetLastError());
                continue;
            }

            println!("luid low: {:?}",luid1.LowPart);
            println!("luid high: {:?}",luid1.HighPart);
            luids[i].Luid = luid1;
            luids[i].Attributes = SE_PRIVILEGE_ENABLED;

            let mut token1 = std::mem::zeroed::<TOKEN_PRIVILEGES>();
            token1.PrivilegeCount = 1 as u32;
            token1.Privileges = [luids[i]];
            let mut prevstate:Vec<u8> = vec![0;2048];
            let mut prevbytesneeded = 0;
            let res = AdjustTokenPrivileges(tokenhandle, 
                0, 
            &mut token1 as *mut _ as *mut TOKEN_PRIVILEGES, 
            prevstate.len() as u32, 
            prevstate.as_mut_ptr() as *mut TOKEN_PRIVILEGES, 
            &mut prevbytesneeded);
            if res == 0{
                println!("AdjustTokenPrivileges failed: {}",GetLastError());
            }

        }

        /*tokenprivs.Privileges = luids.as_mut_ptr() as *mut c_void;


        let mut prevstate:Vec<u8> = vec![0;2048];
        let mut prevbytesneeded = 0;
        let res = AdjustTokenPrivileges(tokenhandle, 
            0, 
            &mut tokenprivs as *mut _ as *mut TOKEN_PRIVILEGES, 
            prevstate.len() as u32, 
            prevstate.as_mut_ptr() as *mut TOKEN_PRIVILEGES, 
            &mut prevbytesneeded);
        
        if res == 0{
            println!("AdjustTokenPrivileges failed: {}",GetLastError());
        }*/

    }
}
