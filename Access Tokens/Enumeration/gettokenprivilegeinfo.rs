pub fn gettokenprivilegeinfo(tokenhandle: *mut c_void) {
    unsafe {
        let mut bytesneeded = 0;
        let res = GetTokenInformation(tokenhandle, 3, std::ptr::null_mut(), 0, &mut bytesneeded);

        if bytesneeded == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];
        let res = GetTokenInformation(
            tokenhandle,
            3,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytesneeded,
        );

        if res == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let mut privs = *(buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES);

        for i in 0..privs.PrivilegeCount{
            let privname = luidtousernamew (&mut ((*((buffer.as_mut_ptr() as usize + 4 + 
            (i as usize * std::mem::size_of::<LUID_AND_ATTRIBUTES>()) ) as *mut LUID_AND_ATTRIBUTES) ).Luid ) );
            
            println!("{}",privname);
        }


    }
}
