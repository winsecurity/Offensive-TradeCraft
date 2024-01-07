pub fn gettokenownerinfo(tokenhandle: *mut c_void){
    unsafe{

        let mut bytesneeded = 0;
        let res = GetTokenInformation(tokenhandle, 
            4, std::ptr::null_mut(), 0, &mut bytesneeded);

        if bytesneeded == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];
        let res = GetTokenInformation(
            tokenhandle,
            4,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytesneeded,
        );

        if res == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let tokenowner = *(buffer.as_mut_ptr() as *mut TOKEN_OWNER);

        let owner = sidtousernamew(tokenowner.Owner);
        println!("OWNER: {}",owner);
    }

}
