pub fn gettokenimpersonationlevel(tokenhandle: *mut c_void){
    unsafe{

        if isimpersonatedtoken(tokenhandle) == false{
            println!("Not an impersonation token");
            return ();
        }

        
        let mut bytesneeded = 0;
        let res = GetTokenInformation(tokenhandle, 
            9, std::ptr::null_mut(), 0, &mut bytesneeded);

        if bytesneeded == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            //return false;
        }

        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];
        let res = GetTokenInformation(
            tokenhandle,
            9,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytesneeded,
        );

        if res == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            //return false;
        }


        println!("{:?}",buffer);

    }
}
