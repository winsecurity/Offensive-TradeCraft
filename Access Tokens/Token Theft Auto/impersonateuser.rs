pub fn impersonatetoken(tokenhandle: *mut c_void){
    unsafe{

        let res = ImpersonateLoggedOnUser(tokenhandle);

        if res==0{
            println!("ImpersonateLoggedOnUser failed: {}",GetLastError());
        }

    }
}

