pub fn msv10auth(){
    unsafe{
        

        let mut lsahandle = 0 as *mut c_void;
        //let mut secmode = 0;
        //let mut lsastring = mylsastring::new("User32LogonProcess");
        let ntstatus = LsaConnectUntrusted(&mut lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaRegisterLogonProcess failed: {:x?}",ntstatus);
            return ();
        }


        let mut kerberos = mylsastring::new("MSV1_0");
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
            &mut kerberos as *mut _ as *mut LSA_STRING,
             &mut packagehandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
            return ();
        }


        let mut ilogon = std::mem::zeroed::<MSV1_0_INTERACTIVE_LOGON>();
        ilogon.MessageType = MsV1_0InteractiveLogon;
        
        let mut username = std::mem::zeroed::<UNICODE_STRING>();
        let mut usernamebuffer = "test1".encode_utf16().collect::<Vec<u16>>();
        username.Buffer = usernamebuffer.as_mut_ptr() as *mut u16;
        username.Length = usernamebuffer.len() as u16;
        username.MaximumLength = usernamebuffer.len() as u16 + 1;


        let mut password = std::mem::zeroed::<UNICODE_STRING>();
        let mut passwordbuffer = "HASHHERE".encode_utf16().collect::<Vec<u16>>();
        password.Buffer = passwordbuffer.as_mut_ptr() as *mut u16;
        password.Length = passwordbuffer.len() as u16;
        password.MaximumLength = passwordbuffer.len() as u16 + 1;



        let mut domain = std::mem::zeroed::<UNICODE_STRING>();
        let mut domainbuffer = "tech69.local".encode_utf16().collect::<Vec<u16>>();
        domain.Buffer = domainbuffer.as_mut_ptr() as *mut u16;
        domain.Length = domainbuffer.len() as u16;
        domain.MaximumLength = domainbuffer.len() as u16 + 1;

        ilogon.UserName = std::mem::transmute(username);
        ilogon.Password = std::mem::transmute(password);
        ilogon.LogonDomainName = std::mem::transmute(domain);


        let mut tokensource = std::mem::zeroed::<TOKEN_SOURCE>();
        tokensource.SourceName = (*b"User32\0\0").map(|u| u as i8);
        tokensource.SourceIdentifier = std::mem::zeroed::<LUID>();


        let mut origin = std::mem::zeroed::<LSA_STRING>();
        let mut buffer3 = "Testingorigin".bytes().collect::<Vec<u8>>();
        origin.Length = buffer3.len() as u16;
        origin.MaximumLength = buffer3.len() as u16+1;
        origin.Buffer = buffer3.as_mut_ptr() as *mut i8;


        let mut profilebuf = 0 as *mut c_void;
        let mut profilebuflength = 0;
        let mut luid = std::mem::zeroed::<LUID>();
        let mut tokenhandle = 0 as *mut c_void;
        let mut quota = std::mem::zeroed::<QUOTA_LIMITS>();
        let mut logonstatus = 0;
        let ntstatus = LsaLogonUser(lsahandle, 
           &mut origin ,
            2, 
            packagehandle,
             &mut ilogon as *mut _ as *mut c_void, 
             std::mem::size_of::<MSV1_0_INTERACTIVE_LOGON>() as u32,
              std::ptr::null_mut(), 
              &mut tokensource, 
             &mut profilebuf , 
             &mut profilebuflength, 
             &mut luid, 
             &mut tokenhandle, 
             &mut quota, &mut logonstatus);

        println!("logon status: {:x?}",logonstatus);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLogonUser failed: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
            return ();
        }

        LsaFreeMemory(profilebuf);

        LsaDeregisterLogonProcess(lsahandle);




    }
}

