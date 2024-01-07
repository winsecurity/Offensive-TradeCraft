pub fn getlogonsessions(){
    unsafe{

        let mut numberofsessions = 0;
        let mut temppointer = 0 as *mut LUID;
        let res = LsaEnumerateLogonSessions(&mut numberofsessions,
             &mut temppointer);

        if res!=STATUS_SUCCESS{
            println!("LsaEnumerateLogonSessions failed: {}",res);
            return ();
        }    

        println!("number of sessions: {}",numberofsessions);
        for i in 0..numberofsessions{
            let mut luid1 = *((temppointer as usize + (i as usize*std::mem::size_of::<LUID>()) )as *mut LUID);
            
            let mut sessiondata = 0 as *mut SECURITY_LOGON_SESSION_DATA;
            let status = LsaGetLogonSessionData(&mut luid1, 
                &mut sessiondata as *mut *mut SECURITY_LOGON_SESSION_DATA);
            
            if status!=STATUS_SUCCESS{
                println!("LsaGetLogonSessionData failed: {}",status);
                continue;
            }

            let mut logondata = *(sessiondata );
            
            let username=   lsaunicodetostring(&logondata.UserName, GetCurrentProcess());
            let domainname =   lsaunicodetostring(&logondata.LogonDomain, GetCurrentProcess());

            println!("Username: {}",username);
            println!("Domain name: {}",domainname);
            println!("Logon type: {}",logondata.LogonType);
            println!("luid1 high: {:x?}",luid1.HighPart);
            println!("luid1 low: {:x?}",luid1.LowPart);
            println!();
        }

    }
}
