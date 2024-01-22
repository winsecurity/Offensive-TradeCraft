pub fn getcachedtickets(){
    unsafe{

        let mut lsahandle = 0 as *mut c_void;
        let ntstatus = LsaConnectUntrusted(&mut lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaConnectUntrusted failed: {}",ntstatus);
            return ();
        }
        println!("[+] LsaConnectUntrusted connection success");


        let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
        let mut buffer = "Kerberos".bytes().collect::<Vec<u8>>();
        lsastring.Length = buffer.len() as u16;
        lsastring.MaximumLength = buffer.len() as u16 ;
        lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;

        
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
             &mut lsastring, &mut packagehandle);
       
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
        }
        println!("packagehandle: {:x?}",packagehandle);

        
        let mut requestcache =std::mem::zeroed::<KERB_QUERY_TKT_CACHE_REQUEST>();
        requestcache.MessageType = KerbQueryTicketCacheMessage;
        requestcache.LogonId = std::mem::zeroed::<LUID>();


        let mut tcktresp = 0 as *mut c_void;
        let mut returnlen = 0;
        let mut pstatus = 0;
        let res =LsaCallAuthenticationPackage(lsahandle, 
            packagehandle,
             &mut requestcache as *mut _ as *mut c_void, 
             std::mem::size_of_val(&requestcache) as u32, 
             &mut tcktresp, 
             &mut returnlen,
              &mut pstatus);
        if res!=STATUS_SUCCESS{
            println!("LsaCallAuthenticationPackage failed: {}",res);
        }
        
        println!("res: {:x?}",res);
        println!("returned length: {}",returnlen);
        println!("ticket response: {:x?}",tcktresp);
        println!("protocol status: {:x?}",pstatus);

        if returnlen>0{
            let tickets = RemoteParse::<KERB_QUERY_TKT_CACHE_RESPONSE>(GetCurrentProcess(), tcktresp);
            if tickets.is_ok(){
                let ticketlist = tickets.unwrap();
                println!("Number of tickets in cache: {}",ticketlist.CountOfTickets);
                
                for i in 0..ticketlist.CountOfTickets{
                   
                   let ticketcacheinfo =  *((tcktresp as usize + 8 + (i as usize * std::mem::size_of::<KERB_TICKET_CACHE_INFO>())) as *mut KERB_TICKET_CACHE_INFO);
                    let servername = unicodetostring(std::mem::transmute(&ticketcacheinfo.ServerName), GetCurrentProcess());
                    let realmname = unicodetostring(std::mem::transmute(&ticketcacheinfo.RealmName), GetCurrentProcess());
                
                    println!("servername: {}",servername);
                    println!("realmname: {}",realmname);
                    println!("ticket flags: {:x?}",ticketcacheinfo.TicketFlags);
                    
                    let starttime = LargeIntegerToSystemTime(&ticketcacheinfo.StartTime).unwrap();
                    let endtime = LargeIntegerToSystemTime(&ticketcacheinfo.EndTime).unwrap();
                    let renewtime = LargeIntegerToSystemTime(&ticketcacheinfo.RenewTime).unwrap();

                    println!("Start Time: {}",starttime);
                    println!("End Time: {}",endtime);
                    println!("Renew Time: {}",renewtime);
                    println!();


                }
            
            }    

        }

        let ntstatus = LsaDeregisterLogonProcess(lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaDeregisterLogonProcess failed: {:x?}",ntstatus);
            return ();
        }
        println!("[+] Deregistering from lsa success");

    }
}




pub fn LargeIntegerToSystemTime(li: &LARGE_INTEGER)
-> Result<String, String>{
    unsafe{

        let mut st = std::mem::zeroed::<SYSTEMTIME>();
        let res = FileTimeToSystemTime(li as *const _ as *const FILETIME, &mut st);
        if res==0{
            return Err(format!("FileTimeToSystemTime failed: {}",GetLastError()));
        }

        return Ok(format!("day/month/year: {}/{}/{}, hr/min/sec: {}:{}:{}",
                st.wDay,st.wMonth,st.wYear,st.wHour,st.wMinute,st.wSecond));

    }
}



