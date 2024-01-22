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

        let mut name1 = "cifs/win2016".encode_utf16().collect::<Vec<u16>>();
        let mut targetservice = std::mem::zeroed::<UNICODE_STRING>();
        targetservice.Buffer = name1.as_mut_ptr() as *mut u16;
        targetservice.Length = name1.len() as u16;
        targetservice.MaximumLength = (name1.len() as u16) + 1;


        let mut ticketrequest: KERB_RETRIEVE_TKT_REQUEST = std::mem::zeroed::<KERB_RETRIEVE_TKT_REQUEST>();
        ticketrequest.MessageType = KerbRetrieveTicketMessage;
        ticketrequest.LogonId = std::mem::zeroed::<LUID>();
        ticketrequest.TargetName = std::mem::transmute(targetservice) ;
        ticketrequest.TicketFlags = 0;
        ticketrequest.CacheOptions = 0;
        //ticketrequest.EncryptionType = KERB_ETYPE_NULL;
        
        let mut tcktresp = 0 as *mut c_void;
        let mut returnlen = 0;
        let mut pstatus = 0;
        let res =LsaCallAuthenticationPackage(lsahandle, 
            packagehandle,
             &mut ticketrequest as *mut _ as *mut c_void, 
             std::mem::size_of_val(&ticketrequest) as u32, 
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

        /*if returnlen>0{
            let extticket = RemoteParse::<KERB_EXTERNAL_TICKET>(GetCurrentProcess(), tcktresp);
            if extticket.is_ok(){
                let ticket = extticket.unwrap();
                
                
                println!("domainname: {}",unicodetostring(std::mem::transmute(&ticket.DomainName), GetCurrentProcess()));
                println!("Ticket flags: {}",ticket.Flags);
                println!("Encoded ticket size: {}",ticket.EncodedTicketSize);

                /*let mut servicename = *(ticket.ClientName);
                for i in 0..servicename.NameCount{
                    let eachname = *( ((&mut servicename as *mut _ as usize)+ 4 + (i as usize*std::mem::size_of::<UNICODE_STRING>())) as *mut UNICODE_STRING);
                    println!("servicename: {}",unicodetostring(&eachname, GetCurrentProcess()));
                }*/

                println!("{}",ReadStringFromMemory(GetCurrentProcess(), ticket.EncodedTicket as *mut c_void));

            }    

        }*/

        let ntstatus = LsaDeregisterLogonProcess(lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaDeregisterLogonProcess failed: {:x?}",ntstatus);
            return ();
        }
        println!("[+] Deregistering from lsa success");
