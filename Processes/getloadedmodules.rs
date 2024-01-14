pub fn getloadedmodules(prochandle: *mut c_void) -> HashMap<String,usize>{
    unsafe{
        let mut modules: HashMap<String,usize> = HashMap::new();
        let mut bytesneeded = 1024 as u32;
        let mut buffer = loop{

            let mut buffer2 = vec![0u8;bytesneeded as usize];
            let ntstatus = NtQueryInformationProcess(prochandle, 
                0, 
                buffer2.as_mut_ptr() as *mut c_void, 
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                 &mut bytesneeded);
            if NT_SUCCESS(ntstatus){
                break buffer2;
            }
        };

        

        let pbi = *(buffer.as_mut_ptr() as *mut PROCESS_BASIC_INFORMATION);
        let peb = RemoteParse::<PEB>(prochandle, pbi.PebBaseAddress as *const c_void).unwrap();
        let ldrdata = RemoteParse::<PEB_LDR_DATA>(prochandle, peb.Ldr as *const c_void).unwrap();
    
        let firstentry = ldrdata.InLoadOrderModuleList.Flink;

        let table1 = RemoteParse::<LDR_DATA_TABLE_ENTRY>(prochandle, firstentry as *const c_void).unwrap();
        
        let mut nexttable = table1.clone();
        //println!("{:x?}",firstentry);
        let dllname = unicodetostring(&table1.BaseDllName, prochandle);
        let dllbaseaddress = table1.DllBase;
        modules.insert(dllname.trim_end_matches("\0").to_string(), dllbaseaddress as usize);
       


        loop{

            if nexttable.InLoadOrderLinks.Flink == firstentry{
                break;
            }
            
            nexttable = RemoteParse::<LDR_DATA_TABLE_ENTRY>(prochandle, nexttable.InLoadOrderLinks.Flink as *const c_void).unwrap();
            let dllname = unicodetostring(&nexttable.BaseDllName, prochandle);
            let dllbaseaddress = nexttable.DllBase;
            modules.insert(dllname.trim_end_matches("\0").to_string(), dllbaseaddress as usize);
       
            
        
        }

        return modules;

    }
}

