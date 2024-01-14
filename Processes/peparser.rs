#![allow(dead_code)]

use std::collections::HashMap;
use std::{fs::File, io::Read};

use ntapi::ntobapi::NtQueryObject;
use ntapi::ntobapi::OBJECT_INFORMATION_CLASS;
use ntapi::ntobapi::OBJECT_TYPE_INFORMATION;
use ntapi::ntpsapi::PROCESSINFOCLASS;
use winapi::ctypes::*;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::shared::sddl::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::DuplicateHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::lsalookup::LSA_UNICODE_STRING;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::memoryapi::*;
use winapi::um::ntlsa::SECURITY_LOGON_SESSION_DATA;
use winapi::um::ntsecapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winnt::{TOKEN_INFORMATION_CLASS, TOKEN_USER};
use winapi::um::ntlsa::*;
use ntapi::ntexapi::*;
use winapi::um::synchapi::*;
use winapi::um::tlhelp32::*;
use winapi::shared::winerror::*;
use itertools::Itertools;
use winapi::um::memoryapi::*;

pub struct peparser{
    pub filecontents: Vec<u8>,
    pub memorycontents:Vec<u8>
}


// associated functions
impl peparser{

    fn parsefromfile(filepath:&str) -> Result<peparser, String>{
        let res = File::open(filepath);
        if res.is_err(){
            return Err(res.err().unwrap().to_string());
        }
        let mut buffer = vec![0u8;4096000];
        let res2 = res.unwrap().read(&mut buffer);
        if res2.is_err(){
            return Err(res2.err().unwrap().to_string());
        }
        // checking if its pe file or not
        if buffer[0]!=0x4d && buffer[1]!=0x5a{
            
            return Err("Not a valid PE file".to_string());
        }

        return Ok(peparser{filecontents:buffer,memorycontents:Vec::new()});

    }


    fn parsefrommemory(prochandle:*mut c_void,baseaddress:*const c_void)
    -> Result<peparser,String>{

        // checking if memory points to pe file or not
        let dosheader = RemoteParse::<IMAGE_DOS_HEADER>(prochandle, baseaddress);
        if dosheader.is_err(){
            return Err(dosheader.err().unwrap().to_string());
        }

        if dosheader.unwrap().e_magic!=0x5a4d{
            return Err(format!("Not a valid pe file"));
        }


        let ntheader = RemoteParse::<IMAGE_NT_HEADERS64>(prochandle, baseaddress);
        if ntheader.is_err(){
            return Err(ntheader.err().unwrap().to_string());
        }
        let ntheader = ntheader.unwrap();
        if ntheader.FileHeader.Machine!=0x8664{
            return Err("can only parse 64bit".to_string());
        }

        let mut buffer = vec![0;ntheader.OptionalHeader.SizeOfImage as usize];
        unsafe{
            let mut bytesread = 0;
            let res = ReadProcessMemory(prochandle, baseaddress, 
            buffer.as_mut_ptr() as *mut c_void, 
            buffer.len(), &mut bytesread);
        
            if res==0{
                return Err(format!("readprocessmemory failed: {}",GetLastError()));
            }

        }

        return Ok(peparser{filecontents:Vec::new(),memorycontents:buffer});

    }


}



impl peparser{

    fn getdosheader(&self) -> IMAGE_DOS_HEADER{
        if self.filecontents.len()>1{
            unsafe{
                let dosheader = RemoteParse::<IMAGE_DOS_HEADER>(GetCurrentProcess(), self.filecontents.as_ptr() as *const c_void);
                return dosheader.unwrap();
            }
        }
        else if self.memorycontents.len()>1{
            unsafe{
                let dosheader = RemoteParse::<IMAGE_DOS_HEADER>(GetCurrentProcess(), self.memorycontents.as_ptr() as *const c_void);
                return dosheader.unwrap();
            }
        }
        else{
            return unsafe{std::mem::zeroed::<IMAGE_DOS_HEADER>()};
        }

    }

    fn getntheader(&self) -> IMAGE_NT_HEADERS64{
        if self.filecontents.len()>1{
            unsafe{
                let dosheader = self.getdosheader();
                return RemoteParse::<IMAGE_NT_HEADERS64>(GetCurrentProcess(), (self.filecontents.as_ptr() as usize + dosheader.e_lfanew as usize) as *const c_void).unwrap();
            }
        }

        else if self.memorycontents.len()>1{
            unsafe{
                let dosheader = self.getdosheader();
                return RemoteParse::<IMAGE_NT_HEADERS64>(GetCurrentProcess(), (self.memorycontents.as_ptr() as usize + dosheader.e_lfanew as usize) as *const c_void).unwrap();
            }
        }
        else{
            return unsafe{std::mem::zeroed::<IMAGE_NT_HEADERS64>()};
        }

    }


    fn getsectionheaders(&self) -> Vec<IMAGE_SECTION_HEADER> {
        if self.filecontents.len()>1{
            unsafe{
                let dosheader = self.getdosheader();
                let ntheader = self.getntheader();
                let mut sections:Vec<IMAGE_SECTION_HEADER> = Vec::new();
                let mut baseaddress = self.filecontents.as_ptr() as *const c_void;
                for i in 0..ntheader.FileHeader.NumberOfSections{
                    let section = RemoteParse::<IMAGE_SECTION_HEADER>(GetCurrentProcess(), (baseaddress as usize + dosheader.e_lfanew as usize + 
                        std::mem::size_of_val(&ntheader) as usize + 
                        (i as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>())) as *const c_void);
                    sections.push(section.unwrap());
                }
                return sections;
            }
        }
        else {
            unsafe{
                let dosheader = self.getdosheader();
                let ntheader = self.getntheader();
                let mut sections:Vec<IMAGE_SECTION_HEADER> = Vec::new();
                let mut baseaddress = self.memorycontents.as_ptr() as *const c_void;
                for i in 0..ntheader.FileHeader.NumberOfSections{
                    let section = RemoteParse::<IMAGE_SECTION_HEADER>(GetCurrentProcess(), (baseaddress as usize + dosheader.e_lfanew as usize + 
                        std::mem::size_of_val(&ntheader) as usize + 
                        (i as usize * std::mem::size_of::<IMAGE_SECTION_HEADER>())) as *const c_void);
                    sections.push(section.unwrap());
                }
                return sections;
            }
        }
    }


    fn rvatofileoffset(&self,rva:usize) -> Result<usize,String>{
        let sections = self.getsectionheaders();
        for i in 0..sections.len(){
            if rva>=sections[i].VirtualAddress as usize && (rva<=(sections[i].VirtualAddress as usize+unsafe{*sections[i].Misc.VirtualSize()} as usize)){
                let mut fileoffset = rva - sections[i].VirtualAddress as usize;
                 fileoffset += sections[i].PointerToRawData as usize;
                 return Ok(fileoffset);
            }
        }
        return Err("rva not found in sections".to_string());
    }


    fn getimports(&self) -> Result<Vec<HashMap<String,HashMap<String,Vec<usize>>>>, String>{
        
        if self.filecontents.len()>0{
            let mut imports:Vec<HashMap<String,HashMap<String,Vec<usize>>>> = Vec::new();
            

            let ntheader = self.getntheader();
            if ntheader.OptionalHeader.DataDirectory[1].Size==0{
                return Err("no imports".to_string());
            }
           
            let mut firstimportaddress = self.filecontents.as_ptr() as usize + (self.rvatofileoffset(ntheader.OptionalHeader.DataDirectory[1].VirtualAddress as usize).unwrap());
            
            let mut dlls:HashMap<String,HashMap<String,Vec<usize>>> = HashMap::new();
           

            loop{
                
                let firstimport= unsafe{RemoteParse::<IMAGE_IMPORT_DESCRIPTOR>(GetCurrentProcess(), firstimportaddress as *const c_void)}.unwrap();

                if firstimport.Name == 0{
                    break;
                }
                
                let dllname = unsafe{
                    ReadStringFromMemory(GetCurrentProcess(),
                    (self.filecontents.as_ptr() as usize +
                     self.rvatofileoffset(firstimport.Name as usize).unwrap() as usize)
                     as *const c_void
                    )};
                
                
                let mut firstoft = self.filecontents.as_ptr() as usize + unsafe{self.rvatofileoffset(*firstimport.u.OriginalFirstThunk() as usize)}.unwrap();
                let mut firstft = self.filecontents.as_ptr() as usize + unsafe{self.rvatofileoffset(firstimport.FirstThunk as usize)}.unwrap();
                
                let mut funcs:HashMap<String,Vec<usize>> = HashMap::new();
            

                'funloop: loop{
                   
                    let mut thunks:Vec<usize> = Vec::new();
                    let mut oftbuffer = vec![0u8;8];
                    let mut bytesread = 0;
                    unsafe{
                        ReadProcessMemory(GetCurrentProcess(), 
                        firstoft as *mut c_void,
                        oftbuffer.as_mut_ptr() as *mut c_void ,
                        8 , 
                        &mut bytesread);
                    }
                    let importbyname = u64::from_ne_bytes(oftbuffer.try_into().unwrap());
                    //let importbyname = unsafe{RemoteParse::<IMAGE_IMPORT_BY_NAME>(GetCurrentProcess(), firstoft as *const c_void)}.unwrap();
                    
                    if importbyname == 0{
                        break 'funloop;
                    }


                    // reading firstthunk
                    let mut ftbuffer = vec![0u8;8];
                    let mut bytesread = 0;
                    unsafe{
                        ReadProcessMemory(GetCurrentProcess(), 
                        firstft as *mut c_void,
                        ftbuffer.as_mut_ptr() as *mut c_void ,
                        8 , 
                        &mut bytesread);
                    }



                    thunks.push(importbyname as usize);
                    thunks.push(u64::from_ne_bytes(ftbuffer.try_into().unwrap()) as usize);

                    let funcaddress = unsafe { self.filecontents.as_ptr() as usize + 2 + self.rvatofileoffset(importbyname as usize).unwrap() };
                    let functionname = unsafe{
                        ReadStringFromMemory(GetCurrentProcess(), funcaddress as *const c_void)
                    };
                   

                    funcs.insert(functionname, thunks);

                    firstoft += 8 as usize;
                    firstft += 8 as usize;
                }
                
                dlls.insert(dllname, funcs);

                firstimportaddress += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
                println!();
            }
            

            imports.push(dlls);
            return Ok(imports);
        }

        return Ok(Vec::new());
    }



}



fn main() {
    
    let mut pe = peparser::parsefromfile("D:\\red teaming tools\\rust_tooling\\tokens\\target\\release\\tokens.exe");
    if pe.is_err(){
        println!("{}", pe.err().unwrap().to_string());
        return ();
    }
    let mut pe = pe.unwrap();
    println!("{:x?}",pe.getdosheader().e_magic);
    println!("{:x?}",pe.getdosheader().e_lfanew);

    let ntheader = pe.getntheader();
    println!("{:x?}",ntheader.Signature);
    println!("{:x?}",ntheader.FileHeader.Machine);
    println!("{:x?}",ntheader.OptionalHeader.SizeOfImage);
    println!("{:x?}",ntheader.OptionalHeader.SizeOfHeaders);
    println!("{:x?}",ntheader.OptionalHeader.DataDirectory[1].VirtualAddress);

    
    let sections = pe.getsectionheaders();
    for i in 0..sections.len(){
        println!("section name: {}",
        unsafe{ReadStringFromMemory(GetCurrentProcess(), sections[i].Name.as_ptr() as *const c_void)});
        println!("raw address: {:x?}",sections[i].PointerToRawData);
        println!("raw size: {:x?}",sections[i].SizeOfRawData);
        println!("virtual address: {:x?}",sections[i].VirtualAddress);
        println!("virtual size: {:x?}",
        unsafe{sections[i].Misc.VirtualSize()});
        println!();
    }

    println!("{:x?}",pe.getimports().unwrap());


}


pub fn RemoteParse<T>(prochandle:*mut c_void, baseaddress:*const c_void)
 -> Result<T, String> where T:Copy,{
    unsafe{
        
        let ssize = std::mem::size_of::<T>();
        let mut buffer = vec![0u8;ssize];
        let mut bytesread = 0;
        let res = ReadProcessMemory(prochandle, baseaddress,
             buffer.as_mut_ptr() as *mut c_void, 
             buffer.len(), 
            &mut bytesread);
        if res==0{
            return Err(format!("readprocessmemory failed: {}",GetLastError()));
        }

        return Ok(*(buffer.as_mut_ptr() as *mut T));
    }
}





pub fn ReadStringFromMemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut i: isize = 0;
        let mut s = String::new();
        loop {
            let mut a: [u8; 1] = [0];
            ReadProcessMemory(
                prochandle,
                (base as isize + i) as *const c_void,
                a.as_mut_ptr() as *mut c_void,
                1,
                std::ptr::null_mut(),
            );

            if a[0] == 0 || i == 50 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}
