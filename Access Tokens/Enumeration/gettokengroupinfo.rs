use winapi::ctypes::*;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::shared::sddl::*;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::lsalookup::LSA_UNICODE_STRING;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::ntlsa::SECURITY_LOGON_SESSION_DATA;
use winapi::um::ntsecapi::SECURITY_LOGON_SESSION_DATA;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winnt::{TOKEN_INFORMATION_CLASS, TOKEN_USER};
use winapi::um::ntlsa::*;


pub fn gettokengroupinfo(tokenhandle: *mut c_void) {
    unsafe {
        let mut bytesneeded = 0;
        let res = GetTokenInformation(tokenhandle, 2, std::ptr::null_mut(), 0, &mut bytesneeded);

        if bytesneeded == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];
        let res = GetTokenInformation(
            tokenhandle,
            2,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytesneeded,
        );

        if res == 0 {
            println!("gettokeninformation failed: {}", GetLastError());
            return ();
        }

        let mut tokengroups = *(buffer.as_mut_ptr() as *mut TOKEN_GROUPS);

        for i in 0..tokengroups.GroupCount {
            let groups = *((buffer.as_ptr() as usize + (i as usize * 16)) as *const TOKEN_GROUPS);

            let groupname = sidtousernamew(groups.Groups[0].Sid);
            //println!("{}",groups.GroupCount);
            println!("{}", groupname);
        }
    }
}


pub fn luidtousernamew(luid:*mut LUID) -> String{
    unsafe{

        let mut bytesneeded = 0;

        LookupPrivilegeNameW(std::ptr::null_mut(), 
        luid as *mut LUID, 
            std::ptr::null_mut(), &mut bytesneeded);


        if bytesneeded ==0{
            return format!("lookupprivilegenamew failed: {}",GetLastError());
            
        }

        let mut privname:Vec<u16> = vec![0;bytesneeded as usize];
        let res = LookupPrivilegeNameW(std::ptr::null_mut(), 
        luid as *mut LUID, 
            privname.as_mut_ptr() as *mut u16, &mut bytesneeded);


        if res==0{
            return format!("lookupprivilegenamew failed: {}",GetLastError());
        }


        let privilege = String::from_utf16_lossy(&privname);
        return privilege;



    }
}


pub fn sidtousernamew(sid: *mut c_void) -> String {
    unsafe {
        let mut bytesneeded = 0;
        let mut domainbytesneeded = 0;
        let mut acctype = 0;
        let mut accname: Vec<u16> = vec![0; bytesneeded as usize];
        let mut domainname: Vec<u16> = vec![0; domainbytesneeded as usize];

        LookupAccountSidW(
            std::ptr::null_mut(),
            sid,
            accname.as_mut_ptr() as *mut u16,
            &mut bytesneeded,
            domainname.as_mut_ptr() as *mut u16,
            &mut domainbytesneeded,
            &mut acctype,
        );

        if bytesneeded == 0 {
            return format!("lookupaccountsidw failed to {}", GetLastError());
        }

        let mut accname: Vec<u16> = vec![0; bytesneeded as usize];
        let mut domainname: Vec<u16> = vec![0; domainbytesneeded as usize];

        let res = LookupAccountSidW(
            std::ptr::null_mut(),
            sid,
            accname.as_mut_ptr() as *mut u16,
            &mut bytesneeded,
            domainname.as_mut_ptr() as *mut u16,
            &mut domainbytesneeded,
            &mut acctype,
        );
        if res == 0 {
            println!("Lookupaccountsidw failed: {}", GetLastError());
            return String::new();
        }

        let accountname = String::from_utf16_lossy(&accname);
        let domain = String::from_utf16_lossy(&domainname);

        let mut finalstring = String::new();
        finalstring.push_str(&domain.trim());
        finalstring.push('\\');
        finalstring.push_str(&accountname);

        return finalstring;
    }
}

pub fn readunicodestringfrommemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut buffer: Vec<u16> = Vec::new();
        let mut i = 0;

        loop {
            let mut bytesread = 0;
            let mut temp: Vec<u16> = vec![0; 2];
            ReadProcessMemory(
                prochandle,
                (base as usize + (i * 2)) as *const c_void,
                temp.as_mut_ptr() as *mut c_void,
                2,
                &mut bytesread,
            );

            i += 1;
            if temp[0] == 0 && temp[1] == 0 {
                break;
            }

            buffer.push(temp[0]);
            buffer.push(temp[1]);
        }

        return String::from_utf16_lossy(&buffer);
    }
}

