pub fn createkerbs4ulogon(upn:String, realm: String) -> Vec<u8>{
    unsafe{
        let upnbuffer = upn.encode_utf16().collect::<Vec<u16>>();
        let realmbuffer = realm.encode_utf16().collect::<Vec<u16>>();

        let totalsize = std::mem::size_of::<KERB_S4U_LOGON>() + (upnbuffer.len()*2) + (realmbuffer.len()*2);
        let mut mys4u = vec![0u8;totalsize ];



        let mut kerbs4u = std::mem::zeroed::<KERB_S4U_LOGON>();
        kerbs4u.MessageType = KerbS4ULogon;
        kerbs4u.Flags = KERB_S4U_LOGON_FLAG_IDENTIFY;

        kerbs4u.ClientUpn.Buffer = (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>()) as *mut u16;
        kerbs4u.ClientUpn.Length = upnbuffer.len() as u16;
        kerbs4u.ClientUpn.MaximumLength = upnbuffer.len() as u16+1;

        kerbs4u.ClientRealm.Buffer =  (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() + (upnbuffer.len()*2)) as *mut u16;
        kerbs4u.ClientRealm.Length = realmbuffer.len() as u16;
        kerbs4u.ClientRealm.MaximumLength = realmbuffer.len() as u16+1;

        let mut byteswritten = 0;
        WriteProcessMemory(GetCurrentProcess(), 
        mys4u.as_mut_ptr() as *mut c_void, 
        &mut kerbs4u as *mut _ as *mut c_void, 
        std::mem::size_of::<KERB_S4U_LOGON>(), 
        &mut byteswritten);


        WriteProcessMemory(GetCurrentProcess(), 
        (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() )as *mut c_void, 
        upnbuffer.as_ptr() as *const c_void, 
        upnbuffer.len()*2, 
        &mut byteswritten);



        WriteProcessMemory(GetCurrentProcess(), 
        (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() +(upnbuffer.len()*2))as *mut c_void, 
        realmbuffer.as_ptr() as *const c_void, 
        realmbuffer.len()*2, 
        &mut byteswritten);

        return mys4u;
    }
}

