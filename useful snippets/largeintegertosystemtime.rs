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
