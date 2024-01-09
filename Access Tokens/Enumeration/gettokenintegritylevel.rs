pub fn gettokenintegritylevel(tokenhandle: *mut c_void)
 -> Result<String,String>{
    unsafe{

        let mut bytesneeded = 0;
        let mut buffer = vec![0u8;bytesneeded as usize];
        GetTokenInformation(tokenhandle, 
            25, 
            buffer.as_mut_ptr() as *mut c_void, 
            bytesneeded, &mut bytesneeded);

        if bytesneeded==0{
            return Ok(format!("Gettokeninformation failed: {}",GetLastError()));
            
        }

        let mut buffer = vec![0u8;bytesneeded as usize];
        let res = GetTokenInformation(tokenhandle, 
            25, 
            buffer.as_mut_ptr() as *mut c_void, 
            bytesneeded, &mut bytesneeded);


        if res==0{
            return Ok(format!("gettokeninformation failed: {}",GetLastError()));
            
        }

        let tokenmandatory = *(buffer.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL);

        return Ok(format!("{}",sidtousernamew(tokenmandatory.Label.Sid)));




    }
}
