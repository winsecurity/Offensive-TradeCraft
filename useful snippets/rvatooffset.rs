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

