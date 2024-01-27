use std::arch::asm;

pub fn getpebaddress() -> usize{
    unsafe{

        let mut peb:usize = 0;


        

        let v = std::mem::size_of::<usize>();
        if v==8{
            asm!(

                "mov {},qword ptr gs:[0x60]",
                out(reg)peb

            );

            return peb;
            
        }

        else if v==4{
            asm!(

                "mov {},dword ptr fs:[0x30]",
                out(reg) peb

            );
           return peb;
        }
        return 0;
    }
}

