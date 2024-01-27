
use std::arch::asm;
pub fn getimagebaseaddress() -> usize{
    unsafe{
        
        

        let mut imagebase:usize = 0;
        
        let v = std::mem::size_of::<usize>();
       
        if v==8{
            let mut offset:usize = 0x10;
            asm!(

                "add {0},qword ptr gs:[0x60]",
                "mov {1},qword ptr [{0}]",
          
                inout(reg) offset,
                out(reg) imagebase

            );
            return imagebase;
            
        }
       
        else if v==4{
            let mut offset:usize = 0x8;
            asm!(
                
                "add {0},dword ptr fs:[0x30]",
                "mov {1},dword ptr [{0}]",

                inout(reg) offset,
                out(reg) imagebase
            );
            return imagebase;

        }
        return 0;
    }
}
