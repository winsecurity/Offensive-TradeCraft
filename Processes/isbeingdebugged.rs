pub fn isbeingdebugged() {
    unsafe{
        
        let v = std::mem::size_of::<usize>();
        println!("size of usize: {}",v);
        let mut offset:usize = 0x2;

        if v==8{
            let mut isbeingdebugged:u8 = 0;
            
            asm!(

                "add {0}, qword ptr gs:[0x60]",
                "mov {1}, byte ptr [{0}]",
                inout(reg) offset,
                out(reg_byte) isbeingdebugged
                
            );
           
            println!("isbeingdebugged: {}",isbeingdebugged);
        }
        
        /*else if v==4{
            let mut isbeingdebugged:u8 = 0;
            let mut offset:usize = 0x2;

            asm!(

                "add {0},qword ptr fs:[0x30]",
                "mov {1}, byte ptr [{0}]",
                inout(reg) offset,
                out(reg_byte) isbeingdebugged,
              
            );
            println!("isbeingdebugged: {}",isbeingdebugged);
        }*/

    }
}

