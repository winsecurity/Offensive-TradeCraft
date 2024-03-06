	.386
	.model flat,stdcall


	includelib masm32\lib\kernel32.lib

	;GetStdHandle PROTO STDCALL :DWORD

	ExitProcess PROTO STDCALL :DWORD
	;WriteConsoleA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

	;extrn GetStdHandle@4 :PROC :DWORD
	;extrn WriteConsole@20 PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD


	.data
		pebaddress dd 0
		ldr dd 0
		ntdlladdr dd 0
		s1 db "ABCA"
		s1len equ $-s1
		s2 db "ABCD"
		srcfunc db "NtQuerySystemInformation"
		srcfunclen equ $-srcfunc
		
	.code
	
		main:
		
			
			; fs:30h contains peb address
			ASSUME fs:NOTHING
			mov eax,DWORD PTR fs:[30h]
			ASSUME fs:ERROR

		
			mov pebaddress, eax
		
			; pointer to Ldr _peb_ldr_data 
			add eax,0ch
		
			mov eax, DWORD PTR [eax]
			mov ldr,eax
		
			; peb_ldr_data + 0x1c gives pointer to 
			; InInitializationModuleList which contains
			; ntdll.dll, kernelbase.dll, kernel32.dll in order
			mov eax,ldr
			add eax, 1ch

			; InInitializationOrderLinks is 0x10 away from ldr_data_table_entry
			mov eax, DWORD PTR [eax]
			sub eax, 10h
		

			; dllbaseaddress is 0x18 away from ldr_data_table_entry
			add eax, 18h
			mov eax,DWORD PTR [eax]
			mov ntdlladdr, eax

			; we got ntdlladdress in ntdlladdr variable
			; 0x4 + 0x14 + 0x60 gives u starting of image_Data_directory
			; first one is exports
			mov eax,DWORD PTR [eax+60]
			add eax, ntdlladdr
			add eax, 078h
			; mov eax, DWORD PTR [ntdlladdr + eax]
			; now we have pointer to export data directory
			mov eax, DWORD PTR [eax]
			add eax, ntdlladdr

			; now eax points to starting of export section
			mov ebx, eax

			; ecx = numberofnames
			mov ecx, DWORD PTR [ebx+24]
			; edx = addressofnames
			mov edx, DWORD PTR [ebx+32]
			add edx, ntdlladdr
			xor edi, edi

			loop2:
				mov esi, DWORD PTR [edx+edi*4]
				add esi, ntdlladdr
				;add edx,4

				push srcfunclen
				push esi
				push offset srcfunc
				call comparetwostrings	

				; eax gets 1 if two strings are equal
				cmp eax,1
				je foundstring

				inc edi
			
				cmp ecx,edi
				jne loop2
				;jmp Exiting

			Exiting:
				push 0 
				call ExitProcess


			foundstring:
				mov edx, DWORD PTR [ebx+36]
				add edx, ntdlladdr
				xor ecx, ecx
				mov cx, WORD PTR [edx+edi*2]
				mov edx, DWORD PTR [ebx+28]
				add edx, ntdlladdr
				mov eax, DWORD PTR [edx+ecx*4]
				add eax, ntdlladdr
				jmp Exiting

			

			; comparetwostrings( addressofstring1, address
			; ofstring2, lengthofstring1tocheckwithstring2)
			comparetwostrings PROC
				push ebp
				mov ebp, esp
				push esi
				push edi 
				push ecx 
				push edx
				push ebx
				;sub esp, 4*2
				
				; first parameter - adddressofstring1
				mov esi, DWORD PTR [ebp+8]

				; second parameter - addressofstring2
				mov edi, DWORD PTR [ebp+12]

				; third parameter - lengthofstring1
				mov ecx, DWORD PTR [ebp+16]
				inc ecx
				xor edx, edx
				xor ebx,ebx

				loop1:
					push ecx
					mov cl, BYTE PTR [esi+edx]
					mov bl, BYTE PTR [edi+edx]
					cmp cl,bl
					jne notequal
					pop ecx
					dec ecx
					inc edx
				
					cmp ecx,1
					jne loop1
					xor eax,eax
					inc eax
					jmp epilogue

				notequal:
					pop ecx
					xor eax,eax
					
					jmp epilogue



				epilogue:
					;add esp, 4*2
					pop ebx
					pop edx
					pop ecx
					pop edi
					pop esi
					pop ebp
					
					ret 

			comparetwostrings endp

		end main


