	.386
	.model flat,stdcall


	;includelib masm32\lib\kernel32.lib

	;GetStdHandle PROTO STDCALL :DWORD

	;ExitProcess PROTO STDCALL :DWORD
	;WriteConsoleA PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

	;extrn GetStdHandle@4 :PROC :DWORD
	;extrn WriteConsole@20 PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD


	.data
		pebaddress dd 0
		ldr dd 0
		ntdlladdr dd 0
		pi db 16 dup(0)
		s1 db "calc.exe",0
		s1len equ $-s1
		s2 db "ABCA"
		srcfunc db "CreateProcessA"
		srcfunclen equ $-srcfunc
		exports dd 0
		
	.code
	
		main:
		
			; fs:30h contains peb address
			ASSUME fs:NOTHING
			xor eax, eax
			mov eax,DWORD PTR fs:[eax+30h]
			ASSUME fs:ERROR

		
			;mov pebaddress, eax
		
			; pointer to Ldr _peb_ldr_data 
			add eax, 0ch
		
			xor ebx, ebx
			mov eax, DWORD PTR [eax+ebx]
			;mov ldr,eax
		
			; peb_ldr_data + 0x1c gives pointer to 
			; InInitializationModuleList which contains
			; ntdll.dll, kernelbase.dll, kernel32.dll in order
			;mov eax,ldr
			add eax, 1ch

			; InInitializationOrderLinks is 0x10 away from ldr_data_table_entry
			mov eax, DWORD PTR [eax+ebx]
			;sub eax, 10h
		

			; read next 4 bytes to get kernelbase.dll
			;add eax, 10h
			;mov eax, DWORD PTR [eax+ebx]
			; read again 4 bytes to get to inintiializationordermodulelist
			; of kernelbase.dll
			mov eax, DWORD PTR [eax+ebx]
			; getting to starting of ldr_data_table_entry
			sub eax, 10h
			; getting to entrypoint of kernelbase.dll
			add eax, 18h
			mov eax, DWORD PTR [eax+ebx]

			; ntdllbaseaddress is 0x18 away from ldr_data_table_entry
			;add eax, 18h
			;lmov eax,DWORD PTR [eax+ebx]
			;mov ntdlladdr, eax

			xor esi, esi 

			; 4c6f6164 4c696272 61727941 LoadLibraryA
			push esi 
			push 41797261h
			push 7262694ch
			push 64616f4ch
			;push 61727941h
			;push 4c696272h
			;push 4c6f6164h
			mov esi, esp

			push 12
			push esi
			push eax
			call getexportedfunction
			add esp, 16
			;add esp, 12
			; eax contains address of our function
			
			; 75736572 33322e64 6c6c user32.dll
			xor esi, esi 
			push si
			push 6c6ch
			push 642e3233h
			push 72657375h
			mov esi, esp
			
			push esi 
			; eax contains user32.dll baseaddress
			call eax

			add esp, 14


			; 4d657373 61676542 6f7841 MessageBoxA
			xor esi, esi
			push esi
			push 41786fh
			push 42656761h
			push 7373654dh
			mov esi, esp 

			push 11
			push esi 
			push eax 
			call getexportedfunction	
			add esp, 16


			xor esi, esi 
			push esi
			push 41414141h
			mov esi, esp
			; eax contains MessageBoxA function address
			xor ebx, ebx
			push ebx	; type
			push ebx	; caption
			push esi	; text
			push ebx	; handle
			call eax 

			add esp, 8

			ret


			
			getexportedfunction PROC	
				; getexportedfunction( dllbaseaddress,
				; addressoffunctionnamestring, functionnamelength)
				push ebp
				mov ebp, esp
				push ebx 
				push esi
				push edi 
				push ecx 
				push edx 


				mov ebx, eax
				mov ebx, DWORD PTR [ebx+60]
				add ebx, DWORD PTR [ebp+8]
				add ebx, 78h
				mov ebx, DWORD PTR [ebx]
				add ebx, DWORD PTR [ebp+8]


			

				; ecx = number of names
				mov ecx, DWORD PTR [ebx+24]
				inc ecx

				; esi = address of names
				mov esi, DWORD PTR [ebx+32]
				add esi, DWORD PTR [ebp+8]

				xor edx, edx
			
				loop2:
					mov edi, DWORD PTR [esi+edx*4]
					add edi, DWORD PTR [ebp+8]
				 

					push DWORD PTR [ebp+16]
					push edi 
					push DWORD PTR [ebp+12]
					call comparetwostrings 
					cmp eax, 1
					je foundstring 
					inc edx 
					dec ecx
					cmp ecx,1
					jne loop2
					xor eax, eax
					jmp myEpilogue	


			foundstring:
				; edx contains index to nameordinals
				xor ecx, ecx
				mov esi,DWORD PTR [ebx+36]
				add esi,DWORD PTR [ebp+8]
				mov cx, WORD PTR [esi+edx*2]

				mov esi, DWORD PTR [ebx+28]
				add esi, DWORD PTR [ebp+8]
				mov esi, DWORD PTR [esi+ecx*4]
				; esi contains function address
				add esi, DWORD PTR [ebp+8]
				mov eax, esi
				jmp myEpilogue	

			myEpilogue:
			
				pop edx 
				pop ecx 
				pop edi 
				pop esi 
				pop ebx 
				pop ebp 
				ret 12
		getexportedfunction endp

			
			comparetwostrings PROC
			; comparetwostrings( addressofstring1,
			; addressofstring2, lengthofstring1)
				push ebp 
				mov ebp, esp
				push esi
				push edi 
				push edx
				push ecx
				push ebx

				; ebp+4 gives the address of next instruction
				; ebp+8 gives first parameter
				; ebp+12 gives the second parameter
				; ebp+ 16 gives the length to check
				
				mov esi, DWORD PTR [ebp+8]
				mov edi, DWORD PTR [ebp+12]
				mov ecx, DWORD PTR [ebp+16]
				inc ecx

				xor edx,edx 
				xor ebx, ebx

				loop1:
					mov bl, BYTE PTR [esi+edx]
					mov bh, BYTE PTR [edi+edx]
					inc edx
					dec ecx 
					cmp bl,bh
					jne notequal

					cmp ecx,1
					jne loop1
					xor eax, eax
					inc al
					jmp Epilogue

				notequal:
					xor eax, eax
					jmp Epilogue

				Epilogue:
					pop ebx
					pop ecx
					pop edx
					pop edi 
					pop esi
					pop ebp 
					ret 12

			comparetwostrings endp
			

			
		end main


