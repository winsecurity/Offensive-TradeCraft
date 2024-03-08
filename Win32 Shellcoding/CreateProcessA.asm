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

			

			push srcfunclen
			push offset srcfunc
			push eax
			call getexportedfunction
			;add esp, 12
			; eax contains address of our function
			mov edx, eax
			

			xor ebx, ebx
			mov ecx, 30
			zeroing:
				push ebx 
				LOOP zeroing

			; 16 is size of processinfo structure
			;mov edi, 16
			

			; 68 is size of startupinfoa
			mov edi, 68
			push edi
			mov edi, esp  ; edi points to startupinfoa

			xor esi, esi 

			push esi
			; 636d642e657865 cmd.exe
			; 63616c63 2e657865 calc.exe
			; 433a5c57696e646f77735c537973574f5736345c63616c632e657865
			; C:\Windows\SysWOW64\calc.exe
			;push		2e657865h
			;push			63616c63h
			;push			5736345ch
			;push			7973574fh
			;push			77735c53h
			;push			696e646fh
			;push			433a5c57h
			;push		433a5c57h
			push  6578652eh
			push 636c6163h ; pushing calc.exe
			mov esi, esp


			mov ecx, 4
			zeroing2:
				push ebx 
				LOOP zeroing2

			
	
			push esp	; pointer to processinfo
			push edi	; pointer to startupinfoa
			push ebx	; currentdirectory
			push ebx	; pointer to environment block
			push ebx	; creation flags 0 to start immediately
			push ebx	; inherit handles false
			push ebx	; threadattributes
			push ebx	; processattributes
			push esi	; cmdline
			push ebx	; applicationname
			call edx
			;add esp, 40
			add esp, 152
			;mov esp, edx
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


