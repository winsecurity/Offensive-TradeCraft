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
