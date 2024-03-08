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
			
