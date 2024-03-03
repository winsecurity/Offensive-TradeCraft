.386
.model flat,stdcall


;includelib masm32\lib\windows.lib
;includelib masm32\lib\user32.lib
;includelib masm32\lib\kernel32.lib


;extrn ExitProcess@4 :PROC
;extrn MessageBoxA@16 :PROC ;PROTO :DWORD, :DWORD, :DWORD, DWORD

.data
	pebaddress dd 0
	ldr dd 0
	ntdlladdr dd 0

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


	end main

	
