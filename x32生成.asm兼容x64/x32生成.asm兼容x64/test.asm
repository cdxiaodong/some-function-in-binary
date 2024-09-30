.CODE

 getkernelbase PROC
			mov eax, dword ptr fs : [0x30]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax + 0x18]
			ret
 getkernelbase ENDP

END