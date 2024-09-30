#ifndef PROCESSHOLLOWING_H
#define PROCESSHOLLOWING_H

#include "Tools.h"

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

class ProcessHollowing : Tools
{
	std::string targetPath;

	BOOL StartPH(char* pImage);
public:
	ProcessHollowing();
};

#endif // !PROCESSHOLLOWING_H