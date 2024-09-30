#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#pragma warning(disable:4996)

void viewImageFileCharacteristics(WORD);

int _tmain(int argc, TCHAR* argv[])
{
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	PIMAGE_FILE_HEADER pImageFileHeader;
	HANDLE hFile;
	HANDLE hMapObject;
	PUCHAR uFileMap;
	//if(argc<2)
	//return -1;
	if (!(hFile = CreateFile(/*argv[1]*/L"C:\Program Files\WindowsApps\Microsoft.YourPhone_1.22082.117.0_x64__8wekyb3d8bbwe\YourPhoneAppProxy.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0)))
		return -1;
	if (!(hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL)))
		return -1;
	if (!(uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0)))
		return -1;
	pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return -1;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)uFileMap + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return -1;
	pImageFileHeader = (PIMAGE_FILE_HEADER) & (pImageNtHeaders->FileHeader);

	printf("Machine:	0x%04X", pImageFileHeader->Machine);
	((pImageFileHeader->Machine == IMAGE_FILE_MACHINE_I386)
		? printf("(I386) \n")
		: printf(" (?) \n"));
	printf("NumberOfSections:	0x%04X\n", pImageFileHeader->NumberOfSections);
	printf("TimeDateStamp:	0x%08X\n", pImageFileHeader->TimeDateStamp);
	printf("PointerToSymbolTable:	0x08X\n", pImageFileHeader->PointerToSymbolTable);
	printf("NumberOfSymbols:	0x%08X\n", pImageFileHeader->NumberOfSymbols);
	printf("SizeOfOptionalHeader:	0x%04X\n", pImageFileHeader->SizeOfOptionalHeader);
	printf("Characteristics:	0x%04X\n", pImageFileHeader->Characteristics);
	viewImageFileCharacteristics(pImageFileHeader->Characteristics);
	UnmapViewOfFile(uFileMap);
	CloseHandle(hMapObject);
	CloseHandle(hFile);
	return 0;
}

void viewImageFileCharacteristics(WORD wCharacteristics)
{
	char szCharacteristics[100];
	memset(szCharacteristics, 0, 100);
	szCharacteristics[0] = '(';
	if (wCharacteristics & 0x0001)
		strcat(szCharacteristics, "RELOCS_STRIPPED|");
	if (wCharacteristics & 0x0002)
		strcat(szCharacteristics, "EXECUTABLE_IMAGE|");
	if (wCharacteristics & 0x0004)
		strcat(szCharacteristics, "LINE_NUMS_STRIPPED|");
	if (wCharacteristics & 0x0100)
		strcat(szCharacteristics, "32BIT_MACHINE|");
	if (wCharacteristics & 0x0200)
		strcat(szCharacteristics, "DEBUG_STRIPPED|");
	if (wCharacteristics & 0x1000)
		strcat(szCharacteristics, "FILE_SYSTEM|");
	if (wCharacteristics & 0x2000)
		strcat(szCharacteristics, "FILE_DLL|");
	szCharacteristics[strlen(szCharacteristics) - 1] = ')';
	szCharacteristics[strlen(szCharacteristics)] = '\0';
	printf("	%s\n", szCharacteristics);
}