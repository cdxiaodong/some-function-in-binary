// PE.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <winnt.h>
#include <math.h>
void combineSection(_IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr) {
	//所有节内存对齐后的大小的和，这里要求已经修正过内存对齐，只有这样文件对齐大小才会等于内存对齐大小
	DWORD allSectionSize = 0;
	//所有节的权限，初始为第一个节的权限，和后面的每个节的权限进行或操作
	DWORD allSectionCharateristics = sectionArr[0]->Characteristics;
	int i;
	for (i = 0; i < nt->FileHeader.NumberOfSections;i++) {
		allSectionSize += sectionArr[i]->SizeOfRawData;
		allSectionSize = allSection

	
	}


}