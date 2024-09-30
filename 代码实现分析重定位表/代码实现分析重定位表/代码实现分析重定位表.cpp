// PE.cpp : Defines the entry point for the console application.
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