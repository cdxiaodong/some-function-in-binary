// 扩大节.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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

