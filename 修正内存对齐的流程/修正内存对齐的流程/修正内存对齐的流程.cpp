#include <stdio.h>
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