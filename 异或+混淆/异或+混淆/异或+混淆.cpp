// 异或+混淆.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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



