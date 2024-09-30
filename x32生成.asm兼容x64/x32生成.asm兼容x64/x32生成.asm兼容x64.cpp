#include "stdafx.h"
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