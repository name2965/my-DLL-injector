#include "stdafx.h"
#include "DLL_Injector.h"
#include "utils.h"

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 3) {
		printf("Usage: <PID> <DLL_PATH>\n");
		return 0;
	}

	if (InjectThread(_wtoi(argv[1]), DLL_PATH))
		printf("Injection \"%ws\" Success\n", DLL_PATH);
	else
		printf("Injection \"%ws\" Failed\n", DLL_PATH);
	return 0;
}