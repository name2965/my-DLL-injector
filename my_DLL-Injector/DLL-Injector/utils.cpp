#include "stdafx.h"
#include "utils.h"

bool SetPrivilege(_In_z_ const wchar_t* privilege, _In_ bool enable) {
	_ASSERTE(nullptr != privilege);
	if (nullptr == privilege)
		return false;

	HANDLE token = INVALID_HANDLE_VALUE;
	if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token)) {
		if (ERROR_NO_TOKEN == GetLastError()) {
			if (TRUE != ImpersonateSelf(SecurityImpersonation))
				return false;

			if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &token))
				return false;
		}
		else
			return false;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid = { 0 };
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	bool ret = false;
	do {
		if (!LookupPrivilegeValueW(NULL, privilege, &luid)) { break; }

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (enable)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		AdjustTokenPrivileges(token, FALSE, &tp, cb, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS) { break; }

		ret = true;
	} while (false);
	CloseHandle(token);
	return ret;
}

HANDLE AdvancedOpenProcess(_In_ DWORD pid) {
	_ASSERT(NULL != pid);
	if (NULL == pid)
		return INVALID_HANDLE_VALUE;

	HANDLE ret = NULL;
	if (SetPrivilege(L"SeDebugPrivilege", true) != true)
		return ret;

	do {
		ret = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (ret == NULL)
			break;
		if (SetPrivilege(L"SeDebugPrivilege", false) != true) {
			CloseHandle(ret);
			ret = NULL;
			break;
		}
	} while (false);
	return ret;
}

BOOL RtlCreateUserThread(_In_ HANDLE process_handle, _In_ wchar_t* buffer, _In_ SIZE_T buffer_size) {
	HMODULE ntdll = NULL;
	HMODULE kernel32 = NULL;
	HANDLE thread_handle = NULL;
	CLIENT_ID cid;
	PROC_RtlCreateUserThread RtlCreateUserThread = NULL;
	PTHREAD_START_ROUTINE start_address = NULL;

	__try {
		ntdll = LoadLibraryW(L"ntdll.dll");
		if (ntdll == NULL) {
			printf("LoadLibrary(ntdll.dll) Func err gle : 0x%08X", GetLastError());
			return false;
		}

		RtlCreateUserThread = (PROC_RtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
		if (RtlCreateUserThread == NULL) {
			printf("GetProcAddress(RtlCreateUserThread) Func err gle : 0x%08X", GetLastError());
			return false;
		}

		kernel32 = LoadLibrary(L"kernel32.dll");
		if (kernel32 == NULL) {
			printf("LoadLibrary(kernel32.dll) Func err gle : 0x%08X", GetLastError());
			return false;
		}

		start_address = (PTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
		if (start_address == NULL) {
			printf("GetProcAddress(LoadLibraryW) Func err gle : 0x%08X", GetLastError());
			return false;
		}

		NTSTATUS status = RtlCreateUserThread(process_handle, NULL, false, 0, 0, 0, start_address, buffer, &thread_handle, &cid);
		if (status > 0) {
			printf("RtlCreateUserThread failed (0x%08X) status : %x\n", GetLastError(), status);
			return false;
		}

		status = WaitForSingleObject(thread_handle, INFINITE);
		if (status == WAIT_FAILED) {
			printf("WaitForSingleObject failed (0x%08X) status : %x\n", GetLastError(), status);
			return false;
		}
	}

	__finally {
		if (kernel32 != NULL)
			FreeLibrary(kernel32);
		if (ntdll != NULL)
			FreeLibrary(ntdll);
		if (thread_handle != NULL)
			CloseHandle(thread_handle);
	}
	return true;
}

bool InjectThread(_In_ DWORD pid, _In_ const wchar_t* dll_path) {
	_ASSERTE(pid != NULL);
	_ASSERTE(nullptr != dll_path);
	if (pid == NULL || nullptr == dll_path)
		return false;

	HANDLE process_handle = NULL;
	SIZE_T buffer_size = 0;
	wchar_t* buffer = NULL;
	SIZE_T byte_written = 0;

	__try {
		process_handle = AdvancedOpenProcess(pid);
		if (process_handle == NULL) {
			printf("OpenProcess Func err gle : 0x%08X", GetLastError());
			return false;
		}

		buffer_size = wcslen(dll_path) * sizeof(wchar_t) + 1;
		buffer = (wchar_t*)VirtualAllocEx(process_handle, NULL, buffer_size, MEM_COMMIT, PAGE_READWRITE);
		if (buffer == NULL) {
			printf("VirtualAllocEx Func err gle : 0x%08X", GetLastError());
			return false;
		}

		if (WriteProcessMemory(process_handle, buffer, dll_path, buffer_size, &byte_written) != TRUE) {
			printf("WriteProcessMemory Func err gle : 0x%08X", GetLastError());
			return false;
		}

		if (RtlCreateUserThread(process_handle, buffer, buffer_size) != TRUE) {
			printf("RtlCreateUserThread Func err gle : 0x%08X", GetLastError());
			return false;
		}
	}
	__finally {
		if (buffer != NULL)
			VirtualFreeEx(process_handle, buffer, buffer_size, MEM_COMMIT);
		if (process_handle != NULL)
			CloseHandle(process_handle);
	}
	
	return true;
}