#pragma once
#include "stdafx.h"

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(WINAPI* PROC_RtlCreateUserThread)(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	SIZE_T StackReserve,
	SIZE_T StackCommit,
	PTHREAD_START_ROUTINE StartAddress,
	PVOID Parameter,
	PHANDLE ThreadHandle,
	PCLIENT_ID ClientId
	);

bool SetPrivilege(
	_In_z_ const wchar_t* privilege,
	_In_ bool enable
	);

HANDLE AdvancedOpenProcess(_In_ DWORD pid);

bool InjectThread(
	_In_ DWORD pid,
	_In_ const wchar_t* dll_path
	);