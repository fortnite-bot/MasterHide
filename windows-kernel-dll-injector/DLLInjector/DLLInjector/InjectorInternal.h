#pragma once

#include <ntifs.h>

NTSTATUS InjectDllViaRemoteThread(
	_In_ PEPROCESS TargetProcess,
	_In_ PUNICODE_STRING DllPath
);

NTSTATUS CreateTargetApcPayload(
	_In_ PUNICODE_STRING DllPath,
	_Outptr_ PVOID* ApcRoutine,
	_Outptr_ PVOID* ApcContext
);

VOID FreeTargetApcPayload(
	_In_opt_ PVOID ApcRoutine,
	_In_opt_ PVOID ApcContext
);

NTSTATUS QueueUserModeApcToProcessThreads(
	_In_ HANDLE ProcessId,
	_In_ PVOID ApcRoutine,
	_In_opt_ PVOID ApcContext
);
