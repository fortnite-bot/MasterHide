#include "InjectorInternal.h"

#include "apc.h"
#include "diag.h"
#include "pe.h"
#include "process.h"

using LoadLibraryWFn = HANDLE(*)(LPCWSTR lpLibFileName);

struct UserApcArgs {
	wchar_t dll_path[256];
	LoadLibraryWFn load_library;
};

static PVOID FindLoadLibraryW() {
	return get_module_symbol_address((wchar_t*)L"KERNEL32.DLL", (char*)"LoadLibraryW");
}

#pragma optimize("", off)
#pragma runtime_checks("", off)
VOID NTAPI user_mode_apc_callback(PVOID normal_context, PVOID, PVOID) {
	auto args = static_cast<UserApcArgs*>(normal_context);
	args->load_library(args->dll_path);
}

VOID NTAPI user_mode_apc_callback_end() {}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

NTSTATUS CreateTargetApcPayload(PUNICODE_STRING DllPath, PVOID* ApcRoutine, PVOID* ApcContext) {
	if (nullptr == DllPath || nullptr == DllPath->Buffer || nullptr == ApcRoutine || nullptr == ApcContext) {
		DiagLog("CreateTargetApcPayload invalid parameter dll=%p apcRoutine=%p apcContext=%p",
			DllPath ? DllPath->Buffer : nullptr, ApcRoutine, ApcContext);
		return STATUS_INVALID_PARAMETER;
	}

	*ApcRoutine = nullptr;
	*ApcContext = nullptr;

	UserApcArgs user_apc_args = {};
	if (0 == DllPath->Length || 0 != (DllPath->Length % sizeof(WCHAR))) {
		DiagLog("CreateTargetApcPayload bad dll length=0x%X", DllPath->Length);
		return STATUS_INVALID_PARAMETER;
	}
	if (DllPath->Length >= sizeof(user_apc_args.dll_path)) {
		DiagLog("CreateTargetApcPayload dll path too long length=0x%X limit=0x%IX",
			DllPath->Length, sizeof(user_apc_args.dll_path));
		return STATUS_NAME_TOO_LONG;
	}

	RtlCopyMemory(user_apc_args.dll_path, DllPath->Buffer, DllPath->Length);
	user_apc_args.dll_path[DllPath->Length / sizeof(WCHAR)] = L'\0';
	DiagLog("before FindLoadLibraryW dllLen=0x%X", DllPath->Length);
	user_apc_args.load_library = (LoadLibraryWFn)FindLoadLibraryW();
	DiagSetLoadLibraryResult((PVOID)user_apc_args.load_library);
	DiagLog("after FindLoadLibraryW address=%p status=0x%08X",
		user_apc_args.load_library,
		nullptr == user_apc_args.load_library ? STATUS_PROCEDURE_NOT_FOUND : STATUS_SUCCESS);
	if (nullptr == user_apc_args.load_library) {
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	PVOID injected_apc_context = nullptr;
	SIZE_T apc_context_size = sizeof(UserApcArgs);
	DiagLog("before ZwAllocateVirtualMemory(context) base=%p size=0x%IX", injected_apc_context, apc_context_size);
	NTSTATUS status = ZwAllocateVirtualMemory(
		NtCurrentProcess(),
		&injected_apc_context,
		0,
		&apc_context_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	DiagSetContextAllocationStatus(status);
	DiagLog("after ZwAllocateVirtualMemory(context) base=%p size=0x%IX status=0x%08X",
		injected_apc_context, apc_context_size, status);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	RtlCopyMemory(injected_apc_context, &user_apc_args, sizeof(UserApcArgs));

	PVOID injected_apc_routine = nullptr;
	SIZE_T routine_size = reinterpret_cast<ULONG_PTR>(user_mode_apc_callback_end) -
		reinterpret_cast<ULONG_PTR>(user_mode_apc_callback);
	DiagLog("before ZwAllocateVirtualMemory(routine) base=%p size=0x%IX", injected_apc_routine, routine_size);
	status = ZwAllocateVirtualMemory(
		NtCurrentProcess(),
		&injected_apc_routine,
		0,
		&routine_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	DiagSetRoutineAllocationStatus(status, routine_size);
	DiagLog("after ZwAllocateVirtualMemory(routine) base=%p size=0x%IX status=0x%08X",
		injected_apc_routine, routine_size, status);
	if (!NT_SUCCESS(status)) {
		FreeTargetApcPayload(nullptr, injected_apc_context);
		return status;
	}
	RtlCopyMemory(injected_apc_routine, &user_mode_apc_callback, routine_size);

	*ApcRoutine = injected_apc_routine;
	*ApcContext = injected_apc_context;
	return STATUS_SUCCESS;
}

VOID FreeTargetApcPayload(PVOID ApcRoutine, PVOID ApcContext) {
	SIZE_T region_size = 0;
	if (nullptr != ApcRoutine) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &ApcRoutine, &region_size, MEM_RELEASE);
	}
	if (nullptr != ApcContext) {
		region_size = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), &ApcContext, &region_size, MEM_RELEASE);
	}
}

NTSTATUS QueueUserModeApcToProcessThreads(HANDLE ProcessId, PVOID ApcRoutine, PVOID ApcContext) {
	if (nullptr == ProcessId || nullptr == ApcRoutine) {
		DiagLog("QueueUserModeApcToProcessThreads invalid parameter pid=%p routine=%p context=%p",
			ProcessId, ApcRoutine, ApcContext);
		return STATUS_INVALID_PARAMETER;
	}

	ProcessInfo process_info = {};
	DiagLog("before get_process_info_by_pid pid=%p", ProcessId);
	NTSTATUS status = get_process_info_by_pid(reinterpret_cast<size_t>(ProcessId), &process_info);
	DiagSetThreadEnumerationStatus(status, NT_SUCCESS(status) ? process_info.number_of_threads : 0);
	DiagLog("after get_process_info_by_pid pid=%p threads=%Iu status=0x%08X",
		ProcessId, NT_SUCCESS(status) ? process_info.number_of_threads : 0, status);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	if (0 == process_info.number_of_threads || nullptr == process_info.threads_id) {
		DiagSetThreadEnumerationStatus(STATUS_NOT_FOUND, 0);
		DiagLog("no threads for pid=%p", ProcessId);
		return STATUS_NOT_FOUND;
	}

	DiagSetStage(InjectionDiagnosticStageQueueApc);
	ULONG queued_apcs = 0;
	NTSTATUS last_status = STATUS_NOT_FOUND;
	for (size_t i = 0; i < process_info.number_of_threads; i++) {
		PKTHREAD target_thread = nullptr;
		DiagLog("before PsLookupThreadByThreadId tid=%p", (HANDLE)process_info.threads_id[i]);
		status = PsLookupThreadByThreadId((HANDLE)process_info.threads_id[i], &target_thread);
		if (!NT_SUCCESS(status)) {
			DiagNoteThreadLookupFailure(process_info.threads_id[i], status);
			DiagLog("after PsLookupThreadByThreadId tid=%p thread=%p status=0x%08X",
				(HANDLE)process_info.threads_id[i], target_thread, status);
			last_status = status;
			continue;
		}
		DiagLog("after PsLookupThreadByThreadId tid=%p thread=%p status=0x%08X",
			(HANDLE)process_info.threads_id[i], target_thread, status);

		DiagLog("before call_apc tid=%p routine=%p context=%p",
			(HANDLE)process_info.threads_id[i], ApcRoutine, ApcContext);
		status = call_apc(target_thread, ApcRoutine, ApcContext);
		DiagNoteApcQueueResult(process_info.threads_id[i], status);
		DiagLog("after call_apc tid=%p status=0x%08X",
			(HANDLE)process_info.threads_id[i], status);
		if (NT_SUCCESS(status)) {
			queued_apcs++;
		}
		else {
			last_status = status;
		}
		ObDereferenceObject(target_thread);
	}

	ExFreePool(process_info.threads_id);
	return queued_apcs > 0 ? STATUS_SUCCESS : last_status;
}
