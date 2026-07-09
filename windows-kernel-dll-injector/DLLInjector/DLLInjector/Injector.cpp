#include "Injector.h"

#include "InjectorInternal.h"

extern "C" NTSTATUS InjectDllIntoProcess(HANDLE ProcessId, PUNICODE_STRING DllPath) {
	if (nullptr == ProcessId || nullptr == DllPath || nullptr == DllPath->Buffer || 0 == DllPath->Length) {
		return STATUS_INVALID_PARAMETER;
	}

	PEPROCESS target_process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	PVOID injected_apc_routine = nullptr;
	PVOID injected_apc_context = nullptr;

	KAPC_STATE apc_state;
	KeStackAttachProcess(target_process, &apc_state);
	status = CreateTargetApcPayload(DllPath, &injected_apc_routine, &injected_apc_context);
	KeUnstackDetachProcess(&apc_state);

	if (NT_SUCCESS(status)) {
		status = QueueUserModeApcToProcessThreads(ProcessId, injected_apc_routine, injected_apc_context);
		if (!NT_SUCCESS(status)) {
			KeStackAttachProcess(target_process, &apc_state);
			FreeTargetApcPayload(injected_apc_routine, injected_apc_context);
			KeUnstackDetachProcess(&apc_state);
		}
	}

	ObDereferenceObject(target_process);
	return status;
}
