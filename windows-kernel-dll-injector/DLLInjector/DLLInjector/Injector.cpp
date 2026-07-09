#include "Injector.h"

#include "diag.h"
#include "InjectorInternal.h"

extern "C" NTSTATUS InjectDllIntoProcess(HANDLE ProcessId, PUNICODE_STRING DllPath) {
	if (nullptr == ProcessId || nullptr == DllPath || nullptr == DllPath->Buffer || 0 == DllPath->Length) {
		return STATUS_INVALID_PARAMETER;
	}

	PEPROCESS target_process = nullptr;
	DiagSetStage(InjectionDiagnosticStageProcessLookup);
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
	DiagSetProcessLookupStatus(status);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[INJDIAG] PsLookupProcessByProcessId failed: pid=%p status=0x%08X\n", ProcessId, status);
		DiagSetOverallStatus(status);
		return status;
	}

	PVOID injected_apc_routine = nullptr;
	PVOID injected_apc_context = nullptr;

	KAPC_STATE apc_state;
	DiagSetStage(InjectionDiagnosticStagePayloadCreation);
	KeStackAttachProcess(target_process, &apc_state);
	status = CreateTargetApcPayload(DllPath, &injected_apc_routine, &injected_apc_context);
	KeUnstackDetachProcess(&apc_state);

	if (NT_SUCCESS(status)) {
		DiagSetStage(InjectionDiagnosticStageThreadEnumeration);
		status = QueueUserModeApcToProcessThreads(ProcessId, injected_apc_routine, injected_apc_context);
		if (!NT_SUCCESS(status)) {
			KeStackAttachProcess(target_process, &apc_state);
			FreeTargetApcPayload(injected_apc_routine, injected_apc_context);
			KeUnstackDetachProcess(&apc_state);
		}
	}
	else {
		DbgPrint("[INJDIAG] CreateTargetApcPayload failed: pid=%p status=0x%08X\n", ProcessId, status);
	}

	ObDereferenceObject(target_process);
	DbgPrint("[INJDIAG] inject complete pid=%p status=0x%08X\n", ProcessId, status);
	DiagSetOverallStatus(status);
	return status;
}
