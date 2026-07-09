#include "Injector.h"

#include "diag.h"
#include "InjectorInternal.h"

extern "C" NTSTATUS InjectDllIntoProcess(HANDLE ProcessId, PUNICODE_STRING DllPath) {
	if (nullptr == ProcessId || nullptr == DllPath || nullptr == DllPath->Buffer || 0 == DllPath->Length) {
		DiagLog("InjectDllIntoProcess invalid parameter pid=%p dll=%p len=0x%X",
			ProcessId, DllPath ? DllPath->Buffer : nullptr, DllPath ? DllPath->Length : 0);
		return STATUS_INVALID_PARAMETER;
	}

	PEPROCESS target_process = nullptr;
	DiagSetStage(InjectionDiagnosticStageProcessLookup);
	DiagLog("before PsLookupProcessByProcessId pid=%p", ProcessId);
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
	DiagSetProcessLookupStatus(status);
	DiagLog("after PsLookupProcessByProcessId pid=%p target=%p status=0x%08X", ProcessId, target_process, status);
	if (!NT_SUCCESS(status)) {
		DiagSetOverallStatus(status);
		return status;
	}

	PVOID injected_apc_routine = nullptr;
	PVOID injected_apc_context = nullptr;

	KAPC_STATE apc_state;
	DiagSetStage(InjectionDiagnosticStagePayloadCreation);
	DiagLog("before KeStackAttachProcess target=%p pid=%p", target_process, ProcessId);
	KeStackAttachProcess(target_process, &apc_state);
	DiagLog("after KeStackAttachProcess target=%p pid=%p", target_process, ProcessId);
	status = CreateTargetApcPayload(DllPath, &injected_apc_routine, &injected_apc_context);
	DiagLog("CreateTargetApcPayload pid=%p routine=%p context=%p status=0x%08X",
		ProcessId, injected_apc_routine, injected_apc_context, status);
	KeUnstackDetachProcess(&apc_state);
	DiagLog("after KeUnstackDetachProcess target=%p pid=%p", target_process, ProcessId);

	if (NT_SUCCESS(status)) {
		DbgPrint("[Injector] DLL path written to target, about to queue APCs... pid=%p routine=%p context=%p\n",
			ProcessId, injected_apc_routine, injected_apc_context);
		DiagSetStage(InjectionDiagnosticStageThreadEnumeration);
		status = QueueUserModeApcToProcessThreads(ProcessId, injected_apc_routine, injected_apc_context);
		if (!NT_SUCCESS(status)) {
			DiagLog("queue apc failed pid=%p status=0x%08X, freeing payload", ProcessId, status);
			DiagLog("before KeStackAttachProcess cleanup target=%p pid=%p", target_process, ProcessId);
			KeStackAttachProcess(target_process, &apc_state);
			DiagLog("after KeStackAttachProcess cleanup target=%p pid=%p", target_process, ProcessId);
			FreeTargetApcPayload(injected_apc_routine, injected_apc_context);
			KeUnstackDetachProcess(&apc_state);
			DiagLog("after KeUnstackDetachProcess cleanup target=%p pid=%p", target_process, ProcessId);
		}
	}

	ObDereferenceObject(target_process);
	DiagLog("inject complete pid=%p status=0x%08X routine=%p context=%p", ProcessId, status, injected_apc_routine, injected_apc_context);
	DiagSetOverallStatus(status);
	return status;
}
