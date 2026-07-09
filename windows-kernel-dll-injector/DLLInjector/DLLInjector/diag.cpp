#include "diag.h"

#include <ntstrsafe.h>
#include <stdarg.h>

extern "C" InjectionLogSlot g_LogBuffer[DIAG_LOG_ENTRY_COUNT] = {};
extern "C" volatile LONG g_LogWriteIndex = -1;

namespace {

InjectionDiagnosticSnapshot g_diag_snapshot = {};
bool g_diag_initialized = false;

void ResetLogBuffer() {
	for (size_t i = 0; i < RTL_NUMBER_OF(g_LogBuffer); i++) {
		g_LogBuffer[i].Sequence = -1;
		g_LogBuffer[i].Line.Length = 0;
		g_LogBuffer[i].Line.MaximumLength = sizeof(g_LogBuffer[i].Storage);
		g_LogBuffer[i].Line.Buffer = g_LogBuffer[i].Storage;
		g_LogBuffer[i].Storage[0] = '\0';
	}
	InterlockedExchange(&g_LogWriteIndex, -1);
}

void ResetSnapshot(unsigned long long pid) {
	RtlZeroMemory(&g_diag_snapshot, sizeof(g_diag_snapshot));
	g_diag_snapshot.version = 1;
	g_diag_snapshot.pid = pid;
	g_diag_snapshot.stage = InjectionDiagnosticStageIoctlReceived;
	g_diag_snapshot.overall_status = STATUS_PENDING;
}

}  // namespace

void DiagInitialize() {
	ResetLogBuffer();
	ResetSnapshot(0);
	g_diag_initialized = true;
}

void DiagReset(unsigned long long pid) {
	if (!g_diag_initialized) {
		return;
	}

	ResetLogBuffer();
	ResetSnapshot(pid);
	DiagLog("begin injection pid=%p", (HANDLE)(ULONG_PTR)pid);
}

void DiagSetDllPathLength(unsigned long dll_path_length_bytes) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.dll_path_length_bytes = dll_path_length_bytes;
}

void DiagSetStage(InjectionDiagnosticStage stage) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.stage = stage;
}

void DiagSetOverallStatus(NTSTATUS status) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.overall_status = status;
	g_diag_snapshot.stage = InjectionDiagnosticStageComplete;
}

void DiagSetProcessLookupStatus(NTSTATUS status) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.process_lookup_status = status;
}

void DiagSetLoadLibraryResult(PVOID load_library_address) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.load_library_address =
		static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(load_library_address));
	g_diag_snapshot.load_library_status = nullptr == load_library_address
		? STATUS_PROCEDURE_NOT_FOUND
		: STATUS_SUCCESS;
}

void DiagSetContextAllocationStatus(NTSTATUS status) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.context_alloc_status = status;
}

void DiagSetRoutineAllocationStatus(NTSTATUS status, SIZE_T apc_routine_size) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.routine_alloc_status = status;
	g_diag_snapshot.apc_routine_size = static_cast<unsigned long long>(apc_routine_size);
}

void DiagSetThreadEnumerationStatus(NTSTATUS status, size_t thread_count) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.thread_enumeration_status = status;
	g_diag_snapshot.enumerated_thread_count = static_cast<unsigned long long>(thread_count);
}

void DiagNoteThreadLookupFailure(size_t thread_id, NTSTATUS status) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.last_thread_id = static_cast<unsigned long long>(thread_id);
	g_diag_snapshot.last_thread_status = status;
	if (0 == g_diag_snapshot.first_thread_lookup_failure_id) {
		g_diag_snapshot.first_thread_lookup_failure_id = static_cast<unsigned long long>(thread_id);
		g_diag_snapshot.first_thread_lookup_failure_status = status;
	}
}

void DiagNoteApcQueueResult(size_t thread_id, NTSTATUS status) {
	if (!g_diag_initialized) {
		return;
	}
	g_diag_snapshot.last_thread_id = static_cast<unsigned long long>(thread_id);
	g_diag_snapshot.last_thread_status = status;
	if (NT_SUCCESS(status)) {
		g_diag_snapshot.queued_apc_count++;
		if (0 == g_diag_snapshot.first_queue_success_thread_id) {
			g_diag_snapshot.first_queue_success_thread_id = static_cast<unsigned long long>(thread_id);
		}
	}
	else if (0 == g_diag_snapshot.first_queue_failure_thread_id) {
		g_diag_snapshot.first_queue_failure_thread_id = static_cast<unsigned long long>(thread_id);
		g_diag_snapshot.first_queue_failure_status = status;
	}
}

void DiagCopy(_Out_ InjectionDiagnosticSnapshot* snapshot) {
	if (!g_diag_initialized || nullptr == snapshot) {
		return;
	}
	*snapshot = g_diag_snapshot;
}

void DiagLog(_In_z_ _Printf_format_string_ PCSTR format, ...) {
	if (!g_diag_initialized || nullptr == format) {
		return;
	}

	LONG ticket = InterlockedIncrement(&g_LogWriteIndex);
	ULONG slot_index = static_cast<ULONG>(ticket) % RTL_NUMBER_OF(g_LogBuffer);
	auto& slot = g_LogBuffer[slot_index];

	va_list args;
	va_start(args, format);
	NTSTATUS status = RtlStringCbVPrintfA(slot.Storage, sizeof(slot.Storage), format, args);
	va_end(args);

	if (!NT_SUCCESS(status)) {
		RtlStringCbCopyA(slot.Storage, sizeof(slot.Storage), "<format failure>");
	}

	size_t text_length = 0;
	if (!NT_SUCCESS(RtlStringCbLengthA(slot.Storage, sizeof(slot.Storage), &text_length))) {
		text_length = 0;
		slot.Storage[0] = '\0';
	}

	slot.Sequence = ticket;
	slot.Line.Length = static_cast<USHORT>(text_length);
	slot.Line.MaximumLength = sizeof(slot.Storage);
	slot.Line.Buffer = slot.Storage;

	DbgPrint("[INJDIAG][%04ld] %s\n", ticket, slot.Storage);
}
