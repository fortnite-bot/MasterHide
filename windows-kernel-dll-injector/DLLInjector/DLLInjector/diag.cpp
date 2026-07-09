#include "diag.h"

namespace {

KSPIN_LOCK g_diag_lock;
InjectionDiagnosticSnapshot g_diag_snapshot = {};
bool g_diag_initialized = false;

template <typename Fn>
void WithDiagLock(Fn&& fn) {
	if (!g_diag_initialized) {
		return;
	}

	KIRQL old_irql = PASSIVE_LEVEL;
	KeAcquireSpinLock(&g_diag_lock, &old_irql);
	fn();
	KeReleaseSpinLock(&g_diag_lock, old_irql);
}

}  // namespace

void DiagInitialize() {
	KeInitializeSpinLock(&g_diag_lock);
	RtlZeroMemory(&g_diag_snapshot, sizeof(g_diag_snapshot));
	g_diag_snapshot.version = 1;
	g_diag_initialized = true;
}

void DiagReset(unsigned long long pid) {
	WithDiagLock([&]() {
		RtlZeroMemory(&g_diag_snapshot, sizeof(g_diag_snapshot));
		g_diag_snapshot.version = 1;
		g_diag_snapshot.pid = pid;
		g_diag_snapshot.stage = InjectionDiagnosticStageIoctlReceived;
		g_diag_snapshot.overall_status = STATUS_PENDING;
	});
}

void DiagSetDllPathLength(unsigned long dll_path_length_bytes) {
	WithDiagLock([&]() {
		g_diag_snapshot.dll_path_length_bytes = dll_path_length_bytes;
	});
}

void DiagSetStage(InjectionDiagnosticStage stage) {
	WithDiagLock([&]() {
		g_diag_snapshot.stage = stage;
	});
}

void DiagSetOverallStatus(NTSTATUS status) {
	WithDiagLock([&]() {
		g_diag_snapshot.overall_status = status;
		g_diag_snapshot.stage = InjectionDiagnosticStageComplete;
	});
}

void DiagSetProcessLookupStatus(NTSTATUS status) {
	WithDiagLock([&]() {
		g_diag_snapshot.process_lookup_status = status;
	});
}

void DiagSetLoadLibraryResult(PVOID load_library_address) {
	WithDiagLock([&]() {
		g_diag_snapshot.load_library_address =
			static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(load_library_address));
		g_diag_snapshot.load_library_status = nullptr == load_library_address
			? STATUS_PROCEDURE_NOT_FOUND
			: STATUS_SUCCESS;
	});
}

void DiagSetContextAllocationStatus(NTSTATUS status) {
	WithDiagLock([&]() {
		g_diag_snapshot.context_alloc_status = status;
	});
}

void DiagSetRoutineAllocationStatus(NTSTATUS status, SIZE_T apc_routine_size) {
	WithDiagLock([&]() {
		g_diag_snapshot.routine_alloc_status = status;
		g_diag_snapshot.apc_routine_size = static_cast<unsigned long long>(apc_routine_size);
	});
}

void DiagSetThreadEnumerationStatus(NTSTATUS status, size_t thread_count) {
	WithDiagLock([&]() {
		g_diag_snapshot.thread_enumeration_status = status;
		g_diag_snapshot.enumerated_thread_count = static_cast<unsigned long long>(thread_count);
	});
}

void DiagNoteThreadLookupFailure(size_t thread_id, NTSTATUS status) {
	WithDiagLock([&]() {
		g_diag_snapshot.last_thread_id = static_cast<unsigned long long>(thread_id);
		g_diag_snapshot.last_thread_status = status;
		if (0 == g_diag_snapshot.first_thread_lookup_failure_id) {
			g_diag_snapshot.first_thread_lookup_failure_id = static_cast<unsigned long long>(thread_id);
			g_diag_snapshot.first_thread_lookup_failure_status = status;
		}
	});
}

void DiagNoteApcQueueResult(size_t thread_id, NTSTATUS status) {
	WithDiagLock([&]() {
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
	});
}

void DiagCopy(_Out_ InjectionDiagnosticSnapshot* snapshot) {
	if (nullptr == snapshot) {
		return;
	}

	WithDiagLock([&]() {
		*snapshot = g_diag_snapshot;
	});
}
