#pragma once

#include <ntifs.h>

#include "common.h"

#define DIAG_LOG_ENTRY_COUNT 64
#define DIAG_LOG_TEXT_CAPACITY 160

struct InjectionLogSlot {
	LONG Sequence;
	ANSI_STRING Line;
	CHAR Storage[DIAG_LOG_TEXT_CAPACITY];
};

extern "C" InjectionLogSlot g_LogBuffer[DIAG_LOG_ENTRY_COUNT];
extern "C" volatile LONG g_LogWriteIndex;

void DiagInitialize();

void DiagReset(unsigned long long pid);
void DiagSetDllPathLength(unsigned long dll_path_length_bytes);
void DiagSetStage(InjectionDiagnosticStage stage);
void DiagSetOverallStatus(NTSTATUS status);
void DiagSetProcessLookupStatus(NTSTATUS status);
void DiagSetLoadLibraryResult(PVOID load_library_address);
void DiagSetContextAllocationStatus(NTSTATUS status);
void DiagSetRoutineAllocationStatus(NTSTATUS status, SIZE_T apc_routine_size);
void DiagSetThreadEnumerationStatus(NTSTATUS status, size_t thread_count);
void DiagNoteThreadLookupFailure(size_t thread_id, NTSTATUS status);
void DiagNoteApcQueueResult(size_t thread_id, NTSTATUS status);
void DiagCopy(_Out_ InjectionDiagnosticSnapshot* snapshot);
void DiagLog(_In_z_ _Printf_format_string_ PCSTR format, ...);
