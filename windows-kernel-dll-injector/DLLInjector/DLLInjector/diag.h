#pragma once

#include <ntifs.h>

#include "common.h"

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
