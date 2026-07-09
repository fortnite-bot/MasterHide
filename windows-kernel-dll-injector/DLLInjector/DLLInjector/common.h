#pragma once

#include <stddef.h>

struct InjectDllArgs {
	size_t pid;
	wchar_t dll_path[256];
};

enum InjectionDiagnosticStage : unsigned long {
	InjectionDiagnosticStageIdle = 0,
	InjectionDiagnosticStageIoctlReceived = 1,
	InjectionDiagnosticStageProcessLookup = 2,
	InjectionDiagnosticStagePayloadCreation = 3,
	InjectionDiagnosticStageThreadEnumeration = 4,
	InjectionDiagnosticStageQueueApc = 5,
	InjectionDiagnosticStageComplete = 6
};

struct InjectionDiagnosticSnapshot {
	unsigned long version;
	unsigned long stage;
	long overall_status;
	unsigned long reserved;
	unsigned long long pid;
	unsigned long dll_path_length_bytes;
	long process_lookup_status;
	unsigned long long load_library_address;
	long load_library_status;
	long context_alloc_status;
	long routine_alloc_status;
	unsigned long long apc_routine_size;
	long thread_enumeration_status;
	unsigned long long enumerated_thread_count;
	unsigned long long queued_apc_count;
	unsigned long long first_queue_success_thread_id;
	unsigned long long first_thread_lookup_failure_id;
	long first_thread_lookup_failure_status;
	unsigned long long first_queue_failure_thread_id;
	long first_queue_failure_status;
	unsigned long long last_thread_id;
	long last_thread_status;
};

#define INJECT_DLL_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GET_INJECT_DIAGNOSTIC_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1338, METHOD_BUFFERED, FILE_READ_DATA)
