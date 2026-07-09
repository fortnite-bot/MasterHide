#pragma once

// Disable annoying warnings
#pragma warning(disable: 4100)   // unreferenced formal parameter
#pragma warning(disable: 4189)   // local variable initialized but not referenced

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define TAG 'Mstr'

// Debug output macro
#define DBGPRINT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

// Missing system information classes
#define SystemExtendedHandleInformation (SYSTEM_INFORMATION_CLASS)64
#define SystemCodeIntegrityInformation  (SYSTEM_INFORMATION_CLASS)103

#define CODEINTEGRITY_OPTION_ENABLED    0x01
#define CODEINTEGRITY_OPTION_TESTSIGN   0x02

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

// Object information classes
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

// Handle information structures
typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG NumberOfHandles;
    ULONG Reserved;
    struct {
        ULONG ProcessId;
        UCHAR ObjectTypeNumber;
        UCHAR Flags;
        USHORT Handle;
        PVOID Object;
        ACCESS_MASK GrantedAccess;
    } Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// Function prototypes
extern "C" NTKERNELAPI NTSTATUS ZwQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

extern "C" NTKERNELAPI NTSTATUS ZwDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

extern "C" NTKERNELAPI NTSTATUS ZwQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS *Process
);

extern "C" NTKERNELAPI VOID KeStackAttachProcess(
    PKPROCESS Process,
    PRKAPC_STATE ApcState
);

extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(
    PRKAPC_STATE ApcState
);

// Global SSDT pointers (used in ssdt.cpp / shadow_ssdt.cpp)
extern PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable;
extern PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTableShadow;