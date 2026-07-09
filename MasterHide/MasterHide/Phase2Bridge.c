#include "Phase2Bridge.h"
#include "..\..\windows-kernel-dll-injector\DLLInjector\DLLInjector\Injector.h"

#define SystemProcessInformation 5
#define PHASE2_POOL_TAG 'B2HP'

typedef struct _PHASE2_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG Reserved1;
    ULONGLONG CycleTime;
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
} PHASE2_SYSTEM_PROCESS_INFORMATION, *PPHASE2_SYSTEM_PROCESS_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static BOOLEAN g_Injected = FALSE;

static NTSTATUS FindExplorerProcessId(_Out_ PHANDLE Pid);

NTSTATUS Phase2_TriggerInjection(void)
{
    HANDLE explorerPid = NULL;
    UNICODE_STRING dllPath = RTL_CONSTANT_STRING(L"\\??\\C:\\Windows\\Temp\\inject.dll");
    NTSTATUS status;

    if (g_Injected) {
        return STATUS_SUCCESS;
    }

    status = FindExplorerProcessId(&explorerPid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Phase2] explorer.exe not found, status 0x%08X\n", (ULONG)status);
        return status;
    }

    status = InjectDllIntoProcess(explorerPid, &dllPath);
    if (NT_SUCCESS(status)) {
        g_Injected = TRUE;
        DbgPrint("[Phase2] DLL injected into explorer.exe successfully\n");
    }

    return status;
}

static NTSTATUS FindExplorerProcessId(_Out_ PHANDLE Pid)
{
    PVOID processBuffer = NULL;
    SIZE_T processBufferSize = 0x10000;
    UNICODE_STRING explorerName = RTL_CONSTANT_STRING(L"explorer.exe");
    NTSTATUS status;

    if (Pid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Pid = NULL;

    for (;;) {
        processBuffer = ExAllocatePool2(POOL_FLAG_PAGED, processBufferSize, PHASE2_POOL_TAG);
        if (processBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemProcessInformation,
            processBuffer,
            (ULONG)processBufferSize,
            NULL
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePool(processBuffer);
            processBuffer = NULL;
            processBufferSize += 0x10000;
            continue;
        }

        break;
    }

    if (NT_SUCCESS(status)) {
        PPHASE2_SYSTEM_PROCESS_INFORMATION process =
            (PPHASE2_SYSTEM_PROCESS_INFORMATION)processBuffer;

        for (;;) {
            if (process->ImageName.Buffer != NULL &&
                RtlEqualUnicodeString(&process->ImageName, &explorerName, TRUE)) {
                *Pid = process->ProcessId;
                status = STATUS_SUCCESS;
                break;
            }

            if (process->NextEntryOffset == 0) {
                status = STATUS_NOT_FOUND;
                break;
            }

            process = (PPHASE2_SYSTEM_PROCESS_INFORMATION)
                ((PUCHAR)process + process->NextEntryOffset);
        }
    }

    if (processBuffer != NULL) {
        ExFreePool(processBuffer);
    }

    return status;
}
