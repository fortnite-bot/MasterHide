#include "Injector.h"
#include "diag.h"
#include "InjectorInternal.h"
#include <ntstrsafe.h>

// ---------------------------------------------------------------------------
// Registry checkpoint helper – writes a status string under the MasterHide service key
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Main injection entry point – uses remote thread instead of APC
// ---------------------------------------------------------------------------
extern "C" NTSTATUS InjectDllIntoProcess(HANDLE ProcessId, PUNICODE_STRING DllPath)
{
    if (nullptr == ProcessId || nullptr == DllPath || nullptr == DllPath->Buffer || 0 == DllPath->Length)
    {
        DiagLog("InjectDllIntoProcess invalid parameter pid=%p dll=%p len=0x%X",
            ProcessId, DllPath ? DllPath->Buffer : nullptr, DllPath ? DllPath->Length : 0);
        WriteCheckpointWithStatus("Invalid parameter", STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    DiagReset(static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(ProcessId)));
    DiagSetDllPathLength(DllPath->Length);

    PEPROCESS target_process = nullptr;
    DiagSetStage(InjectionDiagnosticStageProcessLookup);
    DiagLog("before PsLookupProcessByProcessId pid=%p", ProcessId);

    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &target_process);
    DiagSetProcessLookupStatus(status);
    DiagLog("after PsLookupProcessByProcessId pid=%p target=%p status=0x%08X", ProcessId, target_process, status);

    if (!NT_SUCCESS(status))
    {
        WriteCheckpointWithStatus("PsLookupProcessByProcessId failed", status);
        DiagSetOverallStatus(status);
        return status;
    }
    WriteCheckpoint("PsLookupProcessByProcessId OK");

    // The new injection function handles attach/detach internally
    DiagSetStage(InjectionDiagnosticStagePayloadCreation);
    DiagLog("before InjectDllViaRemoteThread pid=%p dll=%wZ", ProcessId, DllPath);

    status = InjectDllViaRemoteThread(target_process, DllPath);

    DiagLog("after InjectDllViaRemoteThread pid=%p status=0x%08X", ProcessId, status);

    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_TIMEOUT) {
            WriteCheckpointWithStatus("Remote thread wait timed out", status);
        }
        else if (status == STATUS_UNSUCCESSFUL) {
            WriteCheckpointWithStatus("LoadLibraryW returned NULL", status);
        }
        else {
            WriteCheckpointWithStatus("InjectDllViaRemoteThread failed", status);
        }
        DbgPrint("[Injector] Remote thread injection failed: 0x%08X\n", status);
    }
    else
    {
        WriteCheckpoint("Injection confirmed");
        DbgPrint("[Injector] LoadLibraryW succeeded in pid=%p\n", ProcessId);
    }

    ObDereferenceObject(target_process);
    DiagLog("inject complete pid=%p status=0x%08X", ProcessId, status);
    DiagSetOverallStatus(status);
    return status;
}
