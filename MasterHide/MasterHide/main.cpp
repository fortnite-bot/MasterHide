#include "stdafx.h"
#include "Phase2Bridge.h"
#include "..\..\windows-kernel-dll-injector\DLLInjector\DLLInjector\diag.h"

extern "C" volatile LONG g_Phase2ExplorerLoaderReady = 0;
extern "C" volatile LONG g_Phase2ExplorerInjectionIssued = 0;
extern "C" HANDLE g_Phase2TargetExplorerPid = NULL;

// Forward declarations
extern "C" VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

extern "C" VOID LoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

// Force callbacks into a non‑paged section (still needed for later if we fix Verifier)
#pragma alloc_text(PROCESS, ProcessNotifyCallback)
#pragma alloc_text(PROCESS, LoadImageNotify)

// ---------------------------------------------------------------------------
static bool IsInteractiveProcessSession(_In_ PEPROCESS Process)
{
    const ACCESS_MASK processQueryAccess = 0x0400;
    HANDLE processHandle = NULL;
    PROCESS_SESSION_INFORMATION sessionInfo = {};

    NTSTATUS status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        processQueryAccess,
        *PsProcessType,
        KernelMode,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    status = ZwQueryInformationProcess(
        processHandle,
        ProcessSessionInformation,
        &sessionInfo,
        sizeof(sessionInfo),
        NULL);

    ZwClose(processHandle);
    return NT_SUCCESS(status) && sessionInfo.SessionId != 0;
}

static bool IsTargetDwmProcess(
    _In_ PEPROCESS Process,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PUNICODE_STRING allocatedImageName = NULL;
    PCUNICODE_STRING imageName = NULL;
    const UNICODE_STRING targetName = RTL_CONSTANT_STRING(L"explorer.exe");

    if (CreateInfo != NULL &&
        CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL &&
        CreateInfo->ImageFileName->Length != 0) {
        imageName = CreateInfo->ImageFileName;
    }
    else {
        NTSTATUS status = SeLocateProcessImageName(Process, &allocatedImageName);
        if (!NT_SUCCESS(status) || allocatedImageName == NULL) {
            return false;
        }

        imageName = allocatedImageName;
    }

    USHORT nameStart = imageName->Length / sizeof(WCHAR);
    while (nameStart > 0) {
        const WCHAR ch = imageName->Buffer[nameStart - 1];
        if (ch == L'\\' || ch == L'/') {
            break;
        }

        --nameStart;
    }

    UNICODE_STRING baseName;
    baseName.Buffer = imageName->Buffer + nameStart;
    baseName.Length = imageName->Length - (nameStart * sizeof(WCHAR));
    baseName.MaximumLength = baseName.Length;

    const bool isMatch = RtlEqualUnicodeString(&baseName, &targetName, TRUE) != FALSE;

    if (allocatedImageName != NULL) {
        ExFreePool(allocatedImageName);
    }

    return isMatch;
}

static bool IsExplorerReadyModule(_In_ PCUNICODE_STRING ImageName)
{
    const UNICODE_STRING shell32 = RTL_CONSTANT_STRING(L"shell32.dll");
    const UNICODE_STRING explorerFrame = RTL_CONSTANT_STRING(L"explorerframe.dll");

    USHORT nameStart = ImageName->Length / sizeof(WCHAR);
    while (nameStart > 0) {
        const WCHAR ch = ImageName->Buffer[nameStart - 1];
        if (ch == L'\\' || ch == L'/') {
            break;
        }

        --nameStart;
    }

    UNICODE_STRING baseName;
    baseName.Buffer = ImageName->Buffer + nameStart;
    baseName.Length = ImageName->Length - (nameStart * sizeof(WCHAR));
    baseName.MaximumLength = baseName.Length;

    return RtlEqualUnicodeString(&baseName, &shell32, TRUE) != FALSE ||
        RtlEqualUnicodeString(&baseName, &explorerFrame, TRUE) != FALSE;
}

// ---------------------------------------------------------------------------
// Driver unload
// ---------------------------------------------------------------------------
void OnDriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNREFERENCED_PARAMETER(pDriverObject);

    DbgPrint("[MasterHide] Unloading...\n");

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

    ssdt::Destroy();
    sssdt::Destroy();

    LARGE_INTEGER LargeInteger{ };
    LargeInteger.QuadPart = -11000000;
    KeDelayExecutionThread(KernelMode, FALSE, &LargeInteger);
    tools::UnloadImages();

    DbgPrint("[MasterHide] Driver unloaded.\n");
}

// ---------------------------------------------------------------------------
// Callback implementations
// ---------------------------------------------------------------------------
VOID ProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo == NULL) {
        return;
    }

    if (!IsTargetDwmProcess(Process, CreateInfo)) {
        return;
    }

    if (!IsInteractiveProcessSession(Process)) {
        return;
    }

    g_Phase2TargetExplorerPid = ProcessId;
    DbgPrint("[Callback] New explorer.exe PID=%p – waiting for loader\n", ProcessId);

    NTSTATUS callbackStatus = Phase2_TriggerInjectionForPid(ProcessId, TRUE);
    if (!NT_SUCCESS(callbackStatus)) {
        DbgPrint("[Callback] Injection failed for PID=%p: 0x%X\n", ProcessId, callbackStatus);
    }
}

VOID LoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName == NULL || FullImageName->Buffer == NULL || ProcessId == NULL) {
        return;
    }

    if (g_Phase2TargetExplorerPid != NULL && ProcessId != g_Phase2TargetExplorerPid) {
        return;
    }

    if (!IsExplorerReadyModule(FullImageName)) {
        return;
    }

    g_Phase2TargetExplorerPid = ProcessId;
    InterlockedExchange(&g_Phase2ExplorerLoaderReady, 1);

    DbgPrint("[Callback] explorer.exe loader ready via %wZ PID=%p\n", FullImageName, ProcessId);
}

// ---------------------------------------------------------------------------
// DriverEntry – made callback registration non‑fatal
// ---------------------------------------------------------------------------
extern "C" NTSTATUS NTAPI DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

    if (!pDriverObject)
        return STATUS_FAILED_DRIVER_ENTRY;

    pDriverObject->DriverUnload = &OnDriverUnload;
    DiagInitialize();
    DbgPrint("[MinTest] Driver loaded.\n");

    // Debug: print addresses of the callback functions
    DbgPrint("[Debug] ProcessNotifyCallback address = 0x%p\n", ProcessNotifyCallback);
    DbgPrint("[Debug] LoadImageNotify address       = 0x%p\n", LoadImageNotify);

    // Try to register process creation callback – but don't fail if it doesn't work
    NTSTATUS cbStatus = PsSetCreateProcessNotifyRoutineEx(
        ProcessNotifyCallback,
        FALSE   // FALSE = register
    );
    DbgPrint("[Debug] PsSetCreateProcessNotifyRoutineEx returned 0x%08X\n", cbStatus);

    if (!NT_SUCCESS(cbStatus)) {
        DbgPrint("[MasterHide] Warning: Could not register process callback (0x%X) – "
                 "driver will still function for initial injection.\n", cbStatus);
        // Do NOT return an error – continue loading
    } else {
        DbgPrint("[MasterHide] Process callback registered.\n");
    }

    // Try to register image load callback – also non‑fatal
    NTSTATUS imageCbStatus = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    DbgPrint("[Debug] PsSetLoadImageNotifyRoutine returned 0x%08X\n", imageCbStatus);

    if (!NT_SUCCESS(imageCbStatus)) {
        DbgPrint("[MasterHide] Warning: Could not register image callback (0x%X).\n", imageCbStatus);
    } else {
        DbgPrint("[MasterHide] Load-image callback registered.\n");
    }

    // Initial injection into existing explorer.exe – this is the critical part
    NTSTATUS startupStatus = Phase2_TriggerInjection();
    DbgPrint("[Debug] Phase2_TriggerInjection returned 0x%08X\n", startupStatus);

    if (startupStatus == STATUS_NOT_FOUND) {
        DbgPrint("[MasterHide] No running explorer.exe found during startup.\n");
    }
    else if (!NT_SUCCESS(startupStatus)) {
        DbgPrint("[MasterHide] Initial injection failed: 0x%X\n", startupStatus);
    }
    else {
        DbgPrint("[MasterHide] Initial injection confirmed.\n");
    }

    DbgPrint("[MinTest] Driver ready.\n");
    // Always return success so the driver stays loaded
    return STATUS_SUCCESS;
}