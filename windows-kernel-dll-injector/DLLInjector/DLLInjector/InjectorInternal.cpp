#include "InjectorInternal.h"

#include "diag.h"
#include "pe.h"
#include "process.h"
#include <ntstrsafe.h>   // for RtlStringCbCopyW

extern "C" NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect);

extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

static constexpr ACCESS_MASK kProcessCreateThreadAccess = 0x0002;
static constexpr ACCESS_MASK kProcessVmOperationAccess = 0x0008;
static constexpr ACCESS_MASK kProcessVmWriteAccess = 0x0020;
static constexpr LONGLONG kRemoteThreadWaitTimeout100ns = -50000000LL;

// ------------------------------------------------------------------
// Shellcode: x64 stub that loads a DLL by calling LoadLibraryW and stores
// the returned module handle in a remote result slot.
// LoadLibraryW is patched at offset 6, the result slot at offset 18.
// RCX contains the DLL path when the thread starts.
static const UCHAR g_RemoteThreadShellcode[] = {
	0x48, 0x83, 0xEC, 0x28,							// sub rsp, 28h
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0 (patched)
	0xFF, 0xD0,											// call rax
	0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, 0 (patched)
	0x48, 0x89, 0x02,									// mov [rdx], rax
	0x48, 0x83, 0xC4, 0x28,							// add rsp, 28h
	0xC3												// ret
};

// Patch the shellcode with the real LoadLibraryW address and result buffer.
static void PatchShellcode(
    _In_ PVOID shellcodeBuffer,
    _In_ PVOID loadLibraryAddress,
    _In_ PVOID resultBufferAddress)
{
	*(PVOID*)((PUCHAR)shellcodeBuffer + 6) = loadLibraryAddress;
	*(PVOID*)((PUCHAR)shellcodeBuffer + 18) = resultBufferAddress;
}

// ------------------------------------------------------------------
// Look up LoadLibraryW in kernel32.dll (using the PE parser from pe.cpp)
static PVOID FindLoadLibraryW()
{
	return get_module_symbol_address((wchar_t*)L"KERNEL32.DLL", (char*)"LoadLibraryW");
}

// ---------------------------------------------------------------
// Prototype of RtlCreateUserThread (from ntoskrnl export)
// ---------------------------------------------------------------
typedef NTSTATUS (NTAPI* PFN_RtlCreateUserThread)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_ ULONG StackZeroBits,
    _Inout_opt_ PULONG StackReserved,
    _Inout_opt_ PULONG StackCommit,
    _In_ PVOID StartAddress,
    _In_opt_ PVOID StartParameter,
    _Out_ PHANDLE ThreadHandle,
    _Out_ PCLIENT_ID ClientId
);

// ---------------------------------------------------------------
// One‑time resolver for RtlCreateUserThread (exported, always available)
// ---------------------------------------------------------------
static PFN_RtlCreateUserThread ResolveRtlCreateUserThread()
{
    static PFN_RtlCreateUserThread s_pfn = NULL;
    if (s_pfn == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"RtlCreateUserThread");
        s_pfn = (PFN_RtlCreateUserThread)MmGetSystemRoutineAddress(&routineName);
        if (s_pfn == NULL)
            DiagLog("RtlCreateUserThread not found in ntoskrnl exports");
    }
    return s_pfn;
}

// ---------------------------------------------------------------
// Create a user‑mode thread in the target process using RtlCreateUserThread
// ---------------------------------------------------------------
static NTSTATUS CreateRemoteThreadInProcess(
    _In_ PEPROCESS Process,
    _In_ PVOID StartRoutine,
    _In_ PVOID Argument,
    _Out_opt_ PHANDLE ThreadHandle)
{
    PFN_RtlCreateUserThread pfn = ResolveRtlCreateUserThread();
    if (pfn == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    if (ThreadHandle != NULL) {
        *ThreadHandle = NULL;
    }

    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        kProcessCreateThreadAccess | kProcessVmOperationAccess | kProcessVmWriteAccess,
        NULL,
        KernelMode,
        &hProcess);
    if (!NT_SUCCESS(status))
    {
        DiagLog("ObOpenObjectByPointer failed: 0x%X", status);
        return status;
    }

    HANDLE hThread = NULL;
    CLIENT_ID cid;
    status = pfn(
        hProcess,       // ProcessHandle
        NULL,           // SecurityDescriptor (optional)
        FALSE,          // CreateSuspended = FALSE (run immediately)
        0,              // StackZeroBits
        NULL,           // StackReserved (NULL = default)
        NULL,           // StackCommit (NULL = default)
        StartRoutine,   // user‑mode entry point
        Argument,       // passed as the thread’s argument
        &hThread,
        &cid);

    DiagLog("RtlCreateUserThread returned 0x%X, hThread = %p", status, hThread);

    if (!NT_SUCCESS(status) && hThread != NULL) {
        ZwClose(hThread);
        hThread = NULL;
    }

    if (NT_SUCCESS(status) && ThreadHandle != NULL) {
        *ThreadHandle = hThread;
        hThread = NULL;
    }

    if (hThread != NULL) {
        ZwClose(hThread);
    }

    ZwClose(hProcess);
    return status;
}
// ------------------------------------------------------------------
// Free memory allocated in the target process (reuses existing logic)
static VOID FreeTargetMemory(PVOID* Address, SIZE_T Size)
{
	UNREFERENCED_PARAMETER(Size);

	if (*Address != NULL) {
		SIZE_T releaseSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), Address, &releaseSize, MEM_RELEASE);
		*Address = NULL;
	}
}

static NTSTATUS WaitForRemoteThread(_In_ HANDLE ThreadHandle)
{
	LARGE_INTEGER timeout;
	timeout.QuadPart = kRemoteThreadWaitTimeout100ns;

	NTSTATUS status = ZwWaitForSingleObject(ThreadHandle, FALSE, &timeout);
	DiagLog("ZwWaitForSingleObject returned 0x%X", status);
	return status;
}

// Main injection function – replaces both CreateTargetApcPayload and Queue*APCs
NTSTATUS InjectDllViaRemoteThread(
	_In_ PEPROCESS TargetProcess,
	_In_ PUNICODE_STRING DllPath)
{
	if (TargetProcess == NULL || DllPath == NULL || DllPath->Buffer == NULL || DllPath->Length == 0)
		return STATUS_INVALID_PARAMETER;

	KAPC_STATE apcState;
	KeStackAttachProcess(TargetProcess, &apcState);

	// 1. Resolve LoadLibraryW
	PVOID pLoadLibrary = FindLoadLibraryW();
	DiagLog("LoadLibraryW address: %p", pLoadLibrary);
	if (pLoadLibrary == NULL) {
		KeUnstackDetachProcess(&apcState);
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	// 2. Allocate RW memory for the DLL path (Win32 format)
	PWSTR pRemotePath = NULL;
	const SIZE_T pathBytes = DllPath->Length + sizeof(WCHAR);
	SIZE_T pathRegionSize = pathBytes;
	NTSTATUS status = ZwAllocateVirtualMemory(
		NtCurrentProcess(),
		(PVOID*)&pRemotePath,
		0,
		&pathRegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&apcState);
		DiagLog("Failed to allocate path: 0x%X", status);
		return status;
	}
	RtlCopyMemory(pRemotePath, DllPath->Buffer, DllPath->Length);
	pRemotePath[DllPath->Length / sizeof(WCHAR)] = L'\0';  // ensure null termination
	DiagLog("Allocated DLL path at %p: %wZ", pRemotePath, DllPath);

	// 3. Allocate a remote buffer that captures the LoadLibraryW result.
	PVOID pRemoteLoadResult = NULL;
	const SIZE_T loadResultBytes = sizeof(ULONGLONG);
	SIZE_T loadResultRegionSize = loadResultBytes;
	status = ZwAllocateVirtualMemory(
		NtCurrentProcess(),
		&pRemoteLoadResult,
		0,
		&loadResultRegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		FreeTargetMemory((PVOID*)&pRemotePath, pathBytes);
		KeUnstackDetachProcess(&apcState);
		DiagLog("Failed to allocate load result buffer: 0x%X", status);
		return status;
	}
	RtlZeroMemory(pRemoteLoadResult, loadResultBytes);
	DiagLog("Allocated load result buffer at %p", pRemoteLoadResult);

	// 4. Allocate writable memory for the shellcode, then flip it to RX.
	PVOID pRemoteShellcode = NULL;
	const SIZE_T shellcodeBytes = sizeof(g_RemoteThreadShellcode);
	SIZE_T shellcodeRegionSize = shellcodeBytes;
	status = ZwAllocateVirtualMemory(
		NtCurrentProcess(),
		&pRemoteShellcode,
		0,
		&shellcodeRegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		FreeTargetMemory(&pRemoteLoadResult, loadResultBytes);
		FreeTargetMemory((PVOID*)&pRemotePath, pathBytes);
		KeUnstackDetachProcess(&apcState);
		DiagLog("Failed to allocate shellcode: 0x%X", status);
		return status;
	}
	RtlCopyMemory(pRemoteShellcode, g_RemoteThreadShellcode, shellcodeBytes);
	PatchShellcode(pRemoteShellcode, pLoadLibrary, pRemoteLoadResult);
	DiagLog("Allocated shellcode at %p, patched with LoadLibraryW %p", pRemoteShellcode, pLoadLibrary);

	ULONG oldProtect = 0;
	PVOID protectBase = pRemoteShellcode;
	SIZE_T protectSize = shellcodeBytes;
	status = ZwProtectVirtualMemory(
		NtCurrentProcess(),
		&protectBase,
		&protectSize,
		PAGE_EXECUTE_READ,
		&oldProtect);
	if (!NT_SUCCESS(status)) {
		FreeTargetMemory(&pRemoteShellcode, shellcodeBytes);
		FreeTargetMemory(&pRemoteLoadResult, loadResultBytes);
		FreeTargetMemory((PVOID*)&pRemotePath, pathBytes);
		KeUnstackDetachProcess(&apcState);
		DiagLog("ZwProtectVirtualMemory failed: 0x%X", status);
		return status;
	}
	DiagLog("Updated shellcode protection, old protect=0x%X", oldProtect);

	// 5. Detach from the target process.
	KeUnstackDetachProcess(&apcState);

	// 6. Create the remote thread and wait for LoadLibraryW to complete.
	HANDLE hRemoteThread = NULL;
	status = CreateRemoteThreadInProcess(TargetProcess, pRemoteShellcode, pRemotePath, &hRemoteThread);
	if (!NT_SUCCESS(status)) {
		// On failure, free the memory we allocated (re-attach to free).
		KeStackAttachProcess(TargetProcess, &apcState);
		FreeTargetMemory(&pRemoteShellcode, shellcodeBytes);
		FreeTargetMemory(&pRemoteLoadResult, loadResultBytes);
		FreeTargetMemory((PVOID*)&pRemotePath, pathBytes);
		KeUnstackDetachProcess(&apcState);
		DiagLog("RtlCreateUserThread failed: 0x%X", status);
		return status;
	}

	DiagLog("Remote thread created successfully");
	status = WaitForRemoteThread(hRemoteThread);
	ZwClose(hRemoteThread);
	if (!NT_SUCCESS(status)) {
		DiagLog("Remote thread wait failed: 0x%X", status);
		return status;
	}

	KeStackAttachProcess(TargetProcess, &apcState);
	ULONGLONG loadResult = 0;
	if (pRemoteLoadResult != NULL) {
		loadResult = *(volatile ULONGLONG*)pRemoteLoadResult;
	}
	FreeTargetMemory(&pRemoteShellcode, shellcodeBytes);
	FreeTargetMemory(&pRemoteLoadResult, loadResultBytes);
	FreeTargetMemory((PVOID*)&pRemotePath, pathBytes);
	KeUnstackDetachProcess(&apcState);

	DiagSetLoadLibraryResult((PVOID)(ULONG_PTR)loadResult);
	DiagLog("LoadLibraryW returned 0x%p", (PVOID)(ULONG_PTR)loadResult);
	if (loadResult == 0) {
		DiagLog("LoadLibraryW returned NULL");
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

// ------------------------------------------------------------------
// The old APC queueing function is no longer used. Keep it empty if needed
// for backward compatibility, or delete it entirely from the interface.
NTSTATUS QueueUserModeApcToProcessThreads(HANDLE, PVOID, PVOID) {
	return STATUS_NOT_IMPLEMENTED;
}

// The old payload creation function – no longer used.
NTSTATUS CreateTargetApcPayload(PUNICODE_STRING, PVOID*, PVOID*) {
	return STATUS_NOT_IMPLEMENTED;
}

// The old free function – can be removed, but kept to satisfy existing calls.
VOID FreeTargetApcPayload(PVOID ApcRoutine, PVOID ApcContext) {
	SIZE_T size = 0;
	if (ApcRoutine) ZwFreeVirtualMemory(NtCurrentProcess(), &ApcRoutine, &size, MEM_RELEASE);
	if (ApcContext) { size = 0; ZwFreeVirtualMemory(NtCurrentProcess(), &ApcContext, &size, MEM_RELEASE); }
}
