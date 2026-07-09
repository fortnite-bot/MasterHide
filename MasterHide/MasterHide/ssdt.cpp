#include "stdafx.h"

PSYSTEM_SERVICE_TABLE g_KeServiceDescriptorTable = NULL;

// Signature scan for KeServiceDescriptorTable (works on 19045)
ULONGLONG GetKeServiceDescriptorTable64()
{
    PUCHAR start = (PUCHAR)__readmsr(0xC0000082);
    ULONG limit = 4096;

    for (ULONG i = 0; i < limit; i++)
    {
        if (start[i] == 0x4C && start[i + 1] == 0x8D && start[i + 2] == 0x15)
        {
            INT32 relOffset = *(PINT32)(start + i + 3);
            ULONGLONG ssdtAddr = (ULONGLONG)(start + i + 7) + relOffset;
            DBGPRINT("Found KeServiceDescriptorTable at 0x%p\n", ssdtAddr);
            return ssdtAddr;
        }
    }
    DBGPRINT("Failed to locate KeServiceDescriptorTable!\n");
    return 0;
}

ULONGLONG GetSSDTFuncCurAddr64(ULONG id)
{
    LONG dwtmp = 0;
    PULONG ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = ServiceTableBase[id];
    dwtmp = dwtmp >> 4;
    return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
    ULONG dwtmp = 0;
    PULONG ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
    dwtmp = dwtmp << 4;
    return dwtmp;
}

bool HookSSDT(PUCHAR pCode, ULONG ulCodeSize, PVOID pNewFunction, PVOID* pOldFunction, ULONG SyscallNum)
{
    if (!pNewFunction || !pOldFunction || SyscallNum <= 0)
        return false;

    DBGPRINT("[ HookSSDT ] Syscall: 0x%X\n", SyscallNum);

    *pOldFunction = PVOID(GetSSDTFuncCurAddr64(SyscallNum));
    DBGPRINT("[ HookSSDT ] Original: 0x%p\n", *pOldFunction);

    *(PULONG64)(jmp_trampoline + 3) = ULONG64(pNewFunction);

    const ULONG trampolineSize = sizeof(jmp_trampoline);

    // Search for code cave, skipping first 0x1000 bytes to avoid critical code
    DBGPRINT("[ HookSSDT ] Searching for code cave (offset 0x1000)...\n");
    auto pCodeCave = utils::FindCodeCave(pCode + 0x1000, ulCodeSize - 0x1000, trampolineSize);
    if (!pCodeCave)
    {
        DBGPRINT("[ HookSSDT ] Failed to find a suitable code cave.\n");
        return false;
    }
    DBGPRINT("[ HookSSDT ] Code Cave: 0x%p\n", pCodeCave);

    // MDL for code cave
    auto Mdl = IoAllocateMdl(pCodeCave, trampolineSize, 0, 0, NULL);
    if (!Mdl)
    {
        DBGPRINT("[ HookSSDT ] IoAllocateMdl failed!\n");
        return false;
    }
    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    auto Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!Mapping)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        DBGPRINT("[ HookSSDT ] MmMapLockedPagesSpecifyCache failed!\n");
        return false;
    }

    // Copy trampoline via writable mapping (no CR0 change)
    RtlCopyMemory(Mapping, jmp_trampoline, trampolineSize);

    // Compute new SSDT entry
    auto ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;
    auto SsdtEntry = GetOffsetAddress(ULONG64(pCodeCave));
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += ServiceTableBase[SyscallNum] & 0x0F;

    // MDL-map the SSDT entry itself for safe writing
    PULONG pSsdtAddr = &ServiceTableBase[SyscallNum];
    MDL* pSsdtMdl = IoAllocateMdl(pSsdtAddr, sizeof(ULONG), FALSE, FALSE, NULL);
    if (pSsdtMdl)
    {
        MmProbeAndLockPages(pSsdtMdl, KernelMode, IoReadAccess);
        PULONG pMappedSsdt = (PULONG)MmMapLockedPagesSpecifyCache(pSsdtMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (pMappedSsdt)
        {
            *pMappedSsdt = SsdtEntry;
            MmUnmapLockedPages(pMappedSsdt, pSsdtMdl);
        }
        MmUnlockPages(pSsdtMdl);
        IoFreeMdl(pSsdtMdl);
    }

    // Cleanup code cave mappings
    MmUnmapLockedPages(Mapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    DBGPRINT("[ HookSSDT ] HookSSDT complete.\n");
    return true;
}

bool UnhookSSDT(PVOID pFunction, ULONG SyscallNum)
{
    if (!pFunction || SyscallNum <= 0)
        return false;

    auto ServiceTableBase = (PULONG)g_KeServiceDescriptorTable->ServiceTableBase;

    auto SsdtEntry = GetOffsetAddress(ULONG64(pFunction));
    SsdtEntry &= 0xFFFFFFF0;
    SsdtEntry += ServiceTableBase[SyscallNum] & 0x0F;

    // MDL-mapped safe write
    PULONG pSsdtAddr = &ServiceTableBase[SyscallNum];
    MDL* pSsdtMdl = IoAllocateMdl(pSsdtAddr, sizeof(ULONG), FALSE, FALSE, NULL);
    if (pSsdtMdl)
    {
        MmProbeAndLockPages(pSsdtMdl, KernelMode, IoReadAccess);
        PULONG pMappedSsdt = (PULONG)MmMapLockedPagesSpecifyCache(pSsdtMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (pMappedSsdt)
        {
            *pMappedSsdt = SsdtEntry;
            MmUnmapLockedPages(pMappedSsdt, pSsdtMdl);
        }
        MmUnlockPages(pSsdtMdl);
        IoFreeMdl(pSsdtMdl);
    }

    DBGPRINT("[ UnhookSSDT ] UnhookSSDT complete.\n");
    return true;
}

void ssdt::Init()
{
#ifndef USE_KASPERSKY
    g_KeServiceDescriptorTable = PSYSTEM_SERVICE_TABLE(GetKeServiceDescriptorTable64());
    DBGPRINT("KeServiceDescriptorTable: 0x%p\n", g_KeServiceDescriptorTable);
    if (!g_KeServiceDescriptorTable)
        return;

    auto KiServiceTable = PULONG(g_KeServiceDescriptorTable->ServiceTableBase);
    DBGPRINT("KeServiceDescriptorTable->ServiceTableBase: 0x%p\n", KiServiceTable);
    if (!KiServiceTable)
        return;

    DBGPRINT("KeServiceDescriptorTable->NumberOfServices: %lld\n", g_KeServiceDescriptorTable->NumberOfServices);

    auto ntoskrnl = ULONG64(tools::GetNtKernelBase());
    DBGPRINT("ntoskrnl: 0x%llx\n", ntoskrnl);
    if (!ntoskrnl)
        return;

    ULONG ulCodeSize = 0;
    auto pCode = PUCHAR(tools::GetImageTextSection(ntoskrnl, &ulCodeSize));
    if (pCode)
    {
        DBGPRINT("ntoskrnl.exe .text section %p\n", pCode);

        // Hook only NtQuerySystemInformation for now (others disabled for stability)
        if (HookSSDT(pCode, ulCodeSize, &hkNtQuerySystemInformation,
             reinterpret_cast<PVOID*>(&oNtQuerySystemInformation), SYSCALL_NTQUERYSYSINFO))
        {
            DBGPRINT("NtQuerySystemInformation hooked successfully!\n");
        }
        else
        {
            DBGPRINT("Failed to hook NtQuerySystemInformation!\n");
        }
    }
#else
    // Kaspersky path not used
#endif
}

void ssdt::Destroy()
{
#ifndef USE_KASPERSKY
    if (!g_KeServiceDescriptorTable)
        return;

    if (!UnhookSSDT(oNtQuerySystemInformation, SYSCALL_NTQUERYSYSINFO))
        DBGPRINT("Failed to unhook NtQuerySystemInformation!\n");
#endif
}