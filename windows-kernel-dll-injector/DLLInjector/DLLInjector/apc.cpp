#include "apc.h"

#define DLLINJECTOR_POOL_TAG 'jILD'

VOID NTAPI KernelAPC(PRKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) {
    ExFreePool(apc);
}

VOID NTAPI RundownAPC(PRKAPC apc) {
    ExFreePool(apc);
}

NTSTATUS call_apc(PKTHREAD target_thread, PVOID target_function, PVOID params) {
    KAPC* apc = static_cast<KAPC*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DLLINJECTOR_POOL_TAG));
    if (nullptr == apc) {
        return STATUS_UNSUCCESSFUL;
    }
    KeInitializeApc(apc,
        target_thread,
        OriginalApcEnvironment,
        KernelAPC,
        RundownAPC,
        reinterpret_cast<PKNORMAL_ROUTINE>(target_function),
        UserMode,
        params);

    if (!KeInsertQueueApc(apc, nullptr, nullptr, 0)) {
        ExFreePool(apc);
    	return STATUS_UNSUCCESSFUL;
    }
	return STATUS_SUCCESS;
}
