#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

extern volatile LONG g_Phase2ExplorerLoaderReady;
extern volatile LONG g_Phase2ExplorerInjectionIssued;
extern HANDLE g_Phase2TargetExplorerPid;

NTSTATUS Phase2_TriggerInjection(void);
NTSTATUS Phase2_TriggerInjectionForPid(_In_ HANDLE Pid, _In_ BOOLEAN WaitForLoader);

// Spawn jtl.exe as SYSTEM in the same session as the cached explorer PID
NTSTATUS Phase2_SpawnSystemJtl(void);

#ifdef __cplusplus
}
#endif