#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

extern volatile LONG g_Phase2ExplorerLoaderReady;
extern volatile LONG g_Phase2ExplorerInjectionIssued;
extern HANDLE g_Phase2TargetExplorerPid;
// Monitor thread control
extern volatile LONG g_MonitorStop;
extern HANDLE g_hMonitorThread;
extern volatile LONG g_TopmostStop;
extern HANDLE g_hTopmostThread;

NTSTATUS Phase2_TriggerInjection(void);
NTSTATUS Phase2_TriggerInjectionForPid(_In_ HANDLE Pid, _In_ BOOLEAN WaitForLoader);
VOID TopmostInjectorThread(_In_ PVOID StartContext);

// Monitor thread – checks for new explorer.exe and triggers injection
VOID ExplorerMonitorThread(_In_ PVOID StartContext);

#ifdef __cplusplus
}
#endif