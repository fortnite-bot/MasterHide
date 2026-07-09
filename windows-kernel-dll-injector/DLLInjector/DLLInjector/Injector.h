#pragma once

#include <ntdef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Injects a DLL into the given process using APC.
// ProcessId - target process ID.
// DllPath   - full NT path to the DLL, for example \??\C:\Windows\Temp\inject.dll.
NTSTATUS InjectDllIntoProcess(
	_In_ HANDLE ProcessId,
	_In_ PUNICODE_STRING DllPath
);

#ifdef __cplusplus
}
#endif
