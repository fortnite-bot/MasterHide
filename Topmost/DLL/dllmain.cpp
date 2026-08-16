#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <stddef.h> // Add this line at the top of your file for size_t

#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#pragma comment(lib, "user32.lib")

static void Log(const wchar_t* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    wchar_t buf[512];
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    FILE* f = _wfopen(L"C:\\Windows\\Temp\\topmost_log.txt", L"a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(f, L"[%02d:%02d:%02d.%03d TID %lu] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(), buf);
        fclose(f);
    }
}

DWORD WINAPI KeepTopmost(LPVOID lpParam)
{
    Log(L"KeepTopmost started");
    Sleep(500);

    // Find our console window
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        Log(L"GetConsoleWindow() succeeded, HWND = 0x%p", hwnd);
    }
    else {
        Log(L"GetConsoleWindow() failed, enumerating windows");
        DWORD pid = GetCurrentProcessId();
        EnumWindows([](HWND h, LPARAM lParam) -> BOOL {
            DWORD wpid;
            GetWindowThreadProcessId(h, &wpid);
            if (wpid == (DWORD)lParam && IsWindowVisible(h)) {
                *(HWND*)&lParam = h;  // store and stop
                return FALSE;
            }
            return TRUE;
            }, (LPARAM)&hwnd);
        if (hwnd) {
            Log(L"Found window by PID: HWND = 0x%p", hwnd);
        }
        else {
            Log(L"Failed to find any visible window for this process");
            return 1;
        }
    }

    // Force topmost loop
    int loopCount = 0;
    while (IsWindow(hwnd)) {
        BOOL ret = SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
        if (!ret) {
            DWORD err = GetLastError();
            if (loopCount == 0) Log(L"SetWindowPos failed, error = %lu", err);
        }
        else {
            if (loopCount == 0) Log(L"SetWindowPos succeeded");
        }
        Sleep(50);
        if (++loopCount % 20 == 0) {
            LONG_PTR ex = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
            Log(L"Loop %d: style=0x%08X, topmost=%d", loopCount, (DWORD)ex, (ex & WS_EX_TOPMOST) != 0);
        }
    }
    Log(L"Window destroyed, exiting");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        Log(L"DLL loaded");
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, KeepTopmost, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}