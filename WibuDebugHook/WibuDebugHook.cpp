#include <windows.h>

#include "minhook/MinHook.h"

#ifdef _WIN64
#pragma comment(lib, "minhook/libMinHook.x64.lib")
#else
#pragma comment(lib, "minhook/libMinHook.x86.lib")
#endif //_WIN64

typedef BOOL(WINAPI *p_CreateProcessA)(
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation);

typedef HANDLE(WINAPI *p_OpenProcess)(
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandle,
    __in DWORD dwProcessId);

static p_CreateProcessA o_CreateProcessA;
static p_OpenProcess o_OpenProcess;
static DWORD hollowPid = 0;

static BOOL WINAPI hook_CreateProcessA(
    __in_opt    LPCSTR lpApplicationName,
    __inout_opt LPSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPCSTR lpCurrentDirectory,
    __in        LPSTARTUPINFOA lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation)
{
    auto result = o_CreateProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
    if(!hollowPid && result)
    {
        if(!lpApplicationName &&
            lpCommandLine &&
            !lpProcessAttributes &&
            !lpThreadAttributes &&
            !bInheritHandles &&
            dwCreationFlags == CREATE_SUSPENDED &&
            !lpEnvironment &&
            !lpCurrentDirectory)
        {
            hollowPid = lpProcessInformation->dwProcessId;
        }
    }
    return result;
}

static HANDLE WINAPI hook_OpenProcess(
    __in DWORD dwDesiredAccess,
    __in BOOL bInheritHandle,
    __in DWORD dwProcessId)
{
    auto hProcess = o_OpenProcess(
        dwDesiredAccess,
        bInheritHandle,
        dwProcessId);
    if(!hProcess && hollowPid && dwProcessId == hollowPid)
        hProcess = HANDLE(1);
    return hProcess;
}

static bool hook()
{
    if(MH_Initialize() != MH_OK)
        return false;
    auto kernel32 = GetModuleHandleW(L"kernelbase.dll") ? L"kernelbase.dll" : L"kernel32.dll";
    if(MH_CreateHookApi(kernel32, "CreateProcessA", &hook_CreateProcessA, (LPVOID*)&o_CreateProcessA) != MH_OK)
        return false;
    if(MH_CreateHookApi(kernel32, "OpenProcess", &hook_OpenProcess, (LPVOID*)&o_OpenProcess) != MH_OK)
        return false;
    if(MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        return false;
    return true;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    if(fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        hook();
    }
    return TRUE;
}