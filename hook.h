#pragma once
#include <windows.h>

EXTERN_C
BOOL WINAPI
HkHookProcessCreation (
    PCSTR ModuleName32,
    PCSTR ModuleName64
    );

EXTERN_C
BOOL WINAPI
HkCreateProcessW (
    LPCWSTR ApplicationName,
    LPWSTR CommandLine,
    LPSECURITY_ATTRIBUTES ProcessAttributes,
    LPSECURITY_ATTRIBUTES ThreadAttributes,
    BOOL InheritHandles,
    DWORD CreationFlags,
    PVOID Environment,
    PCWSTR CurrentDirectory,
    LPSTARTUPINFO StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation,
    PCSTR ModuleName32,
    PCSTR ModuleName64
    );

EXTERN_C
BOOL WINAPI
HkHookExportedFunction (
    PVOID Function,
    PVOID Replacement,
    PVOID* Original
    );
