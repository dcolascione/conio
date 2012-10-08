#include "xdefs.h"
#include <stdio.h>
#include <wchar.h>
#include "hook.h"

static BOOL (WINAPI *HkpOriginalCreateProcessW)(
    LPCWSTR ApplicationName,
    LPWSTR CommandLine,
    LPSECURITY_ATTRIBUTES ProcessAttributes,
    LPSECURITY_ATTRIBUTES ThreadAttributes,
    BOOL InheritHandles,
    DWORD CreationFlags,
    LPVOID Environment,
    LPCWSTR CurrentDirectory,
    LPSTARTUPINFOW StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation
    );

static PSTR HkpModuleName32;
static PSTR HkpModuleName64;
static ULONG HkpTlsIndex;

enum HKP_INITIALIZATION_STATE {
    HkpInitNotStarted    = 0,
    HkpInitInitializing  = 1,
    HkpInitDone          = 2,
    HkpInitFailed        = 3
};

static
BOOL WINAPI
HkpHookedCreateProcessW (
    LPCWSTR ApplicationName,
    LPWSTR CommandLine,
    LPSECURITY_ATTRIBUTES ProcessAttributes,
    LPSECURITY_ATTRIBUTES ThreadAttributes,
    BOOL InheritHandles,
    DWORD CreationFlags,
    LPVOID Environment,
    LPCWSTR CurrentDirectory,
    LPSTARTUPINFOW StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation
    )
{
    ULONG_PTR InHook = (ULONG_PTR) TlsGetValue (HkpTlsIndex);
    BOOL Result;

    if (InHook) {
        return HkpOriginalCreateProcessW (
            ApplicationName,
            CommandLine,
            ProcessAttributes,
            ThreadAttributes,
            InheritHandles,
            CreationFlags,
            Environment,
            CurrentDirectory,
            StartupInfo,
            ProcessInformation);
    }

    InHook = 1;
    if (!TlsSetValue (HkpTlsIndex, (PVOID) InHook)) {
        return FALSE;
    }

    Result = HkCreateProcessW (
        ApplicationName,
        CommandLine,
        ProcessAttributes,
        ThreadAttributes,
        InheritHandles,
        CreationFlags,
        Environment,
        CurrentDirectory,
        StartupInfo,
        ProcessInformation,
        HkpModuleName32,
        HkpModuleName64);

    InHook = 0;
    (VOID) TlsSetValue (HkpTlsIndex, (PVOID) InHook);
    return Result;
}

EXTERN_C
BOOL WINAPI
HkHookProcessCreation (
    PCSTR ModuleName32,
    PCSTR ModuleName64
)
/*++

Routine Description:

    This routine arranges for the hook library to intercept all
    process done made by the current process and inject the given DLLs
    into any child processes.

Arguments:

    ModuleName32 - Supplies the name of the DLL to use for 32-bit
                   child processes.

    ModuleName64 - Supplies the name of the DLL to use for 64-bit
                   child processes.

Return Value:

    TRUE on success; FALSE on failure.

Environment:

    Arbitrary.

--*/
{
    ULONG ModuleName32Length;
    ULONG ModuleName64Length;
    BOOL Result = FALSE;
    static volatile LONG InitState = HkpInitNotStarted;

    if (ModuleName32 == NULL ||
        ModuleName64 == NULL)
    {
        SetLastError (ERROR_INVALID_PARAMETER);
        goto Out;
    }

    //
    // If another thread is doing initialization, poll until it's
    // finished.  (We can't use the INIT_ONCE stuff because our
    // headers are missing it.)
    //

    while (InterlockedCompareExchange (&InitState,
                                       HkpInitInitializing,
                                       HkpInitNotStarted)
           == HkpInitInitializing)
    {
        Sleep (0);
    }

    //
    // If another thread was doing initialization, it will have ended
    // up in one of these two states.  Initialization is not
    // idempotent, so if we've failed once, it's not safe to try
    // again.
    //

    if (InitState == HkpInitDone) {
        return TRUE;
    }

    if (InitState == HkpInitFailed) {
        SetLastError (ERROR_BAD_ENVIRONMENT);
        return FALSE;
    }

    HkpTlsIndex = TlsAlloc ();
    if (HkpTlsIndex == TLS_OUT_OF_INDEXES) {
        goto Out;
    }

    ModuleName32Length = strlen (ModuleName32) + 1;
    HkpModuleName32 = LocalAlloc (0, ModuleName32Length);
    if (HkpModuleName32 == NULL) {
        goto Out;
    }

    memcpy (HkpModuleName32, ModuleName32, ModuleName32Length);

    ModuleName64Length = strlen (ModuleName64) + 1;
    HkpModuleName64 = LocalAlloc (0, ModuleName64Length);
    if (HkpModuleName64 == NULL) {
        goto Out;
    }

    memcpy (HkpModuleName64, ModuleName64, ModuleName64Length);

    if (!HkHookExportedFunction (
            (PVOID) GetProcAddress (GetModuleHandle (L"kernel32.dll"),
                                    "CreateProcessW"),
            HkpHookedCreateProcessW,
            (PVOID*) &HkpOriginalCreateProcessW))
    {
        goto Out;
    }

    Result = TRUE;

  Out:

    InitState = (Result ? HkpInitDone : HkpInitFailed );
    return Result;
}


//
// Define HkpForceImport32 and, on WIN64, HkpForceImport64.  Most of
// the code is the same, so we just include the implementation twice
// and tweak it differently each time.
//

#define FORCEIMPORT_32 1
#include "forceimport.c"
#undef FORCEIMPORT_32

#ifdef _WIN64
#define FORCEIMPORT_64 1
#include "forceimport.c"
#undef FORCEIMPORT_64
#endif

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
    LPCSTR ModuleName32,
    LPCSTR ModuleName64
    )
/*++

Routine Description:

    This routine works like CreateProcess, except that
    the child is modified before being allowed to run so that
    the given DLL is loaded.

Arguments:

    See CreateProcess.

Return Value:

    See CreateProcess.

Environment:

    See CreateProcess.

--*/
{
    BOOL CreatedProcess = FALSE;
    BOOL Result = FALSE;
    DWORD LastError;
    BOOL AmIWow64;
    BOOL IsChildWow64;

    //
    // First, create the child process suspended so we
    // can modify its import table.
    //

    if (!CreateProcessW (
            ApplicationName,
            CommandLine,
            ProcessAttributes,
            ThreadAttributes,
            InheritHandles,
            CreationFlags | CREATE_SUSPENDED,
            Environment,
            CurrentDirectory,
            StartupInfo,
            ProcessInformation))
    {
        goto Out;
    }

    CreatedProcess = TRUE;

    if (!IsWow64Process (GetCurrentProcess (), &AmIWow64) ||
        !IsWow64Process (ProcessInformation->hProcess, &IsChildWow64))
    {
        goto Out;
    }

#if _WIN64
    if (IsChildWow64) {
        Result = HkpForceImport32 (ProcessInformation->hProcess,
                                   ModuleName32);
    } else {
        Result = HkpForceImport64 (ProcessInformation->hProcess,
                                   ModuleName64);
    }
#else
    //
    // _WIN64 and AmIWow64 are both FALSE only when running on a
    // native 32-bit sytem.
    //

    UNREFERENCED_PARAMETER (ModuleName64);

    if (AmIWow64 == FALSE || IsChildWow64 == TRUE) {
        Result = HkpForceImport32 (ProcessInformation->hProcess,
                                   ModuleName32);
    } else {
        SetLastError (ERROR_NOT_SUPPORTED);
        Result = FALSE;
    }
#endif

    if (!Result) {
        goto Out;
    }

    if ((CreationFlags & CREATE_SUSPENDED) == 0) {
        ResumeThread (ProcessInformation->hThread);
    }

    Result = TRUE;

    Out:

    if (CreatedProcess && Result == FALSE) {
        LastError = GetLastError ();
        TerminateProcess (ProcessInformation->hProcess, 1);
        CloseHandle (ProcessInformation->hProcess);
        CloseHandle (ProcessInformation->hThread);
        SetLastError (LastError);
    }

    return Result;
}

BOOL
HkpHookFunctionExport (
    PVOID Function,
    PVOID Replacement,
    PXLDR_DATA_TABLE_ENTRY Module
    )
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PBYTE ModuleBase;

    PIMAGE_DATA_DIRECTORY DirExport;
    PIMAGE_EXPORT_DIRECTORY Export;
    PULONG Functions;
    ULONG i;
    PVOID FunctionVa;
    ULONG OldProtect;

    ModuleBase = (PBYTE) Module->DllBase;
    DosHeader = (PIMAGE_DOS_HEADER) ModuleBase;
    NtHeaders = (PIMAGE_NT_HEADERS) (ModuleBase + DosHeader->e_lfanew);

    //
    // Only touch 32-bit DLLs.  In a WOW64 process, 64-bit DLLs will
    // be on the list, but we won't be able to do anything about them.
    //

    if (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return TRUE;
    }

    DirExport = &NtHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT];

    Export = (PIMAGE_EXPORT_DIRECTORY)
        (ModuleBase + DirExport->VirtualAddress);

    Functions = (PULONG) (ModuleBase + Export->AddressOfFunctions);

    for (i = 0; i < Export->NumberOfFunctions; ++i) {
        FunctionVa = ModuleBase + Functions[i];
        if (FunctionVa == Function) {
            if (!VirtualProtect (&Functions[i],
                                 sizeof (Functions[i]),
                                 PAGE_WRITECOPY,
                                 &OldProtect))
            {
                return FALSE;
            }

            Functions[i] = (PBYTE) Replacement - ModuleBase;

            if (!VirtualProtect (&Functions[i],
                                 sizeof (Functions[i]),
                                 OldProtect,
                                 &OldProtect))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOL
HkpHookFunctionImport (
    PVOID Function,
    PVOID Replacement,
    PXLDR_DATA_TABLE_ENTRY Module
    )
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PBYTE ModuleBase;

    PIMAGE_DATA_DIRECTORY DirImport;
    PIMAGE_IMPORT_DESCRIPTOR Import;
    PIMAGE_IMPORT_DESCRIPTOR ImportEnd;
    PIMAGE_THUNK_DATA Thunk;

    ULONG OldProtect;

    ModuleBase = (PBYTE) Module->DllBase;
    DosHeader = (PIMAGE_DOS_HEADER) ModuleBase;
    NtHeaders = (PIMAGE_NT_HEADERS) (ModuleBase + DosHeader->e_lfanew);

    //
    // Modify all imports to point to the hook.  This step takes care
    // of modules that have already been loaded.
    //

    DirImport = &NtHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT];

    Import = (PIMAGE_IMPORT_DESCRIPTOR)
        (ModuleBase + DirImport->VirtualAddress);

    ImportEnd = (PIMAGE_IMPORT_DESCRIPTOR)
        ((PBYTE) Import + DirImport->Size);

    while (Import < ImportEnd &&
           Import->Name != 0 &&
           Import->FirstThunk != 0)
    {
        Thunk = (PIMAGE_THUNK_DATA) (ModuleBase + Import->FirstThunk);

        for (; Thunk->u1.Function != 0; ++Thunk) {
            if (Thunk->u1.Function == (ULONG_PTR) Function) {
                if (!VirtualProtect (&Thunk->u1.Function,
                                     sizeof (Thunk->u1.Function),
                                     PAGE_WRITECOPY,
                                     &OldProtect))
                {
                    return FALSE;
                }

                Thunk->u1.Function = (ULONG_PTR) Replacement;

                if (!VirtualProtect (&Thunk->u1.Function,
                                     sizeof (Thunk->u1.Function),
                                     OldProtect,
                                     &OldProtect))
                {
                    return FALSE;
                }
            }
        }

        ++Import;
    }

    return TRUE;
}

EXTERN_C
BOOL WINAPI
HkHookExportedFunction (
    PVOID Function,
    PVOID Replacement,
    PVOID* Original
    )
/*++

Routine Description:

    This routine replaces references to Function with references to
    Replacement.  It works by scanning all import and export tables.
    The original function remains callable.

Arguments:

    Function - Supplies the function to replace.

    Replacement - Supplies the function that replaces Function.

Return Value:

    None.

Environment:

    Arbitrary.

--*/
{
    NTSTATUS nt;
    XPROCESS_BASIC_INFORMATION Bi;
    PXPEB Peb;
    PLIST_ENTRY ModuleList;
    PLIST_ENTRY Entry;
    PXLDR_DATA_TABLE_ENTRY Module;
    BOOL Result = FALSE;

    nt = NtQueryInformationProcess (
        GetCurrentProcess (),
        ProcessBasicInformation,
        &Bi,
        sizeof (Bi),
        NULL);

    if (!NT_SUCCESS (nt)) {
        SetLastError (RtlNtStatusToDosError (nt));
        goto Out;
    }

    Peb = (PXPEB) Bi.PebBaseAddress;
    ModuleList = &Peb->LoaderData->InMemoryOrderModuleList;

    for (Entry = ModuleList->Flink;
         Entry != ModuleList;
         Entry = Entry->Flink)
    {
        Module = CONTAINING_RECORD (Entry,
                                    XLDR_DATA_TABLE_ENTRY,
                                    InMemoryOrderLinks);

        if (!HkpHookFunctionImport (Function, Replacement, Module)) {
            goto Out;
        }

        if (!HkpHookFunctionExport (Function, Replacement, Module)) {
            goto Out;
        }
    }

    if (Original != NULL) {
        *Original = Function; // Remains callable
    }

    Result = TRUE;

  Out:

    return Result;
}
