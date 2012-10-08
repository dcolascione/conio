#include <stdio.h>
#include <windows.h>
#include "conio.h"
#include "coniop.h"
#include "hook.h"

BOOL ConpInheritConsoleInformation (VOID);

BOOL WINAPI
DllMain (HINSTANCE Inst,
         DWORD Reason,
         LPVOID NullIfDynamic)
{
    UNREFERENCED_PARAMETER (NullIfDynamic);

    switch (Reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls (Inst);

            if (!HkHookProcessCreation (
                    "conio-32.dll",
                    "conio-64.dll")
                || !ConpHookApis ()
                || !ConpInheritConsoleInformation ()
                )
            {
                return FALSE;
            }

            break;
    }

    return TRUE;
}

__declspec (dllexport)
VOID
DummyFunction (
    VOID
    )
{
}
