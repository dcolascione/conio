#include <windows.h>
#include <stdio.h>
#include "conio.h"

wchar_t*
errmsg (
    DWORD errorcode)

/*++

Routine Description:

    Return a description of a Win32 error code.  The returned string
    should be freed with free().

Arguments:

    errorcode - Supplies the Win32 error to describe.

Return Value:

    Heap-allocated error message string, or NULL on allocation
    failure.

Environment:

    Arbitrary.

--*/

{
    wchar_t* msg = NULL;
    wchar_t* allocmsg;

    FormatMessage (
        (FORMAT_MESSAGE_FROM_SYSTEM|
         FORMAT_MESSAGE_ALLOCATE_BUFFER|
         FORMAT_MESSAGE_IGNORE_INSERTS),
        NULL,
        errorcode,
        0,
        (wchar_t*)&msg,
        0,
        NULL);

    if (msg == NULL) {
        wchar_t buf[1024] = L"";
        _snwprintf (buf, countof (buf),
                    L"[unknown error: 0x%lx]",
                    (unsigned long)errorcode);
        return wcsdup (buf);
    }

    if (msg[wcslen (msg) - 1] == '\n') {
        msg[wcslen (msg) - 1] = '\0';
    }

    allocmsg = wcsdup (msg);
    LocalFree (msg);
    return allocmsg;
}

wchar_t*
errmsg_module (
    HRESULT errorcode,
    HMODULE module)

/*++

Routine Description:

    Return a description of an HRESULT, optionally for a specific
    module.  The returned string should be freed with free().

Arguments:

    errorcode - Supplies the HRESULT to describe.

    module - Supplies the module to search for an error string.  If
             NULL, search the system list.

Return Value:

    Heap-allocated error message string, or NULL on allocation
    failure.

Environment:

    Arbitrary.

--*/

{
    wchar_t* msg = NULL;
    wchar_t* allocmsg;
    DWORD flags;

    flags = (FORMAT_MESSAGE_FROM_SYSTEM|
             FORMAT_MESSAGE_ALLOCATE_BUFFER|
             FORMAT_MESSAGE_IGNORE_INSERTS);

    if (module != NULL) {
        flags |= FORMAT_MESSAGE_FROM_HMODULE;
    }

    FormatMessage (
        flags,
        module,
        errorcode,
        0,
        (wchar_t*)&msg,
        0,
        NULL);

    if (msg == NULL) {
        wchar_t buf[1024] = L"";
        _snwprintf (buf, countof (buf),
                    L"[unknown HRESULT: 0x%lx]",
                    (unsigned long)errorcode);
        return wcsdup (buf);
    }

    if (msg[wcslen (msg) - 1] == '\n') {
        msg[wcslen (msg) - 1] = '\0';
    }

    allocmsg = wcsdup (msg);
    LocalFree (msg);
    return allocmsg;
}

int
main(int argc, char** argv)
{
    return 0;
}

