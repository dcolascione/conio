//
// This file defines a function that forces another program to import
// a particular DLL.  We include this file several times in order to
// define different versions of this function.
//

#if FORCEIMPORT_32
# define HkpForceImport HkpForceImport32
# define HKP_NT_HEADERS IMAGE_NT_HEADERS32
# define HKP_IMAGE_THUNK_DATA IMAGE_THUNK_DATA32
#elif FORCEIMPORT_64
# define HkpForceImport HkpForceImport64
# define HKP_NT_HEADERS IMAGE_NT_HEADERS64
# define HKP_IMAGE_THUNK_DATA IMAGE_THUNK_DATA64
#else
# error Unknown forceimport configuration
#endif

BOOL
HkpForceImport (
    HANDLE Process,
    PCSTR ModuleName
    )
/*++

Routine Description:

    Force the given process to require a given DLL.  Process must have
    been started in CREATE_SUSPENDED mode and never resumed.  This
    routine modifies the import table of the executable image of the
    given process such so that it has a load-time dependency on
    ordinal 1 in ModuleName.

Arguments:

    Process - Supplies the process to modify.

    ModuleName - Supplies the file name of the module to load.  This
                 module must export ordinal 1.

Return Value:

    BOOL.

Environment:

    Arbitrary.

--*/
{
    NTSTATUS nt;
    XPEB Peb;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS32 NtHeaders;
    XPROCESS_BASIC_INFORMATION Bi;
    SIZE_T BytesRead;

    PIMAGE_DATA_DIRECTORY DirImport;
    PIMAGE_DATA_DIRECTORY DirBoundImport;

    PBYTE RemoteBase;
    PBYTE RemoteNtHeaders;

    ULONG ModuleNameSize;
    ULONG NewImportTableSize;
    PBYTE Payload = NULL;
    PBYTE RemotePayload;
    ULONG PayloadSize;
    HKP_IMAGE_THUNK_DATA* NewImportEntry;
    ULONG NewImportEntryOffset;
    PIMAGE_IMPORT_DESCRIPTOR NewImportTable;
    ULONG NewImportTableOffset;
    ULONG OldProtection;

    //
    // Find the location of the image header in the remote process and
    // read it into local memory.
    //

    nt = NtQueryInformationProcess (
        Process,
        ProcessBasicInformation,
        &Bi,
        sizeof (Bi),
        NULL);

    if (!NT_SUCCESS (nt)) {
        SetLastError (RtlNtStatusToDosError (nt));
    }

    if (!ReadProcessMemory (Process,
                            Bi.PebBaseAddress,
                            &Peb,
                            sizeof (Peb),
                            &BytesRead))
    {
        goto Out;
    }

    RemoteBase = (PBYTE) Peb.ImageBaseAddress;

    if (!ReadProcessMemory (Process,
                            RemoteBase,
                            &DosHeader,
                            sizeof (DosHeader),
                            &BytesRead))
    {
        goto Out;
    }

    RemoteNtHeaders = RemoteBase + DosHeader.e_lfanew;

    if (!ReadProcessMemory (Process,
                            RemoteNtHeaders,
                            &NtHeaders,
                            sizeof (NtHeaders),
                            &BytesRead))
    {
        goto Out;
    }

    //
    // XXX: support 64-bit processes.
    //

    if (NtHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        SetLastError (ERROR_NOT_SUPPORTED);
        goto Out;
    }

    //
    // Defeat binding.
    //

    NtHeaders.FileHeader.TimeDateStamp += 1;

    //
    // Build a replacement import directory by prefixing the existing
    // import directory with our dummy import.
    //

    DirImport = &NtHeaders.OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT];

    ModuleNameSize = strlen (ModuleName) + 1;
    NewImportTableSize = ( DirImport->Size +
                           sizeof (IMAGE_IMPORT_DESCRIPTOR) );

    PayloadSize  = 0;
    PayloadSize += ModuleNameSize;
    PayloadSize += 8 - (PayloadSize % 8);
    NewImportEntryOffset = PayloadSize;
    PayloadSize += sizeof (HKP_IMAGE_THUNK_DATA);
    PayloadSize += 8 - (PayloadSize % 8);
    NewImportTableOffset = PayloadSize;
    PayloadSize += NewImportTableSize;

    RemotePayload = VirtualAllocEx (Process, NULL,
                                    PayloadSize,
                                    MEM_COMMIT,
                                    PAGE_READWRITE);

    if (!RemotePayload) {
        goto Out;
    }

    Payload = LocalAlloc (LMEM_ZEROINIT, PayloadSize);
    if (!Payload) {
        goto Out;
    }

    memcpy (Payload, ModuleName, ModuleNameSize);

    NewImportEntry = (HKP_IMAGE_THUNK_DATA*)
        (Payload + NewImportEntryOffset);

    NewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)
        (Payload + NewImportTableOffset);

    if (!ReadProcessMemory (
            Process,
            RemoteBase + DirImport->VirtualAddress,
            &NewImportTable[1],
            DirImport->Size,
            &BytesRead))
    {
        goto Out;
    }

    NewImportEntry->u1.Ordinal = 0x80000001;
    NewImportTable->Name = RemotePayload - RemoteBase;
    NewImportTable->FirstThunk =
        (RemotePayload + NewImportEntryOffset) - RemoteBase;

    if (!WriteProcessMemory (Process,
                             RemotePayload,
                             Payload,
                             PayloadSize,
                             &BytesRead))
    {
        goto Out;
    }

    DirImport->VirtualAddress =
        RemotePayload + NewImportTableOffset - RemoteBase;

    DirImport->Size = NewImportTableSize;

    //
    // Clear the alterate bound import directory so that
    // the loader is forced to use the regular imports.
    //

    DirBoundImport = &NtHeaders.OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    ZeroMemory (DirBoundImport, sizeof (*DirBoundImport));

    //
    // Finally, overwrite the image header in the remote process with
    // our fixed version.
    //

    if (!VirtualProtectEx (Process,
                           RemoteNtHeaders,
                           sizeof (NtHeaders),
                           PAGE_WRITECOPY,
                           &OldProtection))
    {
        goto Out;
    }

    if (!WriteProcessMemory (Process,
                             RemoteNtHeaders,
                             &NtHeaders,
                             sizeof (NtHeaders),
                             &BytesRead))
    {
        goto Out;
    }

    return TRUE;

  Out:

    LocalFree (Payload);
    return FALSE;
}

#undef HkpForceImport
#undef HKP_NT_HEADERS
#undef HKP_IMAGE_THUNK_DATA
