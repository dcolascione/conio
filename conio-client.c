#include <windows.h>
#include <stdio.h>
#include "conio.h"
#include "coniop.h"
#include "hook.h"

//
// This file hooks many Win32 functions in order to create the
// illusion that we have slave-side pseudoconsole handles.  The
// resulting implementation has the same characteristics as
// pre-Windows-8 system console handles, which are also implemented in
// userspace.
//
// NO NEED TO SUPPORT
// ------------------
//
// Console handles in Windows 7 and below didn't work with these
// functions, so we don't need to implement support here.  (Any
// program using these functions on console handles never worked.)
//
// ReadFileEx
// WriteFileEx
// Nt*
// SetThreadpoolWait
// OpenFile
// CreateFile with FILE_FLAG_OVERLAPPED
// DuplicateHandle across process boundaries
//

//
// When true, forward hooked APIs directly to OS functions.  The HOOK
// functions set this variable to true while they are inside a hooked
// API.  (It's legal and safe for a hook implementation to set this
// variable back to FALSE if it knows it wants to call the hooked
// version of an API.)
//

static __thread BOOL ConpAreHooksInhibited;

//
// Our fake console handles end one of the tags below so we can
// distinguish them from ordinary kernel handles.  The tags must be
// odd in order to avoid accidental collision with kernel handles,
// which are all even.
//

#define CON_TAG_MASK 0xFFFF
#define CON_SLAVE_TAG 0x1201

//
// CON_SLAVE holds information pertaining to one console handle.
//

typedef struct _CON_SLAVE {

    //
    // Reference count for this structure.  While there is a
    // one-to-one mapping between HANDLE and CON_SLAVE, routines that
    // _use_ CON_SLAVE objects take a reference to them so that
    // concurrent closes and other operations on the handle are safe.
    //

    LONG ReferenceCount;

    //
    // See {Get,Set}HandleInformation
    //

    ULONG HandleFlags;

    //
    // Communication with the server happens over this pipe.  WHEN WE
    // DUP THE HANDLE, WE DO NOT DUP THE PIPE HANDLE.  THAT WOULD LEAD
    // TO CONFOUNDED REPLIES FROM THE SERVER AS TWO ACTORS TRIED TO
    // COMMUNICATE OVER THE SAME PIPE.  INSTEAD, WE CREATE A BRAND-NEW
    // CONNECTION TO THE PIPE WHEN WE DUP THE HANDLE.
    //
    // FOR SIMILAR REASONS, ONLY ONE THREAD MAY USE THE PIPE AT A
    // TIME.  ACCESS TO THE PIPE IS CONTROLLED BY PipeLock, WHICH MUST
    // BE HELD IN EXCLUSIVE MODE WHEN SENDING TO THE PIPE OR READING
    // FROM IT.
    //

    SRWLOCK PipeLock;
    HANDLE Pipe;

    //
    // We use these values to reconstruct the pipe name in case we
    // need to create another connection to the pipe.
    //

    ULONG ServerPid;
    ULONG Cookie;

} CON_SLAVE, *PCON_SLAVE;

static SRWLOCK ConpHandleTableLock = SRWLOCK_INIT;
static PCON_SLAVE* ConpHandleTable;
static ULONG ConpHandleTableSize; // In elements

static HANDLE ConpAttachedConsole;

static
BOOL
ConpIsSlave (
    HANDLE Handle
    )
/*++

Routine Description:

    Determine whether the given handle might be a pointer to a console
    slave.

Arguments:

    Handle - Supplies a handle that might be a slave handle.

Return Value:

    TRUE if the handle matches the bit pattern of a slave handle;
    FALSE otherwise.  No error is set.

Environment:

    Arbitrary.

--*/
{
    return ((ULONG) Handle & CON_TAG_MASK) == CON_SLAVE_TAG;
}

static
PCON_SLAVE
ConpReferenceSlaveHandle (
    HANDLE SlaveHandle
    )
/*++

Routine Description:

    Obtain a reference to the slave object referred to by SlaveHandle.

Arguments:

    SlaveHandle - Supplies the handle to dereference

Return Value:

    On success, return a pointer (with reference) to the slave.  On failure,
    return NULL with thread error set.

Environment:

    Arbitrary.

--*/
{
    ULONG Index;
    PCON_SLAVE Slave = NULL;

    CONP_ASSERT (ConpIsSlave (SlaveHandle));

    Index = (ULONG) SlaveHandle >> 16;

    //
    // Take the handle table lock so the operation of referencing the
    // handle and bumping the object's reference count is atomic,
    // protecting us from a concurrent close of the handle.
    //

    if (Index < ConpHandleTableSize) {
        AcquireSRWLockExclusive (&ConpHandleTableLock);
        Slave = ConpHandleTable[Index];
        if (Slave != NULL) {
            InterlockedIncrement (&Slave->ReferenceCount);
        }

        ReleaseSRWLockExclusive (&ConpHandleTableLock);
    }

    if (Slave == NULL) {
        SetLastError (ERROR_INVALID_HANDLE);
    }

    return Slave;
}

static
VOID
ConpDereferenceSlave (
    PCON_SLAVE Slave
    )
/*++

Routine Description:

    This routine removes a reference to the
    given input object.

Arguments:

    Input - Supplies a pointer to the object to dereference.

Return Value:

    None.

Environment:

    Arbitrary.

--*/
{
    LONG NewReferenceCount = InterlockedDecrement (&Slave->ReferenceCount);

    CONP_ASSERT (NewReferenceCount >= 0);

    if (NewReferenceCount == 0) {
        if (Slave->Pipe) {
            CloseHandle (Slave->Pipe);
        }

        LocalFree (Slave);
    }
}

static
BOOL
ConpCloseSlaveHandle (
    HANDLE SlaveHandle
    )
/*++

Routine Description:

    This routine closes the given slave-object handle.  If the handle
    is valid, return TRUE. Otherwise, return FALSE with the last error
    set to ERROR_INVALID_HANDLE.

Arguments:

    SlaveHandle - Supplies the slave handle to close.

Return Value:

    TRUE on success; FALSE on error.  On error, the thread error is
    set.

Environment:

    Arbitrary.

--*/
{
    ULONG Index;
    BOOL Result;
    PCON_SLAVE Slave;

    CONP_ASSERT (ConpIsSlave (SlaveHandle));

    Index = (ULONG) SlaveHandle >> 16;
    Slave = NULL;

    AcquireSRWLockExclusive (&ConpHandleTableLock);

    if (Index < ConpHandleTableSize) {
        Slave = ConpHandleTable[Index];
        if (Slave->HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) {
            ReleaseSRWLockExclusive (&ConpHandleTableLock);
            return TRUE;
        }

        ConpHandleTable[Index] = NULL;
    }

    ReleaseSRWLockExclusive (&ConpHandleTableLock);

    if (Slave == NULL) {
        SetLastError (ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ConpDereferenceSlave (Slave);
    return TRUE;
}

static
HANDLE
ConpInsertHandle (
    PCON_SLAVE Slave
    )
/*++

Routine Description:

    This routine allocates a new handle that points to Slave.  Slave's
    reference count will be incremented by one.

Arguments:

    Slave - Supplies the existing slave object to reference.

Return Value:

    On success, return a new slave handle.  On error, return NULL with
    thread error set.

Environment:

    Arbitrary.

--*/
{
    ULONG FreeEntry;
    ULONG NewHandleTableSize;
    PCON_SLAVE* NewHandleTable;

    AcquireSRWLockExclusive (&ConpHandleTableLock);

    for (FreeEntry = 0;
         FreeEntry < ConpHandleTableSize;
         ++FreeEntry)
    {
        if (ConpHandleTable[FreeEntry] == NULL) {
            break;
        }
    }

    if (FreeEntry == ConpHandleTableSize) {
        NewHandleTableSize = ConpHandleTableSize * 2;
        if (NewHandleTableSize < 16) {
            NewHandleTableSize = 16;
        }

        NewHandleTable = LocalAlloc (
            0,
            sizeof (*ConpHandleTable) * NewHandleTableSize);

        if (NewHandleTable == NULL) {
            ReleaseSRWLockExclusive (&ConpHandleTableLock);
            return NULL;
        }

        memcpy (NewHandleTable,
                ConpHandleTable,
                sizeof (*NewHandleTable) * ConpHandleTableSize);

        ZeroMemory (&NewHandleTable[ConpHandleTableSize],
                    sizeof (*NewHandleTable)
                    * (NewHandleTableSize - ConpHandleTableSize));

        LocalFree (ConpHandleTable);
        ConpHandleTable = NewHandleTable;
        ConpHandleTableSize = NewHandleTableSize;
    }

    ConpHandleTable[FreeEntry] = Slave;
    InterlockedIncrement (&Slave->ReferenceCount);
    ReleaseSRWLockExclusive (&ConpHandleTableLock);
    return (HANDLE) ( (FreeEntry << 16) | CON_SLAVE_TAG );
}

static
BOOL
ConpDuplicateSlaveHandle (
    HANDLE Source,
    HANDLE* Destination,
    BOOL Inherit
    )
/*++

Routine Description:

    Duplicate Source by creating another connection to the named pipe
    to which Source is connected.

Arguments:

    Source - Supplies the handle to duplicate.

    Destination - Receives, on success, the duplicated handle.

    Inherit - Indicates whether the new handle is marked inheritable.

Return Value:

    TRUE on success; FALSE on error, with thread-error set.

Environment:

    Arbitrary.

--*/
{
    PCON_SLAVE ExistingSlave;
    HANDLE NewSlaveHandle;
    BOOL Result = FALSE;

    ExistingSlave = ConpReferenceSlaveHandle (Source);
    if (ExistingSlave == NULL) {
        goto Out;
    }

    if (!ConpConnectSlaveHandle (ExistingSlave->ServerPid,
                                 ExistingSlave->Cookie,
                                 Inherit ? HANDLE_FLAG_INHERIT : 0,
                                 &NewSlaveHandle))
    {
        goto Out;
    }

    *Destination = NewSlaveHandle;
    Result = TRUE;

  Out:

    if (ExistingSlave) {
        ConpDereferenceSlave (ExistingSlave);
    }

    return Result;
}

static
BOOL
ConpReadAll (
    /* In */  HANDLE Handle,
    /* Out */ PVOID Buffer,
    /* In */  ULONG BytesToRead
    )
/*++

Routine Description:

    Read all the given bytes or fail.

Arguments:

    Handle - Supplies the handle to read from.

    Buffer - Receives the read bytes.

    BytesToRead - Supplies the number of bytes to read.

Return Value:

    TRUE on success (all bytes read); FALSE on failure with thread-error set.

Environment:

    Arbitrary.

--*/
{
    ULONG BytesReadTotal;
    ULONG BytesReadThisTime;

    BytesReadTotal = 0;

    while (BytesReadTotal < BytesToRead) {
        if (!ReadFile (Handle,
                       (PBYTE) Buffer + BytesReadTotal,
                       BytesToRead - BytesReadTotal,
                       &BytesReadThisTime,
                       NULL /* Overlapped */))
        {
            return FALSE;
        }

        BytesReadTotal += BytesReadThisTime;
    }

    return TRUE;
}

static
BOOL
ConpWriteAll (
    /* In */  HANDLE Handle,
    /* Out */ LPCVOID Buffer,
    /* In */  ULONG BytesToWrite
    )
/*++

Routine Description:

    Write all the given bytes or fail.

Arguments:

    Handle - Supplies the handle to read from.

    Buffer - Receives the read bytes.

    BytesToWrite - Supplies the number of bytes to read.

Return Value:

    TRUE on success (all bytes read); FALSE on failure with thread-error set.

Environment:

    Arbitrary.

--*/
{
    ULONG BytesWritenTotal;
    ULONG BytesWritenThisTime;

    BytesWritenTotal = 0;

    while (BytesWritenTotal < BytesToWrite) {
        if (!WriteFile (Handle,
                       (PBYTE) Buffer + BytesWritenTotal,
                       BytesToWrite - BytesWritenTotal,
                       &BytesWritenThisTime,
                       NULL /* Overlapped */))
        {
            return FALSE;
        }

        BytesWritenTotal += BytesWritenThisTime;
    }

    return TRUE;
}

static
BOOL
ConpExchangeMessage (
    /* In */    PCON_SLAVE Slave,
    /* InOut */ PCON_MESSAGE Message,
    /* In */    ULONG OutgoingMessageSize,
    /* In */    LPCVOID OutgoingPayload,
    /* In */    CON_MESSAGE_TYPE ExpectedReplyType,
    /* In */    ULONG ExpectedReplySize,
    /* Out */   PVOID IncomingPayload,
    /* In */    ULONG MaximumIncomingPayloadSize
    )
/*++

Routine Description:

    This routine exchanges a message with the server for slave handle
    Slave.

Arguments:

    Slave - Supplies the slave object we want to use for
            communication.

    Message - Supplies the message to send and receives the server's
              reply.  Message->Size supplies the _total_ number of
              bytes send, and Message->Size receives the _total_
              number of bytes received.

              Message must point to a buffer of at least sizeof
              (*Message) bytes.

    OutgoingMessageSize - Supplies the number of bytes of Message to
                          send.

    OutgoingPayload - If OutgoingMessageSize is less than
                      Message->Size, send the remaining bytes from the
                      buffer pointed to by Outgoing Payload.

    ExpectedReplyType - Supplies the type of message we expect to
                        receive from the server.  If we get a
                        different message type, close the connection
                        with a protocol error.

    ExpectedReplySize - Supplies the size of a payload of
                        ExpectedReplyType.  Any excess bytes are
                        written to IncomingPayload, up to
                        MaximumIncomingPayloadSize.

    IncomingPayload - Receives any incoming bytes in excess of
                      ExpectedReplySize are written here, up to
                      MaximumIncomingPayloadSize.

    MaximumIncomingPayloadSize - Supplies the maximum number of bytes
                                 to write to IncomingPayload.  If we
                                 receive more bytes, fail with a
                                 protocol error.

Return Value:

    TRUE on success; FALSE on failure with thread-error set.

Environment:

    Call without Slave->PipeLock held.

--*/
{
    AcquireSRWLockExclusive (&Slave->PipeLock);

    if (Slave->Pipe == NULL) {
        ReleaseSRWLockExclusive (&Slave->PipeLock);
        SetLastError (ERROR_BROKEN_PIPE);
        return FALSE;
    }

    //
    // Send payload to the server, optionally gathering from an
    // auxiliary payload buffer.
    //

    ConpTrace (L"CLIENT: sending ck:%lu size:%lu type:%lu",
               Slave->Cookie, Message->Size, Message->Type);

    if (!ConpWriteAll (Slave->Pipe, Message, OutgoingMessageSize) ||
        !ConpWriteAll (Slave->Pipe, OutgoingPayload,
                       Message->Size - OutgoingMessageSize))
    {
        goto ProtocolError;
    }

    //
    // Read reply from the server, optionally scattering to an
    // auxiliary payload buffer.
    //

    ZeroMemory (Message, sizeof (*Message));
    if (!ConpReadAll (Slave->Pipe,
                      Message,
                      CON_MESSAGE_SIZE (Type)))
    {
        goto ProtocolError;
    }

    ConpTrace (L"CLIENT: recv header ck:%lu size:%lu type:%lu",
               Slave->Cookie, Message->Size, Message->Type);

    //
    // Treat the generic error reply specially --- this way, callers
    // can treat protocol errors and server errors the same way.
    //

    if (Message->Type == ConReplyError) {
        if (!ConpReadAll (Slave->Pipe,
                          (PBYTE) Message + CON_MESSAGE_SIZE (Type),
                          ( CON_MESSAGE_SIZE (ErrorReply)
                            - CON_MESSAGE_SIZE (Type))))
        {
            goto ProtocolError;
        }

        ConpTrace (L"Error reply. Code: 0x%lx", Message->ErrorReply.ErrorCode);

        ReleaseSRWLockExclusive (&Slave->PipeLock);
        SetLastError (Message->ErrorReply.ErrorCode);
        return FALSE;
    }

    if (Message->Type != ExpectedReplyType ||
        Message->Size > ExpectedReplySize + MaximumIncomingPayloadSize)
    {
        SetLastError (ERROR_INVALID_DATA);
        goto ProtocolError;
    }

    if (!ConpReadAll (Slave->Pipe,
                      (PBYTE) Message + CON_MESSAGE_SIZE (Type),
                      ExpectedReplySize - CON_MESSAGE_SIZE (Type)))
    {
        goto ProtocolError;
    }

    if (!ConpReadAll (Slave->Pipe,
                      IncomingPayload,
                      Message->Size - ExpectedReplySize))
    {
        goto ProtocolError;
    }

    ReleaseSRWLockExclusive (&Slave->PipeLock);
    return TRUE;

  ProtocolError:

    //
    // We reach here when we've detected that the server is sending us
    // gibberish.  Close the connection and fail any further
    // operations on this handle.
    //

    CloseHandle (Slave->Pipe);
    Slave->Pipe = NULL;
    ReleaseSRWLockExclusive (&Slave->PipeLock);
    return FALSE;
}

static
HANDLE
ConpHandleClearLowBit (
    HANDLE Handle
    )
/*++

Routine Description:

    Return the value of Handle without its low bit.

Arguments:

    Handle - Supplies the handle to examine.

Return Value:

    Handle with low bit cleared.

Environment:

    Arbitrary.

--*/

{
    ULONG_PTR HandleValue = (ULONG_PTR) Handle;
    ULONG_PTR LowBit = 1;
    return (HANDLE) (HandleValue &~ LowBit);
}

static
BOOL
ConpSlaveReadFile (
    PCON_SLAVE Slave,
    LPVOID Buffer,
    DWORD NumberOfBytesToRead,
    LPDWORD NumberOfBytesRead,
    LPOVERLAPPED Overlapped
    )
{
    CON_MESSAGE Message;
    ULONG LocalBytesRead;

    if (NumberOfBytesRead) {
        *NumberOfBytesRead = 0;
    }

    //
    // Send the ReadFile request to the server and read the header of
    // the reply.  This header tells us how many bytes of payload to
    // read; we read the payload directly into the user's buffer.
    //

    ZeroMemory (&Message, sizeof (Message));
    Message.Size = CON_MESSAGE_SIZE (ReadFile);
    Message.Type = ConMsgReadFile;
    Message.ReadFile.RequestedReadSize = NumberOfBytesToRead;

    if (!ConpExchangeMessage (Slave,
                              &Message,
                              Message.Size,
                              NULL /* OutgoingPayload */,
                              ConReplyReadFile,
                              CON_MESSAGE_SIZE (ReadFileReply),
                              Buffer,
                              NumberOfBytesToRead))
    {
        return FALSE;
    }

    LocalBytesRead = Message.Size - CON_MESSAGE_SIZE (ReadFileReply);
    if (NumberOfBytesRead) {
        *NumberOfBytesRead = LocalBytesRead;

    }

    if (Overlapped) {
        Overlapped->InternalHigh = LocalBytesRead;
        if (ConpHandleClearLowBit (Overlapped->hEvent)) {
            (VOID) SetEvent (ConpHandleClearLowBit (Overlapped->hEvent));
        }
    }

    return TRUE;
}

static
BOOL
ConpSlaveWriteFile (
    PCON_SLAVE Slave,
    LPCVOID Buffer,
    DWORD NumberOfBytesToWrite,
    LPDWORD NumberOfBytesWritten,
    LPOVERLAPPED Overlapped
    )
{
    BOOL Result = FALSE;
    CON_MESSAGE Message;

    if (NumberOfBytesWritten) {
        *NumberOfBytesWritten = 0;
    }

    //
    // Send the ReadFile request to the server and read the header of
    // the reply.  This header tells us how many bytes of payload to
    // read; we read the payload directly into the user's buffer.
    //

    ZeroMemory (&Message, sizeof (Message));
    Message.Size = CON_MESSAGE_SIZE (WriteFile) + NumberOfBytesToWrite;
    Message.Type = ConMsgWriteFile;

    if (!ConpExchangeMessage (Slave,
                              &Message,
                              CON_MESSAGE_SIZE (WriteFile),
                              Buffer,
                              ConReplyWriteFile,
                              CON_MESSAGE_SIZE (WriteFileReply),
                              NULL /* IncomingPayload */,
                              0 /* MaximumIncomingPayloadSize */))
    {
        return FALSE;
    }

    if (NumberOfBytesWritten) {
        *NumberOfBytesWritten = Message.WriteFileReply.NumberBytesWritten;
    }

    if (Overlapped) {
        Overlapped->InternalHigh = Message.WriteFileReply.NumberBytesWritten;
        if (ConpHandleClearLowBit (Overlapped->hEvent)) {
            (VOID) SetEvent (ConpHandleClearLowBit (Overlapped->hEvent));
        }
    }

    return TRUE;
}

static
ULONG
ConpWaitForObjects (
    ULONG Count,
    const HANDLE* Handles,
    ULONG Milliseconds,
    BOOL UseMsgWait,
    ULONG WakeMask,
    ULONG Flags
    )
{
    abort (); // XXXXXXXXXXXXXX
    return 0;
}

BOOL
ConpConnectSlaveHandle (
    /* In */  ULONG ServerPid,
    /* In */  ULONG Cookie,
    /* In */  ULONG HandleFlags,
    /* Out */ HANDLE* NewHandle
    )
{
    WCHAR PipeName[ARRAYSIZE (CON_PIPE_FORMAT)];
    PCON_SLAVE Slave = NULL;
    BOOL Result = FALSE;
    HANDLE LocalNewHandle;

    Slave = LocalAlloc (LMEM_ZEROINIT, sizeof (*Slave));
    if (Slave == NULL) {
        goto Out;
    }

    Slave->ReferenceCount = 1;

    swprintf (PipeName, CON_PIPE_FORMAT, ServerPid, Cookie);

    Slave->Pipe = CreateFile (
        PipeName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL /* No special security */,
        OPEN_ALWAYS,
        SECURITY_IDENTIFICATION,
        NULL /* TemplateFile */);

    if (Slave->Pipe == INVALID_HANDLE_VALUE) {
        Slave->Pipe = NULL;
        goto Out;
    }

    Slave->Cookie = Cookie;
    Slave->ServerPid = ServerPid;
    Slave->HandleFlags = HandleFlags;

    LocalNewHandle = ConpInsertHandle (Slave);
    if (LocalNewHandle == NULL) {
        goto Out;
    }

    *NewHandle = LocalNewHandle;
    Result = TRUE;

  Out:

    if (Slave != NULL) {
        ConpDereferenceSlave (Slave);
    }

    return Result;
}

BOOL
ConpInheritConsoleInformation (
    VOID
    )
{
    BOOL Result = FALSE;
    WCHAR StartupInfoSectionName[ARRAYSIZE (CON_STARTINFO_FORMAT)];
    HANDLE Section = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    PCON_STARTUP_INFO ConStartupInfo = NULL;
    ULONG i;

    //
    // Map the startup section into our address space.  The section
    // will have been created by our parent and injected into this
    // process.
    //

    swprintf (StartupInfoSectionName,
              CON_STARTINFO_FORMAT,
              GetCurrentProcessId ());

    Section = OpenFileMapping (FILE_MAP_READ,
                               FALSE /* InheritHandle */,
                               StartupInfoSectionName);

    if (Section == NULL) {
        if (GetLastError () == ERROR_FILE_NOT_FOUND) {
            Result = TRUE;
        }

        goto Out;
    }

    ConStartupInfo = MapViewOfFile (Section, FILE_MAP_READ, 0, 0, 0);
    if (ConStartupInfo == NULL) {
        goto Out;
    }

    if (VirtualQuery (ConStartupInfo, &mbi,
                      sizeof (ConStartupInfo)) == 0)
    {
        goto Out;
    }

    if (mbi.RegionSize < sizeof (*ConStartupInfo)) {
        SetLastError (ERROR_INVALID_DATA);
        goto Out;
    }



  Out:

    if (Section != NULL) {
        CloseHandle (Section);
    }

    if (ConStartupInfo != NULL) {
        UnmapViewOfFile (ConStartupInfo);
    }

    return Result;
}

//
// We define COLLECTING_HOOKS and preprocess this file at build time
// to generate conio-client.c, which we #include below in order to
// register all hooks declared with HOOK.
//

#ifdef COLLECTING_HOOKS
# define HOOK(api, ret, argdecl, arguse)        \
    ConpGenHook##api;
#else
# define HOOK(api,ret,argdecl,arguse)                  \
    static ret (WINAPI *ConpOrig##api) argdecl;        \
    static ret WINAPI ConpHookBody##api argdecl;       \
    static ret WINAPI ConpHook##api argdecl {          \
        ret Result;                                    \
        if (ConpAreHooksInhibited) {                   \
            return ConpOrig##api arguse;               \
        }                                              \
                                                       \
        ConpAreHooksInhibited = TRUE;                  \
        Result = ConpHookBody##api arguse;             \
        ConpAreHooksInhibited = FALSE;                 \
        return Result;                                 \
    }                                                  \
                                                       \
    static ret WINAPI ConpHookBody##api argdecl

#endif /* COLLECTING_HOOKS */

HOOK (GetFileType, DWORD,
      ( HANDLE Handle ),
      ( Handle ))
{
    if (ConpIsSlave (Handle)) {
        PCON_SLAVE Slave = ConpReferenceSlaveHandle (Handle);
        if (Slave == NULL) {
            return FILE_TYPE_UNKNOWN;
        }

        ConpDereferenceSlave (Slave);
        return FILE_TYPE_CHAR;
    }

    return GetFileType (Handle);
}

HOOK (CreateFileA, HANDLE,
      ( LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile ),
      ( lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile ))
{
    if (lpFileName && ConpAttachedConsole) {
        PCWSTR MagicName;

        if (!stricmp (lpFileName, "CON")) {
            MagicName = L"CON";
        } else if (!stricmp (lpFileName, "CONIN$")) {
            MagicName = L"CONIN$";
        } else if (!stricmp (lpFileName, "CONOUT$")) {
            MagicName = L"CONOUT$";
        } else {
            MagicName = NULL;
        }

        if (MagicName != NULL) {
            ConpAreHooksInhibited = FALSE;
            return CreateFileW (MagicName,
                                dwDesiredAccess,
                                dwShareMode,
                                lpSecurityAttributes,
                                dwCreationDisposition,
                                dwFlagsAndAttributes,
                                hTemplateFile);
        }
    }

    return CreateFileA (lpFileName,
                        dwDesiredAccess,
                        dwShareMode,
                        lpSecurityAttributes,
                        dwCreationDisposition,
                        dwFlagsAndAttributes,
                        hTemplateFile);
}

HOOK (CreateFileW, HANDLE,
      ( LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile ),
      ( lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile ))
{
    if (lpFileName && ConpAttachedConsole) {
        if (!wcsicmp (lpFileName, L"CON") ||
            !wcsicmp (lpFileName, L"CONIN$") ||
            !wcsicmp (lpFileName, L"CONOUT$"))
        {
            HANDLE NewSlaveHandle;
            BOOL Inherit = ( lpSecurityAttributes &&
                             lpSecurityAttributes->bInheritHandle );
            if (ConpDuplicateSlaveHandle (
                    ConpAttachedConsole,
                    &NewSlaveHandle,
                    Inherit)
                == FALSE)
            {
                return INVALID_HANDLE_VALUE;
            }

            return NewSlaveHandle;
        }
    }

    return CreateFileW (lpFileName,
                        dwDesiredAccess,
                        dwShareMode,
                        lpSecurityAttributes,
                        dwCreationDisposition,
                        dwFlagsAndAttributes,
                        hTemplateFile);
}

HOOK (DuplicateHandle, BOOL,
      ( HANDLE hSourceProcessHandle,
        HANDLE hSourceHandle,
        HANDLE hTargetProcessHandle,
        LPHANDLE lpTargetHandle,
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        DWORD dwOptions ),
      ( hSourceProcessHandle,
        hSourceHandle,
        hTargetProcessHandle,
        lpTargetHandle,
        dwDesiredAccess,
        bInheritHandle,
        dwOptions ))
{
    if (ConpIsSlave (hSourceHandle)) {
        if (hSourceProcessHandle != GetCurrentProcess () ||
            hTargetProcessHandle != GetCurrentProcess ())
        {
            SetLastError (ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        return ConpDuplicateSlaveHandle (
            hSourceHandle,
            lpTargetHandle,
            bInheritHandle);
    }

    return DuplicateHandle(
        hSourceProcessHandle,
        hSourceHandle,
        hTargetProcessHandle,
        lpTargetHandle,
        dwDesiredAccess,
        bInheritHandle,
        dwOptions);
}

HOOK (FlushFileBuffers, BOOL,
      ( HANDLE File ),
      ( File ))
{
    if (ConpIsSlave (File)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FlushFileBuffers (File);
}

HOOK (CloseHandle, BOOL,
      ( HANDLE Object ),
      ( Object ))
{
    if (ConpIsSlave (Object)) {
        return ConpCloseSlaveHandle (Object);
    }

    return CloseHandle (Object);
}

HOOK (ReadFile, BOOL,
      ( HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped ),
      ( hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped ))
{
    if (ConpIsSlave (hFile)) {
        PCON_SLAVE Slave = ConpReferenceSlaveHandle (hFile);
        BOOL Result = FALSE;

        if (Slave) {
            Result = ConpSlaveReadFile (Slave,
                                         lpBuffer,
                                         nNumberOfBytesToRead,
                                         lpNumberOfBytesRead,
                                         lpOverlapped);

            ConpDereferenceSlave (Slave);
        }

        return Result;
    }

    return ReadFile (hFile, lpBuffer, nNumberOfBytesToRead,
                     lpNumberOfBytesRead, lpOverlapped);
}

HOOK (WriteFile, BOOL,
      ( HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped ),
      ( hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped ))
{
    if (ConpIsSlave (hFile)) {
        PCON_SLAVE Slave = ConpReferenceSlaveHandle (hFile);
        BOOL Result = FALSE;

        if (Slave) {
            Result = ConpSlaveWriteFile (Slave,
                                         lpBuffer,
                                         nNumberOfBytesToWrite,
                                         lpNumberOfBytesWritten,
                                         lpOverlapped);

            ConpDereferenceSlave (Slave);
        }

        return Result;
    }

    return WriteFile (hFile,
                      lpBuffer,
                      nNumberOfBytesToWrite,
                      lpNumberOfBytesWritten,
                      lpOverlapped);
}

HOOK (WaitForSingleObject, DWORD,
      ( HANDLE hHandle,
        DWORD dwMilliseconds ),
      ( hHandle,
        dwMilliseconds ))
{
    if (ConpIsSlave (hHandle)) {
        ULONG Flags = 0;

        return ConpWaitForObjects (
            1, &hHandle,
            dwMilliseconds,
            FALSE /* WaitForMessages */,
            0 /* WakeMask */,
            Flags);
    }

    return WaitForSingleObject (hHandle, dwMilliseconds);
}

HOOK (WaitForSingleObjectEx, DWORD,
      ( HANDLE hHandle,
        DWORD dwMilliseconds,
        BOOL bAlertable ),
      ( hHandle,
        dwMilliseconds,
        bAlertable ))
{
    if (ConpIsSlave (hHandle)) {
        ULONG Flags = 0;

        if (bAlertable) {
            Flags |= MWMO_ALERTABLE;
        }

        return ConpWaitForObjects (
            1, &hHandle,
            dwMilliseconds,
            FALSE /* WaitForMessages */,
            0 /* WakeMask */,
            Flags);
    }

    return WaitForSingleObjectEx (
        hHandle, dwMilliseconds, bAlertable);
}

HOOK (WaitForMultipleObjects, DWORD,
      ( DWORD nCount,
        const HANDLE *lpHandles,
        BOOL bWaitAll,
        DWORD dwMilliseconds ),
      ( nCount,
        lpHandles,
        bWaitAll,
        dwMilliseconds ))
{
    ULONG i;

    for (i = 0; i < nCount; ++i) {
        if (ConpIsSlave (lpHandles[i])) {
            ULONG Flags = 0;

            return ConpWaitForObjects (
                nCount, lpHandles,
                dwMilliseconds,
                FALSE /* WaitForMessages */,
                0 /* WakeMask */,
                Flags);
        }
    }

    return WaitForMultipleObjects (nCount, lpHandles, bWaitAll,
                                   dwMilliseconds);
}

HOOK (WaitForMultipleObjectsEx, DWORD,
      ( DWORD nCount,
        const HANDLE *lpHandles,
        BOOL bWaitAll,
        DWORD dwMilliseconds,
        BOOL bAlertable ),
      ( nCount,
        lpHandles,
        bWaitAll,
        dwMilliseconds,
        bAlertable ))
{
    ULONG i;

    for (i = 0; i < nCount; ++i) {
        if (ConpIsSlave (lpHandles[i])) {
            ULONG Flags = 0;

            if (bAlertable) {
                Flags |= MWMO_ALERTABLE;
            }

            return ConpWaitForObjects (
                nCount, lpHandles,
                dwMilliseconds,
                FALSE /* WaitForMessages */,
                0 /* WakeMask */,
                Flags);
        }
    }

    return WaitForMultipleObjectsEx (nCount, lpHandles, bWaitAll,
                                     dwMilliseconds, bAlertable);
}

HOOK (MsgWaitForMultipleObjects, DWORD,
      ( DWORD nCount,
        const HANDLE *lpHandles,
        BOOL bWaitAll,
        DWORD dwMilliseconds,
        DWORD dwWakeMask ),
      ( nCount,
        lpHandles,
        bWaitAll,
        dwMilliseconds,
        dwWakeMask ))
{
    ULONG i;

    for (i = 0; i < nCount; ++i) {
        if (ConpIsSlave (lpHandles[i])) {
            return ConpWaitForObjects (
                nCount, lpHandles,
                dwMilliseconds,
                TRUE /* WaitForMessages */,
                dwWakeMask,
                0 /* Flags */);
        }
    }

    return MsgWaitForMultipleObjects (nCount, lpHandles, bWaitAll,
                                      dwMilliseconds, dwWakeMask);
}

HOOK (MsgWaitForMultipleObjectsEx, DWORD,
      ( DWORD nCount,
        const HANDLE *lpHandles,
        DWORD dwMilliseconds,
        DWORD dwWakeMask,
        DWORD dwFlags ),
      ( nCount,
        lpHandles,
        dwMilliseconds,
        dwWakeMask,
        dwFlags ))
{
    ULONG i;

    for (i = 0; i < nCount; ++i) {
        if (ConpIsSlave (lpHandles[i])) {
            return ConpWaitForObjects (
                nCount, lpHandles,
                dwMilliseconds,
                TRUE /* WaitForMessages */,
                dwWakeMask,
                dwFlags);
        }
    }

    return MsgWaitForMultipleObjectsEx (nCount, lpHandles,
                                        dwMilliseconds, dwWakeMask,
                                        dwFlags);
}

HOOK (RegisterWaitForSingleObject, BOOL,
      ( PHANDLE phNewWaitObject,
        HANDLE hObject,
        WAITORTIMERCALLBACK Callback,
        PVOID Context,
        ULONG dwMilliseconds,
        ULONG dwFlags ),
      ( phNewWaitObject,
        hObject,
        Callback,
        Context,
        dwMilliseconds,
        dwFlags ))
{
    if (ConpIsSlave (hObject)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return RegisterWaitForSingleObject (phNewWaitObject,
                                        hObject,
                                        Callback,
                                        Context,
                                        dwMilliseconds,
                                        dwFlags);
}

HOOK (AddConsoleAliasA, BOOL,
      ( LPSTR Source,
        LPSTR Target,
        LPSTR ExeName ),
      ( Source,
        Target,
        ExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return AddConsoleAliasA (Source, Target, ExeName);
}

HOOK (AddConsoleAliasW, BOOL,
      ( LPWSTR Source,
        LPWSTR Target,
        LPWSTR ExeName ),
      ( Source,
        Target,
        ExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return AddConsoleAliasW (Source, Target, ExeName);
}

HOOK (AllocConsole, BOOL,
      ( VOID ),
      ( ))
{
    return AllocConsole ();
}

HOOK (AttachConsole, BOOL,
      ( DWORD ProcessId ),
      ( ProcessId ))
{
    return AttachConsole (ProcessId);
}

HOOK (CreateConsoleScreenBuffer, HANDLE,
      ( DWORD dwDesiredAccess,
        DWORD dwShareMode,
        const SECURITY_ATTRIBUTES *lpSecurityAttributes,
        DWORD dwFlags,
        LPVOID lpScreenBufferData ),
      ( dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwFlags,
        lpScreenBufferData ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return CreateConsoleScreenBuffer(
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwFlags,
        lpScreenBufferData);
}

HOOK (FillConsoleOutputAttribute, BOOL,
      ( HANDLE hConsoleOutput,
        WORD wAttribute,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfAttrsWritten ),
      ( hConsoleOutput,
        wAttribute,
        nLength,
        dwWriteCoord,
        lpNumberOfAttrsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FillConsoleOutputAttribute (hConsoleOutput,
                                       wAttribute,
                                       nLength,
                                       dwWriteCoord,
                                       lpNumberOfAttrsWritten);
}

HOOK (FillConsoleOutputCharacterA, BOOL,
      ( HANDLE hConsoleOutput,
        CHAR cCharacter,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfCharsWritten ),
      ( hConsoleOutput,
        cCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FillConsoleOutputCharacterA (
        hConsoleOutput,
        cCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten);
}

HOOK (FillConsoleOutputCharacterW, BOOL,
      ( HANDLE hConsoleOutput,
        WCHAR cCharacter,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfCharsWritten ),
      ( hConsoleOutput,
        cCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FillConsoleOutputCharacterW (
        hConsoleOutput,
        cCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten);
}

HOOK (FlushConsoleInputBuffer, BOOL,
      ( HANDLE hConsoleInput ),
      ( hConsoleInput ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FlushConsoleInputBuffer (hConsoleInput);
}

HOOK (FreeConsole, BOOL,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return FreeConsole ();
}

HOOK (GenerateConsoleCtrlEvent, BOOL,
      ( DWORD dwCtrlEvent,
        DWORD dwProcessGroupId ),
      ( dwCtrlEvent,
        dwProcessGroupId ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GenerateConsoleCtrlEvent (dwCtrlEvent, dwProcessGroupId);
}

HOOK (GetConsoleAliasA, DWORD,
      ( LPSTR lpSource,
        LPSTR lpTargetBuffer,
        DWORD TargetBufferLength,
        LPSTR lpExeName ),
      ( lpSource,
        lpTargetBuffer,
        TargetBufferLength,
        lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasA (lpSource,
                             lpTargetBuffer,
                             TargetBufferLength,
                             lpExeName);
}


HOOK (GetConsoleAliasW, DWORD,
      ( LPWSTR lpSource,
        LPWSTR lpTargetBuffer,
        DWORD TargetBufferLength,
        LPWSTR lpExeName ),
      ( lpSource,
        lpTargetBuffer,
        TargetBufferLength,
        lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasW (lpSource,
                             lpTargetBuffer,
                             TargetBufferLength,
                             lpExeName);
}

HOOK (GetConsoleAliasesA, DWORD,
      ( PSTR lpAliasBuffer,
        DWORD AliasBufferLength,
        PSTR lpExeName ),
      ( lpAliasBuffer,
        AliasBufferLength,
        lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasesA (
        lpAliasBuffer,
        AliasBufferLength,
        lpExeName );
}

HOOK (GetConsoleAliasesW, DWORD,
      ( LPWSTR lpAliasBuffer,
        DWORD AliasBufferLength,
        LPWSTR lpExeName ),
      ( lpAliasBuffer,
        AliasBufferLength,
        lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasesW (
        lpAliasBuffer,
        AliasBufferLength,
        lpExeName );
}

HOOK (GetConsoleAliasesLengthA, DWORD,
      ( LPSTR lpExeName ),
      ( lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasesLengthA (lpExeName );
}

HOOK (GetConsoleAliasesLengthW, DWORD,
      ( LPWSTR lpExeName ),
      ( lpExeName ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasesLengthW (lpExeName );
}

HOOK (GetConsoleAliasExesA, DWORD,
      ( LPSTR lpExeNameBuffer,
        DWORD ExeNameBufferLength ),
      ( lpExeNameBuffer,
        ExeNameBufferLength ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesA (
        lpExeNameBuffer,
        ExeNameBufferLength );
}

HOOK (GetConsoleAliasExesW, DWORD,
      ( LPWSTR lpExeNameBuffer,
        DWORD ExeNameBufferLength ),
      ( lpExeNameBuffer,
        ExeNameBufferLength ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesW (
        lpExeNameBuffer,
        ExeNameBufferLength );
}

HOOK (GetConsoleAliasExesLengthA, DWORD,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesLengthA ();
}

HOOK (GetConsoleAliasExesLengthW, DWORD,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesLengthW ();
}

HOOK (GetConsoleCP, UINT,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleCP ();
}

HOOK (GetConsoleCursorInfo, BOOL,
      ( HANDLE hConsoleOutput,
        PCONSOLE_CURSOR_INFO lpConsoleCursorInfo ),
      ( hConsoleOutput,
        lpConsoleCursorInfo ))
{
    return GetConsoleCursorInfo (
        hConsoleOutput,
        lpConsoleCursorInfo );
}

HOOK (GetConsoleDisplayMode, BOOL,
      ( LPDWORD lpModeFlags ),
      ( lpModeFlags ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleDisplayMode (lpModeFlags );
}

HOOK (GetConsoleFontSize, COORD,
      ( HANDLE hConsoleOutput,
        DWORD nFont ),
      ( hConsoleOutput,
        nFont ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        COORD Zero;

        ZeroMemory (&Zero, sizeof (Zero));
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return Zero;
    }

    return GetConsoleFontSize (hConsoleOutput,
                               nFont );
}

HOOK (GetConsoleHistoryInfo, BOOL,
      ( PCONSOLE_HISTORY_INFO lpConsoleHistoryInfo ),
      ( lpConsoleHistoryInfo ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleHistoryInfo (lpConsoleHistoryInfo );
}

HOOK (GetConsoleMode, BOOL,
      ( HANDLE hConsoleHandle,
        LPDWORD lpMode ),
      ( hConsoleHandle,
        lpMode ))
{
    if (ConpIsSlave (hConsoleHandle)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleMode (hConsoleHandle, lpMode );
}

HOOK (GetConsoleOriginalTitleA, DWORD,
      ( LPSTR lpConsoleTitleA,
        DWORD nSize ),
      ( lpConsoleTitleA,
        nSize ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleOriginalTitleA (lpConsoleTitleA, nSize );
}

HOOK (GetConsoleOriginalTitleW, DWORD,
      ( LPWSTR lpConsoleTitle,
        DWORD nSize ),
      ( lpConsoleTitle,
        nSize ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleOriginalTitleW (lpConsoleTitle, nSize );
}

HOOK (GetConsoleOutputCP, UINT,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleOutputCP ();
}

HOOK (GetConsoleProcessList, DWORD,
      ( LPDWORD lpdwProcessList,
        DWORD dwProcessCount ),
      ( lpdwProcessList,
        dwProcessCount ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleProcessList (lpdwProcessList, dwProcessCount );
}

HOOK (GetConsoleScreenBufferInfo, BOOL,
      ( HANDLE hConsoleOutput,
        PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo ),
      ( hConsoleOutput,
        lpConsoleScreenBufferInfo ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleScreenBufferInfo (
        hConsoleOutput,
        lpConsoleScreenBufferInfo );
}

HOOK (GetConsoleScreenBufferInfoEx, BOOL,
      ( HANDLE hConsoleOutput,
        PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx ),
      ( hConsoleOutput,
        lpConsoleScreenBufferInfoEx ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleScreenBufferInfoEx (
        hConsoleOutput,
        lpConsoleScreenBufferInfoEx );
}

HOOK (GetConsoleSelectionInfo, BOOL,
      ( PCONSOLE_SELECTION_INFO lpConsoleSelectionInfo ),
      ( lpConsoleSelectionInfo ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleSelectionInfo (lpConsoleSelectionInfo );
}

HOOK (GetConsoleTitleA, DWORD,
      ( LPSTR lpConsoleTitle,
        DWORD nSize ),
      ( lpConsoleTitle,
        nSize ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleTitleA (lpConsoleTitle, nSize );
}

HOOK (GetConsoleTitleW, DWORD,
      ( LPWSTR lpConsoleTitle,
        DWORD nSize ),
      ( lpConsoleTitle,
        nSize ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleTitleW (lpConsoleTitle, nSize );
}

HOOK (GetConsoleWindow, HWND,
      ( VOID ),
      ( ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return NULL;
    }

    return GetConsoleWindow ();
}

HOOK (GetCurrentConsoleFont, BOOL,
      ( HANDLE hConsoleOutput,
        BOOL bMaximumWindow,
        PCONSOLE_FONT_INFO lpConsoleCurrentFont ),
      ( hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFont ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }


    return GetCurrentConsoleFont (
        hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFont );
}

HOOK (GetCurrentConsoleFontEx, BOOL,
      ( HANDLE hConsoleOutput,
        BOOL bMaximumWindow,
        PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx ),
      ( hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFontEx ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetCurrentConsoleFontEx (
        hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFontEx );
}

HOOK (GetLargestConsoleWindowSize, COORD,
    ( HANDLE hConsoleOutput ),
    ( hConsoleOutput ))
{
    if (ConpAttachedConsole) {
        COORD Zero;

        ZeroMemory (&Zero, sizeof (Zero));
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return Zero;
    }

    return GetLargestConsoleWindowSize (
        hConsoleOutput );
}

HOOK (GetNumberOfConsoleInputEvents, BOOL,
    ( HANDLE hConsoleInput,
      LPDWORD lpcNumberOfEvents ),
    ( hConsoleInput,
      lpcNumberOfEvents ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetNumberOfConsoleInputEvents (
        hConsoleInput,
        lpcNumberOfEvents );
}

HOOK (GetNumberOfConsoleMouseButtons, BOOL,
      ( LPDWORD lpNumberOfMouseButtons ),
      ( lpNumberOfMouseButtons ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetNumberOfConsoleMouseButtons (
        lpNumberOfMouseButtons );
}

HOOK (PeekConsoleInputA, BOOL,
    ( HANDLE hConsoleInput,
      PINPUT_RECORD lpBuffer,
      DWORD nLength,
      LPDWORD lpNumberOfEventsRead ),
    ( hConsoleInput,
      lpBuffer,
      nLength,
      lpNumberOfEventsRead ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return PeekConsoleInputA (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead );
}

HOOK (PeekConsoleInputW, BOOL,
    ( HANDLE hConsoleInput,
      PINPUT_RECORD lpBuffer,
      DWORD nLength,
      LPDWORD lpNumberOfEventsRead ),
    ( hConsoleInput,
      lpBuffer,
      nLength,
      lpNumberOfEventsRead ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return PeekConsoleInputW (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead );
}

HOOK (ReadConsoleA, BOOL,
      ( HANDLE hConsoleInput,
        LPVOID lpBuffer,
        DWORD nNumberOfCharsToRead,
        LPDWORD lpNumberOfCharsRead,
        LPVOID pInputControl ),
      ( hConsoleInput,
        lpBuffer,
        nNumberOfCharsToRead,
        lpNumberOfCharsRead,
        pInputControl ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleA (
        hConsoleInput,
        lpBuffer,
        nNumberOfCharsToRead,
        lpNumberOfCharsRead,
        pInputControl );
}

HOOK (ReadConsoleW, BOOL,
      ( HANDLE hConsoleInput,
        LPVOID lpBuffer,
        DWORD nNumberOfCharsToRead,
        LPDWORD lpNumberOfCharsRead,
        LPVOID pInputControl ),
      ( hConsoleInput,
        lpBuffer,
        nNumberOfCharsToRead,
        lpNumberOfCharsRead,
        pInputControl ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleW (
        hConsoleInput,
        lpBuffer,
        nNumberOfCharsToRead,
        lpNumberOfCharsRead,
        pInputControl );
}

HOOK (ReadConsoleInputA, BOOL,
      ( HANDLE hConsoleInput,
        PINPUT_RECORD lpBuffer,
        DWORD nLength,
        LPDWORD lpNumberOfEventsRead ),
      ( hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleInputA (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead );
}

HOOK (ReadConsoleInputW, BOOL,
      ( HANDLE hConsoleInput,
        PINPUT_RECORD lpBuffer,
        DWORD nLength,
        LPDWORD lpNumberOfEventsRead ),
      ( hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleInputW (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsRead );
}

HOOK (ReadConsoleOutputA, BOOL,
      ( HANDLE hConsoleOutput,
        PCHAR_INFO lpBuffer,
        COORD dwBufferSize,
        COORD dwBufferCoord,
        PSMALL_RECT lpReadRegion ),
      ( hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpReadRegion ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleOutputA (
        hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpReadRegion );
}

HOOK (ReadConsoleOutputW, BOOL,
      ( HANDLE hConsoleOutput,
        PCHAR_INFO lpBuffer,
        COORD dwBufferSize,
        COORD dwBufferCoord,
        PSMALL_RECT lpReadRegion ),
      ( hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpReadRegion ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleOutputW (
        hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpReadRegion );
}

HOOK (ReadConsoleOutputAttribute, BOOL,
      ( HANDLE hConsoleOutput,
        LPWORD lpAttribute,
        DWORD nLength,
        COORD dwReadCoord,
        LPDWORD lpNumberOfAttrsRead ),
      ( hConsoleOutput,
        lpAttribute,
        nLength,
        dwReadCoord,
        lpNumberOfAttrsRead ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleOutputAttribute (
        hConsoleOutput,
        lpAttribute,
        nLength,
        dwReadCoord,
        lpNumberOfAttrsRead );
}

HOOK (ReadConsoleOutputCharacterA, BOOL,
      ( HANDLE hConsoleOutput,
        LPSTR lpCharacter,
        DWORD nLength,
        COORD dwReadCoord,
        LPDWORD lpNumberOfCharsRead ),
      ( hConsoleOutput,
        lpCharacter,
        nLength,
        dwReadCoord,
        lpNumberOfCharsRead ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleOutputCharacterA (
        hConsoleOutput,
        lpCharacter,
        nLength,
        dwReadCoord,
        lpNumberOfCharsRead );
}

HOOK (ReadConsoleOutputCharacterW, BOOL,
      ( HANDLE hConsoleOutput,
        LPWSTR lpCharacter,
        DWORD nLength,
        COORD dwReadCoord,
        LPDWORD lpNumberOfCharsRead ),
      ( hConsoleOutput,
        lpCharacter,
        nLength,
        dwReadCoord,
        lpNumberOfCharsRead ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ReadConsoleOutputCharacterW (
        hConsoleOutput,
        lpCharacter,
        nLength,
        dwReadCoord,
        lpNumberOfCharsRead );
}

HOOK (ScrollConsoleScreenBufferA, BOOL,
      ( HANDLE hConsoleOutput,
        const SMALL_RECT *lpScrollRectangle,
        const SMALL_RECT *lpClipRectangle,
        COORD dwDestinationOrigin,
        const CHAR_INFO *lpFill ),
      ( hConsoleOutput,
        lpScrollRectangle,
        lpClipRectangle,
        dwDestinationOrigin,
        lpFill ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ScrollConsoleScreenBufferA (
        hConsoleOutput,
        lpScrollRectangle,
        lpClipRectangle,
        dwDestinationOrigin,
        lpFill );
}

HOOK (ScrollConsoleScreenBufferW, BOOL,
      ( HANDLE hConsoleOutput,
        const SMALL_RECT *lpScrollRectangle,
        const SMALL_RECT *lpClipRectangle,
        COORD dwDestinationOrigin,
        const CHAR_INFO *lpFill ),
      ( hConsoleOutput,
        lpScrollRectangle,
        lpClipRectangle,
        dwDestinationOrigin,
        lpFill ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return ScrollConsoleScreenBufferW (
        hConsoleOutput,
        lpScrollRectangle,
        lpClipRectangle,
        dwDestinationOrigin,
        lpFill );
}

HOOK (SetConsoleActiveScreenBuffer, BOOL,
    ( HANDLE hConsoleOutput ),
    ( hConsoleOutput ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleActiveScreenBuffer (hConsoleOutput);
}

HOOK (SetConsoleCP, BOOL,
      ( UINT wCodePageID ),
      ( wCodePageID ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleCP (wCodePageID );
}

HOOK (SetConsoleCtrlHandler, BOOL,
      ( PHANDLER_ROUTINE HandlerRoutine,
        BOOL Add ),
      ( HandlerRoutine,
        Add ))
{
    // XXX: maintain shadow copy of handler list
    return SetConsoleCtrlHandler (HandlerRoutine, Add );
}

HOOK (SetConsoleCursorInfo, BOOL,
      ( HANDLE hConsoleOutput,
        const CONSOLE_CURSOR_INFO *lpConsoleCursorInfo ),
      ( hConsoleOutput,
        lpConsoleCursorInfo ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleCursorInfo (
        hConsoleOutput,
        lpConsoleCursorInfo );
}

HOOK (SetConsoleCursorPosition, BOOL,
      ( HANDLE hConsoleOutput,
        COORD dwCursorPosition ),
      ( hConsoleOutput,
        dwCursorPosition ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleCursorPosition (
        hConsoleOutput,
        dwCursorPosition );
}

HOOK (SetConsoleDisplayMode, BOOL,
      ( HANDLE hConsoleOutput,
        DWORD dwFlags,
        PCOORD lpNewScreenBufferDimensions ),
      ( hConsoleOutput,
        dwFlags,
        lpNewScreenBufferDimensions ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleDisplayMode (
        hConsoleOutput,
        dwFlags,
        lpNewScreenBufferDimensions );
}

HOOK (SetConsoleHistoryInfo, BOOL,
      ( PCONSOLE_HISTORY_INFO lpConsoleHistoryInfo ),
      ( lpConsoleHistoryInfo ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleHistoryInfo (
        lpConsoleHistoryInfo );
}

HOOK (SetConsoleMode, BOOL,
      ( HANDLE hConsoleHandle,
        DWORD dwMode ),
      ( hConsoleHandle,
        dwMode ))
{
    if (ConpIsSlave (hConsoleHandle)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleMode (
        hConsoleHandle,
        dwMode );
}

HOOK (SetConsoleOutputCP, BOOL,
      ( UINT wCodePageID ),
      ( wCodePageID ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleOutputCP (
        wCodePageID );
}

HOOK (SetConsoleScreenBufferInfoEx, BOOL,
      ( HANDLE hConsoleOutput,
        PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx ),
      ( hConsoleOutput,
        lpConsoleScreenBufferInfoEx ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleScreenBufferInfoEx (
        hConsoleOutput,
        lpConsoleScreenBufferInfoEx );
}

HOOK (SetConsoleScreenBufferSize, BOOL,
      ( HANDLE hConsoleOutput,
        COORD dwSize ),
      ( hConsoleOutput,
        dwSize ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleScreenBufferSize (
        hConsoleOutput,
        dwSize );
}

HOOK (SetConsoleTextAttribute, BOOL,
      ( HANDLE hConsoleOutput,
        WORD wAttributes ),
      ( hConsoleOutput,
        wAttributes ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleTextAttribute (
        hConsoleOutput,
        wAttributes );
}

HOOK (SetConsoleTitleA, BOOL,
      ( LPCSTR lpConsoleTitle ),
      ( lpConsoleTitle ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleTitleA (lpConsoleTitle );
}

HOOK (SetConsoleTitleW, BOOL,
      ( LPCWSTR lpConsoleTitle ),
      ( lpConsoleTitle ))
{
    if (ConpAttachedConsole) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleTitleW (lpConsoleTitle );
}

HOOK (SetConsoleWindowInfo, BOOL,
      ( HANDLE hConsoleOutput,
        BOOL bAbsolute,
        const SMALL_RECT *lpConsoleWindow ),
      ( hConsoleOutput,
        bAbsolute,
        lpConsoleWindow ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleWindowInfo (
        hConsoleOutput,
        bAbsolute,
        lpConsoleWindow );
}

HOOK (SetCurrentConsoleFontEx, BOOL,
      ( HANDLE hConsoleOutput,
        BOOL bMaximumWindow,
        PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx ),
      ( hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFontEx ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetCurrentConsoleFontEx (
        hConsoleOutput,
        bMaximumWindow,
        lpConsoleCurrentFontEx );
}

HOOK (WriteConsoleA, BOOL,
      ( HANDLE hConsoleOutput,
        const VOID *lpBuffer,
        DWORD nNumberOfCharsToWrite,
        LPDWORD lpNumberOfCharsWritten,
        LPVOID lpReserved ),
      ( hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReserved ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleA (
        hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReserved );
}

HOOK (WriteConsoleW, BOOL,
      ( HANDLE hConsoleOutput,
        const VOID *lpBuffer,
        DWORD nNumberOfCharsToWrite,
        LPDWORD lpNumberOfCharsWritten,
        LPVOID lpReserved ),
      ( hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReserved ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleW (
        hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReserved );
}

HOOK (WriteConsoleInputA, BOOL,
      ( HANDLE hConsoleInput,
        const INPUT_RECORD *lpBuffer,
        DWORD nLength,
        LPDWORD lpNumberOfEventsWritten ),
      ( hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsWritten ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleInputA (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsWritten );
}

HOOK (WriteConsoleInputW, BOOL,
      ( HANDLE hConsoleInput,
        const INPUT_RECORD *lpBuffer,
        DWORD nLength,
        LPDWORD lpNumberOfEventsWritten ),
      ( hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsWritten ))
{
    if (ConpIsSlave (hConsoleInput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleInputW (
        hConsoleInput,
        lpBuffer,
        nLength,
        lpNumberOfEventsWritten );
}

HOOK (WriteConsoleOutputA, BOOL,
      ( HANDLE hConsoleOutput,
        const CHAR_INFO *lpBuffer,
        COORD dwBufferSize,
        COORD dwBufferCoord,
        PSMALL_RECT lpWriteRegion ),
      ( hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpWriteRegion ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleOutputA (
        hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpWriteRegion );
}

HOOK (WriteConsoleOutputW, BOOL,
      ( HANDLE hConsoleOutput,
        const CHAR_INFO *lpBuffer,
        COORD dwBufferSize,
        COORD dwBufferCoord,
        PSMALL_RECT lpWriteRegion ),
      ( hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpWriteRegion ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleOutputW (
        hConsoleOutput,
        lpBuffer,
        dwBufferSize,
        dwBufferCoord,
        lpWriteRegion );
}

HOOK (WriteConsoleOutputAttribute, BOOL,
      ( HANDLE hConsoleOutput,
        const WORD *lpAttribute,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfAttrsWritten ),
      ( hConsoleOutput,
        lpAttribute,
        nLength,
        dwWriteCoord,
        lpNumberOfAttrsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleOutputAttribute (
        hConsoleOutput,
        lpAttribute,
        nLength,
        dwWriteCoord,
        lpNumberOfAttrsWritten );
}

HOOK (WriteConsoleOutputCharacterA, BOOL,
      ( HANDLE hConsoleOutput,
        LPCSTR lpCharacter,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfCharsWritten ),
      ( hConsoleOutput,
        lpCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleOutputCharacterA (
        hConsoleOutput,
        lpCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten );
}

HOOK (WriteConsoleOutputCharacterW, BOOL,
      ( HANDLE hConsoleOutput,
        LPCWSTR lpCharacter,
        DWORD nLength,
        COORD dwWriteCoord,
        LPDWORD lpNumberOfCharsWritten ),
      ( hConsoleOutput,
        lpCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten ))
{
    if (ConpIsSlave (hConsoleOutput)) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return WriteConsoleOutputCharacterW (
        hConsoleOutput,
        lpCharacter,
        nLength,
        dwWriteCoord,
        lpNumberOfCharsWritten );
}

HOOK (CreateProcessW, BOOL,
      ( LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFO lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation),
      ( lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation))
{
    //
    // Create child suspended so we can propagate console information
    // to it.
    //

    if (CreateProcessW (lpApplicationName,
                        lpCommandLine,
                        lpProcessAttributes,
                        lpThreadAttributes,
                        bInheritHandles,
                        dwCreationFlags | CREATE_SUSPENDED,
                        lpEnvironment,
                        lpCurrentDirectory,
                        lpStartupInfo,
                        lpProcessInformation)
        == FALSE)
    {
        return FALSE;
    }

    //
    // An explicit DETACHED_PROCESS tells us not to propagate any
    // console to the client.  CREATE_NEW_CONSOLE means to always give
    // the child a brand new console.
    //

    // XXX: inherit console crap!

    if ((dwCreationFlags & CREATE_SUSPENDED) == 0) {
        ResumeThread (lpProcessInformation->hThread);
    }

    return TRUE;
}

HOOK (GetHandleInformation, BOOL,
      ( HANDLE hObject,
        LPDWORD lpdwFlags ),
      ( hObject,
        lpdwFlags ))
{
    if (ConpIsSlave (hObject)) {
        PCON_SLAVE Slave;

        Slave = ConpReferenceSlaveHandle (hObject);
        if (Slave == NULL) {
            return FALSE;
        }

        *lpdwFlags = Slave->HandleFlags;
        ConpDereferenceSlave (Slave);
        return TRUE;
    }

    return GetHandleInformation (hObject, lpdwFlags);
}

HOOK (SetHandleInformation, BOOL,
      ( HANDLE hObject,
        DWORD dwMask,
        DWORD dwFlags ),
      ( hObject,
        dwMask,
        dwFlags ))
{
    if (ConpIsSlave (hObject)) {
        PCON_SLAVE Slave;
        ULONG Flags;

        Slave = ConpReferenceSlaveHandle (hObject);
        if (Slave == NULL) {
            return FALSE;
        }

        Flags = Slave->HandleFlags;
        Flags = (Flags &~ dwMask) | dwFlags;
        Slave->HandleFlags = Flags;
        ConpDereferenceSlave (Slave);
        return TRUE;
    }

    return SetHandleInformation (hObject, dwMask, dwFlags);
}

BOOL
ConpHookApi (
    PCSTR ApiName,
    PVOID HookFunction,
    PVOID BackupVariable
    )
{
    static const PCWSTR Dlls[] = {
        L"kernelbase.dll",
        L"kernel32.dll",
        L"user32.dll"
    };

    ULONG i;
    ULONG NumberReplacements;
    PVOID Original;

    NumberReplacements = 0;

    for (i = 0; i < ARRAYSIZE (Dlls); ++i) {
        Original = (PVOID) GetProcAddress (
            GetModuleHandle (Dlls[i]),
            ApiName);

        if (Original != NULL) {
            if (!HkHookExportedFunction (
                    Original,
                    HookFunction,
                    BackupVariable))
            {
                return FALSE;
            }

#if 0
            fprintf (stderr, "hooked %S!%s orig:%p new:%p saved:%p\n",
                     Dlls[i], ApiName,
                     Original,
                     HookFunction,
                     * ((PVOID*) BackupVariable));

            fflush (stderr);
#endif

            NumberReplacements += 1;
            break;
        }
    }


    if (NumberReplacements == 0) {
        SetLastError (ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return TRUE;
}

BOOL
ConpHookApis (
    VOID
    )
{
#ifndef COLLECTING_HOOKS
# define REGHOOK(api)                                                   \
    if (!ConpHookApi (# api, ConpHook##api, &ConpOrig##api )) {         \
        return FALSE;                                                   \
    }

# include "conio-client-generated.c"

#endif

    return TRUE;
}

VOID
ConpTrace (
    PCWSTR Format,
    ...)
{
    va_list Args;
    ULONG SavedError;
    static SRWLOCK TraceLock;

    SavedError = GetLastError ();
    AcquireSRWLockExclusive (&TraceLock);
    {
        va_start (Args, Format);
        vfwprintf (stderr, Format, Args);
        fputwc (L'\n', stderr);
        fflush (stderr);
        va_end (Args);
    }
    ReleaseSRWLockExclusive (&TraceLock);
    SetLastError (SavedError);
}
