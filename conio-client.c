#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "conio.h"
#include "coniop.h"
#include "hook.h"
#include "xdefs.h"
#include "miniddk.h"

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
// Use TLS APIs directly instead of __thread in order
// to avoid taking a C runtime dependency.
//

static ULONG ConpTlsIndex;

//
// Our fake console handles end one of the tags below so we can
// distinguish them from ordinary kernel handles.  The tags must be
// odd in order to avoid accidental collision with kernel handles,
// which are all even.
//

#define CON_TAG_MASK 0xFFFF
#define CON_SLAVE_TAG 0x1201

//
// Similarly, these values match Win32's fake-console handles.  It's
// important that our pseudo-console handles do _not_ match.
//

#define CON_W32_MASK 0x10000003
#define CON_W32_TAG  0x00000003

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
    // See coniop.h.
    //

    ULONG Flags;

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

typedef struct _CON_SHADOW_ATTRIBUTE {
    LIST_ENTRY AttributeLink;
    DWORD Flags;
    DWORD_PTR Attribute;
    PVOID Value;
    SIZE_T Size;
} CON_SHADOW_ATTRIBUTE, *PCON_SHADOW_ATTRIBUTE;

typedef struct _CON_SHADOW_ATTRIBUTE_LIST {
    LIST_ENTRY ShadowAttributeLink;
    LPPROC_THREAD_ATTRIBUTE_LIST AttributeList;
    ULONG AttributeCount;
    ULONG Flags;
    SIZE_T Size;
    PCON_SLAVE ChildAttach;
    LIST_ENTRY Attributes;
    HANDLE* ParentProcess; // XXX
} CON_SHADOW_ATTRIBUTE_LIST, *PCON_SHADOW_ATTRIBUTE_LIST;

//
// Lock order:
//
// ConpShadowAttributeLock
// ConpAttachedConsoleLock
// ConpHandleTableLock
// Individual slave pipelocks
//

//
// Maintain a list of shadow structures for every undeleted
// PROC_THREAD_ATTRIBUTE_LIST.  We store in these shadow structures a
// copy of the inherited handle table and a reference to the slave we
// should inherit.
//

static SRWLOCK ConpShadowAttributeLock;
static LIST_ENTRY ConpShadowAttributes = {
    &ConpShadowAttributes,
    &ConpShadowAttributes
};

//
// This lock governs all access to ConpAttachedInput.
//

static SRWLOCK ConpAttachedConsoleLock;
static PCON_SLAVE ConpAttachedInput;
static HANDLE ConpAttachedStdin;
static HANDLE ConpAttachedStdout;
static HANDLE ConpAttachedStderr;
static BOOL ConpIsAnyConsoleAttached;

static SRWLOCK ConpHandleTableLock;
static PCON_SLAVE* ConpHandleTable;
static ULONG ConpHandleTableSize; // In elements

static
BOOL
ConpAttachConsole (
    /* In */ ULONG ServerPid,
    /* In */ ULONG Cookie
    );

static
HANDLE
ConpIndexToHandle (
    ULONG Index
    );

static
ULONG
ConpHandleToIndex (
    HANDLE Handle
    );

static
BOOL
ConpAreHooksEnabled (
    VOID
    )
{
    ULONG_PTR TlsInfo = (ULONG_PTR) TlsGetValue (ConpTlsIndex);
    return TlsInfo == 0; // Sense is flipped so that zero-init is "on"
}

static
VOID
ConpSetHooksEnabled (
    BOOL Enabled
    )
{
    ULONG_PTR TlsInfo = !Enabled;
    CONP_VERIFY (TlsSetValue (ConpTlsIndex, (PVOID) TlsInfo));
}

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
BOOL
ConpIsWindowsConsole (
    HANDLE Handle
    )
/*++

Routine Description:

    Determine whether the given handle might be a console handle from
    the Win32 userspace console layer.

Arguments:

    Handle - Supplies a handle to test.

Return Value:

    TRUE if the handle is probably a Windows console handle.

Environment:

    Arbitrary.

--*/
{
    return ((ULONG) Handle & CON_W32_MASK) == CON_W32_TAG;
}

static
BOOL
ConpIsAttachedAsSlave (
    VOID
    )
/*++

Routine Description:

    This routine determines whether the current process is attached to
    a pseudo-console.

Arguments:

    None.

Return Value:

    TRUE if attached; FALSE otherwise.

Environment:

    Arbitrary.

--*/
{
    BOOL IsAttached;

    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);
    IsAttached = (ConpAttachedInput != NULL);
    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);

    return IsAttached;
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

    Index = ConpHandleToIndex (SlaveHandle);

    //
    // Take the handle table lock so the operation of referencing the
    // handle and bumping the object's reference count is atomic,
    // protecting us from a concurrent close of the handle.
    //

    AcquireSRWLockExclusive (&ConpHandleTableLock);
    if (Index < ConpHandleTableSize) {
        Slave = ConpHandleTable[Index];
        if (Slave != NULL) {
            InterlockedIncrement (&Slave->ReferenceCount);
        }

    }

    ReleaseSRWLockExclusive (&ConpHandleTableLock);
    if (Slave == NULL) {
        SetLastError (ERROR_INVALID_HANDLE);
    }

    return Slave;
}

static
PCON_SLAVE
ConpReferenceAttachedConsole (
    VOID
    )
/*++

Routine Description:

    This routine returns a reference to the currently-attached console
    input queue.

Arguments:

    None.

Return Value:

    Pointer to slave object on success; on error, NULL with
    thread-error set.

Environment:

    Call without locks held.

--*/
{
    PCON_SLAVE AttachedInput = NULL;

    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);

    AttachedInput = ConpAttachedInput;
    if (AttachedInput) {
        InterlockedIncrement (&AttachedInput->ReferenceCount);
    }

    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);

    if (AttachedInput == NULL) {
        SetLastError (ERROR_INVALID_HANDLE); // XXX Same as Windows?
    }

    return AttachedInput;
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
            CONP_VERIFY (CloseHandle (Slave->Pipe));
        }

        CONP_VERIFY (!LocalFree (Slave));
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

    Index = ConpHandleToIndex (SlaveHandle);
    Slave = NULL;

    AcquireSRWLockExclusive (&ConpHandleTableLock);

    if (Index < ConpHandleTableSize) {
        Slave = ConpHandleTable[Index];
        if ((Slave->Flags & CON_HANDLE_PROTECT_FROM_CLOSE) == 0) {
            ConpHandleTable[Index] = NULL;
        }
    }

    ReleaseSRWLockExclusive (&ConpHandleTableLock);

    if (Slave == NULL) {
        SetLastError (ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if ((Slave->Flags & CON_HANDLE_PROTECT_FROM_CLOSE) == 0) {
        ConpDereferenceSlave (Slave);
    }

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
    return ConpIndexToHandle (FreeEntry);
}

static
BOOL
ConpDuplicateSlaveHandle (
    HANDLE Source,
    HANDLE* Destination,
    ULONG DesiredAccess,
    ULONG DuplicateOptions,
    BOOL Inherit
    )
/*++

Routine Description:

    Duplicate Source by creating another connection to the named pipe
    to which Source is connected.

Arguments:

    Source - Supplies the handle to duplicate.

    Destination - Receives, on success, the duplicated handle.

    DesiredAccess - Supplies the access desired to the new handle.

    DuplicateOptions - See DuplicateHandle.

    Inherit - Indicates whether the new handle is marked inheritable.

Return Value:

    TRUE on success; FALSE on error, with thread-error set.

Environment:

    Arbitrary.

--*/
{
    BOOL Result = FALSE;
    HANDLE NewSlaveHandle;
    ULONG Index;
    ULONG NewFlags;
    PCON_SLAVE ExistingSlave = NULL;

    //
    // When the caller gives us DUPLICATE_CLOSE_SOURCE, we need to
    // atomically duplicate the original handle and close the
    // original, and we need to make sure the original is closed even
    // if the operation fails.  To implement these semantics, we need
    // to manually probe the handle table instead of relying on
    // ConpReferenceSlaveHandle followed by a ConpCloseSlaveHandle ---
    // someone could sneak in between the two calls and change the
    // meaning of the handle.
    //

    AcquireSRWLockExclusive (&ConpHandleTableLock);

    Index = ConpHandleToIndex (Source);
    if (Index < ConpHandleTableSize) {
        ExistingSlave = ConpHandleTable[Index];
        if (ExistingSlave != NULL) {
            if (DuplicateOptions & DUPLICATE_CLOSE_SOURCE) {
                ConpHandleTable[Index] = NULL; // Transfer reference
            } else {
                InterlockedIncrement (&ExistingSlave->ReferenceCount);
            }
        }
    }

    ReleaseSRWLockExclusive (&ConpHandleTableLock);

    if (ExistingSlave == NULL) {
        SetLastError (ERROR_INVALID_HANDLE);
        goto Out;
    }

    if (DuplicateOptions & DUPLICATE_SAME_ACCESS) {
        NewFlags = ExistingSlave->Flags & (CON_HANDLE_READ_ACCESS |
                                           CON_HANDLE_WRITE_ACCESS );
    } else {
        NewFlags = 0;

        if (DesiredAccess & GENERIC_READ) {
            NewFlags |= CON_HANDLE_READ_ACCESS;
        }

        if (DesiredAccess & GENERIC_WRITE) {
            NewFlags |= CON_HANDLE_WRITE_ACCESS;
        }
    }

    if (Inherit) {
        NewFlags |= CON_HANDLE_INHERIT;
    }

    if (!ConpConnectSlaveHandle (ExistingSlave->ServerPid,
                                 ExistingSlave->Cookie,
                                 NewFlags,
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

        //
        // XXX: "Headless mode" where we handle some requests even if
        // the server is dead.
        //

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

    ConpTrace (L"CLIENT: recv ck:%lu size:%lu type:%lu",
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

        ConpTrace (L"Error reply. Code: 0x%lx",
                   Message->ErrorReply.ErrorCode);

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

    CONP_VERIFY (CloseHandle (Slave->Pipe));
    Slave->Pipe = NULL;
    ReleaseSRWLockExclusive (&Slave->PipeLock);
    return FALSE;
}

static
HANDLE
ConpClearLowHandleBit (
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
        if (ConpClearLowHandleBit (Overlapped->hEvent)) {
            (VOID) SetEvent (ConpClearLowHandleBit (Overlapped->hEvent));
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
        if (ConpClearLowHandleBit (Overlapped->hEvent)) {
            (VOID) SetEvent (ConpClearLowHandleBit (Overlapped->hEvent));
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

static
BOOL
ConpConnectSlave (
    /* In */  ULONG ServerPid,
    /* In */  ULONG Cookie,
    /* In */  ULONG Flags,
    /* Out */ PCON_SLAVE* NewSlave
    )
/*++

Routine Description:

    Connect to a master object identified by ServerPid and Cookie and
    return a new slave pointer.  The slave isn't yet inserted in the
    handle table.

Arguments:

    ServerPid - Supplies the PID of the server for the handle.

    Cookie - Supplies a server-allocated opaque ID for the handle.

    Flags - Supplies handle flags.

    NewSlave - Receives a new slave on success.  The new slave has a
               reference count of one.

Return Value:

    TRUE on success; FALSE on failure with thread-error set.

Environment:

    Arbitrary.

--*/
{
    WCHAR PipeName[ARRAYSIZE (CON_PIPE_FORMAT)];
    PCON_SLAVE Slave;
    BOOL Result = FALSE;
    HANDLE LocalNewHandle;
    CON_MESSAGE Message;

    Slave = LocalAlloc (LMEM_ZEROINIT, sizeof (*Slave));
    if (Slave == NULL) {
        goto Out;
    }

    Slave->ReferenceCount = 1;
    Slave->Cookie = Cookie;
    Slave->ServerPid = ServerPid;
    Slave->Flags = Flags;

    CONP_VERIFY (swprintf (PipeName, CON_PIPE_FORMAT, ServerPid, Cookie)
                 == ARRAYSIZE (CON_PIPE_FORMAT) - 1);

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

        //
        // Don't fail here: duplicating a disconnected handle is a
        // reasonable thing to do.
        //
    }

    //
    // Tell the server what kind of handle we have.
    //

    ZeroMemory (&Message, CON_MESSAGE_SIZE (InitializeConnection));
    Message.Size = CON_MESSAGE_SIZE (InitializeConnection);
    Message.Type = ConMsgInitializeConnection;
    Message.InitializeConnection.Flags = Flags;

    if (ConpExchangeMessage (
            Slave, &Message,
            Message.Size,
            NULL,
            ConReplyInitializeConnection,
            CON_MESSAGE_SIZE (InitializeConnectionReply),
            NULL, 0)
        == FALSE)
    {
        goto Out;
    }

    ConpTrace (L"CLIENT: connected ck:%lu nck:%lu",
               Slave->Cookie,
               Message.InitializeConnectionReply.NewCookie);

    Slave->Cookie = Message.InitializeConnectionReply.NewCookie;
    *NewSlave = Slave;
    Slave = NULL;
    Result = TRUE;

  Out:

    if (Slave != NULL) {
        ConpDereferenceSlave (Slave);
    }

    return Result;
}

BOOL
ConpConnectSlaveHandle (
    /* In */  ULONG ServerPid,
    /* In */  ULONG Cookie,
    /* In */  ULONG Flags,
    /* Out */ HANDLE* NewHandle
    )
/*++

Routine Description:

    Connect to a master object identified by ServerPid and Cookie and
    return a new slave handle.

Arguments:

    ServerPid - Supplies the PID of the server for the handle.

    Cookie - Supplies a server-allocated opaque ID for the handle.

    Flags - Supplies handle flags.

    NewHandle - Receives a new slave handle on success.

Return Value:

    TRUE on success; FALSE on failure with thread-error set.

Environment:

    Arbitrary.

--*/
{
    PCON_SLAVE NewSlave;

    if (!ConpConnectSlave (ServerPid, Cookie, Flags, &NewSlave)) {
        return FALSE;
    }

    *NewHandle = ConpInsertHandle (NewSlave);
    ConpDereferenceSlave (NewSlave);
    return *NewHandle != NULL;
}

BOOL
ConpInheritConsoleInformation (
    VOID
    )
/*++

Routine Description:

    See whether our parent gave us information about what console
    handles we should inherit; if so, inherit them.

Arguments:

    None.

Return Value:

    TRUE on success; FALSE on error with thread-error set.  This routine
    succeeds if there are no handles to inherit.

Environment:

    DllMain.

--*/
{
    BOOL Result = FALSE;
    WCHAR StartupInfoSectionName[ARRAYSIZE (CON_STARTINFO_FORMAT)];
    HANDLE Section = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    PCON_STARTUP_INFO ConStartupInfo = NULL;
    PCON_STARTUP_HANDLE HandleInfo;
    ULONG i;
    ULONG LargestHandle;
    ULONG NewHandleTableSize;
    BOOL OldHooksEnabled = ConpAreHooksEnabled ();
    PCON_SLAVE Slave = NULL;
    ULONG ExpectedSectionSize;

    ConpSetHooksEnabled (FALSE);

    //
    // Map the startup section into our address space.  The section
    // will have been created by our parent and injected into this
    // process.
    //

    CONP_VERIFY (
        swprintf (StartupInfoSectionName,
                  CON_STARTINFO_FORMAT,
                  GetCurrentProcessId ())
        == ARRAYSIZE (CON_STARTINFO_FORMAT) - 1);

    Section = OpenFileMapping (FILE_MAP_READ,
                               FALSE /* InheritHandle */,
                               StartupInfoSectionName);

    if (Section == NULL) {

        if (GetLastError () == ERROR_FILE_NOT_FOUND ||
            GetLastError () == ERROR_PATH_NOT_FOUND)
        {
            Result = TRUE;
        } else {
            ConpTrace (L"OpenFileMapping FAILED 0x%lx [%s]",
                       GetLastError (),
                       StartupInfoSectionName);
        }

        goto Out;
    }

    ConpTrace (L"Found inheritance section!");

    ConStartupInfo = MapViewOfFile (Section, FILE_MAP_READ, 0, 0, 0);
    if (ConStartupInfo == NULL) {
        goto Out;
    }

    if (VirtualQuery (ConStartupInfo, &mbi,
                      sizeof (mbi)) == 0)
    {
        ConpTrace (L"VirtualQuery: 0x%lx", GetLastError ());
        goto Out;
    }

    if (mbi.RegionSize < sizeof (*ConStartupInfo)) {
        SetLastError (ERROR_INVALID_DATA);
        goto Out;
    }

    if (ConStartupInfo->Version != CON_SHARED_DATA_VERSION) {
        SetLastError (ERROR_PRODUCT_VERSION);
        goto Out;
    }

    if (ConStartupInfo->SectionHandle) {
        CONP_VERIFY (
            CloseHandle (
                LongToHandle (ConStartupInfo->SectionHandle)));
    }

    ExpectedSectionSize =
        sizeof (*ConStartupInfo)
        + sizeof (ConStartupInfo->Handle[0]) *
        ConStartupInfo->NumberHandles;

    if (mbi.RegionSize < ExpectedSectionSize) {
        ConpTrace (L"Section too small to contain claimed information");
    }

    //
    // Learn about any handles the parent gave us.
    //

    if (ConStartupInfo->NumberHandles > 0) {
        LargestHandle = 0;

        for (i = 0; i < ConStartupInfo->NumberHandles; ++i) {
            HandleInfo = &ConStartupInfo->Handle[i];
            if (HandleInfo->HandleValue > LargestHandle) {
                LargestHandle = HandleInfo->HandleValue;
            }
        }

        NewHandleTableSize = 16;
        while (NewHandleTableSize <= LargestHandle) {
            NewHandleTableSize *= 2;
        }

        ConpHandleTable = LocalAlloc (LMEM_ZEROINIT, NewHandleTableSize);
        if (ConpHandleTable == NULL) {
            goto Out;
        }

        ConpHandleTableSize = NewHandleTableSize;
        for (i = 0; i < ConStartupInfo->NumberHandles; ++i) {
            HandleInfo = &ConStartupInfo->Handle[i];
            if (!ConpConnectSlave (
                    HandleInfo->ServerPid,
                    HandleInfo->Cookie,
                    HandleInfo->Flags,
                    &Slave))
            {
                goto Out;
            }

            ConpTrace (L"Inherited handle %p ck:%lu pipe:%p",
                       ConpIndexToHandle (HandleInfo->HandleValue),
                       Slave->Cookie,
                       Slave->Pipe);

            if (HandleInfo->DummyInheritedHandle) {
                CONP_VERIFY (CloseHandle (
                                 LongToHandle (
                                     HandleInfo->DummyInheritedHandle)));
            }

            ConpHandleTable[HandleInfo->HandleValue] = Slave;
            Slave = NULL; // Transfer reference to handle table
        }
    }

    //
    // If we inherited our parent's console, try attaching to it.
    //

    if (ConStartupInfo->AttachConsoleHandle) {
        ConpTrace (L"Attach handle %p",
                   ConStartupInfo->AttachConsoleHandle);

        FreeConsole ();
        Slave = ConpReferenceSlaveHandle (
            ConStartupInfo->AttachConsoleHandle);

        ConpCloseSlaveHandle (ConStartupInfo->AttachConsoleHandle);

        if (Slave) {
            AcquireSRWLockExclusive (&ConpAttachedConsoleLock);
            (VOID) ConpAttachConsole (Slave->ServerPid, Slave->Cookie);
            ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);
            ConpDereferenceSlave (Slave);
            Slave = NULL;
        }

        ConpTrace (L"getout: %p", GetStdHandle (STD_OUTPUT_HANDLE));
    }

    Result = TRUE;

  Out:

    if (Section != NULL) {
        CONP_VERIFY (CloseHandle (Section));
    }

    if (ConStartupInfo != NULL) {
        CONP_VERIFY (UnmapViewOfFile (ConStartupInfo));
    }

    if (Slave != NULL) {
        ConpDereferenceSlave (Slave);
    }

    ConpSetHooksEnabled (OldHooksEnabled);
    return Result;
}

static
BOOL
ConpIsHandleInList (
    HANDLE Needle,
    HANDLE* Haystack,
    SIZE_T HaystackLength
    )
{
    SIZE_T i;

    for (i = 0 ; i < HaystackLength; ++i) {
        if (Haystack[i] == Needle) {
            return TRUE;
        }
    }

    return FALSE;
}

static
HANDLE
ConpIndexToHandle (
    ULONG Index
    )
{
    return (HANDLE) ( (Index << 16) | CON_SLAVE_TAG );
}

static
ULONG
ConpHandleToIndex (
    HANDLE Handle
    )
{
    CONP_ASSERT (ConpIsSlave (Handle));

    return (ULONG) Handle >> 16;
}

static
BOOL
ConpPropagateInheritance (
    HANDLE FrozenChild,
    PCON_SLAVE ChildAttach,
    BOOL HandleListPresent,
    HANDLE* HandleList,
    SIZE_T HandleListLength
    )
/*++

Routine Description:

    Propagate pseudo-console inheritance information to a child that
    we've started CREATE_SUSPENDED.

Arguments:

    FrozenChild - Supplies a handle to the fresh child process.

    ChildAttach - Supplies a slave connected to the console to which
                  FrozenChild will attach itself.

    HandleListPresent - Supplies an indication of whether HandleList
                        contains a limiting set of handles for
                        inheritance.

    HandleList - Supplies a pointer to a list of HandleListLength
                 handles.  Only handles in the list will be inherited.

    HandleListLength - Supplies the number of handles in the buffer to
                       which HandleList points.

Return Value:

    TRUE on success; FALSE on error with thread-error set.

Environment:

    Call without locks held.

--*/
{
    NTSTATUS nt;
    BOOL Result = FALSE;
    HANDLE StartupInfoSection = NULL;
    WCHAR StartupInfoSectionName[ARRAYSIZE (CON_STARTINFO_FORMAT)];
    ULONG i, j;
    ULONG StartupInfoSize;
    PCON_STARTUP_INFO ConStartupInfo = NULL;
    PCON_STARTUP_HANDLE HandleInfo;
    HANDLE RemoteChildHandle;
    HANDLE ChildAttachHandle = NULL;
    ULONG ChildAttachIndex = -1;
    BOOL HandleTableLockHeld = FALSE;

    //
    // The child opens the startup info handle by name, then closes
    // both the handle it used in that open and the handle we dup into
    // the child.  We dup a handle to the section into the child so
    // that the section stays alive until the child opens it even if
    // we go away in the meantime.
    //

    CONP_VERIFY (swprintf (StartupInfoSectionName,
                           CON_STARTINFO_FORMAT,
                           GetProcessId (FrozenChild))
                 == ARRAYSIZE (CON_STARTINFO_FORMAT) - 1);

    if (ChildAttach) {
        ChildAttachHandle = ConpInsertHandle (ChildAttach);
        if (!ChildAttachHandle) {
            goto Out;
        }

        ChildAttachIndex = ConpHandleToIndex (ChildAttachHandle);
    }

#define SHOULD_INHERIT(idx)                                          \
    (i == ChildAttachIndex ||                                        \
     (ConpHandleTable[i]                                             \
      && (ConpHandleTable[i]->Flags & CON_HANDLE_INHERIT)            \
      && (HandleListPresent == FALSE ||                              \
          ConpIsHandleInList (ConpIndexToHandle (i),                 \
                              HandleList,                            \
                              HandleListLength))))

    AcquireSRWLockExclusive (&ConpHandleTableLock);
    HandleTableLockHeld = TRUE;

    //
    // Figure out how many handles the child is inheriting.
    //

    for (i = 0, j = 0; i < ConpHandleTableSize; ++i) {
        if (SHOULD_INHERIT (i)) {
            j++;
        }
    }

    ConpTrace (L"INHERIT: nr:%u hlp:%lu", j, HandleListPresent);
    ConpTrace (L"PID is %lu sleeping for 10s...",
               GetProcessId (FrozenChild));

    Sleep (10000);

    StartupInfoSize = (sizeof (*ConStartupInfo) +
                       j * sizeof (ConStartupInfo->Handle[0]));

    StartupInfoSection = CreateFileMapping (
        INVALID_HANDLE_VALUE,
        NULL /* No special security */,
        PAGE_READWRITE,
        0, StartupInfoSize,
        StartupInfoSectionName);

    if (!StartupInfoSection) {
        ConpTrace (L"Could not create inheritance section 0x%lx [%s]",
                   GetLastError (),
                   StartupInfoSectionName);

        goto Out;
    }

    //
    // Build the inheritance information.  Note that ConStartupInfo is
    // already zeroed when we get it from the OS.
    //

    ConStartupInfo = MapViewOfFile (StartupInfoSection,
                                    FILE_MAP_READ | FILE_MAP_WRITE,
                                    0, 0, 0);

    if (!ConStartupInfo) {
        goto Out;
    }

    ConStartupInfo->Version = CON_SHARED_DATA_VERSION;

    if (ChildAttachHandle) {
        ConStartupInfo->AttachConsoleHandle = ChildAttachHandle;
    }

    ConpTrace (L"ChildAttachHandle: %p", ChildAttachHandle);

    ConStartupInfo->NumberHandles = j;

    for (i = 0, j = 0; i < ConpHandleTableSize; ++i) {
        if (SHOULD_INHERIT (i)) {
            HandleInfo = &ConStartupInfo->Handle[j++];
            HandleInfo->HandleValue = i;

            ConpTrace (L"INHERIT: propagating handle %u", i);

            if (ConpHandleTable[i]->Pipe) {
                if (!DuplicateHandle (GetCurrentProcess (),
                                      ConpHandleTable[i]->Pipe,
                                      FrozenChild,
                                      &RemoteChildHandle,
                                      0 /* Child has no access */,
                                      FALSE /* InheritHandle */,
                                      0 /* Options */))
                {
                    goto Out;
                }

                HandleInfo->DummyInheritedHandle =
                    HandleToLong (RemoteChildHandle);
            }

            HandleInfo->ServerPid = ConpHandleTable[i]->ServerPid;
            HandleInfo->Cookie = ConpHandleTable[i]->Cookie;
            HandleInfo->Flags = ConpHandleTable[i]->Flags;
        }
    }

    if (!DuplicateHandle (GetCurrentProcess (),
                          StartupInfoSection,
                          FrozenChild,
                          &RemoteChildHandle,
                          GENERIC_READ,
                          FALSE /* InheritHandle */,
                          0 /* Options */))
    {
        goto Out;
    }

    ConStartupInfo->SectionHandle = HandleToLong (RemoteChildHandle);
    Result = TRUE;

  Out:

    if (HandleTableLockHeld) {
        ReleaseSRWLockExclusive (&ConpHandleTableLock);
    }

    if (StartupInfoSection) {
        CONP_VERIFY (CloseHandle (StartupInfoSection));
    }

    if (ConStartupInfo) {
        CONP_VERIFY (UnmapViewOfFile (ConStartupInfo));
    }

    if (ChildAttachHandle) {
        CONP_VERIFY (ConpCloseSlaveHandle (ChildAttachHandle));
    }

    return Result;

#undef SHOULD_INHERIT

}

static
PCON_ATTACH_SHARED
ConpMapAttachShared (
    VOID
    )
/*++

Routine Description:

    This routine returns a pointer to the shared section describing
    the console (if any) to which the current process is attached.
    The section is created lazily the first time this routine is
    called and persists until the current process exits.

    Each call to this function re-maps the shared section.  The caller
    must unmap this view by calling UnmapViewOfFile.

Arguments:

    None.

Return Value:

    On success, a pointer to the shared information.  On error,
    NULL with thread-error set.

Environment:

    Arbitrary.

--*/
{
    static SRWLOCK Lock;
    static HANDLE AttachSection;
    static BOOL First;

    PCON_ATTACH_SHARED AttachShared = NULL;
    WCHAR AttachSectionName[ARRAYSIZE (CON_ATTACHINFO_FORMAT)+1];

    AcquireSRWLockExclusive (&Lock);

    if (AttachSection == NULL) {
        CONP_VERIFY (swprintf (AttachSectionName,
                               CON_ATTACHINFO_FORMAT,
                               GetCurrentProcessId ())
                     == ARRAYSIZE (CON_ATTACHINFO_FORMAT) - 1);

        AttachSection = CreateFileMapping (
            INVALID_HANDLE_VALUE,
            NULL /* No special security */,
            PAGE_READWRITE,
            0,
            sizeof (*AttachShared),
            AttachSectionName);

        if (AttachSection == NULL) {
            goto Out;
        }
    }

    AttachShared = MapViewOfFile (AttachSection,
                                  FILE_MAP_READ | FILE_MAP_WRITE,
                                  0, 0, /* Low, High offsets */
                                  0 /* Map whole section */);

    if (AttachShared == NULL) {
        goto Out;
    }

    if (First == FALSE) {
        First = TRUE;
        AttachShared->Version = CON_SHARED_DATA_VERSION;
    }

  Out:

    ReleaseSRWLockExclusive (&Lock);
    return AttachShared;
}

static
VOID
ConpUpdateAttachInfo (
    PCON_ATTACH_SHARED AttachShared,
    CON_ATTACH_INFO AttachInfo
    )
/*++

Routine Description:

    This routine updates the attachment information exported to other
    processes by setting it to AttachInfo in such a way that other
    processes read atomic snapshots of the attachment information.

Arguments:

    AttachShared - Supplies a view of the shared memory region.

    AttachInfo - Supplies the information to export.

Return Value:

    None.

Environment:

    Serialize all calls to this routine.

--*/
{
    memcpy (&AttachShared->Info[!(AttachShared->Sequence & 1)],
            &AttachInfo,
            sizeof (AttachInfo));

    MemoryBarrier ();
    AttachShared->Sequence += 1;
}

static
BOOL
ConpReadAttachInfo (
    ULONG ProcessId,
    PCON_ATTACH_INFO AttachInfo
    )
/*++

Routine Description:

    This routine reads the process attachment information
    for the given process.

Arguments:

    ProcessId - Supplies the PID of the process to inspect.

    AttachInfo - Receives the attachment information.

Return Value:

    TRUE on success; FALSE on error with thread-error set.

Environment:

    Arbitrary.

--*/
{
    BOOL Result = FALSE;
    HANDLE AttachSection = NULL;
    PCON_ATTACH_SHARED AttachShared = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    WCHAR AttachSectionName[ARRAYSIZE (CON_ATTACHINFO_FORMAT)+1];
    ULONG Sequence;

    CONP_VERIFY (swprintf (AttachSectionName,
                           CON_ATTACHINFO_FORMAT,
                           ProcessId)
                 == ARRAYSIZE (CON_ATTACHINFO_FORMAT) - 1);

    AttachSection = OpenFileMapping (PAGE_READONLY,
                                     FALSE /* Inherit */,
                                     AttachSectionName);

    if (AttachSection == NULL) {

        //
        // If the given process doesn't have an attach-info section,
        // we consider that successfully reading an attach information
        // block of all zero.
        //

        if (GetLastError () == ERROR_FILE_NOT_FOUND ||
            GetLastError () == ERROR_PATH_NOT_FOUND)
        {
            ZeroMemory (AttachInfo, sizeof (*AttachInfo));
            Result = TRUE;
        }

        goto Out;
    }

    AttachShared = MapViewOfFile (
        AttachSection,
        FILE_MAP_READ,
        0, 0, 0);

    if (AttachShared == NULL) {
        goto Out;
    }

    if (!VirtualQuery (AttachShared, &mbi, sizeof (mbi))) {
        goto Out;
    }

    if (mbi.RegionSize < sizeof (*AttachShared)) {
        SetLastError (ERROR_INVALID_DATA);
        goto Out;
    }

    if (AttachShared->Version == 0) { // Not initialized
        ZeroMemory (AttachInfo, sizeof (*AttachInfo));
        Result = TRUE;
        goto Out;
    }

    if (AttachShared->Version != CON_SHARED_DATA_VERSION) {
        SetLastError (ERROR_PRODUCT_VERSION);
        goto Out;
    }

    //
    // If the sequence at the start of the copy doesn't match the
    // sequence at the end of the copy, the other process was updating
    // the shared information while we copied it.  Try again.
    //

    do {
        Sequence = AttachShared->Sequence;
        MemoryBarrier ();
        memcpy (AttachInfo,
                &AttachShared->Info[Sequence & 1],
                sizeof (*AttachInfo));

        MemoryBarrier ();
    } while (Sequence != AttachShared->Sequence &&
             (Sleep (0), TRUE));

    Result = TRUE;

  Out:

    if (AttachSection) {
        CONP_VERIFY (CloseHandle (AttachSection));
    }

    if (AttachShared) {
        CONP_VERIFY (UnmapViewOfFile (AttachShared));
    }

    return Result;

}

static
ULONG
ConpSlaveCookie (
    HANDLE SlaveHandle
    )
{
    PCON_SLAVE Slave = ConpReferenceSlaveHandle (SlaveHandle);
    ULONG Cookie;

    CONP_ASSERT (Slave);

    Cookie = Slave->Cookie;
    ConpDereferenceSlave (Slave);
    return Cookie;
}

static
BOOL
ConpAttachConsole (
    /* In */ ULONG ServerPid,
    /* In */ ULONG Cookie
    )
/*++

Routine Description:

    This routine attaches to the given console.

Arguments:

    ServerPid - Supplies the PID of the server hosting the
                pseudo-console.

    Cookie - Supplies the cookie corresponding to any
             object in the given console.

Return Value:

    TRUE on success; FALSE on failure with thread-error set.

Environment:

    Call with ConpAttachedConsoleLock held.  The current process must
    not be attached to a console.

--*/
{
    BOOL Result = FALSE;
    STARTUPINFO si;
    PCON_SLAVE AttachSlave = NULL;
    PCON_ATTACH_SHARED AttachShared = NULL;
    CON_ATTACH_INFO AttachInfo;

    HANDLE ReplacementStdin = NULL;
    HANDLE ReplacementStdout = NULL;
    HANDLE ReplacementStderr = NULL;

    BOOL NeedNewStdout;
    BOOL NeedNewStderr;

    PXPEB Peb;
    XPROCESS_BASIC_INFORMATION Bi;

    CONP_ASSERT (ConpIsAnyConsoleAttached == FALSE);
    CONP_ASSERT (ConpAttachedInput == NULL);
    CONP_ASSERT (ConpAttachedStdin == NULL);
    CONP_ASSERT (ConpAttachedStdout == NULL);
    CONP_ASSERT (ConpAttachedStderr == NULL);

    GetStartupInfo (&si);

    CONP_VERIFY (
        NT_SUCCESS (
            NtQueryInformationProcess (
                GetCurrentProcess (),
                ProcessBasicInformation,
                &Bi,
                sizeof (Bi),
                NULL)));

    Peb = (PXPEB) Bi.PebBaseAddress;

    //
    // Make sure we'll be able to export attachment information to
    // other processes.
    //

    AttachShared = ConpMapAttachShared ();
    if (AttachShared == NULL) {
        goto Out;
    }

    //
    // Figure out which standard handles we'll replace.  If we're
    // going to replace a standard handle, perform the connection to
    // the console server _before_ we do the
    // CON_HANDLE_CONNECT_ATTACHED connection: this way, if something
    // goes wrong, we don't show up as briefly attached to the
    // console.
    //

    if ((si.dwFlags & STARTF_USESTDHANDLES) == 0 ||
        GetStdHandle (STD_INPUT_HANDLE) == NULL ||
        ConpIsWindowsConsole (GetStdHandle (STD_INPUT_HANDLE)))
    {
        if (!ConpConnectSlaveHandle (ServerPid,
                                     Cookie,
                                     ( CON_HANDLE_READ_ACCESS |
                                       CON_HANDLE_CONNECT_NO_OUTPUT ),
                                     &ReplacementStdin))
        {
            goto Out;
        }
    }

    NeedNewStdout = ((si.dwFlags & STARTF_USESTDHANDLES) == 0 ||
                     GetStdHandle (STD_OUTPUT_HANDLE) == NULL ||
                     ConpIsWindowsConsole (GetStdHandle (STD_OUTPUT_HANDLE)));

    NeedNewStderr = ((si.dwFlags & STARTF_USESTDHANDLES) == 0 ||
                     GetStdHandle (STD_ERROR_HANDLE) == NULL ||
                     ConpIsWindowsConsole (GetStdHandle (STD_ERROR_HANDLE)));

    if (NeedNewStdout || NeedNewStderr) {
        if (!ConpConnectSlaveHandle (ServerPid,
                                     Cookie,
                                     ( CON_HANDLE_READ_ACCESS |
                                       CON_HANDLE_WRITE_ACCESS |
                                       CON_HANDLE_CONNECT_ACTIVE_OUTPUT ),
                                     &ReplacementStdout))
        {
            goto Out;
        }

        if (NeedNewStdout && NeedNewStderr) {
            if (!ConpDuplicateSlaveHandle (
                    ReplacementStdout,
                    &ReplacementStderr,
                    0, DUPLICATE_SAME_ACCESS, FALSE))
            {
                goto Out;
            }
        } else if (!NeedNewStdout && NeedNewStderr) {
            ReplacementStderr = ReplacementStdout;
            ReplacementStdout = NULL;
        }
    }

    //
    // Connect to the console's input queue.  Tell the server that
    // this connection is special and that as long as it lasts, this
    // process is attached to the given console.  If cookie refers to
    // a console output buffer, make sure the connection actually
    // refers only to the console input.
    //

    if (!ConpConnectSlave (ServerPid,
                           Cookie,
                           ( CON_HANDLE_READ_ACCESS       |
                             CON_HANDLE_CONNECT_ATTACHED  |
                             CON_HANDLE_CONNECT_NO_OUTPUT ),
                           &AttachSlave))
    {
        goto Out;
    }

    //
    // We've successfully attached to the console.  Commit to the new
    // console.  There are no failure paths past this point.
    //

    ConpAttachedInput = AttachSlave;
    AttachSlave = NULL;
    ConpIsAnyConsoleAttached = TRUE;

    Peb->ProcessParameters->WindowFlags &= ~STARTF_USEHOTKEY;

    if (ReplacementStdin) {
        ConpAttachedStdin = ReplacementStdin;
        SetStdHandle (STD_INPUT_HANDLE, ReplacementStdin);
        ReplacementStdin = NULL;
    }

    if (ReplacementStdout) {
        ConpAttachedStdout = ReplacementStdout;
        SetStdHandle (STD_OUTPUT_HANDLE, ReplacementStdout);
        ReplacementStdout = NULL;
    }

    if (ReplacementStderr) {
        ConpAttachedStderr = ReplacementStderr;
        SetStdHandle (STD_ERROR_HANDLE, ReplacementStderr);
        ReplacementStderr = NULL;
    }

    ZeroMemory (&AttachInfo, sizeof (AttachInfo));
    AttachInfo.ServerPid = ConpAttachedInput->ServerPid;
    AttachInfo.Cookie = ConpAttachedInput->Cookie;
    ConpUpdateAttachInfo (AttachShared, AttachInfo);

    // XXX: control-code handling --- use long polling?
    // XXX: set thread (?) language id to match console

    Result = TRUE;

  Out:

    if (AttachSlave) {
        ConpDereferenceSlave (AttachSlave);
    }

    if (AttachShared) {
        CONP_VERIFY (UnmapViewOfFile (AttachShared));
    }

    if (ReplacementStdin) {
        CONP_VERIFY (ConpCloseSlaveHandle (ReplacementStdin));
    }

    if (ReplacementStdout) {
        CONP_VERIFY (ConpCloseSlaveHandle (ReplacementStdout));
    }

    if (ReplacementStderr) {
        CONP_VERIFY (ConpCloseSlaveHandle (ReplacementStderr));
    }

    return Result;
}

static
BOOL
ConpFreeConsole (
    VOID
    )
/*++

Routine Description:

    This routine detaches from the current pseudo-console; it is
    normally called by a hooked FreeConsole, which first checks
    whether the current console is a pseudo-console.

Arguments:

    None.

Return Value:

    TRUE on success; FALSE on error with thread-error set.

Environment:

    Call with ConpAttachedConsoleLock held.

--*/
{
    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);

    if (ConpAttachedInput) {
        ConpDereferenceSlave (ConpAttachedInput);
        ConpAttachedInput = NULL;
    }

    if (ConpAttachedStdin) {
        if (GetStdHandle (STD_INPUT_HANDLE) == ConpAttachedStdin) {
            SetStdHandle (STD_INPUT_HANDLE, NULL);
        }

        CONP_VERIFY (ConpCloseSlaveHandle (ConpAttachedStdin));
        ConpAttachedStdin = NULL;
    }

    if (ConpAttachedStdout) {
        if (GetStdHandle (STD_OUTPUT_HANDLE) == ConpAttachedStdout) {
            SetStdHandle (STD_OUTPUT_HANDLE, NULL);
        }

        CONP_VERIFY (ConpCloseSlaveHandle (ConpAttachedStdout));
        ConpAttachedStdout = NULL;
    }

    if (ConpAttachedStderr) {
        if (GetStdHandle (STD_ERROR_HANDLE) == ConpAttachedStderr) {
            SetStdHandle (STD_ERROR_HANDLE, NULL);
        }

        CONP_VERIFY (ConpCloseSlaveHandle (ConpAttachedStderr));
        ConpAttachedStderr = NULL;
    }

    ConpIsAnyConsoleAttached = FALSE;
    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);

    return TRUE;
}

static
PCON_SHADOW_ATTRIBUTE_LIST
ConpFindShadowAttributes (
    LPPROC_THREAD_ATTRIBUTE_LIST AttributeList
    )
/*++

Routine Description:

    Find a shadow attribute structure given a real attribute pointer.

Arguments:

    AttributeList - Supplies an attribute list.

Return Value:

    Return the shadow attribute pointer or NULL on error.

Environment:

    Call with ConpShadowAttributeLock held.

--*/
{
    PLIST_ENTRY Entry;
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes;

    for (Entry = ConpShadowAttributes.Flink;
         Entry != &ConpShadowAttributes;
         Entry = Entry->Flink)
    {
        ShadowAttributes = CONTAINING_RECORD (Entry,
                                              CON_SHADOW_ATTRIBUTE_LIST,
                                              ShadowAttributeLink);

        if (ShadowAttributes->AttributeList == AttributeList) {
            return ShadowAttributes;
        }
    }

    return NULL;
}

BOOL CONIO_API
ConSetChildAttach (
    PVOID AttributeList,
    HANDLE SlaveHandle
    )
{
    BOOL Result = FALSE;
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes;
    PCON_SLAVE Slave;

    Slave = ConpReferenceSlaveHandle (SlaveHandle);
    if (Slave == NULL) {
        goto Out;
    }

    AcquireSRWLockExclusive (&ConpShadowAttributeLock);
    ShadowAttributes = ConpFindShadowAttributes (AttributeList);
    if (ShadowAttributes == NULL) {
        SetLastError (ERROR_INVALID_PARAMETER);
        goto Out;
    }

    {
        PCON_SLAVE Tmp = ShadowAttributes->ChildAttach;
        ShadowAttributes->ChildAttach = Slave; // Transfer ownership
        Slave = Tmp;
    }

    Result = TRUE;

  Out:

    ReleaseSRWLockExclusive (&ConpShadowAttributeLock);

    if (Slave) {
        ConpDereferenceSlave (Slave);
    }

    return Result;
}

static
BOOL
ConpFindShadowHandleList (
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes,
    HANDLE** HandleList,
    SIZE_T* HandleListLength
    )
{
    PLIST_ENTRY Entry;
    PCON_SHADOW_ATTRIBUTE Attribute;

    for (Entry = ShadowAttributes->Attributes.Flink;
         Entry != &ShadowAttributes->Attributes;
         Entry = Entry->Flink)
    {
        Attribute = CONTAINING_RECORD (Entry,
                                       CON_SHADOW_ATTRIBUTE,
                                       AttributeLink);

        if (Attribute->Attribute == PROC_THREAD_ATTRIBUTE_HANDLE_LIST) {
            *HandleList = Attribute->Value;
            *HandleListLength = Attribute->Size / sizeof (HANDLE);
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOL
ConpCreateFilteredAttributeList (
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes,
    LPPROC_THREAD_ATTRIBUTE_LIST* FilteredAttributeList
    )
/*++

Routine Description:

    This routine convert a shadowed attribute list into a regular
    attribute list.  The regular attribute list is identical to the
    original attribute list, but with pseudo-console slave handles
    filtered out.

Arguments:

    ShadowAttributes - Supplies the shadow attribute structure.

    FilteredAttributeList - Receives a pointer to the new attribute
                            list.  The caller must release this list
                            by calling DeleteProcThreadAttributeList,
                            then LocalFree.

Return Value:

    TRUE on success; FALSE on error with thread-error set.

Environment:

    Arbitrary.

--*/
{
    BOOL Result = FALSE;
    PCON_SHADOW_ATTRIBUTE Attribute;
    LPPROC_THREAD_ATTRIBUTE_LIST Atl;
    PVOID Value;
    SIZE_T Size;
    PLIST_ENTRY Entry;
    HANDLE* OldHandleList = NULL;
    SIZE_T OldHandleListLength = 0; // Number of handles
    HANDLE* NewHandleList = NULL;
    SIZE_T NewHandleListLength = 0; // Number of handles
    ULONG i;

    (VOID) ConpFindShadowHandleList (ShadowAttributes,
                                     &OldHandleList,
                                     &OldHandleListLength);

    Atl = LocalAlloc (LMEM_ZEROINIT,
                      ShadowAttributes->Size +
                      OldHandleListLength * sizeof (HANDLE));

    if (!Atl) {
        goto Out;
    }

    Size = ShadowAttributes->Size;
    if (!InitializeProcThreadAttributeList (
            Atl,
            ShadowAttributes->AttributeCount,
            ShadowAttributes->Flags,
            &Size))
    {
        goto Out;
    }

    NewHandleList = (HANDLE*) ((PBYTE) Atl + Size);
    for (i = 0; i < OldHandleListLength; ++i) {
        if (!ConpIsSlave (OldHandleList[i])) {
            NewHandleList[NewHandleListLength++] =
                OldHandleList[i];
        }
    }

    for (Entry = ShadowAttributes->Attributes.Flink;
         Entry != &ShadowAttributes->Attributes;
         Entry = Entry->Flink)
    {
        Attribute = CONTAINING_RECORD (Entry,
                                       CON_SHADOW_ATTRIBUTE,
                                       AttributeLink);
        Value = Attribute->Value;
        Size = Attribute->Size;

        if (Attribute->Attribute == PROC_THREAD_ATTRIBUTE_HANDLE_LIST) {
            CONP_ASSERT (Value == OldHandleList);
            CONP_ASSERT (Size = OldHandleListLength * sizeof (HANDLE));
            Value = NewHandleList;
            Size = NewHandleListLength * sizeof (HANDLE);
        }

        if (!UpdateProcThreadAttribute (Atl,
                                        Attribute->Flags,
                                        Attribute->Attribute,
                                        Value,
                                        Size,
                                        NULL,
                                        NULL))
        {
            goto Out;
        }
    }

    *FilteredAttributeList = Atl;
    Atl = NULL;
    Result = TRUE;

  Out:

    if (Atl) {
        DeleteProcThreadAttributeList (Atl);
        LocalFree (Atl);
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
        if (!ConpAreHooksEnabled ()) {                 \
            return ConpOrig##api arguse;               \
        }                                              \
                                                       \
        ConpSetHooksEnabled (FALSE);                   \
        Result = ConpHookBody##api arguse;             \
        ConpSetHooksEnabled (TRUE);                    \
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
    if (lpFileName && ConpIsAttachedAsSlave ()) {
        PCWSTR MagicName;

        if (!_stricmp (lpFileName, "CON")) {
            MagicName = L"CON";
        } else if (!_stricmp (lpFileName, "CONIN$")) {
            MagicName = L"CONIN$";
        } else if (!_stricmp (lpFileName, "CONOUT$")) {
            MagicName = L"CONOUT$";
        } else {
            MagicName = NULL;
        }

        if (MagicName != NULL) {
            ConpSetHooksEnabled (TRUE);
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
    PCON_SLAVE LocalAttachedInput = FALSE;

    //
    // If we're trying to open a console handle, try to acquire a
    // reference to the currently attached input queue.  If we have
    // one, use it to establish a connection.  Otherwise, punt to
    // normal CreateFileW.
    //

    if (lpFileName && ( !_wcsicmp (lpFileName, L"CON")     ||
                        !_wcsicmp (lpFileName, L"CONIN$")  ||
                        !_wcsicmp (lpFileName, L"CONOUT$") ))
    {
        AcquireSRWLockShared (&ConpAttachedConsoleLock);
        if (ConpAttachedInput) {
            LocalAttachedInput = ConpAttachedInput;
            InterlockedIncrement (&LocalAttachedInput->ReferenceCount);
        }

        ReleaseSRWLockShared (&ConpAttachedConsoleLock);
    }

    if (LocalAttachedInput) {
        HANDLE Result = INVALID_HANDLE_VALUE;
        HANDLE NewSlaveHandle;
        ULONG Flags = 0;

        // XXX: should we look for object-specific (i.e., not generic)
        // access bits too?

        if (dwDesiredAccess & GENERIC_READ) {
            Flags |= CON_HANDLE_READ_ACCESS;
        }

        if (dwDesiredAccess & GENERIC_WRITE) {
            Flags |= CON_HANDLE_WRITE_ACCESS;
        }

        if (lpSecurityAttributes &&
            lpSecurityAttributes->bInheritHandle)
        {
            Flags |= CON_HANDLE_INHERIT;
        }

        //
        // MSDN: the meaning of "CON" depends on desired access.
        //

        if (!_wcsicmp (lpFileName, L"CON")) {
            if ( (dwDesiredAccess & GENERIC_READ) &&
                 (dwDesiredAccess & GENERIC_WRITE))
            {
                SetLastError (ERROR_FILE_NOT_FOUND); // Sic.
                goto OutHooked;
            }

            if (dwDesiredAccess & GENERIC_WRITE) {
                lpFileName = L"CONIN$";
            } else {
                lpFileName = L"CONOUT$";
            }
        }

        //
        // Note that there's a difference between connecting to an
        // output buffer with no write access and connecting to the
        // input queue alone.  In the former case, we keep
        // the output buffer alive.
        //

        if (!_wcsicmp (lpFileName, L"CONIN$")) {
            Flags |= CON_HANDLE_CONNECT_NO_OUTPUT;
        }

        if (!ConpConnectSlaveHandle (
                LocalAttachedInput->ServerPid,
                LocalAttachedInput->Cookie,
                Flags,
                &NewSlaveHandle))
        {
            goto OutHooked;
        }

        Result = NewSlaveHandle;

      OutHooked:

        ConpDereferenceSlave (LocalAttachedInput);
        return Result;
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
            dwDesiredAccess,
            dwOptions,
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return AddConsoleAliasW (Source, Target, ExeName);
}

HOOK (AllocConsole, BOOL,
      ( VOID ),
      ( ))
{
    BOOL Result = FALSE;

    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);

    if (ConpIsAnyConsoleAttached) {
        SetLastError (ERROR_ACCESS_DENIED);
        goto Out;
    }

    Result = AllocConsole ();
    if (Result) {
        ConpIsAnyConsoleAttached = TRUE;
    }

  Out:

    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);
    return Result;
}

HOOK (AttachConsole, BOOL,
      ( DWORD ProcessId ),
      ( ProcessId ))
{
    CON_ATTACH_INFO AttachInfo;
    BOOL Result = FALSE;

    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);

    if (ConpIsAnyConsoleAttached) {
        SetLastError (ERROR_ACCESS_DENIED);
        goto Out;
    }

    // XXX: support attaching to parent process

    //
    // Consult the shared section to see whether the given process is
    // attached to a pseudoconsole.  If the process has pseudoconsole
    // information and we can't read it, fail the operation.
    //

    if (!ConpReadAttachInfo (ProcessId, &AttachInfo)) {
        goto Out;
    }

    //
    // If the process to which we're trying to attach isn't attached
    // to a pseudoconsole, punt to the regular console library.
    // Otherwise, try to attach to the pseudo-console.  If either
    // succeeds, we're now attached to a console.
    //

    if (AttachInfo.ServerPid != 0) {
        Result = ConpAttachConsole (AttachInfo.ServerPid,
                                    AttachInfo.Cookie);
    } else {
        Result = AttachConsole (ProcessId);
    }

    if (Result) {
        ConpIsAnyConsoleAttached = TRUE;
    }

  Out:

    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);
    return Result;
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
    if (ConpIsAttachedAsSlave ()) {
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
    BOOL Result;

    AcquireSRWLockExclusive (&ConpAttachedConsoleLock);

    if (ConpAttachedInput) {
        Result = ConpFreeConsole ();
    } else {
        Result = FreeConsole ();
    }

    if (Result) {
        ConpIsAnyConsoleAttached = FALSE;
    }

  Out:

    ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);
    return Result;
}

HOOK (GenerateConsoleCtrlEvent, BOOL,
      ( DWORD dwCtrlEvent,
        DWORD dwProcessGroupId ),
      ( dwCtrlEvent,
        dwProcessGroupId ))
{
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasesLengthA (lpExeName );
}

HOOK (GetConsoleAliasesLengthW, DWORD,
      ( LPWSTR lpExeName ),
      ( lpExeName ))
{
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesLengthA ();
}

HOOK (GetConsoleAliasExesLengthW, DWORD,
      ( VOID ),
      ( ))
{
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleAliasExesLengthW ();
}

HOOK (GetConsoleCP, UINT,
      ( VOID ),
      ( ))
{
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleOriginalTitleW (lpConsoleTitle, nSize );
}

HOOK (GetConsoleOutputCP, UINT,
      ( VOID ),
      ( ))
{
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return GetConsoleTitleW (lpConsoleTitle, nSize );
}

HOOK (GetConsoleWindow, HWND,
      ( VOID ),
      ( ))
{
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
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
    if (ConpIsAttachedAsSlave ()) {
        SetLastError (ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }

    return SetConsoleTitleA (lpConsoleTitle );
}

HOOK (SetConsoleTitleW, BOOL,
      ( LPCWSTR lpConsoleTitle ),
      ( lpConsoleTitle ))
{
    if (ConpIsAttachedAsSlave ()) {
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

// XXX: hook other forms of CreateProcess

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
    BOOL Result = FALSE;
    STARTUPINFOEXW* Si = NULL;
    ULONG SiSize;
    PCON_SHADOW_ATTRIBUTE_LIST Sal;
    LPPROC_THREAD_ATTRIBUTE_LIST Ptal = NULL;

    PCON_SLAVE ChildAttach = NULL;

    HANDLE* HandleList;
    SIZE_T HandleListLength;
    BOOL HandleListPresent = FALSE;

    //
    // Copy the startupinfo so we can modify it.
    //

    SiSize = lpStartupInfo->cb;
    if (SiSize == 0) {
        SiSize = sizeof (*lpStartupInfo);
    }

    Si = LocalAlloc (0, SiSize);
    memcpy (Si, lpStartupInfo, SiSize);

    //
    // If the user gave us extended attributes, substitute a version
    // with all the console pseudo-handles stripped out; if the user
    // set an attach console for the child, use it; and if the
    // attribute list contains a handle list, make sure to constrain
    // the inherited handles to ones on the list.
    //

    if (dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT &&
        sizeof (*Si) <= Si->StartupInfo.cb &&
        Si->lpAttributeList)
    {
        AcquireSRWLockExclusive (&ConpShadowAttributeLock);
        Sal = ConpFindShadowAttributes (Si->lpAttributeList);
        if (Sal) {
            if (!ConpCreateFilteredAttributeList (Sal, &Ptal)) {
                goto Out;
            }

            ConpTrace (L"Sal->ChildAttach %p", Sal->ChildAttach);

            if (Sal->ChildAttach) {
                ChildAttach = Sal->ChildAttach;
                InterlockedIncrement (&ChildAttach->ReferenceCount);
            }

            Si->lpAttributeList = Ptal;

            HandleListPresent =
                ConpFindShadowHandleList (Sal,
                                          &HandleList,
                                          &HandleListLength);
        }

        ReleaseSRWLockExclusive (&ConpShadowAttributeLock);
    }

    //
    // If our caller didn't tell us the console to which the child
    // should be attached, try to figure it out based on process
    // context and flags.
    //

    if (ChildAttach == NULL &&
        (dwCreationFlags & CREATE_NEW_CONSOLE) == 0 &&
        (dwCreationFlags & DETACHED_PROCESS) == 0)
    {
        AcquireSRWLockExclusive (&ConpAttachedConsoleLock);
        if (ConpAttachedInput) {
            ChildAttach = ConpAttachedInput;
            InterlockedIncrement (&ChildAttach->ReferenceCount);
        }

        ReleaseSRWLockExclusive (&ConpAttachedConsoleLock);
    }

    //
    // If the top-level enable switch for handle inheritance isn't
    // given, stop inheritance by pretending we have a zero-length
    // handle list.
    //

    if (bInheritHandles == FALSE) {
        HandleListPresent = TRUE;
        HandleList = NULL;
        HandleListLength = 0;
    }

    if (CreateProcessW (lpApplicationName,
                        lpCommandLine,
                        lpProcessAttributes,
                        lpThreadAttributes,
                        bInheritHandles,
                        dwCreationFlags | CREATE_SUSPENDED,
                        lpEnvironment,
                        lpCurrentDirectory,
                        &Si->StartupInfo,
                        lpProcessInformation)
        == FALSE)
    {
        goto Out;
    }

    //
    // Tell the child about any handles it's inheriting.
    //

    if (!ConpPropagateInheritance (
            lpProcessInformation->hProcess,
            ChildAttach,
            HandleListPresent,
            HandleList,
            HandleListLength))
    {
        ULONG SavedError = GetLastError ();
        (VOID) TerminateProcess (lpProcessInformation->hProcess,
                                 HRESULT_FROM_WIN32 (SavedError));

        CONP_VERIFY (CloseHandle (lpProcessInformation->hThread));
        CONP_VERIFY (CloseHandle (lpProcessInformation->hProcess));
        ZeroMemory (lpProcessInformation, sizeof (*lpProcessInformation));
        SetLastError (SavedError);
        goto Out;
    }

    if ((dwCreationFlags & CREATE_SUSPENDED) == 0) {
        (VOID) ResumeThread (lpProcessInformation->hThread);
    }

    Result = TRUE;

  Out:

    if (Ptal) {
        DeleteProcThreadAttributeList (Ptal);
        LocalFree (Ptal);
    }

    if (ChildAttach) {
        ConpDereferenceSlave (ChildAttach);
    }

    LocalFree (Si);
    return Result;
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

        *lpdwFlags = Slave->Flags & (HANDLE_FLAG_INHERIT |
                                     HANDLE_FLAG_PROTECT_FROM_CLOSE);

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
        ULONG OldFlags;
        ULONG NewFlags;

        Slave = ConpReferenceSlaveHandle (hObject);
        if (Slave == NULL) {
            return FALSE;
        }

        dwMask &= (HANDLE_FLAG_INHERIT |
                   HANDLE_FLAG_PROTECT_FROM_CLOSE);

        do {
            OldFlags = Slave->Flags;
            NewFlags = (OldFlags &~ dwMask) | dwFlags;
        } while (InterlockedCompareExchange ((LONG*) &Slave->Flags,
                                             NewFlags,
                                             OldFlags)
                 != (LONG) OldFlags);

        ConpDereferenceSlave (Slave);
        return TRUE;
    }

    return SetHandleInformation (hObject, dwMask, dwFlags);
}

HOOK (InitializeProcThreadAttributeList, BOOL,
      ( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwAttributeCount,
        DWORD dwFlags,
        PSIZE_T lpSize ),
      ( lpAttributeList,
        dwAttributeCount,
        dwFlags,
        lpSize ))
{
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes;

    if (!InitializeProcThreadAttributeList(lpAttributeList,
                                           dwAttributeCount,
                                           dwFlags,
                                           lpSize))
    {
        return FALSE;
    }

    ShadowAttributes = LocalAlloc (LMEM_ZEROINIT,
                                   sizeof (*ShadowAttributes));

    if (ShadowAttributes == NULL) {
        DeleteProcThreadAttributeList (lpAttributeList);
        return FALSE;
    }

    ShadowAttributes->AttributeList = lpAttributeList;
    ShadowAttributes->AttributeCount = dwAttributeCount;
    ShadowAttributes->Flags = dwFlags;
    ShadowAttributes->Size = *lpSize;
    InitializeListHead (&ShadowAttributes->Attributes);

    AcquireSRWLockExclusive (&ConpShadowAttributeLock);
    InsertHeadList (&ConpShadowAttributes,
                    &ShadowAttributes->ShadowAttributeLink);

    ReleaseSRWLockExclusive (&ConpShadowAttributeLock);

    return TRUE;
}

HOOK (UpdateProcThreadAttribute, BOOL,
      ( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwFlags,
        DWORD_PTR Attribute,
        PVOID lpValue,
        SIZE_T cbSize,
        PVOID lpPreviousValue,
        PSIZE_T lpReturnSize ),
      ( lpAttributeList,
        dwFlags,
        Attribute,
        lpValue,
        cbSize,
        lpPreviousValue,
        lpReturnSize ))
{
    BOOL Result = FALSE;
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes = NULL;
    PCON_SHADOW_ATTRIBUTE ShadowAttribute = NULL;

    AcquireSRWLockExclusive (&ConpShadowAttributeLock);
    ShadowAttributes = ConpFindShadowAttributes (lpAttributeList);

    if (ShadowAttributes) {
        ShadowAttribute = LocalAlloc (LMEM_ZEROINIT,
                                      sizeof (*ShadowAttribute));

        if (!ShadowAttribute) {
            goto Out;
        }

        ShadowAttribute->Flags = dwFlags;
        ShadowAttribute->Attribute = Attribute;
        ShadowAttribute->Value = lpValue;
        ShadowAttribute->Size = cbSize;
        InsertTailList (&ShadowAttributes->Attributes,
                        &ShadowAttribute->AttributeLink);
    }

    if (!UpdateProcThreadAttribute(
            lpAttributeList,
            dwFlags,
            Attribute,
            lpValue,
            cbSize,
            lpPreviousValue,
            lpReturnSize))
    {
        goto Out;
    }

    ShadowAttribute = NULL;
    Result = TRUE;

  Out:

    if (ShadowAttribute) {
        RemoveEntryList (&ShadowAttribute->AttributeLink);
        LocalFree (ShadowAttribute);
    }

    ReleaseSRWLockExclusive (&ConpShadowAttributeLock);
    return Result;
}

HOOK (DeleteProcThreadAttributeList, ULONG,
      ( LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList ),
      ( lpAttributeList ))
{
    PLIST_ENTRY Entry;
    PCON_SHADOW_ATTRIBUTE_LIST ShadowAttributes;
    PCON_SHADOW_ATTRIBUTE Attribute;

    AcquireSRWLockExclusive (&ConpShadowAttributeLock);
    ShadowAttributes = ConpFindShadowAttributes (lpAttributeList);
    if (ShadowAttributes) {
        for (Entry = RemoveHeadList (&ShadowAttributes->Attributes);
             Entry != &ShadowAttributes->Attributes;
             Entry = RemoveHeadList (&ShadowAttributes->Attributes))
        {
            Attribute = CONTAINING_RECORD (Entry,
                                           CON_SHADOW_ATTRIBUTE,
                                           AttributeLink);

            LocalFree (Attribute);
        }

        if (ShadowAttributes->ChildAttach) {
            ConpDereferenceSlave (ShadowAttributes->ChildAttach);
        }

        LocalFree (ShadowAttributes);
    }

    ReleaseSRWLockExclusive (&ConpShadowAttributeLock);

    DeleteProcThreadAttributeList (lpAttributeList);
    return 0; // Ignored
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
/*++

Routine Description:

    This routine initializes the conio client.

Arguments:

    None.

Return Value:

    TRUE on success; FALSE on failure with thread-eror set.

Environment:

    Call once when DLL loads.

--*/
{
    ConpTlsIndex = TlsAlloc ();
    if (ConpTlsIndex == TLS_OUT_OF_INDEXES) {
        return FALSE;
    }

#ifndef COLLECTING_HOOKS
# define REGHOOK(api)                                                   \
    if (!ConpHookApi (# api, ConpHook##api, &ConpOrig##api )) {         \
        return FALSE;                                                   \
    }

# include "conio-client-generated.c"

#endif

    return TRUE;
}

int
Conp_scwprintf (PCWSTR Format, ...)
{
    va_list Args;
    int Length;

    va_start (Args, Format);
    Length = _vscwprintf (Format, Args);
    va_end (Args);
    return Length;
}

VOID
ConpTrace (
    PCWSTR Format,
    ...)
{
    va_list Args;
    ULONG SavedError = GetLastError ();
    int FormatLength;
    int NeededLength;
    PWSTR Buffer = NULL;
    BOOL OldHooksEnabled;
    BOOL ResetHooks = FALSE;


    static SRWLOCK LogLock;
    static HANDLE Log;
    BOOL LogLockHeld = FALSE;
    ULONG BytesWritten;
    PSTR AnsiBuffer = NULL;
    SIZE_T AnsiLength;
    SYSTEMTIME Now;

    if (ConpTlsIndex > 0) {
        ResetHooks = TRUE;
        OldHooksEnabled = ConpAreHooksEnabled ();
        ConpSetHooksEnabled (FALSE);
    }

    GetLocalTime (&Now);

#define PREFIX L"%02u:%02u:%02u: %04u.%04u: ",               \
        Now.wHour, Now.wMinute, Now.wSecond,                 \
        GetCurrentProcessId (), GetCurrentThreadId ()

    NeededLength = 0;
    NeededLength += Conp_scwprintf (PREFIX);

    va_start (Args, Format);
    NeededLength += _vscwprintf (Format, Args);
    va_end (Args);

    NeededLength += 1; // Terminating nul

    Buffer = LocalAlloc (0, sizeof (WCHAR) * (NeededLength));
    if (Buffer == NULL) {
        goto Out;
    }

    FormatLength = 0;
    FormatLength += swprintf (Buffer + FormatLength, PREFIX);
    FormatLength += _vswprintf (Buffer + FormatLength, Format, Args);
    OutputDebugString (Buffer);

    AnsiBuffer = LocalAlloc (0, 2 * (FormatLength + 2));
    AnsiLength = wcstombs (AnsiBuffer, Buffer, 2 * (FormatLength + 2));
    AnsiBuffer[AnsiLength++] = '\n';
    AnsiBuffer[AnsiLength] = '\0';

    AcquireSRWLockExclusive (&LogLock);
    LogLockHeld = TRUE;

    if (Log == NULL) {
        Log = CreateFile (L"conio.log",
                          FILE_APPEND_DATA,
                          ( FILE_SHARE_READ |
                            FILE_SHARE_WRITE |
                            FILE_SHARE_DELETE ),
                          NULL /* No special security */,
                          OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL,
                          NULL);

        if (Log == INVALID_HANDLE_VALUE) {
            Log = NULL;
            goto Out;
        }
    }

    (VOID) WriteFile (Log, AnsiBuffer,
                      AnsiLength,
                      &BytesWritten, NULL);

  Out:

    if (LogLockHeld) {
        ReleaseSRWLockExclusive (&LogLock);
    }

    LocalFree (Buffer);
    LocalFree (AnsiBuffer);

    if (ResetHooks) {
        ConpSetHooksEnabled (OldHooksEnabled);
    }

    SetLastError (SavedError);
}
