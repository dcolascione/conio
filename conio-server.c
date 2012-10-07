#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <assert.h>
#include "conio.h"
#include "miniddk.h"
#include "coniop.h"

typedef struct _CON_CONNECTION CON_CONNECTION, *PCON_CONNECTION;
typedef struct _CON_OUTPUT CON_OUTPUT, *PCON_OUTPUT;

struct _CON_MASTER {

    //
    // This lock protects all fields in this object and all its
    // associated outputs and connections.
    //

    SRWLOCK Lock;

    //
    // Bookkeeping.
    //

    LONG ReferenceCount;
    BOOL ShuttingDown;

    //
    // Process-unique identifier for this master.
    //

    ULONG Cookie;
    ULONG NumberCreatedPipes;

    //
    // Callback information.
    //

    CON_HANDLER Handler;
    PVOID Context;

    //
    // List of all connections to this master or one of its outputs.
    // References are weak references.
    //

    CONDITION_VARIABLE ConnectionRemoved;
    LIST_ENTRY Connections;

    //
    // Weak reference to the currently-active output.
    //

    PCON_OUTPUT ActiveOutput;
};

struct _CON_OUTPUT {
    //
    // References from handles.
    //

    LONG ReferenceCount;

    //
    // Strong reference to master.
    //

    PCON_MASTER Master;

    //
    // The output context.
    //

    PVOID Context;

    //
    // Process-wide unique ID.
    //

    ULONG Cookie;
    ULONG NumberCreatedPipes;
};

typedef enum _CON_CONNECTION_STATE {
    ConConnectionIdle,
    ConConnectionError,
    ConConnectionListening,
    ConConnectionReadingHeader,
    ConConnectionReadingBody,
    ConConnectionSendingReply
} CON_CONNECTION_STATE, *PCON_CONNECTION_STATE;

typedef enum _CON_IO_MODE {
    ConConnectionIoIdle,
    ConConnectionIoRead,
    ConConnectionIoWrite
} CON_IO_MODE, *PCON_IO_MODE;

struct _CON_CONNECTION {
    LONG ReferenceCount;
    CON_CONNECTION_STATE State;

    //
    // Pipe over which we talk to the client.
    //

    OVERLAPPED Ov;
    PTP_IO TpIo;
    HANDLE Pipe;

    //
    // Flags the client sent us for this connection.
    //

    ULONG Flags;

    //
    // Strong reference to master.
    //

    PCON_MASTER Master;

    //
    // Strong reference to output.
    //

    PCON_OUTPUT Output;

    //
    // Link for CON_MASTER's Connections list.
    //

    LIST_ENTRY ConnectionsLink;

    //
    // State for asynchronous IO.
    //

    PBYTE CurrentIoBuffer;
    ULONG TotalIoBytes;
    ULONG CompletedIoBytes;
    CON_IO_MODE IoMode;

    //
    // Temporary buffer for reads and writes.
    //

    PVOID Buffer;
    ULONG BufferSize;
};

BOOL
ConpStartListening (
    PCON_CONNECTION Connection
    );

VOID
ConpDereferenceMaster (
    PCON_MASTER Master
    );

VOID
ConpDereferenceOutput (
    PCON_OUTPUT Output
    );

VOID
ConpDereferenceConnection (
    PCON_CONNECTION Connection
    );

BOOL
ConpCreateConnection (
    /* In */    PCON_MASTER Master,
    /* InOpt */ PCON_OUTPUT Output,
    /* Out */   PCON_CONNECTION* NewConnection
    );

BOOL
ConpStartListening (
    /* In */ PCON_CONNECTION Connection
    );

BOOL
ConpStartReading (
    /* In */ PCON_CONNECTION Connection,
    /* Out */ PVOID Destination,
    /* In */ ULONG NumberBytesToRead
    );

BOOL
ConpStartWriting (
    /* In */ PCON_CONNECTION Connection,
    /* In */ PVOID Source,
    /* In */ ULONG NumberBytesToWrite
    );

BOOL
ConpStartWritingErrorReply (
    /* In */ PCON_CONNECTION Connection,
    /* In */ ULONG Error
    );

VOID
ConpConnectionFreeBuffer (
    /* In */ PCON_CONNECTION Connection
    )
/*++

Routine Description:

    Release the message buffer in Connection; if necessary, call the
    connection handler to do it.

Arguments:

    Connection - Supplies the connection the buffer of which we will
                 free.

Return Value:

    None.

Environment:

    Call without Connection->Master->Lock held.

--*/
{
    LocalFree (Connection->Buffer);
    Connection->Buffer = NULL;
    Connection->BufferSize = 0;
}

BOOL
ConpConnectionAllocateBuffer (
    /* In */ PCON_CONNECTION Connection,
    /* In */ ULONG BufferSize
    )
/*++

Routine Description:

    Make sure Connection->Buffer has at least BufferSize bytes
    available, releasing the existing buffer if necessary.

Arguments:

    Connection - Supplies the connection.

    BufferSize - Supplies the number of bytes to allocate.

Return Value:

    TRUE on success; FALSE on error with thread-error set.

Environment:

    Call without Connection->Master->Lock held.

--*/
{
    ConpConnectionFreeBuffer (Connection);

    Connection->Buffer = LocalAlloc (0, BufferSize);
    if (Connection->Buffer == NULL) {
        return FALSE;
    }

    Connection->BufferSize = BufferSize;
    return TRUE;
}

VOID
ConpOnConnectionConnected (
    PCON_CONNECTION Connection
    )
/*++

Routine Description:

    ConpOnIoCompletion calls this routine when an IO completes while
    the connection is in ConConnectionListening.  This routine tries
    to start another connection to handle additional connections to
    the corresponding object, then begins reading the first message
    header.

Arguments:

    Connection - Supplies the connection to complete.

Return Value:

    None.

Environment:

    IO completion callback.

--*/
{
    PCON_MASTER Master = Connection->Master;
    PCON_CONNECTION NewConnection = NULL;
    BOOL Result = FALSE;

    //
    // Someone connected.  We'll be using this named pipe instance for
    // communication with the client, so try to create another
    // listening connection.  If we can't do that, kill the new
    // connection and reuse it for listening.
    //

    if (!ConpCreateConnection (Connection->Master,
                               Connection->Output,
                               &NewConnection)
        || !ConpStartListening (NewConnection))
    {
        ConpTrace (L"Could not create new connection 0x%lx",
                   GetLastError ());

        if (NewConnection) {
            ConpDereferenceConnection (NewConnection);
            NewConnection = NULL;
        }

        (VOID) DisconnectNamedPipe (Connection->Pipe);
        Connection->State = ConConnectionIdle;

        if (!ConpStartListening (Connection)) {
            goto Out;
        }

        Result = TRUE;
        goto Out;
    }

    //
    // The new connection is now running on its own on another thread.
    //

    ConpDereferenceConnection (NewConnection);
    NewConnection = NULL;

    //
    // Read the message size header from the pipe.  If this operation
    // fails, the caller kills the connection when it removes the last
    // reference count on it.
    //

    if (!ConpConnectionAllocateBuffer (Connection, sizeof (ULONG))) {
        goto Out;
    }

    Connection->State = ConConnectionReadingHeader;

    if (!ConpStartReading (Connection, Connection->Buffer, sizeof (ULONG))) {
        goto Out;
    }

    Result = TRUE;

  Out:

    if (Result == FALSE) {
        Connection->State = ConConnectionError;
    }
}

VOID
ConpOnReadHeader (
    /* In */ PCON_CONNECTION Connection
    )
/*++

Routine Description:

    ConpOnIoCompletion calls this routine when
    it successfully reads a packet header from the pipe.

Arguments:

    Connection - Supplies the connection.

Return Value:

    None.

Environment:

    IO completion callback.

--*/
{
    ULONG ExpectedMessageSize;
    memcpy (&ExpectedMessageSize, Connection->Buffer, sizeof (ULONG));

    //
    // We read the message size without reading the full message, but
    // the message size is logically part of the message structure.
    // To make the message structure look normal, fill in the bit we
    // already read before we read the rest of the structure.
    //

    if (!ConpConnectionAllocateBuffer (Connection, ExpectedMessageSize)) {
        Connection->State = ConConnectionError;
        return;
    }

    memcpy (Connection->Buffer, &ExpectedMessageSize, sizeof (ULONG));
    Connection->State = ConConnectionReadingBody;

    if (!ConpStartReading (Connection,
                           (PBYTE) Connection->Buffer + sizeof (ULONG),
                           ExpectedMessageSize - sizeof (ULONG)))
    {
        Connection->State = ConConnectionError;
    }
}

VOID
ConpPrepareRequest (
    /* In */ PCON_CONNECTION Connection,
    /* Out */ PCON_REQUEST Request
    )
{
    ZeroMemory (Request, sizeof (*Request));
    AcquireSRWLockExclusive (&Connection->Master->Lock);
    {
        Request->Master = Connection->Master;
        Request->Error = ERROR_CALL_NOT_IMPLEMENTED;
        Request->Context = Connection->Master->Context;
        if (Connection->Output) {
            Request->OutputContext = Connection->Output->Context;
        }
    }
    ReleaseSRWLockExclusive (&Connection->Master->Lock);
}

VOID
ConpOnReadBody (
    /* In */ PCON_CONNECTION Connection
    )
/*++

Routine Description:

    ConpOnIoCompletion calls this routine when it successfully reads a
    packet body from the pipe.

Arguments:

    Connection - Supplies the connection.

Return Value:

    None.

Environment:

    IO completion callback.

--*/
{
    BOOL Result;
    PCON_MESSAGE Message;
    PCON_MESSAGE Reply;
    CON_REQUEST Request;

    PVOID UserReplyBuffer = NULL;
    ULONG UserReplyBufferSize = 0;
    BOOL FreeUserBuffer = FALSE;
    ULONG TotalReplySize;

    Result = FALSE;
    Message = Connection->Buffer;

    CONP_ASSERT (sizeof (Message->Size) == sizeof (ULONG));
    CONP_ASSERT (offsetof (CON_MESSAGE, Size) == 0);
    CONP_ASSERT (Connection->BufferSize >= sizeof (ULONG));

#define CHECK_MSG_SIZE(Field)                                           \
    if (Message->Size < CON_MESSAGE_SIZE (Field)) {                     \
        ConpTrace (L"Message too small on CONN %p", Connection);        \
        goto Out;                                                       \
    }

#define CHECK_FLAG(NeededFlags)                                         \
    if ((Connection->Flags & NeededFlags) != NeededFlags) {             \
        if (!ConpStartWritingErrorReply (Connection,                    \
                                         ERROR_ACCESS_DENIED))          \
        {                                                               \
            goto Out;                                                   \
        }                                                               \
                                                                        \
        Result = TRUE;                                                  \
        goto Out;                                                       \
    }

#define MAYBE_SEND_ERROR_REPLY()                                        \
    if (Request.Success == FALSE) {                                     \
        if (!ConpStartWritingErrorReply (Connection, Request.Error)) {  \
            goto Out;                                                   \
        }                                                               \
                                                                        \
        Result = TRUE;                                                  \
        goto Out;                                                       \
    }

#define ALLOCATE_REPLY(MsgType, Field, Extra)                           \
    if (!ConpConnectionAllocateBuffer (                                 \
            Connection,                                                 \
            CON_MESSAGE_SIZE (Field) + (Extra))) {                      \
        goto Out;                                                       \
    }                                                                   \
                                                                        \
    Message = NULL;                                                     \
    Reply = Connection->Buffer;                                         \
    ZeroMemory (Reply, CON_MESSAGE_SIZE (Field));                       \
    Reply->Size = CON_MESSAGE_SIZE(Field) + (Extra);                    \
    Reply->Type = (MsgType);

#define SEND_REPLY() \
    if (!ConpStartWriting (Connection, Reply, Reply->Size)) {   \
        goto Out;                                               \
    }                                                           \

    Connection->State = ConConnectionSendingReply;
    CHECK_MSG_SIZE (Type);

    ConpTrace (
        L"SERVER: recv size:%lu type:%lu",
        Message->Size, Message->Type);

    //
    // Parse the message and call the appropriate handler.
    //

    switch (Message->Type) {
        case ConMsgReadFile: {
            CHECK_MSG_SIZE (ReadFile);
            CHECK_FLAG (CON_HANDLE_READ_ACCESS);

            //
            // Call the handler and ask it to service the client's
            // ReadFile call.  It'll give us a pointer to a buffer
            // containing the reply it wants to send to the client.
            //

            ConpPrepareRequest (Connection, &Request);
            Request.Type = ConReadFile;
            Request.ReadFile.RequestedReadSize =
                Message->ReadFile.RequestedReadSize;

            Connection->Master->Handler (&Request);

            CONP_ASSERT (Request.ReadFile.ReplyBufferSize
                         <= Request.ReadFile.RequestedReadSize);

            UserReplyBuffer = Request.ReadFile.ReplyBuffer;
            UserReplyBufferSize = Request.ReadFile.ReplyBufferSize;
            FreeUserBuffer = TRUE;

            MAYBE_SEND_ERROR_REPLY ();
            ALLOCATE_REPLY (ConReplyReadFile,
                            ReadFileReply,
                            UserReplyBufferSize);

            memcpy (Reply->ReadFileReply.Payload,
                    UserReplyBuffer,
                    UserReplyBufferSize);

            SEND_REPLY ();
            break;
        }

        case ConMsgWriteFile: {
            CHECK_MSG_SIZE (WriteFile);
            CHECK_FLAG (CON_HANDLE_WRITE_ACCESS);

            ConpPrepareRequest (Connection, &Request);
            Request.Type = ConWriteFile;
            Request.WriteFile.Buffer = Message->WriteFile.Payload;
            Request.WriteFile.NumberBytesToWrite =
                Message->Size - CON_MESSAGE_SIZE (WriteFile);

            Connection->Master->Handler (&Request);
            MAYBE_SEND_ERROR_REPLY ();

            ALLOCATE_REPLY (ConReplyWriteFile, WriteFileReply, 0);
            Reply->WriteFileReply.NumberBytesWritten =
                Request.WriteFile.NumberBytesWritten;

            SEND_REPLY ();
            break;
        }

        case ConMsgInitializeConnection: {
            CHECK_MSG_SIZE (InitializeConnection);

            ConpTrace (L"SERVER: ConMsgInitializeConnection flags:0x%lx",
                       Message->InitializeConnection.Flags);
            
            Connection->Flags = Message->InitializeConnection.Flags;

            if (Connection->Output &&
                (Connection->Flags & (CON_HANDLE_CONNECT_NO_OUTPUT |
                                      CON_HANDLE_CONNECT_ACTIVE_OUTPUT)))
            {
                ConpDereferenceOutput (Connection->Output);
                Connection->Output = NULL;
            }

            if (Connection->Flags & CON_HANDLE_CONNECT_ACTIVE_OUTPUT) {
                CONP_ASSERT (Connection->Output == NULL);

                AcquireSRWLockExclusive (&Connection->Master->Lock);
                if (Connection->Master->ActiveOutput == NULL) {
                    ReleaseSRWLockExclusive (&Connection->Master->Lock);
                    goto Out; // Only happens on master shutdown
                }

                Connection->Output = Connection->Master->ActiveOutput;
                Connection->Output->ReferenceCount += 1;
                ReleaseSRWLockExclusive (&Connection->Master->Lock);
            }

            ALLOCATE_REPLY (ConReplyInitializeConnection,
                            InitializeConnectionReply,
                            0);

            Reply->InitializeConnectionReply.NewCookie =
                ( Connection->Output
                  ? Connection->Output->Cookie
                  : Connection->Master->Cookie );

            SEND_REPLY ();
            break;
        }

        default: {
            ConpTrace (L"SERVER: Received unknown message type %u",
                       Message->Type);

            goto Out;
        }
    }

    Result = TRUE;

  Out:

    if (Result == FALSE) {
        Connection->State = ConConnectionError;
    }

    if (FreeUserBuffer) {
        ConpPrepareRequest (Connection, &Request);
        Request.Type = ConFreeReplyBuffer;
        Request.FreeReplyBuffer.ReplyBuffer = UserReplyBuffer;
        Request.FreeReplyBuffer.ReplyBufferSize = UserReplyBufferSize;
        Connection->Master->Handler (&Request);
    }

#undef CHECK_SIZE
}

VOID
ConpOnReplySent (
    PCON_CONNECTION Connection
    )
/*++

Routine Description:

    ConpOnIoCompletion calls this routine when we finish sending the
    response to a request.  This routine starts listening for another
    request.

Arguments:

    Connection - Supplies the connection.

Return Value:

    None.

Environment:

    Threadpool callback.

--*/
{
    BOOL Result = FALSE;

    if (!ConpConnectionAllocateBuffer (Connection, sizeof (ULONG))) {
        goto Out;
    }

    Connection->State = ConConnectionReadingHeader;
    if (!ConpStartReading (Connection, Connection->Buffer, sizeof (ULONG))) {
        goto Out;
    }

    Result = TRUE;

  Out:

    if (Result == FALSE) {
        Connection->State = ConConnectionError;
    }
}

BOOL
ConpConnectionPumpIo (
    /* In */ PCON_CONNECTION Connection,
    /* In */ ULONG NumberBytesCompleted
    )
{
    BOOL Result;
    ULONG RemainingIoBytes;

    CONP_ASSERT (Connection->IoMode == ConConnectionIoRead ||
                 Connection->IoMode == ConConnectionIoWrite);

    CONP_ASSERT (Connection->CompletedIoBytes <= Connection->TotalIoBytes);

    RemainingIoBytes =
        Connection->TotalIoBytes - Connection->CompletedIoBytes;

    CONP_ASSERT (NumberBytesCompleted <= RemainingIoBytes);

    Connection->CompletedIoBytes += NumberBytesCompleted;
    if (Connection->CompletedIoBytes == Connection->TotalIoBytes) {
        Connection->IoMode = ConConnectionIoIdle;
        return TRUE;
    }

    AcquireSRWLockExclusive (&Connection->Master->Lock);
    ZeroMemory (&Connection->Ov, sizeof (Connection->Ov));
    Connection->ReferenceCount += 1;
    StartThreadpoolIo (Connection->TpIo);

    if (Connection->IoMode == ConConnectionIoRead) {
        Result = ReadFile (Connection->Pipe,
                           ( Connection->CurrentIoBuffer
                             + Connection->CompletedIoBytes ),
                           RemainingIoBytes,
                           NULL /* NumberOfBytesRead */,
                           &Connection->Ov);
    } else {
        Result = WriteFile (Connection->Pipe,
                            ( Connection->CurrentIoBuffer
                              + Connection->CompletedIoBytes ),
                            RemainingIoBytes,
                            NULL /* NumberOfBytesWritten */,
                            &Connection->Ov);
    }

    if (Result == FALSE && GetLastError () != ERROR_IO_PENDING) {
        CancelThreadpoolIo (Connection->TpIo);
        Connection->ReferenceCount -= 1;
        goto Out;
    }

    Result = TRUE;

  Out:

    ReleaseSRWLockExclusive (&Connection->Master->Lock);
    return Result;
}

BOOL
ConpStartReading (
    /* In */ PCON_CONNECTION Connection,
    /* Out */ PVOID Destination,
    /* In */ ULONG NumberBytesToRead
    )
{
    BOOL Result = FALSE;

    CONP_ASSERT (Connection->IoMode == ConConnectionIoIdle);

    Connection->CurrentIoBuffer = (PBYTE) Destination;
    Connection->CompletedIoBytes = 0;
    Connection->TotalIoBytes = NumberBytesToRead;
    Connection->IoMode = ConConnectionIoRead;

    return ConpConnectionPumpIo (Connection, 0);
}

BOOL
ConpStartWriting (
    /* In */ PCON_CONNECTION Connection,
    /* In */ PVOID Source,
    /* In */ ULONG NumberBytesToWrite
    )
{
    BOOL Result = FALSE;

    CONP_ASSERT (Connection->IoMode == ConConnectionIoIdle);

    Connection->CurrentIoBuffer = (PBYTE) Source;
    Connection->CompletedIoBytes = 0;
    Connection->TotalIoBytes = NumberBytesToWrite;
    Connection->IoMode = ConConnectionIoWrite;

    return ConpConnectionPumpIo (Connection, 0);
}

BOOL
ConpStartWritingErrorReply (
    /* In */ PCON_CONNECTION Connection,
    /* In */ ULONG Error
    )
{
    PCON_MESSAGE Message;

    if (!ConpConnectionAllocateBuffer (Connection,
                                       CON_MESSAGE_SIZE (ErrorReply)))
    {
        return FALSE;
    }

    Message = Connection->Buffer;
    ZeroMemory (Message, CON_MESSAGE_SIZE (ErrorReply));
    Message->Size = CON_MESSAGE_SIZE (ErrorReply);
    Message->Type = ConReplyError;
    Message->ErrorReply.ErrorCode = Error;

    if (!ConpStartWriting (Connection, Message, Message->Size)) {
        return FALSE;
    }

    return TRUE;
}

VOID CALLBACK
ConpOnIoCompletion (
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PVOID Overlapped,
    ULONG IoResult,
    ULONG_PTR NumberBytes,
    PTP_IO Io
    )
/*++

Routine Description:

    Respond to one of our asynchronous IO operations completing.

Arguments:

    See threadpool API.

Return Value:

    None.

Environment:

    Threadpool callback.

--*/
{
    PCON_CONNECTION Connection = Context;
    PCON_MASTER Master = Connection->Master;
    BOOL IsShuttingDown;

    CONP_ASSERT (Master != NULL);

    AcquireSRWLockExclusive (&Master->Lock);
    {
        CONP_ASSERT (Connection->ReferenceCount > 0);

#if 0
        ConpTrace (L"IO complete: CONN:%p RC:%ld RESULT: 0x%lx",
                   Connection,
                   Connection->ReferenceCount,
                   IoResult);
#endif

        IsShuttingDown = Master->ShuttingDown;
    }
    ReleaseSRWLockExclusive (&Master->Lock);

    //
    // If the console master is going away, we need to exit as quickly
    // as possible and bypass the usual rule processing.
    //

    if (IsShuttingDown) {
        ConpTrace (L"Shutting down CONN:%p", Connection);
        goto Out;
    }

    if (IoResult != NO_ERROR) {
        ConpTrace (L"CONN %p ERROR 0x%lx", Connection, IoResult);
        goto Out;
    }

    if (Connection->IoMode != ConConnectionIoIdle) {
        if (!ConpConnectionPumpIo (Connection, NumberBytes)) {
            ConpTrace (L"CONN %p PUMP ERROR 0x%lx", GetLastError ());
            goto Out;
        }
    }

    if (Connection->IoMode == ConConnectionIoIdle) {

        //
        // Our IO completed, so do the appropriate thing based on the
        // higher-level state of the connection.
        //

        switch (Connection->State) {
            case ConConnectionListening:
                ConpOnConnectionConnected (Connection);
                break;

            case ConConnectionReadingHeader:
                ConpOnReadHeader (Connection);
                break;

            case ConConnectionReadingBody:
                ConpOnReadBody (Connection);
                break;

            case ConConnectionSendingReply:
                ConpOnReplySent (Connection);
                break;

            case ConConnectionIdle:
            case ConConnectionError:
            default:
                abort ();
        }
    }

  Out:

    //
    // Whoever caused us to be called (by issuing an asynchronous IO)
    // added a reference count to he connection for this IO.  Here, we
    // release that reference count.  If we ran into an IO error, we
    // kill the connection here by releasing its last reference.
    //

    ConpDereferenceConnection (Connection);
}

static ULONG ConpCookie;

BOOL
ConpCreateConnection (
    /* In */    PCON_MASTER Master,
    /* InOpt */ PCON_OUTPUT Output,
    /* Out */   PCON_CONNECTION* NewConnection
    )
/*++

Routine Description:

    Create a new connection.  The new connection is in the
    ConConnectionIdle state and is on the master's list of
    connections.

Arguments:

    Master - Supplies the master for the connection.

    Output - Supplies the output associated with the connection.
             Optional.

    NewConnection - Receives a new connection object on success.

Return Value:

    TRUE on success; FALSE on failure, with thread error set.

Environment:

    Master->Lock not held.

--*/
{
    BOOL Result = FALSE;
    PCON_CONNECTION Connection = NULL;
    ULONG PipeFlags;
    WCHAR PipeName[ARRAYSIZE (CON_PIPE_FORMAT)];
    ULONG Cookie;
    ULONG* NumberCreatedPipes;

    AcquireSRWLockExclusive (&Master->Lock);

    //
    // Figure out the name of the pipe for this object.  If we
    // haven't created any pipes for this object before, ask the
    // system to ensure that our pipe is the first instance.
    //

    if (Output) {
        CONP_ASSERT (Output->Master == Master);

        Cookie = Output->Cookie;
        NumberCreatedPipes = &Output->NumberCreatedPipes;
    } else {
        Cookie = Master->Cookie;
        NumberCreatedPipes = &Master->NumberCreatedPipes;
    }

    swprintf (PipeName,
              CON_PIPE_FORMAT,
              GetCurrentProcessId (),
              Cookie);

    //
    // Create the connection object itself and its associated
    // kernel objects.
    //

    Connection = LocalAlloc (LMEM_ZEROINIT, sizeof (*Connection));
    if (Connection == NULL) {
        goto Out;
    }

    Connection->State = ConConnectionIdle;
    Connection->ReferenceCount = 1;

    PipeFlags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (*NumberCreatedPipes == 0) {
        PipeFlags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    Connection->Pipe = CreateNamedPipe (
        PipeName,
        PipeFlags,
        PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES,
        256 * 1024 /* Out buffer size */,
        256 * 1024 /* Input buffer size */,
        0 /* Default timeout */,
        NULL /* No special security */);

    if (Connection->Pipe == INVALID_HANDLE_VALUE) {
        Connection->Pipe = NULL;
        goto Out;
    }

    Connection->TpIo = CreateThreadpoolIo (
        Connection->Pipe,
        (PTP_WIN32_IO_CALLBACK) ConpOnIoCompletion,
        Connection,
        NULL /* Tp environment */);

    if (Connection->TpIo == NULL) {
        goto Out;
    }

    //
    // Success: we've allocated all resources and now have no failure
    // paths.
    //

    if (Output != NULL) {
        Output->ReferenceCount += 1;
        Connection->Output = Output;
    }

    Master->ReferenceCount += 1;
    Connection->Master = Master;
    InsertTailList (&Master->Connections,
                    &Connection->ConnectionsLink);

#if 0
    ConpTrace (L"New object: PN:%s CONN:%p", PipeName, Connection);
#endif

    *NumberCreatedPipes += 1;
    *NewConnection = Connection;
    Connection = NULL;
    Result = TRUE;

  Out:

    ReleaseSRWLockExclusive (&Master->Lock);

    if (Connection != NULL) {
        ConpDereferenceConnection (Connection);
    }

    return Result;
}

BOOL
ConpStartListening (
    PCON_CONNECTION Connection
    )
/*++

Routine Description:

    Take an idle connection and make it start listening for a new
    connection.

Arguments:

    Connection - Supplies the connection.

Return Value:

    TRUE on success; FALSE on error.

Environment:

    Call without Master->Lock held.

--*/
{
    BOOL Result = FALSE;

    AcquireSRWLockExclusive (&Connection->Master->Lock);

    //
    // The caller owns a reference to the connection.  If we
    // successfully start the asynchronous listen, the listening
    // machinery will own another reference, so speculatively add
    // that reference now.
    //

    CONP_ASSERT (Connection->State == ConConnectionIdle);
    CONP_ASSERT (Connection->ReferenceCount > 0);

    if (Connection->Master->ShuttingDown) {
        SetLastError (ERROR_NOT_READY);
        goto Out;
    }

    Connection->ReferenceCount += 1;
    StartThreadpoolIo (Connection->TpIo);
    ZeroMemory (&Connection->Ov, sizeof (Connection->Ov));

    //
    // Actually start the asynchronous listen operation.
    //

    if (!ConnectNamedPipe (Connection->Pipe, &Connection->Ov) &&

        GetLastError () != ERROR_IO_PENDING &&
        GetLastError () != ERROR_PIPE_CONNECTED)
    {
        Connection->ReferenceCount -= 1;
        CancelThreadpoolIo (Connection->TpIo);
        goto Out;
    }

    Connection->State = ConConnectionListening;
    Result = TRUE;

  Out:

    ReleaseSRWLockExclusive (&Connection->Master->Lock);
    return Result;
}

BOOL
ConpCreateOutput (
    PCON_MASTER Master,
    PCON_OUTPUT* NewOutput
    )
/*++

Routine Description:

    Create a new output buffer object.

Arguments:

    Master - Supplies the master object associated with this output.

    NewOutput - On success, receives the new output object.  The new
                object has a reference count of 1.

Return Value:

    TRUE on success; FALSE with thread error set on error.

Environment:

    Call without Master->Lock held.

--*/
{
    PCON_OUTPUT Output = NULL;
    BOOL Result = FALSE;

    Output = LocalAlloc (LMEM_ZEROINIT, sizeof (*Output));
    if (Output == NULL) {
        return FALSE;
    }

    AcquireSRWLockExclusive (&Master->Lock);
    {
        Output->ReferenceCount = 1;
        Output->Cookie = InterlockedIncrement ((LONG*) &ConpCookie);
        Output->Master = Master;
        Master->ReferenceCount += 1;
    }
    ReleaseSRWLockExclusive (&Master->Lock);

    *NewOutput = Output;
    return TRUE;
}

BOOL CONIO_API
ConCreatePseudoConsole (
    CON_HANDLER Handler,
    PVOID Context,
    PCON_MASTER* NewMaster
    )
{
    PCON_MASTER Master = NULL;
    BOOL Result = FALSE;
    PCON_OUTPUT FirstOutput = NULL;
    PCON_CONNECTION InputConnection = NULL;
    PCON_CONNECTION OutputConnection = NULL;

    if (Handler == NULL || NewMaster == NULL) {
        SetLastError (ERROR_INVALID_PARAMETER);
        goto Out;
    }

    //
    // Create the pseudo-console and its first output object.
    //

    Master = LocalAlloc (LMEM_ZEROINIT, sizeof (*Master));
    if (Master == NULL) {
        goto Out;
    }

    Master->ReferenceCount = 1;
    Master->Handler = Handler;
    Master->Context = Context;
    Master->Cookie = InterlockedIncrement ((LONG*) &ConpCookie);
    InitializeListHead (&Master->Connections);

    if (!ConpCreateOutput (Master, &FirstOutput)) {
        goto Out;
    }

    Master->ActiveOutput = FirstOutput;
    Master->ActiveOutput->ReferenceCount += 1;

    //
    // Now set up the initial connection listeners.
    //

    if (!ConpCreateConnection (Master, NULL, &InputConnection)) {
        goto Out;
    }

    if (!ConpCreateConnection (Master, FirstOutput, &OutputConnection)) {
        goto Out;
    }

    if (!ConpStartListening (InputConnection)) {
        goto Out;
    }

    if (!ConpStartListening (OutputConnection)) {
        goto Out;
    }

    *NewMaster = Master;
    Master = NULL;
    Result = TRUE;

    Out:

    if (InputConnection) {
        ConpDereferenceConnection (InputConnection);
    }

    if (OutputConnection) {
        ConpDereferenceConnection (OutputConnection);
    }

    if (Master) {
        ConDestroyPseudoConsole (Master);
    }

    return Result;
}

VOID CONIO_API
ConDestroyPseudoConsole (
    PCON_MASTER Master
    )
{
    PCON_CONNECTION Connection;
    PLIST_ENTRY Entry;
    PCON_OUTPUT OutputToDereference = NULL;

    AcquireSRWLockExclusive (&Master->Lock);
    Master->ShuttingDown = TRUE;

    //
    // Cancel all pending connection IO and wait for IO operations
    // to terminate.

    for (Entry = Master->Connections.Flink;
         Entry != &Master->Connections;
         Entry = Entry->Flink)
    {
        Connection = CONTAINING_RECORD (Entry,
                                        CON_CONNECTION,
                                        ConnectionsLink);

        ConpTrace (L"Canceling IO for CONN %p", Connection);

        if (Connection->Pipe) {
            (VOID) CancelIoEx (Connection->Pipe, NULL);
        }
    }

    while (!IsListEmpty (&Master->Connections)) {
        (VOID) SleepConditionVariableSRW (
            &Master->ConnectionRemoved,
            &Master->Lock,
            INFINITE,
            0);
    }

    if (Master->ActiveOutput) {
        CONP_ASSERT (Master->ReferenceCount == 2);

        OutputToDereference = Master->ActiveOutput;
        Master->ActiveOutput = NULL;
    } else {
        CONP_ASSERT (Master->ReferenceCount == 1);
    }

    ReleaseSRWLockExclusive (&Master->Lock);

    if (OutputToDereference) {
        ConpDereferenceOutput (OutputToDereference);
    }

    ConpDereferenceMaster (Master);
}

VOID CONIO_API
ConDefaultHandleRequest (
    PCON_REQUEST Request
    )
{
    switch (Request->Type) {
        case ConReadFile:

            //
            // Just return end-of-file.
            //

            Request->Success = TRUE;
            Request->ReadFile.ReplyBuffer = NULL;
            Request->ReadFile.ReplyBufferSize = 0;
            break;

        case ConWriteFile:

            //
            // Silently ignore bytes sent by the client.
            //

            Request->Success = TRUE;
            Request->WriteFile.NumberBytesWritten =
                Request->WriteFile.NumberBytesToWrite;

            break;

        case ConCreateConsoleScreenBuffer:
        case ConSetConsoleActiveScreenBuffer:
        case ConDestroyScreenBuffer:
        case ConProcessAttach:
        case ConProcessDetach:
        case ConDestroy:
            Request->Success = TRUE;
            break;

        default:
            Request->Success = FALSE;
            Request->Error = ERROR_NOT_SUPPORTED;
    }
}

HANDLE CONIO_API
ConMakeSlaveHandle (
    PCON_MASTER Master
    )
{
    HANDLE SlaveHandle = NULL;
    PCON_OUTPUT ActiveOutput;

    AcquireSRWLockExclusive (&Master->Lock);
    {
        ActiveOutput = Master->ActiveOutput;
        if (ActiveOutput == NULL) { // Concurrent shutdown on master
            ReleaseSRWLockExclusive (&Master->Lock);
            SetLastError (ERROR_INVALID_ACCESS);
            return NULL;
        }

        ActiveOutput->ReferenceCount += 1;
    }
    ReleaseSRWLockExclusive (&Master->Lock);

    (VOID) ConpConnectSlaveHandle (
        GetCurrentProcessId (),
        ActiveOutput->Cookie,
        ( CON_HANDLE_READ_ACCESS |
          CON_HANDLE_WRITE_ACCESS ),
        &SlaveHandle);

    ConpDereferenceOutput (ActiveOutput);
    return SlaveHandle;
}

VOID
ConpDereferenceMaster (
    PCON_MASTER Master
    )
/*++

Routine Description:

    Remove a reference to the given console master.

Arguments:

    Master - Supplies the master to dereference.

Return Value:

    None.

Environment:

    Master->Lock not held.

--*/
{
    ULONG SavedError = GetLastError ();

    AcquireSRWLockExclusive (&Master->Lock);

    CONP_ASSERT (Master->ReferenceCount > 0);

    Master->ReferenceCount -= 1;

    if (Master->ReferenceCount == 0) {
        ReleaseSRWLockExclusive (&Master->Lock);
        LocalFree (Master);
    } else {
        ReleaseSRWLockExclusive (&Master->Lock);
    }

    SetLastError (SavedError);
}

VOID
ConpDereferenceConnection (
    PCON_CONNECTION Connection
    )
/*++

Routine Description:

    Release a reference to a connection object.

Arguments:

    Connection - Supplies the connection to destroy.  Connection must
                 not be in use

Return Value:

    None.

Environment:

    Call without Connection->Lock or Connection->Master->Lock or
    Connection->Output->Lock held.

--*/
{
    ULONG SavedError = GetLastError ();
    PCON_OUTPUT OutputToDereference = NULL;
    PCON_MASTER MasterToDereference = NULL;
    PCON_MASTER Master = Connection->Master;

    //
    // See whether we have the last reference to this connection.  If
    // so, release the lock and run user cleanup code (which must be
    // called without locks held) before continuing with the actual
    // object destruction (which must happen under lock).
    //

    if (Master) {
        AcquireSRWLockExclusive (&Master->Lock);
    } else {
        CONP_ASSERT (Connection->ReferenceCount == 1);
    }

    CONP_ASSERT (Connection->ReferenceCount > 0);

    Connection->ReferenceCount -= 1;

    if (Connection->ReferenceCount == 0) {
        if (Connection->Pipe) {
            CloseHandle (Connection->Pipe);
        }

        if (Connection->TpIo) {
            CloseThreadpoolIo (Connection->TpIo);
        }

        if (Connection->Master) {
            RemoveEntryList (&Connection->ConnectionsLink);
            WakeAllConditionVariable (&Master->ConnectionRemoved);
            MasterToDereference = Connection->Master;
        }

        if (Connection->Output) {
            OutputToDereference = Connection->Output;
        }

        LocalFree (Connection->Buffer);
        LocalFree (Connection);
    }

    if (Master) {
        ReleaseSRWLockExclusive (&Master->Lock);
    }

    if (OutputToDereference) {
        ConpDereferenceOutput (OutputToDereference);
    }

    if (MasterToDereference) {
        ConpDereferenceMaster (MasterToDereference);
    }

    SetLastError (SavedError);
}

VOID
ConpDereferenceOutput (
    PCON_OUTPUT Output
    )
/*++

Routine Description:

    Remove a reference from an output object.

Arguments:

    Master - Supplies the master for Output.

    Output - Supplies the output to dereference.

Return Value:

    None.

Environment:

    Call without Output->Lock or Output->Master->Lock held.

--*/
{
    ULONG SavedError = GetLastError ();
    PCON_MASTER Master = Output->Master;
    PCON_MASTER MasterToDereference = NULL;

    if (Master) {
        AcquireSRWLockExclusive (&Master->Lock);
    } else {
        CONP_ASSERT (Output->ReferenceCount == 1);
    }

    CONP_ASSERT (Output->ReferenceCount > 0);

    Output->ReferenceCount -= 1;

    if (Output->ReferenceCount == 0) {
        if (Output->Master) {
            MasterToDereference = Output->Master;
        }

        LocalFree (Output);
    }

    if (Master) {
        ReleaseSRWLockExclusive (&Master->Lock);
    }

    if (MasterToDereference) {
        ConpDereferenceMaster (MasterToDereference);
    }

    SetLastError (SavedError);
}
