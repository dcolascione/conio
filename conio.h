#pragma once
#include <winbase.h>
#include <wchar.h>

//
// This structure defines the master side of a pseudoconsole; the
// client has the slave.  The function pointers contained in this
// structure roughly match the documentation listed in the MSDN
// console API reference, except that each takes an additional
// prefixed parameter giving a pointer to the CON_PSEUDO_MASTER struct
// for the calling client.
//
// Users should use CONTAINING_RECORD to associate client-specific
// data with each client-specific CON_PSEUDO_MASTER structure.
//

typedef struct _CON_MASTER CON_MASTER, *PCON_MASTER;

#ifdef CONIO_BUILDING_DLL
# define CONIO_API WINAPI __declspec(dllexport)
#else
# define CONIO_API WINAPI __declspec(dllimport)
#endif

typedef enum _CON_REQUEST_TYPE {
    //
    // ConReadFile:
    //
    // This request is sent when the client calls ReadFile on the
    // console handle.  On input, ReadFile.RequestedReadSize contains
    // the number of bytes the client asked for.  The request handler
    // sets ReadFile.ReplyBuffer to be a pointer to the buffer to send
    // to the client and sets ReadFile.ReplyBufferSize to be the
    // number of bytes to send.  After the buffer is sent, the handler
    // receives the ConFreeReplyBuffer described below.
    //
    // Do not set ReadFile.ReplyBufferSize to be greater than
    // ReadFile.RequestedReadSize.
    //
    // The default handler returns EOF.
    //

    ConReadFile,

    //
    // ConFreeReplyBuffer:
    //
    // This request is sent after the library is done using a buffer
    // holding reply information.
    //
    // The default handler does nothing.
    //

    ConFreeReplyBuffer,

    //
    // ConWriteFile:
    //
    // This request is sent when the client calls WriteFile on the
    // console handle.
    //
    // The default handler eats the output and returns success.
    //

    ConWriteFile,

    //
    // ConCreateConsoleScreenBuffer:
    //
    // This request is sent when the client calls
    // CreateConsoleScreenBuffer.  If the handler completes the
    // request successfully, a new console handle is given to the
    // client.  Subsequent operations on this handle use the
    // CreateConsoleScreenBuffer.NewOutputContext value set by the
    // client.  This value defaults to zero.
    //
    // The default handler returns success and does not modify
    // CreateConsoleScreenBuffer.NewOutputContext.
    //

    ConCreateConsoleScreenBuffer,

    //
    // ConSetConsoleActiveScreenBuffer:
    //
    // This request is sent when the client calls
    // SetConsoleActiveScreenBuffer on an output handle previously
    // created by using CreateConsoleScreenBuffer.  The OutputContext
    // is the output context associated with the current output
    // buffer, while SetScreenBuffer.SwitchToOutputContext refers to
    // the context of the output buffer that the client is about to
    // make current.
    //
    // The default handler returns success.
    //

    ConSetConsoleActiveScreenBuffer,

    //
    // ConDestroyScreenBuffer:
    //
    // This request is sent when the last reference to an output
    // screen buffer is closed.  This request cannot fail; Success and
    // Error are ignored.
    //
    // N.B. The console master object maintains a reference to its
    // active screen buffer; before the master itself is destroyed,
    // only inactive output screen buffers receive this request.
    //
    // When the master is destroyed, it releases its reference to the
    // active screen buffer, causing this request to be issued just
    // before ConDestroyMaster.
    //
    // The default handler does nothing.
    //

    ConDestroyScreenBuffer,

    //
    // ConProcessAttach:
    //
    // This request is sent when a new process attaches
    // to the console.
    //
    // Note that a process can use pseudo-console handles while not
    // being attached to the console, and it may be attached to the
    // console while not having any explicit pseudo-console handles
    // open.  The concepts are orthogonal.
    //
    // The default handler does nothing.
    //

    ConProcessAttach,

    //
    // ConProcessDetatch:
    //
    // This request is sent when a process detached from the console.
    //
    // The default handler does nothing.
    //

    ConProcessDetach,

    //
    // ConDestroy:
    //
    // This request is sent immediately before the console master
    // object is itself destroyed.  This request cannot fail; Success
    // and Error are ignored.  This request is the last request sent
    // to a master object before it is destroyed.
    //
    // The default handler does nothing.
    //

    ConDestroy

} CON_REQUEST_TYPE, *PCON_REQUEST_TYPE;

typedef struct _CON_REQUEST {

    //
    // Supplies the type of request.
    //

    CON_REQUEST_TYPE Type;

    //
    // Supplies the master object for this pseudoconsole.
    //

    PCON_MASTER Master;

    //
    // Receives an indication of whether the handler successfully
    // processed the request.
    //

    BOOL Success;

    //
    // Receives the error code to propagate to the client.  On success
    // (i.e., Success is not FALSE), this field is ignored.
    //

    ULONG Error;

    //
    // Supplies the context the caller associated with this console
    // master.
    //

    PVOID Context;

    //
    // Supplies the context the caller associated with this particular
    // console output buffer.  Some requests are made on handles that
    // are not associated with an output buffer; for these requests,
    // OutputContext is zero.
    //

    PVOID OutputContext;

    //
    // Request-specific information.
    //

    union {
        struct {
            /* In */     ULONG RequestedReadSize;
            /* Out */    PVOID ReplyBuffer;
            /* Out */    ULONG ReplyBufferSize;
        } ReadFile;

        struct {
            /* In */     PVOID Buffer;
            /* In */     ULONG NumberBytesToWrite;
            /* Out */    ULONG NumberBytesWritten;
        } WriteFile;

        struct {
            /* In */  PVOID SwitchToOutputContext;
        } SetScreenBuffer;

        struct {
            /* Out */ PVOID NewOutputContext;
        } CreateConsoleScreenBuffer;

        struct {
            /* In */ PVOID ReplyBuffer;
            /* In */ ULONG ReplyBufferSize;
        } FreeReplyBuffer;

    };
} CON_REQUEST, *PCON_REQUEST;

typedef VOID (WINAPI *CON_HANDLER)(
    /* Inout */ PCON_REQUEST Request
    );

/*++

Routine Description:

    ConCreatePseudoConsole creates a new pseudo-console object.
    Pseudo-console objects allow programs to provide "slave" handles
    that to all outward appearances are conventional console handles,
    but that are actually under the full control of the program
    calling ConCreatePseudoConsole.  Operations on slave console
    handles are turned into calls to the Handler callback supplied to
    ConCreatePseudoConsole.

    Calls to Handler are made from a thread pool.  Multiple calls to
    Handler may be active at any one time.  The pseudoconsole library
    will ensure its data structures are thread safe, but users need to
    protect their own data structures.

    Handler should call ConDefaultHandleRequest if it does not know
    how to handle a particular request.  Note that because
    ConDefaultHandleRequest may call back into Handler, Handler must
    be reentrant.

    ConCreatePseudoConsole may call Handler before returning to the
    caller.

Arguments:

    Handler - Supplies a function that implements console operations.

    MasterContext - Supplies the initial master context for Handler.

    NewMaster - Receives a pointer to the master object for this
                pseudoconsole.

Return Value:

    TRUE on success; FALSE with thread error set on failure.

Environment:

    Arbitrary.

--*/
BOOL CONIO_API
ConCreatePseudoConsole (
    /* In */ CON_HANDLER Handler,
    /* In */ PVOID MasterContext,
    /* Out */ PCON_MASTER* NewMaster
    );

/*++

Routine Description:

    ConGenerateConsoleCtrlEvent sends a console control event to all
    processes currently attached to the pseudo-console.

    This routine returns immediately and does not wait for processes
    attached to the pseudo-console to process the event.

Arguments:

    Master - Supplies the pseudo-console to signal.

    CtrlType - Supplies the type of control message to send.  Unlike
               the Win32 API GenerateConsoleCtrlEvent, this routine
               accepts any CtrlType.

Return Value:

    None.

Environment:

    Arbitrary.

--*/
VOID CONIO_API
ConGenerateConsoleCtrlEvent (
    /* In */ PCON_MASTER Master,
    /* In */ ULONG CtrlType
    );

/*++

Routine Description:

    ConMakeSlaveInputHandle creates a slave handle for the given
    pseudo-console.  This handle may be used with the normal console
    APIs and passed to child processes.  The handle is connected to
    the console's currently-active output buffer.

Arguments:

    Master - Supplies the master object.

Return Value:

    Slave handle on success; on error, NULL and thread error set.

Environment:

    Arbitrary.

--*/
HANDLE CONIO_API
ConMakeSlaveHandle (
    PCON_MASTER Master
    );

/*++

Routine Description:

    ConReleasePseudoConsole destroys a master object.  Any pending
    callbacks are allowed to complete before the object is actually
    destroyed.  ConDestroyPseudoConsole begins the shutdown process
    and may return before it completes.

Arguments:

    Master - Supplies the master object to destroy.

Return Value:

    None.

Environment:

    Arbitrary.

--*/
VOID CONIO_API
ConDestroyPseudoConsole (
    PCON_MASTER Master
    );

/*++

Routine Description:

    ConDefaultHandleRequest handles the given request in the default
    way.  Handler functions should call ConDefaultHandleRequest when
    they do not handle a request themselves.

Arguments:

    Request - Supplies request information.

Return Value:

    None.

Environment:

    Call only from inside a Handler function supplied to
    ConCreatePseudoConsole.

--*/
VOID CONIO_API
ConDefaultHandleRequest (
    PCON_REQUEST Request
    );
