#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <stddef.h>
#include "conio.h"

#ifdef NDEBUG
# define CONP_VERIFY(x) ((x) ? TRUE : FALSE)
# define CONP_ASSERT(x)
#else
# define CONP_VERIFY(x) CONP_ASSERT (x)
//# define CONP_ASSERT(x) assert (x)
#define CONP_ASSERT(x) { if (!(x)) { *((volatile char*)0) = 0; } }
#define abort() CONP_ASSERT (0)
#endif

// XXX: handle cross-session case

//                                           PID      COOKIE
#define CON_PIPE_FORMAT L"\\\\.\\pipe\\conio-%000008X-%000008X"

//                                      CHILDPID
#define CON_STARTINFO_FORMAT L"conio-si-%000008X"

//                                       PID
#define CON_ATTACHINFO_FORMAT L"conio-ai-%000008X"

#define CON_SHARED_DATA_VERSION 1

typedef struct _CON_ATTACH_INFO {
    ULONG ServerPid;
    ULONG Cookie;
} CON_ATTACH_INFO, *PCON_ATTACH_INFO;

//
// Each process attached to a pseudo-console creates one of these
// sections, named according to CON_ATTACHINFO_FORMAT above.
//

typedef struct _CON_ATTACH_SHARED {
    ULONG Version;
    volatile ULONG Sequence; // Low bit is the current info
    CON_ATTACH_INFO Info[2];
} CON_ATTACH_SHARED, *PCON_ATTACH_SHARED;

typedef struct _CON_STARTUP_HANDLE {
    ULONG HandleValue;
    LONG  DummyInheritedHandle;
    ULONG ServerPid;
    ULONG Cookie;
    ULONG Flags;
} CON_STARTUP_HANDLE, *PCON_STARTUP_HANDLE;

typedef struct _CON_STARTUP_INFO {
    ULONG Version;
    LONG SectionHandle;
    HANDLE AttachConsoleHandle;
    ULONG NumberHandles;
    CON_STARTUP_HANDLE Handle[0];
} CON_STARTUP_INFO, *PCON_STARTUP_INFO;

typedef enum _CON_MESSAGE_TYPE {
    ConMsgInitializeConnection = 400,
    ConReplyInitializeConnection,
    ConMsgReadFile,
    ConReplyReadFile,
    ConMsgWriteFile,
    ConReplyWriteFile,
    ConReplyError,
    ConReplySuccess // No payload
} CON_MESSAGE_TYPE, *PCON_MESSAGE_TYPE;

// Handle flags.  Some handles have meaning only to the client; some
// only to the server.  Clients initialize a connection to the server
// by sending a ConMsgInitializeConnection message with some of these
// flags set.

// See HANDLE_FLAG_INHERIT: value is the same.
#define CON_HANDLE_INHERIT                0x1

// See HANDLE_FLAG_PROTECT_FROM_CLOSE: value is the same.
#define CON_HANDLE_PROTECT_FROM_CLOSE     0x2

// Consider the calling process attached to the console via this
// handle.
#define CON_HANDLE_CONNECT_ATTACHED       0x10

// On connect, don't associate this handle with an output buffer.
#define CON_HANDLE_CONNECT_NO_OUTPUT      0x20

// On connect, associate this handle with the console's active output
// buffer.
#define CON_HANDLE_CONNECT_ACTIVE_OUTPUT  0x40

// This handle has read access
#define CON_HANDLE_READ_ACCESS            0x1000

// This handle has write access
#define CON_HANDLE_WRITE_ACCESS           0x2000

typedef struct _CON_MESSAGE {
    ULONG Size;
    ULONG Type;

    union {
        struct {
            ULONG Flags;
        } InitializeConnection;

        struct {
            ULONG NewCookie;
        } InitializeConnectionReply;

        struct {
            ULONG ErrorCode;
        } ErrorReply;

        struct {
            ULONG RequestedReadSize;
        } ReadFile;

        struct {
            BYTE Payload[0];
        } ReadFileReply;

        struct {
            BYTE Payload[0];
        } WriteFile;

        struct {
            ULONG NumberBytesWritten;
        } WriteFileReply;
    };
    
} CON_MESSAGE, *PCON_MESSAGE;

#define CON_MESSAGE_SIZE(Field) \
    RTL_SIZEOF_THROUGH_FIELD (CON_MESSAGE, Field)

//
// Create a slave handle for the given object.
//

BOOL
ConpConnectSlaveHandle (
    /* In */ ULONG ServerPid,
    /* In */ ULONG Cookie,
    /* In */ ULONG Flags,
    /* Out */ HANDLE* NewHandle
    );

VOID ConpTrace (PCWSTR Format, ...);
BOOL ConpHookApis (VOID);

#define MemoryBarrier() __sync_synchronize ()
