#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <stddef.h>
#include "conio.h"

// #define CONP_ASSERT(x) assert (x)

#define CONP_ASSERT(x) { if ((x) == FALSE) { *((volatile char*)0) = 0; } }
#define abort() CONP_ASSERT (0)

//                                           PID      COOKIE
#define CON_PIPE_FORMAT L"\\\\.\\pipe\\conio-%000008X-%000008X"

//                                              CHILD_PID
#define CON_STARTINFO_FORMAT L"Global\\conio-si-%0000008X"

typedef struct _CON_STARTUP_HANDLE {
    ULONG InheritedHandle;
    ULONG PipeHandle;
    ULONG ServerPid;
    ULONG Cookie;
    ULONG HandleFlags;
} CON_STARTUP_HANDLE, *PCON_STARTUP_HANDLE;

typedef struct _CON_STARTUP_INFO {
    ULONG InheritedSectionHandle;
    CON_STARTUP_HANDLE InheritedHandles[0];
} CON_STARTUP_INFO, *PCON_STARTUP_INFO;

typedef enum _CON_MESSAGE_TYPE {
    ConMsgReadFile,
    ConMsgWriteFile,
    ConReplyError,
    ConReplyReadFile,
    ConReplyWriteFile
} CON_MESSAGE_TYPE, *PCON_MESSAGE_TYPE;

typedef struct _CON_MESSAGE {
    ULONG Size;
    ULONG Type;

    union {
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
    /* _In_ */ ULONG ServerPid,
    /* _In_ */ ULONG Cookie,
    /* _Out_ */ HANDLE* NewHandle
    );

VOID ConpTrace (PCWSTR Format, ...);
BOOL ConpHookApis (VOID);

