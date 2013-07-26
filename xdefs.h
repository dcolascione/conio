//
// This file abstracts away platform-specific differences in necessary
// include files and defines X-variants of NT data structures.
//

#pragma once

#include <windows.h>
#ifdef __CYGWIN__
#include <ddk/ntddk.h>
#include <ddk/ntifs.h>
#else
#include <winternl.h>
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _XPROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} XPROCESS_BASIC_INFORMATION;

typedef struct _XPEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} XPEB_LDR_DATA, *PXPEB_LDR_DATA;

typedef struct _XRTL_USER_PROCESS_PARAMETERS \
XRTL_USER_PROCESS_PARAMETERS, *PXRTL_USER_PROCESS_PARAMETERS;

//
// From undocumented.ntinternals.net.
//

struct _XRTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    PVOID                   ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StdInputHandle;
    HANDLE                  StdOutputHandle;
    HANDLE                  StdErrorHandle;
    UNICODE_STRING          CurrentDirectoryPath;
    HANDLE                  CurrentDirectoryHandle;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingPositionLeft;
    ULONG                   StartingPositionTop;
    ULONG                   Width;
    ULONG                   Height;
    ULONG                   CharWidth;
    ULONG                   CharHeight;
    ULONG                   ConsoleTextAttributes;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopName;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
#if 0
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
#endif
};

//
// From undocumented.ntinternals.net.
//

typedef struct _XPEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PXPEB_LDR_DATA          LoaderData;
    PXRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID /* PPEBLOCKROUTINE */  FastPebLockRoutine;
    PVOID /* PPEBLOCKROUTINE */  FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID*                  KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID /*PPEB_FREE_BLOCK */ FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID*                  ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID*                  *ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} XPEB, *PXPEB;

typedef struct _XLDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} XLDR_DATA_TABLE_ENTRY, *PXLDR_DATA_TABLE_ENTRY;

#ifndef DIRECTORY_ALL_ACCESS

#define DIRECTORY_QUERY                   0x0001
#define DIRECTORY_TRAVERSE                0x0002
#define DIRECTORY_CREATE_OBJECT           0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY     0x0008
#define DIRECTORY_ALL_ACCESS              (STANDARD_RIGHTS_REQUIRED | 0xF)

__declspec(dllimport)
NTSTATUS
WINAPI
NtCreateDirectoryObject(
  /*OUT*/ PHANDLE  DirectoryHandle,
  /*IN*/ ACCESS_MASK  DesiredAccess,
  /*IN*/ POBJECT_ATTRIBUTES  ObjectAttributes);

#endif /* DIRECTORY_ALL_ACCESS */

#ifdef __CYGWIN__
typedef PVOID LPPROC_THREAD_ATTRIBUTE_LIST;
#endif

__declspec(dllimport)
BOOL WINAPI InitializeProcThreadAttributeList (
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwAttributeCount,
    DWORD dwFlags,
    PSIZE_T lpSize
    );

__declspec(dllimport)
VOID WINAPI DeleteProcThreadAttributeList (
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
);

__declspec(dllimport)
BOOL WINAPI UpdateProcThreadAttribute (
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags,
    DWORD_PTR Attribute,
    PVOID lpValue,
    SIZE_T cbSize,
    PVOID lpPreviousValue,
    PSIZE_T lpReturnSize
    );

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002
#endif

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT	0x00080000
#endif

typedef struct _XSTARTUPINFOEX {
    STARTUPINFOW StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} XSTARTUPINFOEX, *PXSTARTUPINFOEX;
