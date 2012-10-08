#include <stdio.h>
#include <windows.h>
#include <winable.h>
#include <wchar.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include "conio.h"
#include "xdefs.h"

VOID WINAPI
pty_ConHandleRequest (
    PCON_REQUEST Request
    )
{
  static char msg[22] = "Hello, world!";

  fprintf (stderr, "CONIO: Request type: %u\n", Request->Type);

  switch (Request->Type)
    {

    case ConReadFile:
      Request->Success = TRUE;
      Request->ReadFile.ReplyBuffer = msg;
      Request->ReadFile.ReplyBufferSize = sizeof (msg);

      if (Request->ReadFile.ReplyBufferSize >
          Request->ReadFile.RequestedReadSize)
        {
          Request->ReadFile.ReplyBufferSize =
            Request->ReadFile.RequestedReadSize;
        }

      break;

    case ConWriteFile:
      Request->Success = TRUE;
      Request->WriteFile.NumberBytesWritten =
        Request->WriteFile.NumberBytesToWrite;

      fprintf (stderr, "CONIO: WriteFile: %lu [%s]\n",
               Request->WriteFile.NumberBytesToWrite,
               (char*) Request->WriteFile.Buffer);

      break;

    default:
      return ConDefaultHandleRequest (Request);
  }
}

int
main (int argc, char** argv)
{
  PCON_MASTER master;
  HANDLE slave;
  HANDLE slave_inherit;

  UNREFERENCED_PARAMETER (argc);
  UNREFERENCED_PARAMETER (argv);

  if (!argv[1])
    {
      fprintf (stderr, "no program to run\n");
      fflush (stderr);
      return 1;
    }

  if (!ConCreatePseudoConsole (pty_ConHandleRequest, NULL, &master))
    {
      fprintf (stderr, "ConCreatePseudoConsole: 0x%lx\n",
               GetLastError ());
      return 1;
    }

  slave = ConMakeSlaveHandle (master);
  if (!slave)
    {
      fprintf (stderr, "ConMakeSlaveHandle: 0x%lx\n", GetLastError ());
      return 1;
    }

#if 1

#endif

#if 0
  if (!DuplicateHandle (GetCurrentProcess (),
                        slave,
                        GetCurrentProcess (),
                        &slave_inherit,
                        0,
                        TRUE /* InheritHandle */,
                        DUPLICATE_SAME_ACCESS))
    {
      fprintf (stderr, "DuplicateHandle 0x%lx\n", GetLastError ());
      return 1;
    }
#endif

#if 0
  {
    char buffer[1024];
    ULONG bytes_read;

    if (!ReadFile (slave, buffer, sizeof (buffer), &bytes_read, NULL)) {
      fprintf (stderr, "ReadFile FAILED: 0x%lx\n", GetLastError ());
      return 1;
    }

    fprintf (stderr, "ReadFile success: %lu %s\n",
             bytes_read, buffer);
  }

  {
    char buffer[1024] = "Hello, server!";
    ULONG bytes_written;

    if (!WriteFile (slave, buffer, strlen (buffer) + 1,
                    &bytes_written, NULL))
    {
      fprintf (stderr, "WriteFile FAILED: 0x%lx\n", GetLastError ());
      return 1;
    }

    fprintf (stderr, "WriteFile success: %lun", bytes_written);
  }
#endif

#if 1
  {
    PROCESS_INFORMATION pi;
    PWSTR cmdline = wcsdup (GetCommandLine ());
    ULONG exitcode;
    XSTARTUPINFOEX six;
    LPPROC_THREAD_ATTRIBUTE_LIST atl = NULL;
    SIZE_T atl_size = 0;

    ZeroMemory (&six, sizeof (six));
    six.StartupInfo.cb = sizeof (six);

    InitializeProcThreadAttributeList (NULL, 1, 0, &atl_size);
    atl = malloc (atl_size);
    if (!InitializeProcThreadAttributeList (atl, 1, 0, &atl_size)) {
        fprintf (stderr, "InitializeProcThreadAttributeList 0x%lx\n",
                 GetLastError ());
        return 1;
    }

    if (!ConSetChildAttach (atl, slave)) {
        fprintf (stderr, "ConSetChildAttach 0x%lx\n", GetLastError ());
        return 1;
    }

    six.lpAttributeList = atl;

    while (*cmdline && !isspace (*cmdline)) ++cmdline;
    while (*cmdline && isspace (*cmdline)) ++cmdline;

    if (!CreateProcess (NULL,
                        cmdline,
                        NULL, NULL,
                        TRUE,
                        EXTENDED_STARTUPINFO_PRESENT,
                        NULL /* Environment */,
                        NULL /* CurrentDirectory */,
                        &six.StartupInfo,
                        &pi))
      {
        fprintf (stderr, "CreateProcess: 0x%lx\n", GetLastError ());
        return 1;
      }

    Sleep (1000);

    WaitForSingleObject (pi.hProcess, INFINITE);
    GetExitCodeProcess (pi.hProcess, &exitcode);

    fprintf (stderr, "Child exit: 0x%lx\n", exitcode);
    CloseHandle (pi.hProcess);
    CloseHandle (pi.hThread);
  }
#endif


}
