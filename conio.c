#include <stdio.h>
#include <windows.h>
#include <winable.h>
#include <wchar.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include "conio.h"

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

  UNREFERENCED_PARAMETER (argc);
  UNREFERENCED_PARAMETER (argv);

  LoadLibraryA ("conio-32.dll");

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

    if (!WriteFile (slave, buffer, strlen (buffer) + 1, &bytes_written, NULL)) {
      fprintf (stderr, "WriteFile FAILED: 0x%lx\n", GetLastError ());
      return 1;
    }

    fprintf (stderr, "WriteFile success: %lun", bytes_written);
  }
#endif

  ConDestroyPseudoConsole (master);

  execvp (argv[1], argv + 1);
  fprintf (stderr, "execv: %s\n", strerror (errno));
  return 127;
}
