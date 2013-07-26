CFLAGS=-Wall -Wextra -g -Werror
MINGW32CC=i686-w64-mingw32-gcc

MINGW64CC=x86_64-w64-mingw32-gcc
MINGW64AS=x86_64-w64-mingw32-as

override CPPFLAGS+=-DUNICODE=1 -D_UNICODE=1
override CPPFLAGS+=-D_WIN32_WINNT=0x602

override CFLAGS+=-std=gnu99
override CFLAGS+=-Wno-int-to-pointer-cast
override CFLAGS+=-Wno-pointer-to-int-cast
override CFLAGS+=-Wno-unused
override CFLAGS+=-mthreads
override CFLAGS+=-fno-stack-protector

all: contest conio-32.dll conio-64.dll

# Compile, assemble, and link as separate stages to work around
# "unknown register" tooling bug.
%.s64: %.c conio.h coniop.h
	$(MINGW64CC) $(CPPFLAGS) $(CFLAGS) -S -o $@ $<

%.o64: %.s64
	$(MINGW64AS) -o $@ $<

%.o32: %.c conio.h coniop.h
	$(MINGW32CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

conio-client-generated.c: conio-client.c
	$(MINGW32CC) -P -E -DCOLLECTING_HOOKS \
		  $(CPPFLAGS) $(CFLAGS) $< \
		| sed -nre 's/ConpGenHook([^;]+);/REGHOOK(\1)/p' \
		> $@

conio-client.o32 conio-client.o64: conio-client-generated.c
hook.o32 hook.o64: forceimport.c

CONIO_SOURCES=conio-dll.c conio-client.c conio-server.c hook.c

conio-32.dll: override CPPFLAGS+=-DCONIO_BUILDING_DLL
conio-64.dll: override CPPFLAGS+=-DCONIO_BUILDING_DLL

CONIO_DLL_LDFLAGS=-nostdlib -lkernel32 -lntdll
CONIO_DLL_LDFLAGS+=-lmingwex

conio-32.dll: $(CONIO_SOURCES:%.c=%.o32)
	$(MINGW32CC) $(CFLAGS) -shared        \
		-o $@ $^ $(CONIO_DLL_LDFLAGS) \
		-Wl,-e,_DllMain@12

conio-64.dll: $(CONIO_SOURCES:%.c=%.o64)
	$(MINGW64CC) $(CFLAGS) -shared        \
		-o $@ $^ $(CONIO_DLL_LDFLAGS) \
		-Wl,-e,DllMain

CONTEST_SOURCES=contest.c

contest: $(CONTEST_SOURCES:%.c=%.o32) conio-32.dll
	$(MINGW32CC) $(CFLAGS) -o $@ $^

clean:
	rm -f ./*.exe ./*.dll ./*.o ./*.o64 ./*.o32 ./*.i \
		./*-generated.c ./*.stackdump
