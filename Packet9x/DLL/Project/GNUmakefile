# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

# OPTFLAGS = -g -DDBG
OPTFLAGS = -O
# I am suspicious of -O2 since it hosed wpcap.dll. To be safe, use -O only

CFLAGS = -I ../../../common -shared -mno-cygwin ${OPTFLAGS}
LDFLAGS = -Wl,--out-implib,Packet.a
OBJS = ../Packet32.o
LIBS = -lwsock32

Packet.dll: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o Packet.dll ../Packet.def ${OBJS} ${LIBS}

.c.o:
	${CC} ${CFLAGS} -o $*.o -c $<

clean:
	rm -f ${OBJS} Packet.a Packet.dll

install: Packet.dll
	cp Packet.dll c:/windows/system
