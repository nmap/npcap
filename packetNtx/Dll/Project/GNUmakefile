# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

# OPTFLAGS = -g -DDBG 
OPTFLAGS = -O -D_WINNT4
# I am suspicious of -O2 since it hosed wpcap.dll. To be safe, use -O only

CFLAGS = -I ../../../common -shared -mno-cygwin ${OPTFLAGS} -I..
LDFLAGS = -Wl,--out-implib,libpacket.a
OBJS = ../Packet32.o ../AdInfo.o
LIBS = -lws2_32 -lversion

Packet.dll: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o Packet.dll ../Packet.def ${OBJS} ${LIBS}

.c.o:
	${CC} ${CFLAGS} -o $*.o -c $<

clean:
	${RM} ${OBJS} libpacket.a Packet.dll

install: Packet.dll
	cp Packet.dll c:/winnt/system32
