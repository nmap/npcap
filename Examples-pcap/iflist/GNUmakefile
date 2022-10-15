# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = iflist.o
LIBS = -L ${PCAP_PATH} -lwpcap -lws2_32

all: ${OBJS}
	${CC} ${CFLAGS} -o iflist.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} iflist.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
