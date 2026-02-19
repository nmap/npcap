# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = savedump.o
LIBS = -L ${PCAP_PATH} -lwpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o savedump.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} savedump.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
