# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = readfile_ex.o
LIBS = -L ${PCAP_PATH} -lwpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o readfile_ex.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} readfile_ex.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
