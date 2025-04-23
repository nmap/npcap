# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = pcap_filter.o
LIBS = -L ${PCAP_PATH} -lwpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o pf.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} pf.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
