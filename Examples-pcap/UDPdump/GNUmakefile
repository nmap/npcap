# Makefile for cygwin gcc
# Loris Degioanni

CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = udpdump.o
LIBS = -L ${PCAP_PATH} -lwpcap -lws2_32

all: ${OBJS}
	${CC} ${CFLAGS} -o udpdump.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} udpdump.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
