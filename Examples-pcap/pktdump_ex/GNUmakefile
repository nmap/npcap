CYGWIN_FLAGS = -mno-cygwin
PCAP_PATH = ../../Lib$(LIBARCH)
CFLAGS = -g -O $(CYGWIN_FLAGS) -I ../../Include

OBJS = pktdump_ex.o
LIBS = -L ${PCAP_PATH} -lwpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o pktdump_ex.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} pktdump_ex.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
