# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.com>

# Set according to your system type
SYSTYPE = "NT"
# SYSTYPE = "9x"

# OPTFLAGS = -g
OPTFLAGS = -O
# DO _NOT_ USE -O2! Causes fault upon startup.

#
# Flex and bison allow you to specify the prefixes of the global symbols
# used by the generated parser.  This allows programs to use lex/yacc
# and link against libpcap.  If you don't have flex or bison, get them.
#
LFLAGS = -Ppcap_
YFLAGS = -y -p pcap_

FLEX = flex
BISON = bison

PACKET_DIR = packetNtx
INSTALL_DIR = ${SYSTEMROOT}\system32

CFLAGS = -I ../libpcap -I ../libpcap/bpf -I ../libpcap/lbl \
	-I ../libpcap/Win32/Include -I../libpcap/Win32/Include/ipv6kit \
	-I ../../Common -I ../Win32-Extensions \
	-I ../../../AirPcap_DevPack/include \
	-DLIBPCAP_EXPORTS -DYY_NEVER_INTERACTIVE -Dyylval=pcap_lval \
	-DHAVE_STRERROR -DNEED_ADDRINFO_H -DINET6 -DWIN32 \
	-DSIZEOF_CHAR=1 -DSIZEOF_SHORT=2 -DSIZEOF_INT=4 -DSIZEOF_LONG_LONG=8 -DWPCAP -D'_U_=' \
	-DHAVE_SNPRINTF -DHAVE_VSNPRINTF \
	-DSIZEOF_LONG_LONG=8 \
	-DHAVE_REMOTE -DHAVE_AIRPCAP_API \
	-DHAVE_TC_API \
	-DHAVE_ADDRINFO \
	-DHAVE_LIMITS_H \
	-DYY_NO_UNISTD_H \
	-mno-cygwin -shared ${OPTFLAGS}
LDFLAGS = -Wl,--out-implib,../lib/libwpcap.a
LIBS = -L ../../${PACKET_DIR}/Dll/Project -lpacket -lws2_32
OBJS = ../libpcap/bpf/net/bpf_filter.o \
	../libpcap/bpf_dump.o \
	../libpcap/bpf_image.o \
	../libpcap/etherent.o \
	../libpcap/Win32/Src/ffs.o \
	../libpcap/gencode.o\
	../libpcap/Win32/Src/getnetbynm.o \
	../libpcap/Win32/Src/getnetent.o \
	../libpcap/Win32/Src/getservent.o \
	../libpcap/grammar.o \
	../libpcap/Win32/Src/getaddrinfo.o \
	../libpcap/inet.o \
	../libpcap/Win32/Src/inet_aton.o \
	../libpcap/Win32/Src/inet_net.o \
	../libpcap/Win32/Src/inet_pton.o \
	../libpcap/nametoaddr.o \
	../libpcap/optimize.o \
	../libpcap/pcap-win32.o \
	../libpcap/fad-win32.o \
	../libpcap/pcap.o \
	../libpcap/savefile.o \
	../libpcap/scanner.o \
	../libpcap/pcap-new.o \
	../libpcap/pcap-remote.o \
	../libpcap/sockutils.o \
	../libpcap/Win32/Src/gai_strerror.o \
	../libpcap/pcap-tc.o \
	../Win32-Extensions/Win32-Extensions.o

main: ${OBJS}
	@${RM} -rf ../lib/
	mkdir ../lib/
	${CC} ${CFLAGS} ${LDFLAGS} -o wpcap.dll WPCAP.DEF ${OBJS} ${LIBS}

install:
	cp wpcap.dll ${INSTALL_DIR}

clean:
	${RM} ${OBJS} ../libpcap/scanner.c ../libpcap/grammar.c wpcap.a wpcap.dll

# Keeps intermediate .c files from being deleted
.SECONDARY: ../libpcap/scanner.c ../libpcap/grammar.c

.y.c:
	@${RM} ../libpcap/grammar.c ../libpcap/tokdefs.h
	${BISON} ${YFLAGS} -d $<
	mv y.tab.c ../libpcap/grammar.c
	mv y.tab.h ../libpcap/tokdefs.h
.l.c:
	@${RM} $@
	${FLEX} ${LFLAGS} -t $< >$*.c
.c.o:
	${CC} ${CFLAGS} -o $*.o -c $<
