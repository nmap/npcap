/** @defgroup wpcapfunc Exported functions
 *  @ingroup wpcap
 *  Functions exported by wpcap.dll
 *  @{
 */


/** \name Unix-compatible Functions

	These functions are part of the libpcap library, and therefore work
	both on Windows and on Linux.
	\note errbuf in pcap_open_live(), pcap_open_dead(), pcap_open_offline(), 
	pcap_setnonblock(), pcap_getnonblock(), pcap_findalldevs(), 
	pcap_lookupdev(), and pcap_lookupnet() is assumed to be able to hold at 
	least PCAP_ERRBUF_SIZE chars.
 */
//\{ 

/*! \brief Prototype of the callback function that receives the packets. 

When pcap_dispatch() or pcap_loop() are called by the user, the packets are passed to the application
by means of this callback. user is a user-defined parameter that contains the state of the
capture session, it corresponds to the \e user parameter of pcap_dispatch() and pcap_loop(). pkt_header is
the header associated by the capture driver to the packet. It is NOT a protocol header. pkt_data
points to the data of the packet, including the protocol headers.
*/
typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *pkt_header,
			     const u_char *pkt_data);

/*!	\brief Open a live capture from the network.

	pcap_open_live()  is  used  to  obtain a packet capture descriptor to
	look at packets on the network.  device is a  string  that  specifies
	the  network  device to open; on Linux systems with 2.2 or later kernels, 
	a device argument of "any" or NULL can be used to capture packets  
	from  all  interfaces.   snaplen specifies the maximum number of
	bytes to capture.  If this value is less than the size  of  a  packet
	that is captured, only the first snaplen bytes of that packet will be
	captured and provided as packet data.  A value  of  65535  should  be
	sufficient,  on  most  if  not  all networks, to capture all the data
	available from the packet.  promisc specifies if the interface is  to
	be  put  into promiscuous mode.  (Note that even if this parameter is
	false, the interface could well be in promiscuous mode for some other
	reason.)  For now, this doesn't work on the "any" device; if an argument 
	of "any" or NULL is  supplied,  the  promisc  flag  is  ignored.
	to_ms  specifies  the read timeout in milliseconds.  The read timeout
	is used to arrange that the read not necessarily  return  immediately
	when  a  packet  is seen, but that it wait for some amount of time to
	allow more packets to arrive and to read multiple packets from the OS
	kernel  in  one operation.  Not all platforms support a read timeout;
	on platforms that don't, the read timeout is ignored.  A  zero  value
	for  to_ms,  on  platforms  that support a read timeout, will cause a
	read to wait forever to allow enough packets to arrive, with no timeout.  
	errbuf is used to return error or warning text.  It will be set
	to error text when pcap_open_live() fails and returns  NULL.   errbuf
	may  also  be  set  to warning text when pcap_open_live() succeds; to
	detect this case the caller should  store  a  zero-length  string  in
	errbuf before calling pcap_open_live() and display the warning to the
	user if errbuf is no longer a zero-length string.

\sa pcap_open_offline(), pcap_open_dead(), pcap_findalldevs(), pcap_close()
*/
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf);


/*!	\brief Create a pcap_t structure without starting a capture.

  pcap_open_dead()  is  used for creating a pcap_t structure
  to use when calling the other functions in libpcap.  It is
  typically  used  when just using libpcap for compiling BPF
  code.

\sa pcap_open_offline(), pcap_open_live(), pcap_findalldevs(), pcap_compile(), pcap_setfilter(), pcap_close()
*/
pcap_t *pcap_open_dead(int linktype, int snaplen);


/*!	\brief Open a savefile in the tcpdump/libpcap format to read packets.

	pcap_open_offline() is called to open  a  "savefile"  for  reading.
	fname  specifies  the name of the file to open. The file has the same
	format as those used by tcpdump(1) and tcpslice(1).  The name "-"  in
	a    synonym    for    stdin.     Alternatively,    you    may   call
	pcap_fopen_offline() to read dumped data from an existing open stream
	fp.   Note  that  on  Windows, that stream should be opened in binary
	mode.  errbuf is used to return error  text  and  is  only  set  when
	pcap_open_offline() or pcap_fopen_offline() fails and returns NULL.

\sa pcap_open_live(), pcap_dump_open(), pcap_findalldevs(), pcap_close()
*/
pcap_t *pcap_open_offline(const char *fname, char *errbuf);

/*! \brief Open a file to write packets.

	pcap_dump_open()  is  called  to open a "savefile" for writing. The
	name "-" in a synonym for stdout.  NULL is returned on failure.  p is
	a pcap struct as returned by pcap_open_offline() or pcap_open_live().
	fname specifies the name of the file to open. Alternatively, you  may
	call  pcap_dump_fopen()  to write data to an existing open stream fp.
	Note that on Windows, that stream should be opened  in  binary  mode.
	If NULL is returned, pcap_geterr() can be used to get the error text.

\sa pcap_dump_close(), pcap_dump()
*/
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);

/*! \brief Switch between blocking and nonblocking mode.

       pcap_setnonblock() puts a capture descriptor, opened  with
       pcap_open_live(),  into "non-blocking" mode, or takes it
       out of "non-blocking" mode,  depending  on  whether  the
       nonblock  argument  is non-zero or zero.  It has no effect
       on "savefiles".  If there is an error,  -1  is  returned
       and errbuf is filled in with an appropriate error message;
       otherwise, 0 is returned.  In  "non-blocking"  mode,  an
       attempt to read from the capture descriptor with pcap_dispatch() 
	   will, if no packets are currently available to  be
       read,  return  0  immediately rather than blocking waiting
       for packets to arrive.  pcap_loop() and  pcap_next()  will
       not work in "non-blocking" mode.

\sa pcap_getnonblock(), pcap_dispatch()
*/
int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf);


/*! \brief Get the "non-blocking" state of an interface.

       pcap_getnonblock()  returns  the  current "non-blocking"
       state of the capture descriptor; it always  returns  0  on
       "savefiles".   If  there is an error, -1 is returned and
       errbuf is filled in with an appropriate error message.

\sa pcap_setnonblock()
*/
int pcap_getnonblock(pcap_t *p, char *errbuf);

/*!	\brief Construct a list of network devices that can be 
  opened with pcap_open_live(). 
  
  \note that there may be network devices that cannot be opened with 
  pcap_open_live() by the process calling pcap_findalldevs(), because, 
  for example, that process might not have sufficient privileges to open 
  them for capturing; if so, those devices will not appear on the list.) 
  alldevsp is set to point to the first element of the list; each element 
  of the list is of type \ref pcap_if_t, 

  -1 is returned on failure, in which case errbuf is filled in with an 
  appropriate error message; 0 is returned on success.

\sa struct pcap_if, pcap_freealldevs(), pcap_open_live(), pcap_lookupdev(), pcap_lookupnet()
*/
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);

/*! \brief Free an interface list returned by pcap_findalldevs().

       pcap_freealldevs()  is  used  to  free a list allocated by pcap_findalldevs().

\sa pcap_findalldevs()
*/
void pcap_freealldevs(pcap_if_t *alldevsp);

/*! 	\brief Return the first valid device in the system.
\deprecated Use \ref pcap_findalldevs() or \ref pcap_findalldevs_ex() instead.

       pcap_lookupdev() returns a pointer  to  a  network  device
       suitable  for  use  with pcap_open_live() and pcap_lookupnet().
	   If there is an error, NULL is returned and  errbuf
       is filled in with an appropriate error message.

\sa pcap_findalldevs(), pcap_open_live()
*/
char *pcap_lookupdev(char *errbuf);


/*!	\brief Return the subnet and netmask of an interface.
\deprecated Use \ref pcap_findalldevs() or \ref pcap_findalldevs_ex() instead.

       pcap_lookupnet()  is  used to determine the network number
       and mask associated with the network device device.   Both
       netp  and  maskp are bpf_u_int32 pointers.  A return of -1
       indicates an error in which case errbuf is filled in  with
       an appropriate error message.

\sa pcap_findalldevs()
*/
int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);

/*!	\brief Collect a group of packets.

  pcap_dispatch() is used to collect and process packets. cnt specifies the maximum 
  number of packets to process before returning. This is not a minimum number; when 
  reading a live capture, only one bufferful of packets is read at a time, so fewer 
  than cnt packets may be processed. A cnt of -1 processes all the packets received 
  in one buffer when reading a live capture, or all the packets in the file when 
  reading a ``savefile''. callback specifies a routine to be called with three 
  arguments: a u_char pointer which is passed in from pcap_dispatch(), a const 
  struct \ref pcap_pkthdr pointer,
  and a const u_char pointer to the first caplen (as given in the struct pcap_pkthdr 
  a pointer to which is passed to the callback routine) bytes of data from the packet 
  (which won't necessarily be the entire packet; to capture the entire packet, you 
  will have to provide a value for snaplen in your call to pcap_open_live() that is 
  sufficiently large to get all of the packet's data - a value of 65535 should be 
  sufficient on most if not all networks).

  The number of packets read is returned. 0 is returned if no packets were read from 
  a live capture (if, for example, they were discarded because they didn't pass the 
  packet filter, or if, on platforms that support a read timeout that starts before 
  any packets arrive, the timeout expires before any packets arrive, or if the file 
  descriptor for the capture device is in non-blocking mode and no packets were 
  available to be read) or if no more packets are available in a ``savefile.'' A return 
  of -1 indicates an error in which case pcap_perror() or pcap_geterr() may be used 
  to display the error text. A return of -2 indicates that the loop terminated due to 
  a call to pcap_breakloop() before any packets were processed. If your application 
  uses pcap_breakloop(), make sure that you explicitly check for -1 and -2, rather 
  than just checking for a return value < 0.

  \note when reading a live capture, pcap_dispatch() will not necessarily return when 
  the read times out; on some platforms, the read timeout isn't supported, and, on 
  other platforms, the timer doesn't start until at least one packet arrives. This 
  means that the read timeout should NOT be used in, for example, an interactive 
  application, to allow the packet capture loop to ``poll'' for user input periodically, 
  as there's no guarantee that pcap_dispatch() will return after the timeout expires.

\sa pcap_loop(), pcap_next(), pcap_open_live(), pcap_open_offline(), pcap_handler
*/
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);


/*!	\brief Collect a group of packets.

  pcap_loop() is similar to pcap_dispatch() except it keeps reading packets until cnt 
  packets are processed or an error occurs. It does not return when live read timeouts 
  occur. Rather, specifying a non-zero read timeout to pcap_open_live() and then calling 
  pcap_dispatch() allows the reception and processing of any packets that arrive when 
  the timeout occurs. A negative cnt causes pcap_loop() to loop forever (or at least 
  until an error occurs). -1 is returned on an error; 0 is returned if cnt is exhausted; 
  -2 is returned if the loop terminated due to a call to pcap_breakloop() before any packets
  were processed. If your application uses pcap_breakloop(), make sure that you explicitly 
  check for -1 and -2, rather than just checking for a return value < 0.

\sa pcap_dispatch(), pcap_next(), pcap_open_live(), pcap_open_offline(), pcap_handler
*/
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);


/*! \brief Return the next available packet.

  pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and returns 
  a u_char pointer to the data in that packet. (The pcap_pkthdr struct for that packet is not 
  supplied.) NULL is returned if an error occured, or if no packets were read from a live 
  capture (if, for example, they were discarded because they didn't pass the packet filter, 
  or if, on platforms that support a read timeout that starts before any packets arrive, the 
  timeout expires before any packets arrive, or if the file descriptor for the capture device 
  is in non-blocking mode and no packets were available to be read), or if no more packets are 
  available in a ``savefile.'' Unfortunately, there is no way to determine whether an error 
  occured or not.
\sa pcap_dispatch(), pcap_loop()
*/

u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

/*! \brief Read a packet from an interface or from an offline capture.

This function is used to retrieve the next available packet, bypassing the callback method traditionally 
provided by libpcap.

pcap_next_ex fills the pkt_header and pkt_data parameters (see pcap_handler()) with the pointers to the 
header and to the data of the next captured packet.

The return value can be:
- 1 if the packet has been read without problems
- 0 if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
- -1 if an error occurred
- -2 if EOF was reached reading from an offline capture

\sa pcap_open_live(), pcap_loop(), pcap_dispatch(), pcap_handler()
*/
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);

/*! \brief set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping.

  They will return the number of packets that have been processed so far, or -2 if no packets have been processed so far.
  This routine is safe to use inside a signal handler on UNIX or a console control handler on Windows, as it merely sets 
  a flag that is checked within the loop.
  The flag is checked in loops reading packets from the OS - a signal by itself will not necessarily terminate those 
  loops - as well as in loops processing a set of packets returned by the OS. Note that if you are catching signals on 
  UNIX systems that support restarting system calls after a signal, and calling pcap_breakloop() in the signal handler, 
  you must specify, when catching those signals, that system calls should NOT be restarted by that signal. Otherwise, 
  if the signal interrupted a call reading packets in a live capture, when your signal handler returns after calling 
  pcap_breakloop(), the call will be restarted, and the loop will not terminate until more packets arrive and the call 
  completes.  
  \note pcap_next() will, on some platforms, loop reading packets from the OS; that loop will not necessarily be 
  terminated by a signal, so pcap_breakloop() should be used to terminate packet processing even if pcap_next() is 
  being used.
  pcap_breakloop() does not guarantee that no further packets will be processed by pcap_dispatch() or pcap_loop() after 
  it is called; at most one more packet might be processed.
  If -2 is returned from pcap_dispatch() or pcap_loop(), the flag is cleared, so a subsequent call will resume reading 
  packets. If a positive number is returned, the flag is not cleared, so a subsequent call will return -2 and clear 
  the flag.
*/
void pcap_breakloop(pcap_t *);

/*! \brief Send a raw packet.

This function allows to send a raw packet to the network. p is the interface that 
will be used to send the packet, buf contains the data of the packet to send (including the various 
protocol headers), size is the dimension of the buffer pointed by buf, i.e. the size of the packet to send. 
The MAC CRC doesn't need to be included, because it is transparently calculated and added by the network 
interface driver.
The return value is 0 if the packet is succesfully sent, -1 otherwise.

\sa pcap_open_live()
*/
int pcap_sendpacket(pcap_t *p, u_char *buf, int size);	

/*! \brief Save a packet to disk.

       pcap_dump() outputs a packet to  the  "savefile"  opened
       with  pcap_dump_open().   Note  that its calling arguments
       are suitable for use with pcap_dispatch() or  pcap_loop().
       If   called  directly,  the  user  parameter  is  of  type
       pcap_dumper_t as returned by pcap_dump_open().

\sa pcap_dump_open(), pcap_dump_close(), pcap_dispatch(), pcap_loop()
*/
void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);

/*! \brief Return the file position for a "savefile".

	pcap_dump_ftell() returns the current file position for the "savefile", representing the number of bytes written by
	pcap_dump_open() and pcap_dump() .
	-1 is returned on error.

\sa pcap_dump_open(), pcap_dump()
*/
long pcap_dump_ftell(pcap_dumper_t *);

/*! \brief Compile a packet filter, converting an high level filtering expression 
(see \ref language) in a program that can be interpreted by the kernel-level
filtering engine.

  pcap_compile() is used to compile the string str into a filter program. program 
  is a pointer to a bpf_program struct and is filled in by pcap_compile(). optimize 
  controls whether optimization on the resulting code is performed. netmask 
  specifies the IPv4 netmask of the network on which packets are being captured; 
  it is used only when checking for IPv4 broadcast addresses in the filter program. 
  If the netmask of the network on which packets are being captured isn't known to 
  the program, or if packets are being captured on the Linux "any" pseudo-interface 
  that can capture on more than one network, a value of 0 can be supplied; tests for 
  IPv4 broadcast addreses won't be done correctly, but all other tests in the filter 
  program will be OK. A return of -1 indicates an error in which case pcap_geterr() 
  may be used to display the error text.

\sa pcap_open_live(), pcap_setfilter(), pcap_freecode(), pcap_snapshot()
*/
int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask);

/*!\brief Compile a packet filter without the need of opening an adapter. This function converts an high level filtering expression 
(see \ref language) in a program that can be interpreted by the kernel-level filtering engine.

       pcap_compile_nopcap() is similar to pcap_compile() except 
       that  instead  of passing a pcap structure, one passes the
       snaplen and linktype explicitly.  It  is  intended  to  be
       used  for  compiling filters for direct BPF usage, without
       necessarily having called pcap_open().   A  return  of  -1
       indicates   an  error;  the  error  text  is  unavailable.
       (pcap_compile_nopcap()     is     a     wrapper     around
       pcap_open_dead(),  pcap_compile(),  and  pcap_close(); the
       latter three routines can be used directly in order to get
       the error text for a compilation error.)

       Look at the \ref language section for details on the 
       str parameter.

\sa pcap_open_live(), pcap_setfilter(), pcap_freecode(), pcap_snapshot()
*/
int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, struct bpf_program *program, char *buf, int optimize, bpf_u_int32 mask);


/*! \brief Associate a filter to a capture.

       pcap_setfilter()  is used to specify a filter program.  fp
       is a pointer to a bpf_program struct, usually  the  result
       of  a  call to pcap_compile().  -1 is returned on failure,
       in which case pcap_geterr() may be  used  to  display  the
       error text; 0 is returned on success.

\sa pcap_compile(), pcap_compile_nopcap()
*/
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);


/*! \brief Free a filter.

       pcap_freecode()  is  used  to  free  up  allocated  memory
       pointed to by a bpf_program struct generated by  pcap_compile()  
	   when  that  BPF  program  is no longer needed, for
       example after it has been made the filter  program  for  a
       pcap structure by a call to pcap_setfilter().

\sa pcap_compile(), pcap_compile_nopcap()
*/
void pcap_freecode(struct bpf_program *fp);

/*! \brief Return the link layer of an adapter.

returns the link layer type; link layer types it can return include:

    - DLT_NULL BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order, containing a PF_ value from socket.h for the network-layer protocol of the packet. 
        Note that ``host byte order'' is the byte order of the machine on which the packets are captured, and the PF_ values are for the OS of the machine on which the packets are captured; if a live capture is being done, ``host byte order'' is the byte order of the machine capturing the packets, and the PF_ values are those of the OS of the machine capturing the packets, but if a ``savefile'' is being read, the byte order and PF_ values are not necessarily those of the machine reading the capture file. 
    - DLT_EN10MB Ethernet (10Mb, 100Mb, 1000Mb, and up) 
    - DLT_IEEE802: IEEE 802.5 Token Ring 
    - DLT_ARCNET: ARCNET 
    - DLT_SLIP: SLIP; the link layer header contains, in order:
            -# a 1-byte flag, which is 0 for packets received by the machine and 1 for packets sent by the machine;
            -# a 1-byte field, the upper 4 bits of which indicate the type of packet, as per RFC 1144:
                - 0x40: an unmodified IP datagram (TYPE_IP); 
                - 0x70: an uncompressed-TCP IP datagram (UNCOMPRESSED_TCP), with that byte being the first byte of the raw IP header on the wire, containing the connection number in the protocol field; 
                - 0x80: a compressed-TCP IP datagram (COMPRESSED_TCP), with that byte being the first byte of the compressed TCP/IP datagram header; 
            -# for UNCOMPRESSED_TCP, the rest of the modified IP header, and for COMPRESSED_TCP, the compressed TCP/IP datagram header; 
            -# for a total of 16 bytes; the uncompressed IP datagram follows the header. 

    - DLT_PPP: PPP; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it's PPP without framing, and the packet begins with the PPP header. 
    - DLT_FDDI: FDDI 
    - DLT_ATM_RFC1483: RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an IEEE 802.2 LLC header. 
    - DLT_RAW: raw IP; the packet begins with an IP header. 
    - DLT_PPP_SERIAL: PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547; the first byte will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing. 
    - DLT_PPP_ETHER: PPPoE; the packet begins with a PPPoE header, as per RFC 2516. 
    - DLT_C_HDLC: Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547. 
    - DLT_IEEE802_11: IEEE 802.11 wireless LAN 
    - DLT_FRELAY: Frame Relay 
    - DLT_LOOP: OpenBSD loopback encapsulation; the link layer header is a 4-byte field, in network byte order, containing a PF_ value from OpenBSD's socket.h for the network-layer protocol of the packet. 
        Note that, if a ``savefile'' is being read, those PF_ values are not necessarily those of the machine reading the capture file. 
    - DLT_LINUX_SLL: Linux "cooked" capture encapsulation; the link layer header contains, in order:
		- a 2-byte "packet type", in network byte order, which is one of:
			-# packet was sent to us by somebody else 
			-# packet was broadcast by somebody else 
			-# packet was multicast, but not broadcast, by somebody else 
			-# packet was sent by somebody else to somebody else 
			-# packet was sent by us 
		- a 2-byte field, in network byte order, containing a Linux ARPHRD_ value for the link layer device type;
		- a 2-byte field, in network byte order, containing the length of the link layer address of the sender of the packet (which could be 0);
		- an 8-byte field containing that number of bytes of the link layer header (if there are more than 8 bytes, only the first 8 are present);
		- 2-byte field containing an Ethernet protocol type, in network byte order, or containing 1 for Novell 802.3 frames without an 802.2 LLC header or 4 for frames beginning with an 802.2 LLC header. 
    - DLT_LTALK: Apple LocalTalk; the packet begins with an AppleTalk LLAP header. 
    - DLT_PFLOG: OpenBSD pflog; the link layer header contains, in order:
		- a 4-byte PF_ value, in network byte order;
		- a 16-character interface name;
		- a 2-byte rule number, in network byte order;
		- a 2-byte reason code, in network byte order, which is one of:
			-# match 
			-# bad offset 
			-# fragment 
			-# short 
			-# normalize 
			-# memory
		-a 2-byte action code, in network byte order, which is one of:
			-# passed 
			-# dropped 
			-# scrubbed 
		- a 2-byte direction, in network byte order, which is one of:
			-# incoming or outgoing 
			-# incoming 
			-# outgoing 
    - DLT_PRISM_HEADER: Prism monitor mode information followed by an 802.11 header. 
    - DLT_IP_OVER_FC: RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC. 
    - DLT_SUNATM: SunATM devices; the link layer header contains, in order:
		- a 1-byte flag field, containing a direction flag in the uppermost bit, which is set for packets transmitted by the machine and clear for packets received by the machine, and a 4-byte traffic type in the low-order 4 bits, which is one of:
			-# raw traffic 
			-# LANE traffic 
			-# LLC-encapsulated traffic 
			-# MARS traffic 
			-# IFMP traffic 
			-# ILMI traffic 
			-# Q.2931 traffic 
		- a 1-byte VPI value;
		- a 2-byte VCI field, in network byte order. 
    - DLT_IEEE802_11_RADIO: link-layer information followed by an 802.11 header - see http://www.radiotap.org/ for a description of the link-layer information. 
    - DLT_ARCNET_LINUX: ARCNET, with no exception frames, reassembled packets rather than raw frames, and an extra 16-bit offset field between the destination host and type bytes. 
    - DLT_LINUX_IRDA: Linux-IrDA packets, with a DLT_LINUX_SLL header followed by the IrLAP header. 

\sa pcap_list_datalinks(), pcap_set_datalink(), pcap_datalink_name_to_val()
*/
int pcap_datalink(pcap_t *p);

/*! \brief list datalinks 

  pcap_list_datalinks() is used to get a list of the supported data link types of the 
  interface associated with the pcap descriptor. pcap_list_datalinks() allocates an array 
  to hold the list and sets *dlt_buf. The caller is responsible for freeing the array. -1 
  is returned on failure; otherwise, the number of data link types in the array is returned.

\sa pcap_datalink(), pcap_set_datalink(), pcap_datalink_name_to_val()
*/
int pcap_list_datalinks(pcap_t *p, int **dlt_buf);

/*! \brief Set the current data link type of the pcap 
  descriptor to the type specified by dlt. -1 is returned on failure. */
int pcap_set_datalink(pcap_t *p, int dlt);

/*! \brief Translates a data link type name, which is a DLT_ name 
  with the DLT_ removed, to the corresponding data link type value. The translation is 
  case-insensitive. -1 is returned on failure.
*/
int pcap_datalink_name_to_val(const char *name);

/*! \brief Translates a data link type value to the corresponding data 
link type name. NULL is returned on failure. 
*/
const char *pcap_datalink_val_to_name(int dlt);

/*! \brief Translates a data link type value to a short 
description of that data link type. NULL is returned on failure. 
*/
const char *pcap_datalink_val_to_description(int dlt);


/*! \brief Return the dimension of the packet portion (in bytes) that is delivered to the application.

       pcap_snapshot() returns the snapshot length specified when
       pcap_open_live was called.

\sa pcap_open_live(), pcap_compile(), pcap_compile_nopcap()
*/
int pcap_snapshot(pcap_t *p);


/*! \brief returns true if the current savefile
uses a different byte order than the current system.
*/
int pcap_is_swapped(pcap_t *p);


/*! \brief return the major version number of the pcap library used to write the savefile.

\sa pcap_minor_version()
*/
int pcap_major_version(pcap_t *p);


/*! \brief return the minor version number of the pcap library used to write the savefile.

\sa pcap_major_version()
*/
int pcap_minor_version(pcap_t *p);

/*! \brief Return the standard stream of an offline capture.
 
       pcap_file() returns the standard I/O stream of the "savefile",
       if    a    "savefile"    was    opened   with
       pcap_open_offline(), or NULL,  if  a  network  device  was
       opened with pcap_open_live().
       \deprecated Due to incompatibilities between the C Runtime (CRT) used to
       compile WinPcap and the one used by WinPcap-based applications, this function 
       may return an invalid FILE pointer, i.e. a descriptor that causes all the standard I/O stream 
       functions (ftell, fseek, fclose...) to fail. The function is still available for 
       backwards binary compatibility, only.

\sa pcap_open_offline(), pcap_open_live()
*/
FILE *pcap_file(pcap_t *p);

/*! \brief Return statistics on current capture.

 pcap_stats()  returns  0  and fills in a pcap_stat struct.
 The values represent packet statistics from the  start  of
 the  run  to the time of the call. If there is an error or
 the  underlying  packet  capture  doesn't  support  packet
 statistics,  -1  is  returned  and  the  error text can be
 obtained    with    pcap_perror()    or     pcap_geterr().
 pcap_stats()  is  supported  only on live captures, not on
 "savefiles"; no statistics are stored in  "savefiles",
  so no statistics are available when reading from a "savefile".

\sa pcap_stats_ex(), pcap_open_live()
*/
int pcap_stats(pcap_t *p, struct pcap_stat *ps);

/*! \brief print the text of the last pcap library error on stderr, prefixed by prefix.

\sa pcap_geterr()
*/
void pcap_perror(pcap_t *p, char *prefix);


/*! \brief return the error  text  pertaining  to  the
       last  pcap  library  error.   

       \note the pointer Return will no longer point to a valid 
       error message string after the pcap_t passed to it is closed; 
       you must use or copy the string before closing the pcap_t. 

\sa pcap_perror()
*/
char *pcap_geterr(pcap_t *p);


/*! \brief Provided  in  case  strerror()  isn't
       available.

\sa pcap_perror(), pcap_geterr()
*/
char *pcap_strerror(int error);

/*! \brief Returns a pointer to a string giving information about the 
  version of the libpcap library being used; note that it contains more information than 
  just a version number. 
*/
const char *pcap_lib_version(void);

/*! \brief
       close the files associated with p and deallocates resources.

\sa pcap_open_live(), pcap_open_offline(), pcap_open_dead()
*/
void pcap_close(pcap_t *p);

/*! \brief return the standard I/O stream of the 'savefile' opened by pcap_dump_open(). */
FILE *pcap_dump_file(pcap_dumper_t *p);

/*! \brief Flushes the output buffer to the ``savefile,'' so that any 
     packets written with pcap_dump() but not yet written to the ``savefile'' will be 
     written. -1 is returned on error, 0 on success. 
*/
int pcap_dump_flush(pcap_dumper_t *p);

/*! \brief Closes a savefile.

\sa pcap_dump_open(), pcap_dump()
*/
void pcap_dump_close(pcap_dumper_t *p);

//\}
// End of Unix-compatible functions







/** \name Windows-specific Extensions

	The functions in this section extend libpcap to offer advanced functionalities (like remote packet 
	capture, packet buffer size variation or high-precision packet injection). Howerver, at the moment 
	they can be used only in Windows.
 */
//\{ 

/*!	\brief Returns the AirPcap handler associated with an adapter. This handler can be used to change
           the wireless-related settings of the CACE Technologies AirPcap wireless capture adapters.

\note THIS FUNCTION SHOULD BE CONSIDERED PROVISIONAL, AND MAY BE REPLACED IN THE FUTURE BY A MORE COMPLETE SET
OF FUNCTIONS FOR WIRELESS SUPPORT.

pcap_get_airpcap_handle() allows to obtain the airpcap handle of an open adapter. This handle can be used with
the AirPcap API functions to perform wireless-releated operations, e.g. changing the channel or enabling 
WEP decryption. For more details about the AirPcap wireless capture adapters, see 
http://www.cacetech.com/products/airpcap.html
	
\param p: handle to an open libpcap adapter

\return a pointer to an open AirPcap handle, used internally by the libpcap open adapter. NULL if the libpcap 
 adapter doesn't have wireless support through AirPcap.
*/
PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p);

/*!	\brief Returns if a given filter applies to an offline packet.
	
This function is used to apply a filter to a packet that is currently in memory.
This process does not need to open an adapter; we need just to create the proper filter (by settings
parameters like the snapshot length, or the link-layer type) by means of the pcap_compile_nopcap().

The current API of libpcap does not allow to receive a packet and to filter the packet after it has been
received. However, this can be useful in case you want to filter packets in the application, instead of into 
the receiving process. This function allows you to do the job.
	
\param prog: bpf program (created with the pcap_compile_nopcap() )
\param header: header of the packet that has to be filtered
\param pkt_data: buffer containing the packet, in network-byte order.

\return the length of the bytes that are currently available into the packet if the packet satisfies the filter,
0 otherwise.
*/
int pcap_offline_filter(struct bpf_program *prog, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*! \brief Save a capture to file.

  \note: this function does not work in current version of WinPcap.

pcap_live_dump() dumps the network traffic from an interface to
a file. Using this function the dump is performed at kernel level, therefore it is more efficient than using
pcap_dump().

The parameters of this function are an interface descriptor (obtained with pcap_open_live()), a string with 
the name of the dump file, the maximum size of the file (in bytes) and the maximum number of packets that the file
will contain. Setting maxsize or maxpacks to 0 means no limit. When maxsize or maxpacks are reached, 
the dump ends.

pcap_live_dump() is non-blocking, threfore Return immediately. pcap_live_dump_ended() can be used to 
check the status of the dump process or to wait until it is finished. pcap_close() can instead be used to 
end the dump process.

Note that when one of the two limits is reached, the dump is stopped, but the file remains opened. In order 
to correctly flush the data and put the file in a consistent state, the adapter must be closed with 
pcap_close().


\sa pcap_live_dump_ended(), pcap_open_live(), pcap_close(), pcap_dump_open(), pcap_dump()
*/
int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);


/*! \brief Return the status of the kernel dump process, i.e. tells if one of the limits defined with pcap_live_dump() has been reached.

    \note: this function does not work in current version of WinPcap.

pcap_live_dump_ended() informs the user about the limits that were set with a previous call to 
pcap_live_dump() on the interface pointed by p: if the return value is nonzero, one of the limits has been 
reched and the dump process is currently stopped.

If sync is nonzero, the function blocks until the dump is finished, otherwise Return immediately.

\warning if the dump process has no limits (i.e. if the maxsize and maxpacks arguments of pcap_live_dump() 
were both 0), the dump process will never stop, therefore setting sync to TRUE will block the application 
on this call forever.

\sa pcap_live_dump()
*/
int pcap_live_dump_ended(pcap_t *p, int sync);


/*! \brief Return statistics on current capture.

pcap_stats_ex() extends the pcap_stats() allowing to return more statistical parameters than the old call.
One of the advantages of this new call is that the pcap_stat structure is not allocated by the user; instead,
it is returned back by the system. This allow to extend the pcap_stat structure without affecting backward compatibility
on older applications. These will simply check at the values of the members at the beginning of the structure, 
while only newest applications are able to read new statistical values, which are appended in tail.

To be sure not to read a piece of mamory which has not been allocated by the system, the variable pcap_stat_size
will return back the size of the structure pcap_stat allocated by the system.

\param p: pointer to the pcap_t currently in use.
\param pcap_stat_size: pointer to an integer that will contain (when the function returns back) the size of the
structure pcap_stat as it has been allocated by the system.

\return: a pointer to a pcap_stat structure, that will contain the statistics related to the current device.
The return value is NULL in case of errors, and the  error text can be obtained with pcap_perror() or pcap_geterr().

\warning pcap_stats_ex()  is  supported  only on live captures, not on  "savefiles"; no statistics are stored in
"savefiles", so no statistics are available when reading from a "savefile".

\sa pcap_stats()
*/
struct pcap_stat *pcap_stats_ex(pcap_t *p, int *pcap_stat_size);

/*! \brief Set the size of the kernel buffer associated with an adapter.

\e dim specifies the size of the buffer in bytes.
The return value is 0 when the call succeeds, -1 otherwise. If an old buffer was already created 
with a previous call to pcap_setbuff(), it is deleted and its content is discarded. 
pcap_open_live() creates a 1 MByte buffer by default.

\sa pcap_open_live(), pcap_loop(), pcap_dispatch()
*/
int pcap_setbuff(pcap_t *p, int dim);


/*! \brief Set the working mode of the interface p to mode. 

Valid values for mode are 
MODE_CAPT (default capture mode) and MODE_STAT (statistical mode). See the tutorial "\ref wpcap_tut9"
for details about statistical mode.
*/
int pcap_setmode(pcap_t *p, int mode);


/*! \brief Set the minumum amount of data received by the kernel in a single call.

pcap_setmintocopy() changes the minimum amount of data in the kernel buffer that causes a read from 
the application to return (unless the timeout expires). If the value of \e size is large, the kernel 
is forced to wait the arrival of several packets before copying the data to the user. This guarantees 
a low number of system calls, i.e. low processor usage, and is a good setting for applications like 
packet-sniffers and protocol analyzers. Vice versa, in presence of a small value for this variable, 
the kernel will copy the packets as soon as the application is ready to receive them. This is useful 
for real time applications that need the best responsiveness from the kernel. pcap_open_live() sets a
default mintocopy value of 16000 bytes.

\sa pcap_open_live(), pcap_loop(), pcap_dispatch()
*/
int pcap_setmintocopy(pcap_t *p, int size);



/*! \brief Return the handle of the event associated with the interface p. 

	This event can be passed to functions like WaitForSingleObject() or WaitForMultipleObjects() to wait 
	until the driver's buffer contains some data without performing a read.

	We disourage the use of this function because it is not portable.

\sa pcap_open_live()
*/
HANDLE pcap_getevent(pcap_t *p);

/*! \brief Allocate a send queue. 

This function allocates a send queue, i.e. a buffer containing a set of raw packets that will be transimtted
on the network with pcap_sendqueue_transmit().

memsize is the size, in bytes, of the queue, therefore it determines the maximum amount of data that the 
queue will contain.

Use pcap_sendqueue_queue() to insert packets in the queue.

\sa pcap_sendqueue_queue(), pcap_sendqueue_transmit(), pcap_sendqueue_destroy()
*/
pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);

/*! \brief Destroy a send queue. 

Deletes a send queue and frees all the memory associated with it.

\sa pcap_sendqueue_alloc(), pcap_sendqueue_queue(), pcap_sendqueue_transmit()
*/
void pcap_sendqueue_destroy(pcap_send_queue* queue);

/*! \brief Add a packet to a send queue. 

pcap_sendqueue_queue() adds a packet at the end of the send queue pointed by the queue parameter. 
pkt_header points to a pcap_pkthdr structure with the timestamp and the length of the packet, pkt_data
points to a buffer with the data of the packet.

The pcap_pkthdr structure is the same used by WinPcap and libpcap to store the packets in a file, 
therefore sending a capture file is straightforward.
'Raw packet' means that the sending application will have to include the protocol headers, since every packet 
is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be 
transparently added by the network interface.

\sa pcap_sendqueue_alloc(), pcap_sendqueue_transmit(), pcap_sendqueue_destroy()
*/
int pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);


/*! \brief Send a queue of raw packets to the network.

This function transmits the content of a queue to the wire. p is a 
pointer to the adapter on which the packets will be sent, queue points to a pcap_send_queue structure 
containing the packets to send (see pcap_sendqueue_alloc() and pcap_sendqueue_queue()), sync determines if the 
send operation must be synchronized: if it is non-zero, the packets are sent respecting the timestamps,
otherwise they are sent as fast as possible.

The return value is the amount of bytes actually sent. If it is smaller than the size parameter, an
error occurred during the send. The error can be caused by a driver/adapter problem or by an inconsistent/bogus 
send queue.

\note Using this function is more efficient than issuing a series of pcap_sendpacket(), because the packets are
buffered in the kernel driver, so the number of context switches is reduced. Therefore, expect a better 
throughput when using pcap_sendqueue_transmit.

\note When Sync is set to TRUE, the packets are synchronized in the kernel with a high precision timestamp.
This requires a non-negligible amount of CPU, but allows normally to send the packets with a precision of some 
microseconds (depending on the accuracy of the performance counter of the machine). Such a precision cannot 
be reached sending the packets with pcap_sendpacket().

\sa pcap_sendqueue_alloc(), pcap_sendqueue_queue(), pcap_sendqueue_destroy()
*/
u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);


/*!	\brief Create a list of network devices that can be opened with pcap_open().
	
	This function is a superset of the old 'pcap_findalldevs()', which
	allows listing only the devices present on the local machine.
	Vice versa, pcap_findalldevs_ex() allows listing the devices present on a remote 
	machine as well. Additionally, it can list all the pcap files available into a given folder.
	Moreover, pcap_findalldevs_ex() is platform independent, since it
	relies on the standard pcap_findalldevs() to get addresses on the local machine.

	In case the function has to list the interfaces on a remote machine, it opens a new control
	connection toward that machine, it retrieves the interfaces, and it drops the connection.
	However, if this function detects that the remote machine is in 'active' mode,
	the connection is not dropped and the existing socket is used.

	The 'source' is a parameter that tells the function where the lookup has to be done and
	it uses the same syntax of the pcap_open().

	Differently from the pcap_findalldevs(), the interface names (pointed by the alldevs->name
	and the other ones in the linked list) are already ready to be used in the pcap_open() call.
	Vice versa, the output that comes from pcap_findalldevs() must be formatted with the new
	pcap_createsrcstr() before passing the source identifier to the pcap_open().

	\param source: a char* buffer that keeps the 'source localtion', according to the new WinPcap
	syntax. This source will be examined looking for adapters (local or remote) (e.g. source
	can be 'rpcap://' for local adapters or 'rpcap://host:port' for adapters on a remote host)
	or pcap files (e.g. source can be 'file://c:/myfolder/').<br>
	The strings that must be prepended to the 'source' in order to define if we want
	local/remote adapters or files is defined in the new \link remote_source_string Source 
	Specification Syntax \endlink.

	\param auth: a pointer to a pcap_rmtauth structure. This pointer keeps the information
	required to authenticate the RPCAP connection to the remote host.
	This parameter is not meaningful in case of a query to the local host: in that case
	it can be NULL.

	\param alldevs: a 'struct pcap_if_t' pointer, which will be properly allocated inside
	this function. When the function returns, it is set to point to the first element 
	of the interface list; each element of the list is of type 'struct pcap_if_t'.

	\param errbuf: a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).

	\return '0' if everything is fine, '-1' if some errors occurred. The list of the devices 
	is returned in the 'alldevs' variable.
	When the function returns correctly, 'alldevs' cannot be NULL. In other words, this 
	function returns '-1' also in case the system does not have any interface to list.

	The error message is returned in the 'errbuf' variable. An error could be due to 
	several reasons:
	- libpcap/WinPcap was not installed on the local/remote host
	- the user does not have enough privileges to list the devices / files
	- a network problem
	- the RPCAP version negotiation failed
	- other errors (not enough memory and others).
	
	\warning There may be network devices that cannot be opened with pcap_open() by the process
	calling pcap_findalldevs(), because, for example, that process might not have
	sufficient privileges to open them for capturing; if so, those devices will not 
	appear on the list.

	\warning The interface list must be deallocated manually by using the pcap_freealldevs().
*/
int pcap_findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);


/*!	\brief Accept a set of strings (host name, port, ...), and it returns the complete 
	source string according to the new format (e.g. 'rpcap://1.2.3.4/eth0').

	This function is provided in order to help the user creating the source string
	according to the new format.
	An unique source string is used in order to make easy for old applications to use the
	remote facilities. Think about tcpdump, for example, which has only one way to specify
	the interface on which the capture has to be started.
	However, GUI-based programs can find more useful to specify hostname, port and
	interface name separately. In that case, they can use this function to create the 
	source string before passing it to the pcap_open() function.

	\param source: a user-allocated buffer that will contain the complete source string
	wen the function returns.<br>
	The source will start with an identifier according to the new \link remote_source_string 
	Source Specification Syntax	\endlink.<br>
	This function assumes that the allocated buffer is at least PCAP_BUF_SIZE bytes.

	\param type: its value tells the type of the source we want to create. It can assume 
	the values defined in the \link remote_source_ID Source identification
	Codes \endlink.<br>

	\param host: an user-allocated buffer that keeps the host (e.g. "foo.bar.com") we 
	want to connect to.
	It can be NULL in case we want to open an interface on a local host.

	\param port: an user-allocated buffer that keeps the network port (e.g. "2002") we 
	want to use for the RPCAP protocol.
	It can be NULL in case we want to open an interface on a local host.

	\param name: an user-allocated buffer that keeps the interface name we want to use
	(e.g. "eth0").
	It can be NULL in case the return string (i.e. 'source') has to be used with the
	pcap_findalldevs_ex(), which does not require the interface name.

	\param errbuf: a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).

	\return '0' if everything is fine, '-1' if some errors occurred. The string containing
	the complete source is returned in the 'source' variable.

	\warning If the source is longer than PCAP_BUF_SIZE, the excess characters are truncated.
*/
int pcap_createsrcstr(char *source, int type, const char *host, const char *port, const char *name, char *errbuf);


/*!	\brief Parse the source string and returns the pieces in which the source can be split.

	This call is the other way round of pcap_createsrcstr().
	It accepts a null-terminated string and it returns the parameters related 
	to the source. This includes:
	- the type of the source (file, winpcap on a remote adapter, winpcap on local adapter),
	which is determined by the source prefix (PCAP_SRC_IF_STRING and so on)
	- the host on which the capture has to be started (only for remote captures)
	- the 'raw' name of the source (file name, name of the remote adapter, name 
	of the local adapter), without the source prefix. The string returned does not 
	include the type of the source itself (i.e. the string returned does not include "file://" 
	or rpcap:// or such).

	The user can omit some parameters in case it is not interested in them.

	\param source: a null-terminated string containing the WinPcap source. This source starts
	with an identifier according to the new \link remote_source_string Source Specification Syntax
	\endlink.

	\param type: pointer to an integer, which is used to return the code corrisponding to the 
	selected source. The code will be one defined in the \link remote_source_ID Source identification
	Codes \endlink.<br>
	In case the source string does not exists (i.e. 'source == NULL') or it is empty
	('*source == NULL'), it returns PCAP_SRC_IF_LOCAL (i.e. you are ready to 
	call pcap_open_live() ). This behavior is kept only for compatibility with older 
	applications (e.g. tcpdump); therefore we suggest to move to the new syntax for sources.<br>
	This parameter can be NULL in case the user is not interested in that.

	\param host: user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return 
	the host name on which the capture has to be started.
	This value is meaningful only in case of remote capture; otherwise, the returned 
	string will be empty ("").
	This parameter can be NULL in case the user is not interested in that.

	\param port: user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return 
	the port that has to be used by the RPCAP protocol to contact the other host.
	This value is meaningful only in case of remote capture and if the user wants to use
	a non-standard port; otherwise, the returned string will be empty ("").
	In case of remote capture, an emply string means "use the standard RPCAP port".
	This parameter can be NULL in case the user is not interested in that.

	\param name: user-allocated buffer (of size PCAP_BUF_SIZE) that is used to return 
	the source name, without the source prefix.
	If the name does not exist (for example because source contains 'rpcap://' that means 
	'default local adapter'), it returns NULL.
	This parameter can be NULL in case the user is not interested in that.

	\param errbuf: pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).
	This parameter can be NULL in case the user is not interested in that.

	\return '0' if everything is fine, '-1' if some errors occurred. The requested values
	(host name, network port, type of the source) are returned into the proper variables
	passed by reference.
*/
int pcap_parsesrcstr(const char *source, int *type, char *host, char *port, char *name, char *errbuf);

/*!	\brief Open a generic source in order to capture / send (WinPcap only) traffic.
	
	The pcap_open() replaces all the pcap_open_xxx() functions with a single call.

	This function hides the differences between the different pcap_open_xxx() functions
	so that the programmer does not have to manage different opening function.
	In this way, the 'true' open function is decided according to the source type,
	which is included into the source string (in the form of source prefix).

	This function can rely on the pcap_createsrcstr() to create the string that keeps
	the capture device according to	the new syntax, and the pcap_parsesrcstr() for the
	other way round.

	\param source: zero-terminated string containing the source name to open.
	The source name has to include the format prefix according to the new
	\link remote_source_string Source Specification Syntax\endlink and it cannot be NULL.<br>
	On on Linux systems with 2.2 or later kernels, a device argument of "any"
	(i.e. rpcap://any) can be used to capture packets from all interfaces.
	<br>
	In order to makes the source syntax easier, please remember that:
	- the adapters returned by the pcap_findalldevs_ex() can be used immediately by the pcap_open()
	- in case the user wants to pass its own source string to the pcap_open(), the 
	pcap_createsrcstr() helps in creating the correct source identifier.
	
	\param snaplen: length of the packet that has to be retained.	
	For each packet received by the filter, only the first 'snaplen' bytes are stored 
	in the buffer and passed to the user application. For instance, snaplen equal to 
	100 means that only the first 100 bytes of each packet are stored.

  	\param flags: keeps several flags that can be needed for capturing packets.
	The allowed flags are defined in the \link remote_open_flags pcap_open() flags \endlink.

	\param read_timeout: read timeout in milliseconds.
	The read timeout is used to arrange that the read not necessarily return
	immediately when a packet is seen, but that it waits for some amount of 
	time to allow more packets to arrive and to read multiple packets from 
	the OS kernel in one operation. Not all platforms support a read timeout;
	on platforms that don't, the read timeout is ignored.

	\param auth: a pointer to a 'struct pcap_rmtauth' that keeps the information required to
	authenticate the user on a remote machine. In case this is not a remote capture, this
	pointer can be set to NULL.

	\param errbuf: a pointer to a user-allocated buffer which will contain the error
	in case this function fails. The pcap_open() and findalldevs() are the only two
	functions which have this parameter, since they do not have (yet) a pointer to a
	pcap_t structure, which reserves space for the error string. Since these functions
	do not have (yet) a pcap_t pointer (the pcap_t pointer is NULL in case of errors),
	they need an explicit 'errbuf' variable.
	'errbuf' may also be set to warning text when pcap_open_live() succeds; 
	to detect this case the caller should store a  zero-length string in  
	'errbuf' before calling pcap_open_live() and display the warning to the user 
	if 'errbuf' is no longer a zero-length string.

	\return A pointer to a 'pcap_t' which can be used as a parameter to the following
	calls (pcap_compile() and so on) and that specifies an opened WinPcap session. In case of 
	problems, it returns NULL and the 'errbuf' variable keeps the error message.

	\warning The source cannot be larger than PCAP_BUF_SIZE.

	\warning The following formats are not allowed as 'source' strings:
	- rpcap:// [to open the first local adapter]
	- rpcap://hostname/ [to open the first remote adapter]

*/
pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf);

/*!	\brief Define a sampling method for packet capture.

	This function allows applying a sampling method to the packet capture process.
	The currently sampling methods (and the way to set them) are described into the
	struct pcap_samp. In other words, the user must set the appropriate parameters
	into it; these will be applied as soon as the capture starts.

	\warning Sampling parameters <strong>cannot</strong> be changed when a capture is 
	active. These parameters must be applied <strong>before</strong> starting the capture.
	If they are applied when the capture is in progress, the new settings are ignored.

	\warning Sampling works only when capturing data on Win32 or reading from a file.
	It has not been implemented on other platforms. Sampling works on remote machines
	provided that the probe (i.e. the capturing device) is a Win32 workstation.
*/
struct pcap_samp *pcap_setsampling(pcap_t *p);

/*!	\brief Block until a network connection is accepted (active mode only).

	This function has been defined to allow the client dealing with the 'active mode'.
	In other words, in the 'active mode' the server opens the connection toward the
	client, so that the client has to open a socket in order to wait for connections.
	When a new connection is accepted, the RPCAP protocol starts as usual; the only 
	difference is that the connection is initiated by the server.

	This function accepts only ONE connection, then it closes the waiting socket. This means
	that if some error occurs, the application has to call it again in order to accept another
	connection.

	This function returns when a new connection (coming from a valid host 'connectinghost')
	is accepted; it returns error otherwise.

	\param address: a string that keeps the network address we have to bind to; 
	usually it is NULL (it means 'bind on all local addresses').

	\param port: a string that keeps the network port on which we have to bind to; usually
	it is NULL (it means 'bind on the predefined port', i.e. RPCAP_DEFAULT_NETPORT_ACTIVE).

	\param hostlist: a string that keeps the host name of the host from whom we are
	expecting a connection; it can be NULL (it means 'accept connection from everyone').
	Host names are separated by a whatever character in the RPCAP_HOSTLIST_SEP list.

	\param connectinghost: a user-allocated buffer that will contain the name of the host
	is trying to connect to us.
	This variable must be at least RPCAP_HOSTLIST_SIZE bytes..

	\param auth: a pointer to a pcap_rmtauth structure. This pointer keeps the information
	required to authenticate the RPCAP connection to the remote host.

	\param errbuf: a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).

	\return The SOCKET identifier of the new control connection if everything is fine,
	a negative number if some errors occurred. The error message is returned into the errbuf variable.
	In case it returns '-1', this means 'everything is fine', but the host cannot be admitted.
	In case it returns '-2', in means 'unrecoverable error' (for example it is not able to bind the 
	socket, or something like that).
	In case it returns '-3', it means 'authentication failed'. The authentication check is performed
	only if the connecting host is among the ones that are allowed to connect to this host.

	The host that is connecting to us is returned into the hostlist variable, which ust be allocated
	by the user. This variable contains the host name both in case the host is allowed, 
	and in case the connection is refused.

	\warning Although this function returns the socket established by the new control connection,
	this value should not be used. This value will be stored into some libpcap internal
	variables and it will be managed automatically by the library. In other words, all the
	following calls to findalldevs() and pcap_open() will check if the host is among one that
	already has a control connection in place; if so, that one will be used.

	\warning This function has several problems if used inside a thread, which is stopped
	when this call is blocked into the accept(). In this case, the socket on which we accept
	connections is not freed (thread termination is a very dirty job), so that we are no
	longer able to accept other connections until the program (i.e. the process) stops.
	In order to solve the problem, call the pcap_remoteact_cleanup().
*/
SOCKET pcap_remoteact_accept(const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf);

/*!	\brief Drop an active connection (active mode only).

	This function has been defined to allow the client dealing with the 'active mode'.
	This function closes an active connection that is still in place and it purges
	the host name from the 'activeHost' list.
	From this point on, the client will not have any connection with that host in place.

	\param host: a string that keeps the host name of the host for which we want to
	close the active connection.

	\param errbuf: a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).

	\return '0' if everything is fine, '-1' if some errors occurred. The error message is 
	returned into the errbuf variable.
*/
int pcap_remoteact_close(const char *host, char *errbuf);

/*!	\brief Clean the socket that is currently used in waiting active connections.

	This function does a very dirty job. The fact is that is the waiting socket is not
	freed if the pcap_remoteaccept() is killed inside a new thread. This function is
	able to clean the socket in order to allow the next calls to pcap_remoteact_accept() to work.
	
	This function is useful *only* if you launch pcap_remoteact_accept() inside a new thread,
	and you stops (not very gracefully) the thread (for example because the user changed idea,
	and it does no longer want to wait for an active connection).
	So, basically, the flow should be the following:
	- launch a new thread
	- call the pcap_remoteact_accept
	- if this new thread is killed, call pcap_remoteact_cleanup().
	
	This function has no effects in other cases.

	\return None.
*/
void pcap_remoteact_cleanup();

/*!	\brief Return the hostname of the host that have an active connection with us (active mode only).

	This function has been defined to allow the client dealing with the 'active mode'.
	This function returns the list of hosts that are currently having an active connection
	with us. This function is useful in order to delete an active connection that is still
	in place.

	\param hostlist: a user-allocated string that will keep the list of host that are 
	currently connected with us.

	\param sep: the character that has to be sued as a separator between the hosts (','  for example).

	\param size: size of the hostlist buffer.

	\param errbuf: a pointer to a user-allocated buffer (of size PCAP_ERRBUF_SIZE)
	that will contain the error message (in case there is one).

	\return '0' if everything is fine, '-1' if some errors occurred. The error message is 
	returned into the errbuf variable.
*/
int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf);

//\}
// End of Windows-specific extensions



/*@}*/