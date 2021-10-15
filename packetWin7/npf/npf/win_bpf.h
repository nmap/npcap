/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence 
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  	This product includes software developed by the University of
 *  	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  	@(#)bpf.h   	7.1 (Berkeley) 5/7/91
 *
 */

#ifndef BPF_MAJOR_VERSION

/* BSD style release date */
#define BPF_RELEASE 199606

#ifdef WIN_NT_DRIVER
#include <ndis.h>
#include "time_calls.h"
#endif

typedef	UCHAR u_char;
typedef	USHORT u_short;

#ifdef WIN_NT_DRIVER
typedef	ULONG u_int;
#endif

typedef	LONG bpf_int32;
typedef	ULONG bpf_u_int32;
typedef	ULONG u_int32;

#define BPF_MAXINSNS 512
#define BPF_MAXBUFSIZE 0x8000
#define BPF_MINBUFSIZE 32

/*
 * The instruction data structure.
 */
struct bpf_insn
{
	u_short code;
	u_char jt;
	u_char jf;
	bpf_u_int32 k;
};

/*
 *  Structure for BIOCSETF.
 */
struct bpf_program
{
	u_int bf_len;
	struct bpf_insn* bf_insns;
};

/*
 * Struct returned by BIOCGSTATS.
 */
struct bpf_stat
{
	UINT bs_recv;		///< Number of packets that the driver received from the network adapter 
	///< from the beginning of the current capture. This value includes the packets 
	///< lost by the driver.
	UINT bs_drop;		///< number of packets that the driver lost from the beginning of a capture. 
	///< Basically, a packet is lost when the the buffer of the driver is full. 
	///< In this situation the packet cannot be stored and the driver rejects it.
	UINT ps_ifdrop;		///< drops by interface. XXX not yet supported
	UINT bs_capt;		///< number of packets that pass the filter, find place in the kernel buffer and
	///< thus reach the application.
};

/*
 * Struct return by BIOCVERSION.  This represents the version number of 
 * the filter language described by the instruction encodings below.
 * bpf understands a program iff kernel_major == filter_major &&
 * kernel_minor >= filter_minor, that is, if the value returned by the
 * running kernel has the same major number and a minor number equal
 * equal to or less than the filter being downloaded.  Otherwise, the
 * results are undefined, meaning an error may be returned or packets
 * may be accepted haphazardly.
 * It has nothing to do with the source code version.
 */
struct bpf_version
{
	u_short bv_major;
	u_short bv_minor;
};
/* Current version number of filter architecture. */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1


/*
 * Structure prepended to each packet.
 */
struct bpf_hdr
{
	struct timeval bh_tstamp;	/* time stamp */
	bpf_u_int32 bh_caplen;	/* length of captured portion */
	bpf_u_int32 bh_datalen;	/* original length of packet */
	u_short bh_hdrlen;	/* length of bpf header (this struct
						 plus alignment padding) */
};

/*!
  \brief Dump packet header.

  This structure defines the header associated with the packets in a buffer to be used with PacketSendPackets().
  It is simpler than the bpf_hdr, because it corresponds to the header in the pcap-savefile(5) format.
  This makes straightforward sending pcap dump files to the network.
*/
struct dump_bpf_hdr
{
	struct timeval ts;			///< Time stamp of the packet
	UINT caplen;		///< Length of captured portion. The captured portion can smaller than the 
	///< the original packet, because it is possible (with a proper filter) to 
	///< instruct the driver to capture only a portion of the packets. 
	UINT len;		///< Length of the original packet (off wire).
};


/*
 * Data-link level type codes.
 */

/*
 * These are the types that are the same on all platforms; on other
 * platforms, a <net/bpf.h> should be supplied that defines the additional
 * DLT_* codes appropriately for that platform (the BSDs, for example,
 * should not just pick up this version of "bpf.h"; they should also define
 * the additional DLT_* codes used by their kernels, as well as the values
 * defined here - and, if the values they use for particular DLT_ types
 * differ from those here, they should use their values, not the ones
 * here).
 */
#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */

/*
 * These are values from the traditional libpcap "bpf.h".
 * Ports of this to particular platforms should replace these definitions
 * with the ones appropriate to that platform, if the values are
 * different on that platform.
 */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_RAW		12	/* raw IP */

/*
 * These are values from BSD/OS's "bpf.h".
 * These are not the same as the values from the traditional libpcap
 * "bpf.h"; however, these values shouldn't be generated by any
 * OS other than BSD/OS, so the correct values to use here are the
 * BSD/OS values.
 *
 * Platforms that have already assigned these values to other
 * DLT_ codes, however, should give these codes the values
 * from that platform, so that programs that use these codes will
 * continue to compile - even though they won't correctly read
 * files of these types.
 */
#define DLT_SLIP_BSDOS	15	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	16	/* BSD/OS Point-to-point Protocol */

#define DLT_ATM_CLIP	19	/* Linux Classical-IP over ATM */

/*
 * This value is defined by NetBSD; other platforms should refrain from
 * using it for other purposes, so that NetBSD savefiles with a link
 * type of 50 can be read as this type on all platforms.
 */
#define DLT_PPP_SERIAL	50	/* PPP over serial with HDLC encapsulation */

/*
 * This value was defined by libpcap 0.5; platforms that have defined
 * it with a different value should define it here with that value -
 * a link type of 104 in a save file will be mapped to DLT_C_HDLC,
 * whatever value that happens to be, so programs will correctly
 * handle files with that link type regardless of the value of
 * DLT_C_HDLC.
 *
 * The name DLT_C_HDLC was used by BSD/OS; we use that name for source
 * compatibility with programs written for BSD/OS.
 *
 * libpcap 0.5 defined it as DLT_CHDLC; we define DLT_CHDLC as well,
 * for source compatibility with programs written for libpcap 0.5.
 */
#define DLT_C_HDLC	104	/* Cisco HDLC */
#define DLT_CHDLC	DLT_C_HDLC

/*
 * Reserved for future use.
 * Do not pick other numerical value for these unless you have also
 * picked up the tcpdump.org top-of-CVS-tree version of "savefile.c",
 * which will arrange that capture files for these DLT_ types have
 * the same "network" value on all platforms, regardless of what
 * value is chosen for their DLT_ type (thus allowing captures made
 * on one platform to be read on other platforms, even if the two
 * platforms don't use the same numerical values for all DLT_ types).
 */
#define DLT_IEEE802_11	105	/* IEEE 802.11 wireless */

/*
 * Values between 106 and 107 are used in capture file headers as
 * link-layer types corresponding to DLT_ types that might differ
 * between platforms; don't use those values for new DLT_ new types.
 */

/*
 * OpenBSD DLT_LOOP, for loopback devices; it's like DLT_NULL, except
 * that the AF_ type in the link-layer header is in network byte order.
 *
 * OpenBSD defines it as 12, but that collides with DLT_RAW, so we
 * define it as 108 here.  If OpenBSD picks up this file, it should
 * define DLT_LOOP as 12 in its version, as per the comment above -
 * and should not use 108 for any purpose.
 */
#define DLT_LOOP	108

/*
 * Values between 109 and 112 are used in capture file headers as
 * link-layer types corresponding to DLT_ types that might differ
 * between platforms; don't use those values for new DLT_ new types.
 */

/*
 * This is for Linux cooked sockets.
 */
#define DLT_LINUX_SLL	113

/*
 * The instruction encodings.
 */
/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC	0x07

/* ld/ldx fields */
#define BPF_SIZE(code)	((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)	((code) & 0xe0)
#define		BPF_IMM 	0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)	((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET	0x40
#define BPF_SRC(code)	((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)	((code) & 0x18)
#define		BPF_A		0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define		BPF_TAX		0x00
#define		BPF_TXA		0x80

/* TME instructions */
#define		BPF_TME					0x08

#define		BPF_LOOKUP				0x90   
#define		BPF_EXECUTE				0xa0
#define		BPF_INIT				0xb0
#define		BPF_VALIDATE			0xc0
#define		BPF_SET_ACTIVE			0xd0
#define		BPF_RESET				0xe0
#define		BPF_SET_MEMORY			0x80
#define		BPF_GET_REGISTER_VALUE	0x70
#define		BPF_SET_REGISTER_VALUE	0x60
#define		BPF_SET_WORKING			0x50
#define		BPF_SET_ACTIVE_READ		0x40
#define		BPF_SET_AUTODELETION	0x30
#define		BPF_SEPARATION			0xff

#define		BPF_MEM_EX_IMM	0xc0
#define		BPF_MEM_EX_IND	0xe0
/*used for ST */
#define		BPF_MEM_EX		0xc0


/*
 * Macros for insn array initializers.
 */
#define BPF_STMT(code, k) { (u_short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (u_short)(code), jt, jf, k }

/*
 * Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
 */
#define BPF_MEMWORDS 16

#ifdef __cplusplus
extern "C"
{
#endif

	/*!
	  \brief Validates a filtering program arriving from the user-level app.
	  \param f The filter.
	  \param len Its length, in pseudo instructions.
	  \param mem_ex_size The length of the extended memory, used to validate LD/ST to that memory
	  \return true if f is a valid filter program..
	  
	  The kernel needs to be able to verify an application's filter code. Otherwise, a bogus program could easily 
	  crash the system.
	  This function returns true if f is a valid filter program. The constraints are that each jump be forward and 
	  to a valid code.  The code must terminate with either an accept or reject. 
	*/
	int bpf_validate(struct bpf_insn* f, int len);

	/*!
	  \brief The filtering pseudo-machine interpreter.
	  \param pc The filter.
	  \param p Pointer to a Memory Descriptor List (MDL) containing the packet on which the filter will be executed.
	  \param data_offset The offset to the start of the used data space in the NET_BUFFER structure
	  \param wirelen Original length of the packet.
	  \return The portion of the packet to keep, in bytes. 0 means that the packet must be rejected, -1 means that
	   the whole packet must be kept.
	*/
#ifdef WIN_NT_DRIVER
	u_int bpf_filter(const struct bpf_insn* pc, const PMDL p, u_int data_offset, u_int wirelen);
#else
	u_int bpf_filter(register struct bpf_insn *pc,
		register UCHAR *p,
		u_int wirelen,
		register u_int buflen);
#endif //WIN_NT_DRIVER

#ifdef __cplusplus
}
#endif


#endif
