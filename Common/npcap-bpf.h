/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2023 by Nmap Software LLC ("The Nmap Project").  All
 * rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it is not
 * open source software and may not be redistributed or used in other software
 * without special permission from the Nmap Project. The standard (free) version
 * is usually limited to installation on five systems. For more details, see the
 * LICENSE file included with Npcap and also available at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not a
 * substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap OEM
 * within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may choose
 * between a perpetual unlimited license or a quarterly term license, along with
 * options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to use
 * Npcap OEM internally, without redistribution outside their organization. This
 * allows them to bypass the 5-system usage cap of the Npcap free edition. It
 * includes commercial support and update options, and provides the extra Npcap
 * OEM features such as the silent installer for automated deployment. Prices
 * and details: https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a warranty.
 * Npcap OEM also includes a silent installer for unattended installation.
 * Further details about Npcap OEM are available from https://npcap.com/oem/,
 * and you are also welcome to contact us at sales@nmap.com to ask any questions
 * or set up a license for your organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will be
 * free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial licensing
 * customers) has granted you additional rights to Npcap or Npcap OEM, those
 * additional rights take precedence where they conflict with the terms of the
 * license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features. By sending
 * these changes to the Nmap Project (including through direct email or our
 * mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap. If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. Warranty rights and commercial support are
 * available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license header.
 * We have kept those for attribution purposes, but any license terms granted by
 * those notices apply only to their original work, and not to any changes made
 * by the Nmap Project or to this entire file.
 *
 ***************************************************************************/
/* Portions of this file
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
 */
#ifndef NPCAP_BPF_H
#define NPCAP_BPF_H

/* These are defined by libpcap's bpf.h, so if that has already been included,
 * we want to avoid redefining them here.
 */
#ifndef lib_pcap_bpf_h

#include <winsock2.h>

/*!
  \brief A BPF pseudo-assembly program.

  The program will be injected in the kernel by the PacketSetBPF() function and applied to every incoming packet. 
*/
struct bpf_program
{
	UINT bf_len; ///< Indicates the number of instructions of the program, i.e. the number of struct bpf_insn that will follow.
#ifdef _Field_size_full_  /* SAL annotation */
	_Field_size_full_(bf_len)
#endif
	struct bpf_insn* bf_insns; ///< A pointer to the first instruction of the program.
};

/*!
  \brief A single BPF pseudo-instruction.

  bpf_insn contains a single instruction for the BPF register-machine. It is used to send a filter program to the driver.
*/
struct bpf_insn
{
	USHORT code; ///< Instruction type and addressing mode.
	UCHAR jt;    ///< Jump if true
	UCHAR jf;    ///< Jump if false
	ULONG k;     ///< Generic field used for various purposes.
};

/*!
  \brief Structure that contains a couple of statistics values on the current capture.

  It is used by packet.dll to return statistics about a capture session.
*/
struct bpf_stat
{
	UINT bs_recv;  ///< Number of packets that the driver received from the network adapter 
	///< from the beginning of the current capture. This value includes the packets 
	///< lost by the driver.
	UINT bs_drop;  ///< number of packets that the driver lost from the beginning of a capture. 
	///< Basically, a packet is lost when the the buffer of the driver is full. 
	///< In this situation the packet cannot be stored and the driver rejects it.
	UINT ps_ifdrop; ///< drops by interface. XXX not yet supported
	UINT bs_capt;	///< number of packets that pass the filter, find place in the kernel buffer and
	///< thus reach the application.
};

/* Current version number of filter architecture. */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*!
  \brief Packet header.

  This structure defines the header associated with every packet delivered to the application.
*/
struct bpf_hdr
{
	struct timeval bh_tstamp; ///< The timestamp associated with the captured packet. 
	///< It is stored in a TimeVal structure.
	UINT bh_caplen;   ///< Length of captured portion. The captured portion <b>can be different</b>
	///< from the original packet, because it is possible (with a proper filter)
	///< to instruct the driver to capture only a portion of the packets.
	UINT bh_datalen;  ///< Original length of packet
	USHORT bh_hdrlen; ///< Length of bpf header (this struct plus alignment padding). In some cases,
	///< a padding could be added between the end of this structure and the packet
	///< data for performance reasons. This filed can be used to retrieve the actual data 
	///< of the packet.
};

/*!
  \brief Dump packet header.

  This structure defines the header associated with the packets in a buffer to be used with PacketSendPackets().
  It is simpler than the bpf_hdr, because it corresponds to the header in the pcap-savefile(5) format.
  This makes straightforward sending WinPcap dump files to the network.
*/
struct dump_bpf_hdr
{
	struct timeval ts; ///< Time stamp of the packet
	UINT caplen; ///< Length of captured portion. The captured portion can smaller than the 
	///< the original packet, because it is possible (with a proper filter) to 
	///< instruct the driver to capture only a portion of the packets. 
	UINT len; ///< Length of the original packet (off wire).
};

#endif /* lib_pcap_bpf_h */

/* BPF extensions */
/* Special offsets to mimic Linux kernel's BPF extensions.
 * The names are taken directly from Linux in order to allow libpcap's
 * gencode.c to use the same code for both, but the values are different.
 */
/* The base offset for these extensions */
#define SKF_AD_OFF (-0x1000)
/* The extensions are numbered in the order they were added.
 * Since they are treated like offsets, we space them by 4 to avoid the
 * appearance of reading overlapped memory segments.
 * User can issue BIOCGETINFO(NPF_GETINFO_BPFEXT) to retrieve the value of
 * SKF_AD_MAX, and any extension less than or equal to that value will be
 * supported.
 */
/* Halfword (2 bytes) representing the 802.1q header. */
#define SKF_AD_VLAN_TAG 0
/* Boolean: is there VLAN metadata present? Currently, we cannot distinguish VLAN
 * 0 and priority class 0 (both defaults) from the case of no VLAN tag present,
 * so this will return false in that case. */
#define SKF_AD_VLAN_TAG_PRESENT 4
#define SKF_AD_MAX 4

#endif /* NPCAP_BPF_H */
