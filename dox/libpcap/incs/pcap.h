/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 * @(#) $Header: /usr/cvsroot_private/winpcap/dox/libpcap/incs/pcap.h,v 1.5 2005/11/30 21:48:23 gianlucav Exp $ (LBL)
 */


/** @defgroup wpcap_def Definitions
 *  @ingroup wpcap
 *  Definitions for wpcap.dll
 *  @{
 */

#ifndef lib_pcap_h
#define lib_pcap_h

#include <pcap-stdinc.h>
#include <net/bpf.h>

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_VERSION_MAJOR 2 ///< Major libpcap dump file version. 
#define PCAP_VERSION_MINOR 4 ///< Minor libpcap dump file version. 

#define PCAP_ERRBUF_SIZE 256 ///< Size to use when allocating the buffer that contains the libpcap errors.

/*!
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
typedef	int bpf_int32; ///< 32-bit integer
typedef	u_int bpf_u_int32; ///< 32-bit unsigned integer
#endif

typedef struct pcap pcap_t; ///< Descriptor of an open capture instance. This structure is \b opaque to the user, that handles its content through the functions provided by wpcap.dll.
typedef struct pcap_dumper pcap_dumper_t; ///< libpcap savefile descriptor.
typedef struct pcap_if pcap_if_t; ///< Item in a list of interfaces, see pcap_if
typedef struct pcap_addr pcap_addr_t; ///< Representation of an interface address, see pcap_addr

/*! \brief Header of a libpcap dump file.
 *
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 *
 * Do not change the layout of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 *
 * Also, do not change the interpretation of any of the members of this
 * structure, in any way (this includes using values other than
 * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
 * field).
 *
 * Instead:
 *
 *	introduce a new structure for the new format, if the layout
 *	of the structure changed;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed file
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old file header as well as files with the new file header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major; ///< Libpcap major version.  
	u_short version_minor; ///< Libpcap minor version. 
	bpf_int32 thiszone;	///< gmt to local correction
	bpf_u_int32 sigfigs;	///< accuracy of timestamps
	bpf_u_int32 snaplen;	///< max length saved portion of each pkt
	bpf_u_int32 linktype;	///< data link type (LINKTYPE_*)
};

/*! \brief Header of a packet in the dump file.
 *
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkthdr {
	struct timeval ts;	///< time stamp
	bpf_u_int32 caplen;	///< length of portion present
	bpf_u_int32 len;	///< length this packet (off wire)
};

/*! \brief Structure that keeps statistical values on an interface.
 *
 * As returned by the pcap_stats()
 */
struct pcap_stat {
	u_int ps_recv;		///< number of packets transited on the network
	u_int ps_drop;		///< number of packets dropped by the driver
	u_int ps_ifdrop;	///< drops by interface, not yet supported
#ifdef WIN32
	u_int bs_capt;		///< <b>Win32 specific.</b> number of packets captured, i.e number of packets that are accepted by the filter, that find place in the kernel buffer and therefore that actually reach the application. For backward compatibility, pcap_stats() does not fill this member, so use pcap_stats_ex() to get it.
#endif /* WIN32 */
};

/*! \brief
 * Item in a list of interfaces, used by pcap_findalldevs().
 */
struct pcap_if {
	struct pcap_if *next; ///< if not NULL, a pointer to the next element in the list; NULL for the last element of the list
	char *name;		///< a pointer to a string giving a name for the device to pass to pcap_open_live()
	char *description;	///< if not NULL, a pointer to a string giving a human-readable description of the device
	struct pcap_addr *addresses; ///< a pointer to the first element of a list of addresses for the interface
	u_int flags;		///< PCAP_IF_ interface flags. Currently the only possible flag is \b PCAP_IF_LOOPBACK, that is set if the interface is a loopback interface.
};

#define PCAP_IF_LOOPBACK	0x00000001	///< interface is loopback

/*! \brief
 * Representation of an interface address, used by pcap_findalldevs().
 */
struct pcap_addr {
	struct pcap_addr *next; ///<  if not NULL, a pointer to the next element in the list; NULL for the last element of the list
	struct sockaddr *addr;		///< a pointer to a struct sockaddr containing an address
	struct sockaddr *netmask;	///< if not NULL, a pointer to a struct sockaddr that contains the netmask corresponding to the address pointed to by addr.
	struct sockaddr *broadaddr;	///< if not NULL, a pointer to a struct sockaddr that contains the broadcast address corre­ sponding to the address pointed to by addr; may be null if the interface doesn't support broadcasts
	struct sockaddr *dstaddr;	///< if not NULL, a pointer to a struct sockaddr that contains the destination address corre­ sponding to the address pointed to by addr; may be null if the interface isn't a point- to-point interface
};

#if defined(WIN32)


#define MODE_CAPT 0	///< Capture mode, to be used when calling pcap_setmode()
#define MODE_STAT 1	///< Statistical mode, to be used when calling pcap_setmode()

#endif /* WIN32 */

#ifdef __cplusplus
}
#endif

#endif

/**
 *  @}
 */
