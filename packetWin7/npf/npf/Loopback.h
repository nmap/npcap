/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library
 * and is copyright (c) 2013-2022 by Nmap Software LLC ("The Nmap Project").
 * All rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it
 * is not open source software and may not be redistributed or used in
 * other software without special permission from the Nmap
 * Project. The standard (free) version is usually limited to
 * installation on five systems. For more details, see the LICENSE
 * file included with Npcap and also avaialble at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not
 * a substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap
 * OEM within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may
 * choose between a perpetual unlimited license or a quarterly term license,
 * along with options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to
 * use Npcap OEM internally, without redistribution outside their
 * organization. This allows them to bypass the 5-system usage cap of the
 * Npcap free edition. It includes commercial support and update options, and
 * provides the extra Npcap OEM features such as the silent installer for
 * automated deployment. Prices and details:
 * https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a
 * warranty. Npcap OEM also includes a silent installer for unattended
 * installation. Further details about Npcap OEM are available from
 * https://npcap.com/oem/, and you are also welcome to contact us at
 * sales@nmap.com to ask any questions or set up a license for your
 * organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will
 * be free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial
 * licensing customers) has granted you additional rights to Npcap or
 * Npcap OEM, those additional rights take precedence where they
 * conflict with the terms of the license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features.  By
 * sending these changes to the Nmap Project (including through direct email
 * or our mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap.  If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights and commercial
 * support are available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license
 * header. We have kept those for attribution purposes, but any license terms
 * granted by those notices apply only to their original work, and not to any
 * changes made by the Nmap Project or to this entire file.
 *
 ***************************************************************************/
/*
* Loopback.h
*
* Abstract:
* This file declares common data types and function prototypes used
* throughout loopback packets capturing.
*
* This code is based on Microsoft WFP Network Inspect sample.
*/

#ifndef __LOOPBACK
#define __LOOPBACK

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>

#define IPPROTO_NPCAP_LOOPBACK		250

//
// Protocol headers
//

#pragma pack(push)
#pragma pack (1)

#include "macros.h"

/*
* Structure of a IPv4 header, based on netinet/ip.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP_HEADER
{
	UCHAR     ip_hVerLen;			/* Version (4 bits) + Internet header length (4 bits) */
	UCHAR     ip_TOS;				/* TOS Type of service */
	USHORT    ip_Length;			/* Total length */
	USHORT    ip_ID;				/* Identification */
	USHORT    ip_Flags;				/* Flags (3 bits) + Fragment offset (13 bits) */
	UCHAR     ip_TTL;				/* Time to live */
	UCHAR     ip_Protocol;			/* Protocol */
	USHORT    ip_Checksum;			/* Header checksum */
	ULONG     ip_Src;				/* Source address */
	ULONG     ip_Dst;				/* Destination address */
} IP_HEADER, *PIP_HEADER;

/*
* The length of the IPv4 header.
*/
#define	IP_HDR_LEN		sizeof(IP_HEADER)

/*
* Structure of a IPv6 header, based on netinet/ip6.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP6_HEADER
{
	union
	{
		struct _ip6_HeaderCtl
		{
			ULONG ip6_VerFlow;		/* 4 bits version, 8 bits TC, 20 bits flow-ID */
			USHORT ip6_PLength;		/* Payload length */
			UCHAR ip6_NextHeader;	/* Next header */
			UCHAR ip6_HopLimit;		/* Hop limit */
		} ip6_HeaderCtl;
		UCHAR ip6_VFC;				/* 4 bits version, top 4 bits tclass */
	} ip6_CTL;
	struct in6_addr ip6_Src;		/* Source address */
	struct in6_addr ip6_Dst;		/* Destination address */
} IP6_HEADER, *PIP6_HEADER;

/*
* The length of the IPv6 header.
*/
#define	IPV6_HDR_LEN		sizeof(IP6_HEADER)

/*
* Structure of a ICMP header
* https://www.cymru.com/Documents/ip_icmp.h
*/
typedef struct _ICMP4_HEADER
{
	UCHAR icmp_Type;				/* Message type */
	UCHAR icmp_Code;				/* Type sub-code */
	USHORT icmp_Checksum;
	union
	{
		struct _icmp_Echo
		{
			USHORT	icmp_Id;
			USHORT	icmp_Sequence;
		} icmp_Echo;				/* Echo datagram */
		ULONG	icmp_Gateway;		/* Gateway address */
		struct _icmp_Frag
		{
			USHORT	icmp_Unused;
			USHORT	icmp_Mtu;
		} icmp_Frag;				/* Path MTU discovery */
	} icmp_Un;
} ICMP4_HEADER, *PICMP4_HEADER;

#define ICMP_TYPE_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_CODE_PROT_UNREACH	2	/* Protocol Unreachable		*/

/*
* The length of the IPv6 header.
*/
#define	ICMP_HDR_LEN		sizeof(ICMP4_HEADER)

#pragma pack(pop)

//
// Shared function prototypes
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NPF_RegisterCallouts(
_Inout_ void* deviceObject
	);

_IRQL_requires_(PASSIVE_LEVEL)
void
NPF_UnregisterCallouts(
	);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NPF_InitInjectionHandles(
	);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NPF_FreeInjectionHandles(
	);

#endif // HAVE_WFP_LOOPBACK_SUPPORT

#endif // __LOOPBACK
