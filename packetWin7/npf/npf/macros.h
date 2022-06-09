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
#ifndef __MACRO
#define __MACRO

/* Trace messages for debug build */
#ifdef DBG
#define PRINT_DBG
#endif

#ifdef PRINT_DBG
#define ERROR_DBG(Fmt, ...)   DbgPrintEx( DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,   __FUNCTION__ ": " Fmt, __VA_ARGS__ )
#define WARNING_DBG(Fmt, ...) DbgPrintEx( DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, __FUNCTION__ ": " Fmt, __VA_ARGS__ )
#define TRACE_DBG(Fmt, ...)   DbgPrintEx( DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL,   __FUNCTION__ ": " Fmt, __VA_ARGS__ )
#define INFO_DBG(Fmt, ...)    DbgPrintEx( DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,    __FUNCTION__ ": " Fmt, __VA_ARGS__ )
#else
#define ERROR_DBG(Fmt, ...)
#define WARNING_DBG(Fmt, ...)
#define TRACE_DBG(Fmt, ...)
#define INFO_DBG(Fmt, ...)
#endif

#define TRACE_ENTER() TRACE_DBG("ENTER\n")
#define TRACE_EXIT()  TRACE_DBG("EXIT\n")

#pragma pack(push)
#pragma pack (1)

/*
* The number of bytes in an Ethernet (MAC) address.
*/
#define	ETHER_ADDR_LEN		6

/*
* The number of bytes in the type field.
*/
#define	ETHER_TYPE_LEN		2

/*
* The length of the combined header.
*/
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)

/*
* Structure of a 10Mb/s Ethernet header.
*/
typedef struct _ETHER_HEADER
{
	UCHAR	ether_dhost[ETHER_ADDR_LEN];
	UCHAR	ether_shost[ETHER_ADDR_LEN];
	USHORT	ether_type;
} ETHER_HEADER, *PETHER_HEADER;

/*
* Types in an Ethernet (MAC) header.
*/
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */

/*
* Structure of a DLT_NULL header.
*/
typedef struct _DLT_NULL_HEADER
{
	UINT	null_type;
} DLT_NULL_HEADER, *PDLT_NULL_HEADER;

/*
* The length of the combined header.
*/
#define	DLT_NULL_HDR_LEN	sizeof(DLT_NULL_HEADER)

/*
* Types in a DLT_NULL (Loopback) header.
*/
#define	DLTNULLTYPE_IP		0x00000002	/* IP protocol */
#define	DLTNULLTYPE_IPV6	0x00000018	/* IPv6 */

#pragma pack(pop)

/* Interlocked API requires destination to be aligned to 32-bit boundaries.
 * These functions just assert that to catch errors */
#define INTERLOCKED_ALIGNMENT_BYTES 4
#define ASSERT_INTERLOCKED_ALIGNED(_ptr) NT_ASSERT(((ULONG_PTR)_ptr) % INTERLOCKED_ALIGNMENT_BYTES == 0)
inline LONG
NpfInterlockedIncrement (
		_Inout_ _Interlocked_operand_ LONG volatile *Addend
		)
{
	ASSERT_INTERLOCKED_ALIGNED(Addend);
	return InterlockedIncrement(Addend);
}

inline LONG
NpfInterlockedDecrement (
		_Inout_ _Interlocked_operand_ LONG volatile *Addend
		)
{
	ASSERT_INTERLOCKED_ALIGNED(Addend);
	return InterlockedDecrement(Addend);
}

inline LONG
NpfInterlockedExchangeAdd (
		_Inout_ _Interlocked_operand_ LONG volatile *Addend,
		_In_ LONG Value
		)
{
	ASSERT_INTERLOCKED_ALIGNED(Addend);
	return InterlockedExchangeAdd(Addend, Value);
}
#endif
