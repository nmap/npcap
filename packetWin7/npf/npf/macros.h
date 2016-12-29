/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and my not be redistributed or incorporated    *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
 *                                                                         *
 ***************************************************************************/
#ifndef __MACRO
#define __MACRO

#define NPF_CANCEL_ID_LOW_MASK	 (((ULONG_PTR)-1) >> 8)

#define NPF_GET_NEXT_CANCEL_ID()  												 \
	(PVOID)(Globals.PartialCancelId |   										\
	((NdisInterlockedIncrement((PLONG)&Globals.LocalCancelId)) & NPROT_CANCEL_ID_LOW_MASK))

// #define NPFSetNBLFlags(_NBL, _Flags)     (DWORD) ((_NBL)->ProtocolReserved[0]) |= (_Flags)
// #define NPFClearNBLFlags(_NBL, _Flags)   (DWORD) ((_NBL)->ProtocolReserved[0]) &= ~(_Flags)

// #define NPFSetNBLTag(_NBL, _Flags)		 ((_NBL)->ProtocolReserved[2]) = (_Flags)
// #define NPFGetNBLTag(_NBL)				 ((_NBL)->ProtocolReserved[2])

//////////////////////////////////////////////////////////////////////////////////////////////////
// NPF_Write is waiting for NdisWriteCompleteEvent event, which should be
// signaled by NPF_SendCompleteExForEachOpen() function but it was not called
// on some NIC cards / drivers(virtio, Intel(R) PRO / 1000 MT Desktop Adapter)
// 
// It seems that some drivers are using NET_BUFFER_LIST->Scratch pointer for their own
// data, which overwrite NPF information about file handle which is waiting for completion.
// 
// Workaround the issue by not using NET_BUFFER_LIST->Scratch, but ProtocolReserved.
// I'm not 100% if ProtocolReserved information might not be overwriten on some setup,
// so in the future I would recomend rewriting it to use NET_BUFFER_LIST->Context,
// or some other structure for keeping that information.
// 
// For now it seems that workaround is working good.
// #define NPFSetNBLChildOpen(_NBL, _Flags)		 ((_NBL)->Scratch) = (_Flags)
// #define NPFGetNBLChildOpen(_NBL)				 ((_NBL)->Scratch)
#define NPFSetNBLChildOpen(_NBL, _Flags)		 (RESERVED(_NBL)->ChildOpen) = (_Flags)
#define NPFGetNBLChildOpen(_NBL)				 (RESERVED(_NBL)->ChildOpen)
//////////////////////////////////////////////////////////////////////////////////////////////////

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

#endif
