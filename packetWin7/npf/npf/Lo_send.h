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
/*
* Lo_send.h
*
* Abstract:
* This file declares common data types and function prototypes used
* throughout loopback packets sending.
*
* This code is based on Microsoft Winsock Kernel echosrv sample and
* Google Code wskudp sample.
*/

#ifndef __LO_SEND
#define __LO_SEND

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#pragma once
#include <ntddk.h>
#include <wsk.h>
#include <ndis.h>

#pragma warning(pop)

#define SOCKET_ERROR -1

NTSTATUS
NTAPI
NPF_WSKInitSockets(
	);

VOID
NTAPI
NPF_WSKFreeSockets(
	);

NTSTATUS
NTAPI
NPF_WSKStartup(
	);

VOID
NTAPI
NPF_WSKCleanup(
	);

// NTSTATUS
// NTAPI
// NPF_WSKSendPacket(
// 	IN PCHAR PacketBuff,
// 	IN ULONG BuffSize
// 	);
// 
// NTSTATUS
// NTAPI
// WSKSendPacketInternal(
// 	IN BOOLEAN bIPv4,
// 	IN PCHAR PacketBuff,
// 	IN ULONG BuffSize
// 	);

NTSTATUS
NTAPI
NPF_WSKSendPacket_NBL(
	IN PNET_BUFFER_LIST NetBufferList
	);

NTSTATUS
NTAPI
WSKSendPacketInternal_NBL(
	IN BOOLEAN bIPv4,
	IN PNET_BUFFER_LIST NetBufferList,
	IN ULONG Offset
	);

PWSK_SOCKET
NTAPI
WSKCreateSocket(
	IN ADDRESS_FAMILY AddressFamily,
	IN USHORT SocketType,
	IN ULONG Protocol,
	IN ULONG Flags
	);

NTSTATUS
NTAPI
WSKCloseSocket(
	IN PWSK_SOCKET WskSocket
	);

// LONG
// NTAPI
// WSKSend(
// 	IN PWSK_SOCKET WskSocket,
// 	IN PVOID Buffer,
// 	IN ULONG BufferSize,
// 	IN ULONG Flags
// 	);
// 
// LONG
// NTAPI
// WSKSendTo(
// 	IN PWSK_SOCKET WskSocket,
// 	IN PVOID Buffer,
// 	IN ULONG BufferSize,
// 	__in_opt PSOCKADDR RemoteAddress
// 	);

LONG
NTAPI
WSKSendTo_NBL(
	IN PWSK_SOCKET WskSocket,
	IN PNET_BUFFER_LIST NetBufferList,
	IN ULONG BufferOffset,
	__in_opt PSOCKADDR RemoteAddress
	);

NTSTATUS
NTAPI
WSKBind(
	IN PWSK_SOCKET WskSocket,
	IN PSOCKADDR LocalAddress
	);

#endif // HAVE_WFP_LOOPBACK_SUPPORT

#endif // __LO_SEND
