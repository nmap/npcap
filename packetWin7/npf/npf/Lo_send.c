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
* Lo_send.c
*
* Abstract:
* This file declares common data types and function prototypes used
* throughout loopback packets sending.
*
* This code is based on Microsoft Winsock Kernel echosrv sample and
* Google Code wskudp sample.
*/

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#include "stdafx.h"

#include "Loopback.h"
#include "Lo_send.h"
#include "debug.h"

#define NPF_LOOPBACK_SEND_TYPE_IPV4		1
#define NPF_LOOPBACK_SEND_TYPE_IPV6		0

#define LOG_PORT						3000
#define HTON_SHORT(n)					(((((unsigned short)(n) & 0xFFu  )) << 8) | \
										(((unsigned short)(n) & 0xFF00u) >> 8))
#define HTON_LONG(x)					(((((x)& 0xff)<<24) | ((x)>>24) & 0xff) | \
										(((x) & 0xff0000)>>8) | (((x) & 0xff00)<<8))

extern ULONG					g_DltNullMode;

static WSK_REGISTRATION         g_WskRegistration;
static WSK_PROVIDER_NPI         g_WskProvider;
static WSK_CLIENT_DISPATCH      g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };

PWSK_SOCKET						g_IPv4Socket = NULL;
SOCKADDR_IN						g_IPv4LocalAddress = { 0, };
SOCKADDR_IN						g_IPv4RemoteAddress = { 0, };
PWSK_SOCKET						g_IPv6Socket = NULL;
SOCKADDR_IN6					g_IPv6LocalAddress = { 0, };
SOCKADDR_IN6					g_IPv6RemoteAddress = { 0, };

enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

static LONG g_SocketsState = DEINITIALIZED;


NTSTATUS
NTAPI
NPF_WSKInitSockets(
	)
{
	NTSTATUS		status = STATUS_SUCCESS;

	TRACE_ENTER();

	// IPv4 Socket Initialization
	g_IPv4Socket = WSKCreateSocket(AF_INET, SOCK_RAW, IPPROTO_NPCAP_LOOPBACK, WSK_FLAG_DATAGRAM_SOCKET);
	if (g_IPv4Socket == NULL)
	{
		status = STATUS_UNSUCCESSFUL;
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKInitSockets()::WSKCreateSocket() failed with status 0x%08X\n", status);
		TRACE_EXIT();
		return status;
	}

	g_IPv4LocalAddress.sin_family = AF_INET;
	g_IPv4LocalAddress.sin_addr.s_addr = INADDR_ANY;
	// g_IPv4LocalAddress.sin_port = INADDR_PORT;

	// Bind Required
	status = WSKBind(g_IPv4Socket, (PSOCKADDR) &g_IPv4LocalAddress);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKInitSockets()::WSKBind() failed with status 0x%08X\n", status);
		WSKCloseSocket(g_IPv4Socket);
		TRACE_EXIT();
		return status;
	}

	g_IPv4RemoteAddress.sin_family = AF_INET;
	g_IPv4RemoteAddress.sin_addr.s_addr = HTON_LONG(INADDR_LOOPBACK);
	// g_IPv4RemoteAddress.sin_port = HTON_SHORT(LOG_PORT);

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// IPv6 Socket Initialization
	g_IPv6Socket = WSKCreateSocket(AF_INET6, SOCK_RAW, IPPROTO_NPCAP_LOOPBACK, WSK_FLAG_DATAGRAM_SOCKET);
	if (g_IPv6Socket == NULL)
	{
		status = STATUS_UNSUCCESSFUL;
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKInitSockets()::WSKCreateSocket() failed with status 0x%08X\n", status);
		TRACE_EXIT();
		return status;
	}

	g_IPv6LocalAddress.sin6_family = AF_INET6;
	struct in6_addr in6AnyAddr = IN6ADDR_ANY_INIT;
	g_IPv6LocalAddress.sin6_addr = in6AnyAddr;
	// g_IPv6LocalAddress.sin_port = INADDR_PORT;

	// Bind Required
	status = WSKBind(g_IPv6Socket, (PSOCKADDR) &g_IPv6LocalAddress);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKInitSockets()::WSKBind() failed with status 0x%08X\n", status);
		WSKCloseSocket(g_IPv6Socket);
		TRACE_EXIT();
		return status;
	}

	g_IPv6RemoteAddress.sin6_family = AF_INET6;
	struct in6_addr in6LoopbackAddr = IN6ADDR_LOOPBACK_INIT;
	g_IPv6RemoteAddress.sin6_addr = in6LoopbackAddr;
	// g_IPv6RemoteAddress.sin_port = HTON_SHORT(LOG_PORT);

	TRACE_EXIT();
	return status;
}

VOID
NTAPI
NPF_WSKFreeSockets(
	)
{
	TRACE_ENTER();

	if (g_IPv4Socket)
	{
		WSKCloseSocket(g_IPv4Socket);
		g_IPv4Socket = NULL;
	}

	if (g_IPv6Socket)
	{
		WSKCloseSocket(g_IPv6Socket);
		g_IPv6Socket = NULL;
	}

	TRACE_EXIT();
}

//
// Library initialization routine
//

NTSTATUS
NTAPI
NPF_WSKStartup(
	)
{
	WSK_CLIENT_NPI	WskClient = {0};
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZING, DEINITIALIZED) != DEINITIALIZED)
		return STATUS_ALREADY_REGISTERED;

	WskClient.ClientContext = NULL;
	WskClient.Dispatch = &g_WskDispatch;

	Status = WskRegister(&WskClient, &g_WskRegistration);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKStartup()::WskRegister() failed with status 0x%08X\n", Status);
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		TRACE_EXIT();
		return Status;
	}

	Status = WskCaptureProviderNPI(&g_WskRegistration, WSK_NO_WAIT, &g_WskProvider);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKStartup()::WskCaptureProviderNPI() failed with status 0x%08X\n", Status);
		WskDeregister(&g_WskRegistration);
		InterlockedExchange(&g_SocketsState, DEINITIALIZED);
		TRACE_EXIT();
		return Status;
	}

	InterlockedExchange(&g_SocketsState, INITIALIZED);
	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//
// Library deinitialization routine
//

VOID
NTAPI
NPF_WSKCleanup(
	)
{
	TRACE_ENTER();
	if (InterlockedCompareExchange(&g_SocketsState, INITIALIZED, DEINITIALIZING) != INITIALIZED)
	{
		TRACE_EXIT();
		return;
	}

	WskReleaseProviderNPI(&g_WskRegistration);
	WskDeregister(&g_WskRegistration);

	InterlockedExchange(&g_SocketsState, DEINITIALIZED);
	TRACE_EXIT();
}

// NTSTATUS
// NTAPI
// NPF_WSKSendPacket(
// 	IN PCHAR PacketBuff,
// 	IN ULONG BuffSize
// 	)
// {
// 	PETHER_HEADER		pEthernetHdr = (PETHER_HEADER) PacketBuff;
// 	PDLT_NULL_HEADER	pDltNullHdr = (PDLT_NULL_HEADER) PacketBuff;
// 	NTSTATUS			status = STATUS_UNSUCCESSFUL;
// 
// 	TRACE_ENTER();
// 	
// 	if (g_DltNullMode)
// 	{
// 		if (pDltNullHdr->null_type == DLTNULLTYPE_IP)
// 		{
// 			status = WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV4, PacketBuff + DLT_NULL_HDR_LEN, BuffSize - DLT_NULL_HDR_LEN);
// 		}
// 		else if (pDltNullHdr->null_type == DLTNULLTYPE_IPV6)
// 		{
// 			status = WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV6, PacketBuff + DLT_NULL_HDR_LEN, BuffSize - DLT_NULL_HDR_LEN);
// 		}
// 		else
// 		{
// 			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket() failed with status 0x%08X, not valid loopback IPv4 or IPv6 packet (DLT_NULL)\n", status);
// 		}
// 	}
// 	else
// 	{
// 		if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IP))
// 		{
// 			status = WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV4, PacketBuff + ETHER_HDR_LEN, BuffSize - ETHER_HDR_LEN);
// 		}
// 		else if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IPV6))
// 		{
// 			status = WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV6, PacketBuff + ETHER_HDR_LEN, BuffSize - ETHER_HDR_LEN);
// 		}
// 		else
// 		{
// 			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket() failed with status 0x%08X, not valid loopback IPv4 or IPv6 packet (Ethernet)\n", status);
// 		}
// 	}
// 
// 	TRACE_EXIT();
// 	return status;
// }
// 
// NTSTATUS
// NTAPI
// WSKSendPacketInternal(
// 	IN BOOLEAN bIPv4,
// 	IN PCHAR PacketBuff,
// 	IN ULONG BuffSize
// 	)
// {
// 	NTSTATUS		status = STATUS_SUCCESS;
// 	ULONG			SentBytes;
// 
// 	TRACE_ENTER();
// 
// 	SentBytes = bIPv4 ?
// 		WSKSendTo(g_IPv4Socket, PacketBuff, BuffSize, (PSOCKADDR)& g_IPv4RemoteAddress) :
// 		WSKSendTo(g_IPv6Socket, PacketBuff, BuffSize, (PSOCKADDR)& g_IPv6RemoteAddress);
// 
// 	if (SentBytes != BuffSize)
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendPacketInternal()::WSKSendTo() failed with SentBytes 0x%08X\n", SentBytes);
// 	}
// 
// 	TRACE_EXIT();
// 	return status;
// }

NTSTATUS
NTAPI
NPF_WSKSendPacket_NBL(
	IN PNET_BUFFER_LIST NetBufferList
	)
{
	PMDL				pMdl = NULL;
	ULONG				BuffSize;
	PETHER_HEADER		pEthernetHdr;
	PDLT_NULL_HEADER	pDltNullHdr;
	NTSTATUS			status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	pMdl = NetBufferList->FirstNetBuffer->CurrentMdl;
	if (pMdl)
	{
		NdisQueryMdl(
			pMdl,
			&pEthernetHdr,
			&BuffSize,
			NormalPagePriority);
		pDltNullHdr = (PDLT_NULL_HEADER) pEthernetHdr;
	}
	else
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket_NBL()::NetBufferList->FirstNetBuffer->CurrentMdl failed with pMdl 0x%08X\n", pMdl);

		TRACE_EXIT();
		return status;
	}

	if (pEthernetHdr == NULL)
	{
		//
		//  The system is low on resources. Set up to handle failure
		//  below.
		//
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket_NBL()::NdisQueryMdl() failed with pEthernetHdr 0x%08X\n", pEthernetHdr);

		TRACE_EXIT();
		return status;
	}

	if (g_DltNullMode)
	{
		if (pDltNullHdr->null_type == DLTNULLTYPE_IP)
		{
			status = WSKSendPacketInternal_NBL(NPF_LOOPBACK_SEND_TYPE_IPV4, NetBufferList, DLT_NULL_HDR_LEN);
		}
		else if (pDltNullHdr->null_type == DLTNULLTYPE_IPV6)
		{
			status = WSKSendPacketInternal_NBL(NPF_LOOPBACK_SEND_TYPE_IPV6, NetBufferList, DLT_NULL_HDR_LEN);
		}
		else
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket_NBL() failed with status 0x%08X, not valid loopback IPv4 or IPv6 packet (DLT_NULL)\n", status);
		}
	}
	else
	{
		if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IP))
		{
			status = WSKSendPacketInternal_NBL(NPF_LOOPBACK_SEND_TYPE_IPV4, NetBufferList, ETHER_HDR_LEN);
		}
		else if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IPV6))
		{
			status = WSKSendPacketInternal_NBL(NPF_LOOPBACK_SEND_TYPE_IPV6, NetBufferList, ETHER_HDR_LEN);
		}
		else
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket_NBL() failed with status 0x%08X, not valid loopback IPv4 or IPv6 packet\n", status);
		}
	}

	TRACE_EXIT();
	return status;
}

NTSTATUS
NTAPI
WSKSendPacketInternal_NBL(
	IN BOOLEAN bIPv4,
	IN PNET_BUFFER_LIST NetBufferList,
	IN ULONG Offset
	)
{
	NTSTATUS		status = STATUS_SUCCESS;
	ULONG			SentBytes;

	TRACE_ENTER();

	SentBytes = bIPv4 ?
		WSKSendTo_NBL(g_IPv4Socket, NetBufferList, Offset, (PSOCKADDR)& g_IPv4RemoteAddress) :
		WSKSendTo_NBL(g_IPv6Socket, NetBufferList, Offset, (PSOCKADDR)& g_IPv6RemoteAddress);

	if (SentBytes != NetBufferList->FirstNetBuffer->DataLength - Offset)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendPacketInternal_NBL()::WSKSendTo_NBL() failed with SentBytes 0x%08X\n", SentBytes);
	}

	TRACE_EXIT();
	return status;
}

static
NTSTATUS
NTAPI
CompletionRoutine(
IN PDEVICE_OBJECT 		DeviceObject,
IN PIRP                   Irp,
IN PKEVENT                CompletionEvent
)
{
	ASSERT(CompletionEvent);

	UNREFERENCED_PARAMETER(Irp);
	UNREFERENCED_PARAMETER(DeviceObject);

	TRACE_ENTER();

	KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	TRACE_EXIT();
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
InitWskData(
	OUT PIRP* pIrp,
	OUT PKEVENT CompletionEvent
	)
{
	ASSERT(pIrp);
	ASSERT(CompletionEvent);

	TRACE_ENTER();

	*pIrp = IoAllocateIrp(1, FALSE);
	if (!*pIrp)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "InitWskData()::IoAllocateIrp() failed with status 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*pIrp, CompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);
	TRACE_EXIT();
	return STATUS_SUCCESS;
}

// static
// NTSTATUS
// InitWskBuffer(
// 	IN PVOID Buffer,
// 	IN ULONG BufferSize,
// 	OUT PWSK_BUF WskBuffer
// 	)
// {
// 	NTSTATUS Status = STATUS_SUCCESS;
// 
// 	TRACE_ENTER();
// 
// 	ASSERT(Buffer);
// 	ASSERT(BufferSize);
// 	ASSERT(WskBuffer);
// 
// 	WskBuffer->Offset = 0;
// 	WskBuffer->Length = BufferSize;
// 
// 	WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
// 	if (!WskBuffer->Mdl)
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "InitWskBuffer()::IoAllocateMdl() failed with status 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
// 		TRACE_EXIT();
// 		return STATUS_INSUFFICIENT_RESOURCES;
// 	}
// 
// 	__try
// 	{
// 		if ((WskBuffer->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) != MDL_MAPPED_TO_SYSTEM_VA &&
// 			(WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) != MDL_PAGES_LOCKED &&
// 			(WskBuffer->Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != MDL_SOURCE_IS_NONPAGED_POOL)
// 		{
// 			MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
// 		}
// 	}
// 	__except (EXCEPTION_EXECUTE_HANDLER)
// 	{
// 		TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "InitWskBuffer()::MmProbeAndLockPages(%p) failed with status 0x%08X\n", Buffer, STATUS_ACCESS_VIOLATION);
// 		IoFreeMdl(WskBuffer->Mdl);
// 		Status = STATUS_ACCESS_VIOLATION;
// 	}
// 
// 	TRACE_EXIT();
// 	return Status;
// }
// 
// static
// VOID
// FreeWskBuffer(
// 	IN PWSK_BUF WskBuffer
// 	)
// {
// 	ASSERT(WskBuffer);
// 
// 	TRACE_ENTER();
// 
// 	if ((WskBuffer->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) != MDL_MAPPED_TO_SYSTEM_VA &&
// 		(WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) != MDL_PAGES_LOCKED &&
// 		(WskBuffer->Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != MDL_SOURCE_IS_NONPAGED_POOL)
// 	{
// 		MmUnlockPages(WskBuffer->Mdl);
// 	}
// 	IoFreeMdl(WskBuffer->Mdl);
// 	TRACE_EXIT();
// }

static
NTSTATUS
InitWskBuffer_NBL(
	IN PNET_BUFFER_LIST NetBufferList,
	IN ULONG BufferOffset,
	OUT PWSK_BUF WskBuffer
	)
{
	NTSTATUS Status = STATUS_SUCCESS;

	TRACE_ENTER();

	ASSERT(NetBufferList);
	ASSERT(WskBuffer);

	WskBuffer->Offset = BufferOffset;
	WskBuffer->Length = NetBufferList->FirstNetBuffer->DataLength - BufferOffset;

	WskBuffer->Mdl = NetBufferList->FirstNetBuffer->CurrentMdl;
	if (!WskBuffer->Mdl)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "InitWskBuffer_NBL()::NetBufferList->FirstNetBuffer->CurrentMdl failed with status 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		if ((WskBuffer->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) != MDL_MAPPED_TO_SYSTEM_VA &&
			(WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) != MDL_PAGES_LOCKED &&
			(WskBuffer->Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != MDL_SOURCE_IS_NONPAGED_POOL)
		{
			MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "InitWskBuffer_NBL()::MmProbeAndLockPages(%p) failed with status 0x%08X\n", WskBuffer->Mdl, STATUS_ACCESS_VIOLATION);
		Status = STATUS_ACCESS_VIOLATION;
	}

	TRACE_EXIT();
	return Status;
}

static
VOID
FreeWskBuffer_NBL(
	IN PWSK_BUF WskBuffer
	)
{
	ASSERT(WskBuffer);

	TRACE_ENTER();

	if ((WskBuffer->Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) != MDL_MAPPED_TO_SYSTEM_VA &&
		(WskBuffer->Mdl->MdlFlags & MDL_PAGES_LOCKED) != MDL_PAGES_LOCKED &&
		(WskBuffer->Mdl->MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL) != MDL_SOURCE_IS_NONPAGED_POOL)
	{
		MmUnlockPages(WskBuffer->Mdl);
	}
	TRACE_EXIT();
}

PWSK_SOCKET
NTAPI
WSKCreateSocket(
	IN ADDRESS_FAMILY AddressFamily,
	IN USHORT SocketType,
	IN ULONG Protocol,
	IN ULONG Flags
	)
{
	KEVENT                  CompletionEvent = { 0 };
	PIRP                    Irp = NULL;
	PWSK_SOCKET             WskSocket = NULL;
	NTSTATUS                Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED)
	{
		TRACE_EXIT();
		return NULL;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKCreateSocket()::InitWskData() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return NULL;
	}

	Status = g_WskProvider.Dispatch->WskSocket(
		g_WskProvider.Client,
		AddressFamily,
		SocketType,
		Protocol,
		Flags,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKCreateSocket()::Dispatch::WskSocket() failed with status 0x%08X\n", Status);
	}

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

	IoFreeIrp(Irp);
	TRACE_EXIT();
	return (PWSK_SOCKET)WskSocket;
}

NTSTATUS
NTAPI
WSKCloseSocket(
	IN PWSK_SOCKET WskSocket
	)
{
	KEVENT          CompletionEvent = { 0 };
	PIRP            Irp = NULL;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED || !WskSocket)
	{
		TRACE_EXIT();
		return STATUS_INVALID_PARAMETER;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKCloseSocket()::InitWskData() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return Status;
	}

	Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	else if (Status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKCloseSocket()::Dispatch::WskSocket() failed with status 0x%08X\n", Status);
	}

	IoFreeIrp(Irp);
	TRACE_EXIT();
	return Status;
}

// LONG
// NTAPI
// WSKSend(
// 	IN PWSK_SOCKET WskSocket,
// 	IN PVOID Buffer,
// 	IN ULONG BufferSize,
// 	IN ULONG Flags
// 	)
// {
// 	KEVENT          CompletionEvent = { 0 };
// 	PIRP            Irp = NULL;
// 	WSK_BUF         WskBuffer = { 0 };
// 	LONG            BytesSent = SOCKET_ERROR;
// 	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
// 
// 	TRACE_ENTER();
// 
// 	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
// 	{
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
// 	if (!NT_SUCCESS(Status))
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSend()::InitWskBuffer() failed with status 0x%08X\n", Status);
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = InitWskData(&Irp, &CompletionEvent);
// 	if (!NT_SUCCESS(Status))
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSend()::InitWskData() failed with status 0x%08X\n", Status);
// 		FreeWskBuffer(&WskBuffer);
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskSend(
// 		WskSocket,
// 		&WskBuffer,
// 		Flags,
// 		Irp);
// 	if (Status == STATUS_PENDING)
// 	{
// 		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
// 		Status = Irp->IoStatus.Status;
// 	}
// 	else if (Status != STATUS_SUCCESS)
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSend()::Dispatch::WskSend() failed with status 0x%08X\n", Status);
// 	}
// 
// 	BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;
// 
// 	IoFreeIrp(Irp);
// 	FreeWskBuffer(&WskBuffer);
// 	TRACE_EXIT();
// 	return BytesSent;
// }
// 
// LONG
// NTAPI
// WSKSendTo(
// 	IN PWSK_SOCKET WskSocket,
// 	IN PVOID Buffer,
// 	IN ULONG BufferSize,
// 	__in_opt PSOCKADDR RemoteAddress
// 	)
// {
// 	KEVENT          CompletionEvent = { 0 };
// 	PIRP            Irp = NULL;
// 	WSK_BUF         WskBuffer = { 0 };
// 	LONG            BytesSent = SOCKET_ERROR;
// 	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
// 
// 	TRACE_ENTER();
// 
// 	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
// 	{
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
// 	if (!NT_SUCCESS(Status))
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendTo()::InitWskBuffer() failed with status 0x%08X\n", Status);
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = InitWskData(&Irp, &CompletionEvent);
// 	if (!NT_SUCCESS(Status))
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendTo()::InitWskData() failed with status 0x%08X\n", Status);
// 		FreeWskBuffer(&WskBuffer);
// 		TRACE_EXIT();
// 		return SOCKET_ERROR;
// 	}
// 
// 	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskSendTo(
// 		WskSocket,
// 		&WskBuffer,
// 		0,
// 		RemoteAddress,
// 		0,
// 		NULL,
// 		Irp);
// 	if (Status == STATUS_PENDING)
// 	{
// 		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
// 		Status = Irp->IoStatus.Status;
// 	}
// 	else if (Status != STATUS_SUCCESS)
// 	{
// 		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendTo()::Dispatch::WskSendTo() failed with status 0x%08X\n", Status);
// 	}
// 
// 	BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;
// 
// 	IoFreeIrp(Irp);
// 	FreeWskBuffer(&WskBuffer);
// 	TRACE_EXIT();
// 	return BytesSent;
// }

LONG
NTAPI
WSKSendTo_NBL(
	IN PWSK_SOCKET WskSocket,
	IN PNET_BUFFER_LIST	NetBufferList,
	IN ULONG BufferOffset,
	__in_opt PSOCKADDR RemoteAddress
	)
{
	KEVENT          CompletionEvent = { 0 };
	PIRP            Irp = NULL;
	WSK_BUF         WskBuffer = { 0 };
	LONG            BytesSent = SOCKET_ERROR;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED || !WskSocket || !NetBufferList)
	{
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskBuffer_NBL(NetBufferList, BufferOffset, &WskBuffer);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendTo_NBL()::InitWskBuffer_NBL() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKSendTo_NBL()::InitWskData() failed with status 0x%08X\n", Status);
		FreeWskBuffer_NBL(&WskBuffer);
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)WskSocket->Dispatch)->WskSendTo(
		WskSocket,
		&WskBuffer,
		0,
		RemoteAddress,
		0,
		NULL,
		Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	FreeWskBuffer_NBL(&WskBuffer);
	TRACE_EXIT();
	return BytesSent;
}

NTSTATUS
NTAPI
WSKBind(
	IN PWSK_SOCKET WskSocket,
	IN PSOCKADDR LocalAddress
	)
{
	KEVENT          CompletionEvent = { 0 };
	PIRP            Irp = NULL;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED || !WskSocket || !LocalAddress)
	{
		TRACE_EXIT();
		return STATUS_INVALID_PARAMETER;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "WSKBind()::InitWskData() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return Status;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskBind(
		WskSocket,
		LocalAddress,
		0,
		Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	TRACE_EXIT();
	return Status;
}

#endif // HAVE_WFP_LOOPBACK_SUPPORT
