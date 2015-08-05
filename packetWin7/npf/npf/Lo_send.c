/*
* Copyright (c) 1997 - 2015
* Nmap.org (U.S.)
* All rights reserved.
*
* Lo_send.c
*
* Abstract:
* This file declares common data types and function prototypes used
* throughout loopback packets sending.
*
* This code is based on Microsoft Winsock Kernel echosrv sample and
* Google Code wskudp sample.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
* 3. Neither the name of the Politecnico di Torino nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#include "stdafx.h"

#include "lo_send.h"
#include "debug.h"

static WSK_REGISTRATION         g_WskRegistration;
static WSK_PROVIDER_NPI         g_WskProvider;
static WSK_CLIENT_DISPATCH      g_WskDispatch = { MAKE_WSK_VERSION(1, 0), 0, NULL };

PWSK_SOCKET						g_IPv4Socket = NULL;
SOCKADDR_IN						g_IPv4LocalAddress = { 0, };
SOCKADDR_IN						g_IPv4RemoteAddress = { 0, };
PWSK_SOCKET						g_IPv6Socket = NULL;
SOCKADDR_IN6					g_IPv6LocalAddress = { 0, };
SOCKADDR_IN6					g_IPv6RemoteAddress = { 0, };

#define NPF_LOOPBACK_SEND_TYPE_IPV4		1
#define NPF_LOOPBACK_SEND_TYPE_IPV6		0

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
typedef struct _ETHER_HEADER {
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

enum
{
	DEINITIALIZED,
	DEINITIALIZING,
	INITIALIZING,
	INITIALIZED
};

#define IPPROTO_NPCAP_LOOPBACK		250
#define LOG_PORT					3000
#define HTON_SHORT(n)				(((((unsigned short)(n) & 0xFFu  )) << 8) | \
									(((unsigned short)(n) & 0xFF00u) >> 8))
#define HTON_LONG(x)				(((((x)& 0xff)<<24) | ((x)>>24) & 0xff) | \
									(((x) & 0xff0000)>>8) | (((x) & 0xff00)<<8))

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



NTSTATUS
NTAPI
NPF_WSKSendPacket(
__in PCHAR PacketBuff,
__in ULONG BuffSize
	)
{
	PETHER_HEADER	pEthernetHdr = (PETHER_HEADER) PacketBuff;
	NTSTATUS		status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	PacketBuff = PacketBuff + ETHER_HDR_LEN;
	BuffSize = BuffSize - ETHER_HDR_LEN;
	
	if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IP))
	{
		status = NPF_WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV4, PacketBuff, BuffSize);
	}
	else if (pEthernetHdr->ether_type == RtlUshortByteSwap(ETHERTYPE_IPV6))
	{
		status = NPF_WSKSendPacketInternal(NPF_LOOPBACK_SEND_TYPE_IPV6, PacketBuff, BuffSize);
	}
	else
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacket() failed with status 0x%08X, not valid loopback IPv4 or IPv6 packet\n", status);
	}

	TRACE_EXIT();
	return status;
}

NTSTATUS
NTAPI
NPF_WSKSendPacketInternal(
__in BOOLEAN bIPv4,
__in PCHAR PacketBuff,
__in ULONG BuffSize
)
{
	NTSTATUS		status = STATUS_SUCCESS;
	ULONG			SentBytes;

	TRACE_ENTER();

	SentBytes = bIPv4 ?
		WSKSendTo(g_IPv4Socket, PacketBuff, BuffSize, (PSOCKADDR)& g_IPv4RemoteAddress) :
		WSKSendTo(g_IPv6Socket, PacketBuff, BuffSize, (PSOCKADDR)& g_IPv6RemoteAddress);

	if (SentBytes != BuffSize)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendPacketInternal()::WSKSendTo() failed with SentBytes 0x%08X\n", SentBytes);
	}

	TRACE_EXIT();
	return status;
}


static
NTSTATUS
NTAPI
CompletionRoutine(
__in PDEVICE_OBJECT 		DeviceObject,
__in PIRP                   Irp,
__in PKEVENT                CompletionEvent
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
__out PIRP*             pIrp,
__out PKEVENT   CompletionEvent
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

static
NTSTATUS
InitWskBuffer(
__in  PVOID             Buffer,
__in  ULONG             BufferSize,
__out PWSK_BUF  WskBuffer
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	TRACE_ENTER();

	ASSERT(Buffer);
	ASSERT(BufferSize);
	ASSERT(WskBuffer);

	WskBuffer->Offset = 0;
	WskBuffer->Length = BufferSize;

	WskBuffer->Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
	if (!WskBuffer->Mdl)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "InitWskBuffer()::IoAllocateMdl() failed with status 0x%08X\n", STATUS_INSUFFICIENT_RESOURCES);
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "InitWskBuffer()::MmProbeAndLockPages(%p) failed with status 0x%08X\n", Buffer, STATUS_ACCESS_VIOLATION);
		IoFreeMdl(WskBuffer->Mdl);
		Status = STATUS_ACCESS_VIOLATION;
	}

	TRACE_EXIT();
	return Status;
}

static
VOID
FreeWskBuffer(
__in PWSK_BUF WskBuffer
)
{
	ASSERT(WskBuffer);

	TRACE_ENTER();

	MmUnlockPages(WskBuffer->Mdl);
	IoFreeMdl(WskBuffer->Mdl);
	TRACE_EXIT();
}

PWSK_SOCKET
NTAPI
WSKCreateSocket(
__in ADDRESS_FAMILY			AddressFamily,
__in USHORT                 SocketType,
__in ULONG                  Protocol,
__in ULONG                  Flags
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
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKCreateSocket()::InitWskData() failed with status 0x%08X\n", Status);
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

	WskSocket = NT_SUCCESS(Status) ? (PWSK_SOCKET)Irp->IoStatus.Information : NULL;

	IoFreeIrp(Irp);
	TRACE_EXIT();
	return (PWSK_SOCKET)WskSocket;
}

NTSTATUS
NTAPI
WSKCloseSocket(
__in PWSK_SOCKET WskSocket
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
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKCloseSocket()::InitWskData() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return Status;
	}

	Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	IoFreeIrp(Irp);
	TRACE_EXIT();
	return Status;
}

LONG
NTAPI
WSKSend(
__in PWSK_SOCKET		WskSocket,
__in PVOID				Buffer,
__in ULONG				BufferSize,
__in ULONG				Flags
)
{
	KEVENT          CompletionEvent = { 0 };
	PIRP            Irp = NULL;
	WSK_BUF         WskBuffer = { 0 };
	LONG            BytesSent = SOCKET_ERROR;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
	{
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSend()::InitWskBuffer() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSend()::InitWskData() failed with status 0x%08X\n", Status);
		FreeWskBuffer(&WskBuffer);
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskSend(
		WskSocket,
		&WskBuffer,
		Flags,
		Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}

	BytesSent = NT_SUCCESS(Status) ? (LONG)Irp->IoStatus.Information : SOCKET_ERROR;

	IoFreeIrp(Irp);
	FreeWskBuffer(&WskBuffer);
	TRACE_EXIT();
	return BytesSent;
}

LONG
NTAPI
WSKSendTo(
__in PWSK_SOCKET        WskSocket,
__in PVOID              Buffer,
__in ULONG              BufferSize,
__in_opt PSOCKADDR      RemoteAddress
)
{
	KEVENT          CompletionEvent = { 0 };
	PIRP            Irp = NULL;
	WSK_BUF         WskBuffer = { 0 };
	LONG            BytesSent = SOCKET_ERROR;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	if (g_SocketsState != INITIALIZED || !WskSocket || !Buffer || !BufferSize)
	{
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskBuffer(Buffer, BufferSize, &WskBuffer);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendTo()::InitWskBuffer() failed with status 0x%08X\n", Status);
		TRACE_EXIT();
		return SOCKET_ERROR;
	}

	Status = InitWskData(&Irp, &CompletionEvent);
	if (!NT_SUCCESS(Status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKSendTo()::InitWskData() failed with status 0x%08X\n", Status);
		FreeWskBuffer(&WskBuffer);
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
	FreeWskBuffer(&WskBuffer);
	TRACE_EXIT();
	return BytesSent;
}

NTSTATUS
NTAPI
WSKBind(
__in PWSK_SOCKET        WskSocket,
__in PSOCKADDR          LocalAddress
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
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_WSKBind()::InitWskData() failed with status 0x%08X\n", Status);
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
