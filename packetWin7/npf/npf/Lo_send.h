/*
* Copyright (c) 1997 - 2015
* Nmap.org (U.S.)
* All rights reserved.
*
* Lo_send.h
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
NPF_WSKInitSockets();

VOID
NTAPI
NPF_WSKFreeSockets();

NTSTATUS
NTAPI
NPF_WSKStartup();

VOID
NTAPI
NPF_WSKCleanup();

NTSTATUS
NTAPI
NPF_WSKSendPacket(
__in PCHAR PacketBuff,
__in ULONG BuffSize
);

NTSTATUS
NTAPI
WSKSendPacketInternal(
__in BOOLEAN bIPv4,
__in PCHAR PacketBuff,
__in ULONG BuffSize
);

NTSTATUS
NTAPI
NPF_WSKSendPacket_NBL(
	__in PNET_BUFFER_LIST NetBufferList
	);

NTSTATUS
NTAPI
WSKSendPacketInternal_NBL(
	__in BOOLEAN bIPv4,
	__in PNET_BUFFER_LIST NetBufferList
	);

PWSK_SOCKET
NTAPI
WSKCreateSocket(
__in ADDRESS_FAMILY AddressFamily,
__in USHORT                 SocketType,
__in ULONG                  Protocol,
__in ULONG                  Flags
);

NTSTATUS
NTAPI
WSKCloseSocket(
__in PWSK_SOCKET WskSocket
);

LONG
NTAPI
WSKSend(
__in PWSK_SOCKET        WskSocket,
__in PVOID                      Buffer,
__in ULONG                      BufferSize,
__in ULONG                      Flags
);

LONG
NTAPI
WSKSendTo(
__in PWSK_SOCKET        WskSocket,
__in PVOID                      Buffer,
__in ULONG                      BufferSize,
__in_opt PSOCKADDR      RemoteAddress
);

LONG
NTAPI
WSKSendTo_NBL(
	__in PWSK_SOCKET        WskSocket,
	__in PNET_BUFFER_LIST	NetBufferList,
	__in ULONG				BufferOffset,
	__in_opt PSOCKADDR      RemoteAddress
);

NTSTATUS
NTAPI
WSKBind(
__in PWSK_SOCKET        WskSocket,
__in PSOCKADDR          LocalAddress
);

#endif // HAVE_WFP_LOOPBACK_SUPPORT

#endif // __LO_SEND
