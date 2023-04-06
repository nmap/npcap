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
/*
 * Copyright (c) 2006 - 2010
 * CACE Technologies Inc., Davis (CA)
 * All rights reserved.
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
 * 3. Neither the name of the company (CACE Technologies Inc.) nor the 
 * names of its contributors may be used to endorse or promote products 
 * derived from this software without specific prior written permission.
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

//
// Internal constants
//
#define PACKET_DEPRECATED_INTERNAL_STRUCT_DEFINITIONS_OK
#include <Packet32.h>
#include "debug.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntddndis.h>

#define ADAPTERS_ADDRESSES_INITIAL_BUFFER_SIZE 15000
#define ADAPTERS_ADDRESSES_MAX_TRIES 3

#define DEVICE_PREFIX "\\Device\\"
#define WINPCAP_COMPAT_DEVICE_PREFIX DEVICE_PREFIX "NPF_"
#define NPCAP_LOOPBACK_ADAPTER_BUILTIN "Loopback"

/*!
  \brief Contains comprehensive information about a network adapter.

  This structure is filled with all the accessory information that the user can need about an adapter installed
  on his system.
*/
typedef struct _ADAPTER_INFO  
{
	struct _ADAPTER_INFO *Next;				///< Pointer to the next adapter in the list.
	CHAR Name[ADAPTER_NAME_LENGTH + 1];		///< Name of the device representing the adapter.
	ULONG NameLen; // length of name
	CHAR Description[ADAPTER_DESC_LENGTH + 1];	///< Human understandable description of the adapter
	ULONG DescLen; // length of description
} ADAPTER_INFO, *PADAPTER_INFO;

typedef struct ADAPTERS_INFO_LIST
{
	ULONG NamesLen; // The length of all names and null terminators
	ULONG DescsLen; // The length of all descriptions and null terminators
	ULONGLONG TicksLastUpdate; // The tick count when the list was last updated.
	PADAPTER_INFO Adapters;
} ADINFO_LIST, *PADINFO_LIST;

// After this many ms, regen the list of adapters
#define ADINFO_LIST_STALE_TICK_COUNT 1000


//
// Internal functions
//
_Success_(return == ERROR_SUCCESS)
DWORD PacketPopulateAdaptersInfoList();

#define NPF_OPEN_FLAG_WIFI 0x1
_Success_(return != INVALID_HANDLE_VALUE)
_Must_inspect_result_
HANDLE PacketGetAdapterHandle(_In_ PCCH AdapterNameA, _In_ ULONG NpfOpenFlags);

static inline VOID InterlockedMax(PULONG Location, ULONG NewValue)
{
	ULONG prev;
	// If NewValue is bigger, safely exchange value only if the value hasn't changed.
	// If it has changed, check it again.
	do {
		prev = *Location;
		if (prev >= NewValue)
			return;
	} while (InterlockedCompareExchange((PLONG)Location, NewValue, prev) != (LONG)prev); 
}

// 
// Definitions and functions specific to the CACETech airpcap API
//
#ifdef HAVE_AIRPCAP_API
typedef PCHAR (*AirpcapGetLastErrorHandler)(PAirpcapHandle Handle);
typedef BOOL (*AirpcapGetDeviceListHandler)(AirpcapDeviceDescription **AllDevsP, PCHAR Ebuf);		///< prototype used to dynamically load the dll
typedef VOID (*AirpcapFreeDeviceListHandler)(AirpcapDeviceDescription *AllDevsP);					///< prototype used to dynamically load the dll
typedef PAirpcapHandle (*AirpcapOpenHandler)(LPCSTR DeviceName, PCHAR Ebuf);							///< prototype used to dynamically load the dll	
typedef VOID (*AirpcapCloseHandler)(PAirpcapHandle Handle);											///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapGetLinkTypeHandler)(PAirpcapHandle Handle, AirpcapLinkType* LinkLayer);		///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapSetKernelBufferHandler)(PAirpcapHandle Handle, ULONG Size);					///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapSetFilterHandler)(PAirpcapHandle Handle, void *Instructions, UINT Len);		///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapSetMinToCopyHandler)(PAirpcapHandle Handle, ULONG Bytes);						///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapGetReadEventHandler)(PAirpcapHandle Handle, HANDLE* PReadEvent);				///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapReadHandler)(PAirpcapHandle Handle, PUCHAR BufferToFill, ULONG BufSize, PULONG ReceievedBytes);	///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapGetStatsHandler)(PAirpcapHandle Handle, AirpcapStats *Stats);					///< prototype used to dynamically load the dll
typedef BOOL (*AirpcapWriteHandler)(PAirpcapHandle Handle, PCHAR TxPacket, ULONG PacketLen);		///< prototype used to dynamically load the dll

#endif // HAVE_AIRPCAP_API
