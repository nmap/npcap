/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
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

/*
 This file contains the support functions used by packet.dll to retrieve information about installed 
 adapters, like

	- the adapter list
	- the device associated to any adapter and the description of the adapter
	- physical parameters like the linkspeed or the link layer type
	- the IP and link layer addresses  */

#define UNICODE 1

#include <Packet32.h>
#include "Packet32-Int.h"
#include "debug.h"

#include <ws2tcpip.h>
#include <windowsx.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <WpcapNames.h>


extern BOOLEAN g_bLoopbackSupport;

#define BUFSIZE 512
PADAPTER_INFO g_AdaptersInfoList = NULL;				///< Head of the adapter information list. This list is populated when packet.dll is linked by the application.
HANDLE g_AdaptersInfoMutex = NULL;						///< Mutex that protects the adapter information list. NOTE: every API that takes an ADAPTER_INFO as parameter assumes that it has been called with the mutex acquired.

#define ADAPTERS_ADDRESSES_INITIAL_BUFFER_SIZE 15000
#define ADAPTERS_ADDRESSES_MAX_TRIES 3
static ULONG g_GaaBufLast = ADAPTERS_ADDRESSES_INITIAL_BUFFER_SIZE; // Last good value for GAA buffer size

#ifdef HAVE_AIRPCAP_API
extern AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
extern AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
extern AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
extern AirpcapOpenHandler g_PAirpcapOpen;
extern AirpcapCloseHandler g_PAirpcapClose;
extern AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
extern AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
extern AirpcapSetFilterHandler g_PAirpcapSetFilter;
extern AirpcapGetMacAddressHandler g_PAirpcapGetMacAddress;
extern AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
extern AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
extern AirpcapReadHandler g_PAirpcapRead;
extern AirpcapGetStatsHandler g_PAirpcapGetStats;
#endif /* HAVE_AIRPCAP_API */

/*! 
  \brief Gets the link layer of an adapter, querying the registry.
  \param AdapterObject Handle to an open adapter.
  \param type Pointer to a NetType structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero, otherwise the return value is zero.

  This function retrieves from the registry the link layer and the speed (in bps) of an opened adapter.
  These values are copied in the NetType structure provided by the user.
  The LinkType field of the type parameter can have one of the following values:

  - NdisMedium802_3: Ethernet (802.3) 
  - NdisMediumWan: WAN 
  - NdisMedium802_5: Token Ring (802.5) 
  - NdisMediumFddi: FDDI 
  - NdisMediumAtm: ATM 
  - NdisMediumArcnet878_2: ARCNET (878.2) 
*/
static BOOLEAN PacketGetLinkLayerFromRegistry(LPADAPTER AdapterObject, NetType *type)
{
	BOOLEAN    Status;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1] = {0};
	PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA) IoCtlBuffer;

	TRACE_ENTER();

	//get the link-layer type
	OidData->Oid = OID_GEN_MEDIA_IN_USE;
	OidData->Length = sizeof (ULONG);
	Status = PacketRequest(AdapterObject,FALSE,OidData);
	type->LinkType=*((UINT*)OidData->Data);

	TRACE_PRINT1("Media:%.010d", type->LinkType);

	TRACE_EXIT();
	return Status;
}


/*!
  \brief Adds an entry to the adapter description list.
  \param AdName Name of the adapter to add
  \return If the function succeeds, the return value is nonzero.

  Used by PacketGetAdaptersNPF(). Queries the driver to fill the PADAPTER_INFO describing the new adapter.
*/
static BOOLEAN PacketAddAdapterNPF(PIP_ADAPTER_ADDRESSES pAdapterAddr)
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	LONG		Status;
	LPADAPTER	adapter = NULL;
	PADAPTER_INFO	TmpAdInfo;
	PADAPTER_INFO TAdInfo;	
	CHAR AdName[ADAPTER_NAME_LENGTH];
	HRESULT hrStatus = S_OK;
	
	TRACE_ENTER();
 	TRACE_PRINT1("Trying to add adapter %hs", pAdapterAddr->AdapterName);
	
	// Create the NPF device name from the original device name
	hrStatus = StringCchPrintfA(AdName,
		sizeof(AdName),
		"%s%s",
		NPF_DRIVER_COMPLETE_DEVICE_PREFIX,
		pAdapterAddr->AdapterName);
	if (FAILED(hrStatus)) {
		TRACE_PRINT("PacketAddAdapterNPF: adapter name is too long to be stored into ADAPTER_INFO::Name, simply skip it");
		TRACE_EXIT();
		return FALSE;
	}

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	
	for(TAdInfo = g_AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(_stricmp(AdName, TAdInfo->Name) == 0)
		{
			TRACE_PRINT("PacketAddAdapterNPF: Adapter already present in the list");
			ReleaseMutex(g_AdaptersInfoMutex);
			TRACE_EXIT();
			return TRUE;
		}
	}
	
	//here we could have released the mutex, but what happens if two threads try to add the same adapter? 
	//The adapter would be duplicated on the linked list

	TRACE_PRINT("Trying to open the NPF adapter and see if it's available...");

	// Try to Open the adapter
	adapter = PacketOpenAdapterNPF(AdName);

	if(adapter == NULL)
	{
		TRACE_PRINT("NPF Adapter not available, do not add it to the global list");
		// We are not able to open this adapter. Skip to the next one.
		ReleaseMutex(g_AdaptersInfoMutex);
		TRACE_EXIT();
		return FALSE;
	}

	
	//
	// PacketOpenAdapter was succesful. Consider this a valid adapter and allocate an entry for it
	// In the adapter list
	//
	
	TmpAdInfo = (PADAPTER_INFO) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADAPTER_INFO));
	if (TmpAdInfo == NULL) 
	{
		TRACE_PRINT("AddAdapter: HeapAlloc Failed allocating the buffer for the AdInfo to be added to the global list. Returning.");
		PacketCloseAdapter(adapter);
		ReleaseMutex(g_AdaptersInfoMutex);
		TRACE_EXIT();
		return FALSE;
	}
	
	// Copy the device name
	strncpy_s(TmpAdInfo->Name, sizeof(TmpAdInfo->Name), AdName, _TRUNCATE);

	//we do not need to terminate the string TmpAdInfo->Name, since we have left a char at the end, and
	//the memory for TmpAdInfo was zeroed upon allocation

	// Copy the description
	Status = WideCharToMultiByte(CP_ACP, 0, pAdapterAddr->Description, (int)wcslen(pAdapterAddr->Description), TmpAdInfo->Description, ADAPTER_DESC_LENGTH, NULL, NULL);
	// Conversion error? ensure it's terminated and ignore.
	if (Status == 0) TmpAdInfo->Description[ADAPTER_DESC_LENGTH] = '\0';

	// TODO: If we can map the IfType to a NDIS_MEDIUM enum value, we can skip this part:
	Status = PacketGetLinkLayerFromRegistry(adapter, &(TmpAdInfo->LinkLayer));
	// Average of Xmit and Rcv speeds is historical. Maybe we should report min instead?
	TmpAdInfo->LinkLayer.LinkSpeed = (pAdapterAddr->TransmitLinkSpeed + pAdapterAddr->ReceiveLinkSpeed) / 2;

	PacketCloseAdapter(adapter);

	if (Status == FALSE)
	{
		TRACE_PRINT("PacketAddAdapterNPF: PacketGetLinkLayerFromRegistry failed. Returning.");
		HeapFree(GetProcessHeap(), 0, TmpAdInfo);
		ReleaseMutex(g_AdaptersInfoMutex);
		TRACE_EXIT();
		return FALSE;
	}

	// Retrieve the adapter MAC address querying the NIC driver
	// XXX At the moment only Ethernet is supported.
	TmpAdInfo->MacAddressLen = pAdapterAddr->PhysicalAddressLength;
	if (TmpAdInfo->MacAddressLen > 0)
	{
		memcpy(TmpAdInfo->MacAddress, pAdapterAddr->PhysicalAddress, TmpAdInfo->MacAddressLen);
	}

	TRACE_PRINT6("Successfully obtained the MAC address, it's %.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
		TmpAdInfo->MacAddress[0],
		TmpAdInfo->MacAddress[1],
		TmpAdInfo->MacAddress[2],
		TmpAdInfo->MacAddress[3],
		TmpAdInfo->MacAddress[4],
		TmpAdInfo->MacAddress[5]);
		
	// Retrieve IP addresses
	TmpAdInfo->pNetworkAddresses = NULL;

	PIP_ADAPTER_UNICAST_ADDRESS pAddr = pAdapterAddr->FirstUnicastAddress;
	while (pAddr != NULL)
	{
		ULONG ul = 0;
		PNPF_IF_ADDRESS_ITEM pItem = (PNPF_IF_ADDRESS_ITEM)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NPF_IF_ADDRESS_ITEM));
		if (pItem == NULL)
		{
			TRACE_PRINT("PacketAddAdapterNPF: HeapAlloc failed for NPF_IF_ADDRESS_ITEM");
			break;
		}

		const int AddrLen = pAddr->Address.iSockaddrLength;
		memcpy(&pItem->Addr.IPAddress, pAddr->Address.lpSockaddr, AddrLen);
		struct sockaddr_storage *IfAddr = (struct sockaddr_storage *)pAddr->Address.lpSockaddr;
		struct sockaddr_storage* Subnet = (struct sockaddr_storage *)&pItem->Addr.SubnetMask;
		struct sockaddr_storage* Broadcast = (struct sockaddr_storage *)&pItem->Addr.Broadcast;
		Subnet->ss_family = Broadcast->ss_family = IfAddr->ss_family;
		if (Subnet->ss_family == AF_INET)
		{
			((struct sockaddr_in *)Subnet)->sin_addr.S_un.S_addr = ul = htonl(0xffffffff << (32 - pAddr->OnLinkPrefixLength));
			((struct sockaddr_in *)Broadcast)->sin_addr.S_un.S_addr = ~ul | ((struct sockaddr_in *)IfAddr)->sin_addr.S_un.S_addr;
		}
		else if (IfAddr->ss_family == AF_INET6)
		{
			memset(&((struct sockaddr_in6*)Broadcast)->sin6_addr, 0xff, sizeof(IN6_ADDR));
			for (int i = pAddr->OnLinkPrefixLength, j = 0; i > 0; i-=16, j++)
			{
				if (i > 16)
				{
					((struct sockaddr_in6*)Subnet)->sin6_addr.u.Word[j] = 0xffff;
					((struct sockaddr_in6*)Broadcast)->sin6_addr.u.Word[j] = ((struct sockaddr_in6*)IfAddr)->sin6_addr.u.Word[j];
				}
				else
				{
					const WORD mask = htons(0xffff << (16 - i));
					((struct sockaddr_in6*)Subnet)->sin6_addr.u.Word[j] = mask;
					((struct sockaddr_in6*)Broadcast)->sin6_addr.u.Word[j] = ~mask | ((struct sockaddr_in6*)IfAddr)->sin6_addr.u.Word[j];
				}
			}
		}
		else
		{
			// else unsupported address family, no broadcast or netmask
			Subnet->ss_family = Broadcast->ss_family = 0;
		}

		pItem->Next = TmpAdInfo->pNetworkAddresses;
		TmpAdInfo->pNetworkAddresses = pItem;

		pAddr = pAddr->Next;
	}
		
	TmpAdInfo->Flags = INFO_FLAG_NDIS_ADAPTER;
	
	// Update the AdaptersInfo list
	TmpAdInfo->Next = g_AdaptersInfoList;
	g_AdaptersInfoList = TmpAdInfo;
	
	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_PRINT("PacketAddAdapterNPF: Adapter successfully added to the list");
	TRACE_EXIT();
	return TRUE;
}

static BOOLEAN PacketAddLoopbackAdapter()
{
	PADAPTER_INFO TmpAdInfo;
	LPADAPTER adapter;

	TRACE_ENTER();
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	for (TmpAdInfo = g_AdaptersInfoList; TmpAdInfo != NULL; TmpAdInfo = TmpAdInfo->Next)
	{
		if (_stricmp(FAKE_LOOPBACK_ADAPTER_NAME, TmpAdInfo->Name) == 0)
		{
			TRACE_PRINT("PacketGetAdaptersNPF: Loopback already present in the list");
			ReleaseMutex(g_AdaptersInfoMutex);
			return TRUE;
		}
	}
	TRACE_PRINT("Trying to open the Loopback adapter...");

	// Try to Open the adapter
	adapter = PacketOpenAdapterNPF(FAKE_LOOPBACK_ADAPTER_NAME);

	if (adapter == NULL)
	{
		TRACE_PRINT("Could not open Loopback adapter.");
		// We are not able to open this adapter. Skip to the next one.
		ReleaseMutex(g_AdaptersInfoMutex);
		return FALSE;
	}
	TmpAdInfo = (PADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADAPTER_INFO));
	if (TmpAdInfo == NULL)
	{
		TRACE_PRINT("AddAdapter: HeapAlloc Failed");
		PacketCloseAdapter(adapter);
		ReleaseMutex(g_AdaptersInfoMutex);
		return FALSE;
	}

	// Copy the device name
	strncpy_s(TmpAdInfo->Name, sizeof(TmpAdInfo->Name), FAKE_LOOPBACK_ADAPTER_NAME, _TRUNCATE);
	strncpy_s(TmpAdInfo->Description, sizeof(TmpAdInfo->Description), FAKE_LOOPBACK_ADAPTER_DESCRIPTION, _TRUNCATE);
	TmpAdInfo->LinkLayer.LinkType = (UINT)NdisMediumNull;
	TmpAdInfo->LinkLayer.LinkSpeed = 10 * 1000 * 1000; //we emulate a fake 10MBit Ethernet
	TmpAdInfo->Flags = 0;
	memset(TmpAdInfo->MacAddress, '\0', 6);
	TmpAdInfo->MacAddressLen = 6;
	TmpAdInfo->pNetworkAddresses = NULL;
	PacketCloseAdapter(adapter);

	// Update the AdaptersInfo list
	TmpAdInfo->Next = g_AdaptersInfoList;
	g_AdaptersInfoList = TmpAdInfo;

	ReleaseMutex(g_AdaptersInfoMutex);
	return TRUE;
}

/*!
  \brief Updates the list of the adapters querying the registry.
  \return If the function succeeds, the return value is nonzero.

  This function populates the list of adapter descriptions, retrieving the information from the registry. 
*/
static BOOLEAN PacketGetAdaptersNPF()
{
	ULONG Iterations;
	ULONG BufLen;
	ULONG RetVal = ERROR_SUCCESS;
	PIP_ADAPTER_ADDRESSES AdBuffer, TmpAddr;

	TRACE_ENTER();


	BufLen = g_GaaBufLast;
	AdBuffer = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufLen);
	if (AdBuffer == NULL)
	{
		TRACE_PRINT("PacketGetAdaptersNPF: HeapAlloc Failed");
		TRACE_EXIT();
		return FALSE;
	}
	for (Iterations = 0; Iterations < ADAPTERS_ADDRESSES_MAX_TRIES; Iterations++)
	{

		RetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | // Get everything
			GAA_FLAG_SKIP_DNS_INFO | // Undocumented, reported to help avoid errors on Win10 1809
			// We don't use any of these features:
			GAA_FLAG_SKIP_DNS_SERVER |
			GAA_FLAG_SKIP_ANYCAST |
			GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, AdBuffer, &BufLen);
		if (RetVal == ERROR_BUFFER_OVERFLOW)
		{
			TRACE_PRINT1("PacketGetAdaptersNPF: GetAdaptersAddresses Too small buffer (need %u)", BufLen);
			TmpAddr = (PIP_ADAPTER_ADDRESSES)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AdBuffer, BufLen);
			if (TmpAddr == NULL)
			{
				TRACE_PRINT("PacketGetAdaptersNPF: HeapReAlloc Failed");
				HeapFree(GetProcessHeap(), 0, AdBuffer);
				TRACE_EXIT();
				return FALSE;
			}
			AdBuffer = TmpAddr;
		}
		else
		{
			break;
		}
	}

	if (RetVal != ERROR_SUCCESS)
	{
		TRACE_PRINT("PacketGetAdaptersNPF: GetAdaptersAddresses Failed while retrieving the addresses");
		if (AdBuffer)
		{
			HeapFree(GetProcessHeap(), 0, AdBuffer);
		}
		TRACE_EXIT();
		return FALSE;
	}

	// Stash the value that worked here
	g_GaaBufLast = BufLen;

	for (TmpAddr=AdBuffer; TmpAddr != NULL; TmpAddr = TmpAddr->Next)
	{
		// If the adapter is valid, add it to the list.
		PacketAddAdapterNPF(TmpAddr);
	}
	
	if (g_bLoopbackSupport) {
		PacketAddLoopbackAdapter();
	}

	if (AdBuffer)
	{
		HeapFree(GetProcessHeap(), 0, AdBuffer);
	}
	TRACE_EXIT();
	return TRUE;
}

#ifdef HAVE_AIRPCAP_API
/*!
  \brief Add an airpcap adapter to the adapters info list, gathering information from the airpcap dll
  \param name Name of the adapter.
  \param description description of the adapter.
  \return If the function succeeds, the return value is nonzero.
*/
static BOOLEAN PacketAddAdapterAirpcap(PCCH name, PCCH description)
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	CHAR ebuf[AIRPCAP_ERRBUF_SIZE];
	PADAPTER_INFO TmpAdInfo;
	PAirpcapHandle AirpcapAdapter;
	BOOL GllRes;
	AirpcapLinkType AirpcapLinkLayer;
	BOOLEAN Result = TRUE;

	TRACE_ENTER();
	//XXX what about checking if the adapter already exists???
	
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	do
	{
		
		//
		// check if the adapter is already there, and remove it
		//
		for (TmpAdInfo = g_AdaptersInfoList; TmpAdInfo != NULL; TmpAdInfo = TmpAdInfo->Next)
		{
			if (TmpAdInfo->Flags == INFO_FLAG_AIRPCAP_CARD)
			{
				if (_stricmp(TmpAdInfo->Name, name) == 0)
					break;
			}
		}

		if (TmpAdInfo != NULL)
		{
			//
			// we already have it in the list. Just return
			//
			Result = TRUE;
			break;
		}
		
		//
		// Allocate a descriptor for this adapter
		//			
		//here we do not acquire the mutex, since we are not touching the list, yet.
		TmpAdInfo = (PADAPTER_INFO) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADAPTER_INFO));
		if (TmpAdInfo == NULL) 
		{
			TRACE_PRINT("PacketAddAdapterAirpcap: HeapAlloc Failed");
			Result = FALSE;
			break;
		}
		
		// Copy the device name and description
		StringCchCopyA(TmpAdInfo->Name, 
			sizeof(TmpAdInfo->Name), 
			name);
		
		StringCchCopyA(TmpAdInfo->Description, 
			sizeof(TmpAdInfo->Description), 
			description);
		
		TmpAdInfo->Flags = INFO_FLAG_AIRPCAP_CARD;
		
		if(g_PAirpcapOpen)
		{
			AirpcapAdapter = g_PAirpcapOpen(name, ebuf);
		}
		else
		{
			AirpcapAdapter = NULL;
		}
		
		if(!AirpcapAdapter)
		{
			HeapFree(GetProcessHeap(), 0, TmpAdInfo);
			Result = FALSE;
			break;
		}
		
		GllRes = g_PAirpcapGetLinkType(AirpcapAdapter, &AirpcapLinkLayer);
		if(!GllRes)
		{
			g_PAirpcapClose(AirpcapAdapter);
			HeapFree(GetProcessHeap(), 0, TmpAdInfo);
			Result = FALSE;
			break;
		}
		
		switch(AirpcapLinkLayer) 
		{ 
		case AIRPCAP_LT_802_11:
			TmpAdInfo->LinkLayer.LinkType = (UINT)NdisMediumBare80211;
			break;
		case AIRPCAP_LT_802_11_PLUS_RADIO:
			TmpAdInfo->LinkLayer.LinkType = (UINT)NdisMediumRadio80211;
			break;
		case AIRPCAP_LT_802_11_PLUS_PPI:
			TmpAdInfo->LinkLayer.LinkType = (UINT)NdisMediumPpi;
			break;
		default:
			TmpAdInfo->LinkLayer.LinkType = (UINT)NdisMediumNull; // Note: custom linktype, NDIS doesn't provide an equivalent
			break;
		}			
		
		//
		// For the moment, we always set the speed to 54Mbps, since the speed is not channel-specific,
		// but per packet
		//
		TmpAdInfo->LinkLayer.LinkSpeed = 54000000; 
		
		g_PAirpcapClose(AirpcapAdapter);
		
		// Update the AdaptersInfo list
		TmpAdInfo->Next = g_AdaptersInfoList;
		g_AdaptersInfoList = TmpAdInfo;
	}
	while(FALSE);

	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_EXIT();
	return Result;
}

/*!
  \brief Updates the list of the adapters using the airpcap dll.
  \return If the function succeeds, the return value is nonzero.

  This function populates the list of adapter descriptions, looking for AirPcap cards on the system. 
*/
static BOOLEAN PacketGetAdaptersAirpcap()
{
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	AirpcapDeviceDescription *Devs = NULL, *TmpDevs;
	UINT i;
	
	TRACE_ENTER();

	if(!g_PAirpcapGetDeviceList(&Devs, Ebuf))
	{
		// No airpcap cards found on this system
		TRACE_PRINT("No AirPcap adapters found");
		TRACE_EXIT();
		return FALSE;
	}
	else
	{
		for(TmpDevs = Devs, i = 0; TmpDevs != NULL; TmpDevs = TmpDevs->next)
		{
			PacketAddAdapterAirpcap(TmpDevs->Name, TmpDevs->Description);
		}
	}
	
	g_PAirpcapFreeDeviceList(Devs);
	
	TRACE_EXIT();
	return TRUE;
}
#endif // HAVE_AIRPCAP_API


/*!
\brief Find the information about an adapter scanning the global ADAPTER_INFO list.
  \param AdapterName Name of the adapter whose information has to be retrieved.
  \return If the function succeeds, the return value is non-null.
*/
_Use_decl_annotations_
PADAPTER_INFO PacketFindAdInfo(PCCH AdapterName)
{
	//this function should NOT acquire the g_AdaptersInfoMutex, since it does return an ADAPTER_INFO structure
	PADAPTER_INFO TAdInfo;

	TRACE_ENTER();
	
	if (g_AdaptersInfoList == NULL)
	{
		TRACE_PRINT("Repopulating the adapters info list...");
		PacketPopulateAdaptersInfoList();
	}

	TAdInfo = g_AdaptersInfoList;
	
	while(TAdInfo != NULL)
	{
		if(_stricmp(TAdInfo->Name, AdapterName) == 0) 
		{
			TRACE_PRINT1("Found AdInfo for adapter %hs", AdapterName);
			break;
		}

		TAdInfo = TAdInfo->Next;
	}

	if (TAdInfo == NULL)
	{
		TRACE_PRINT1("NOT found AdInfo for adapter %hs", AdapterName);
	}

	TRACE_EXIT();
	return TAdInfo;
}



/*!
  \brief Updates information about an adapter in the global ADAPTER_INFO list.
  \param AdapterName Name of the adapter whose information has to be retrieved.
  \return If the function succeeds, the return value is TRUE. A false value means that the adapter is no
  more valid or that it is disconnected.
*/
_Use_decl_annotations_
BOOLEAN PacketUpdateAdInfo(PCCH AdapterName)
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	PADAPTER_INFO TAdInfo, PrevAdInfo;
	ULONG Iterations;
	ULONG BufLen;
	ULONG RetVal = ERROR_SUCCESS;
	PIP_ADAPTER_ADDRESSES AdBuffer, TmpAddr;
	PCCH AdapterGuid = NULL;
	BOOLEAN found = FALSE;

	TRACE_ENTER();

	TRACE_PRINT1("Updating adapter info for adapter %hs", AdapterName);
	
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	
	PrevAdInfo = TAdInfo = g_AdaptersInfoList;

	//
	// If an entry for this adapter is present in the list, we destroy it
	//
	while(TAdInfo != NULL)
	{
		if(_stricmp(TAdInfo->Name, AdapterName) == 0)
		{
			if(TAdInfo == g_AdaptersInfoList)
			{
				g_AdaptersInfoList = TAdInfo->Next;
			}
			else
			{
				PrevAdInfo->Next = TAdInfo->Next;
			}

			if (TAdInfo->pNetworkAddresses != NULL)
			{
				PNPF_IF_ADDRESS_ITEM pItem, pNext;

				pItem = TAdInfo->pNetworkAddresses;

				while(pItem != NULL)
				{
					pNext = pItem->Next;

					HeapFree(GetProcessHeap(), 0, pItem);
					pItem = pNext;
				}
			}
			
			HeapFree(GetProcessHeap(), 0, TAdInfo);

			break;
		}

		PrevAdInfo = TAdInfo;

		TAdInfo = TAdInfo->Next;
	}

	ReleaseMutex(g_AdaptersInfoMutex);
	if (_stricmp(AdapterName, FAKE_LOOPBACK_ADAPTER_NAME) == 0) {
		found = (g_bLoopbackSupport && PacketAddLoopbackAdapter());
		TRACE_EXIT();
		return found;
	}

	AdapterGuid = strchr(AdapterName, '{');
	if (AdapterGuid == NULL)
	{
		TRACE_PRINT("PacketUpdateAdInfo: Not a valid adapter name");
		TRACE_EXIT();
		return FALSE;
	}

	BufLen = g_GaaBufLast;
	AdBuffer = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufLen);
	if (AdBuffer == NULL)
	{
		TRACE_PRINT("PacketUpdateAdInfo: HeapAlloc Failed");
		TRACE_EXIT();
		return FALSE;
	}
	for (Iterations = 0; Iterations < ADAPTERS_ADDRESSES_MAX_TRIES; Iterations++)
	{

		RetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | // Get everything
			GAA_FLAG_SKIP_DNS_INFO | // Undocumented, reported to help avoid errors on Win10 1809
			// We don't use any of these features:
			GAA_FLAG_SKIP_DNS_SERVER |
			GAA_FLAG_SKIP_ANYCAST |
			GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, AdBuffer, &BufLen);
		if (RetVal == ERROR_BUFFER_OVERFLOW)
		{
			TRACE_PRINT("PacketUpdateAdInfo: GetAdaptersAddresses Too small buffer");
			TmpAddr = (PIP_ADAPTER_ADDRESSES)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AdBuffer, BufLen);
			if (TmpAddr == NULL)
			{
				TRACE_PRINT("PacketUpdateAdInfo: HeapReAlloc Failed");
				HeapFree(GetProcessHeap(), 0, AdBuffer);
				TRACE_EXIT();
				return FALSE;
			}
			AdBuffer = TmpAddr;
		}
		else
		{
			break;
		}
	}

	if (RetVal != ERROR_SUCCESS)
	{
		TRACE_PRINT("PacketUpdateAdInfo: GetAdaptersAddresses Failed while retrieving the addresses");
		if (AdBuffer)
		{
			HeapFree(GetProcessHeap(), 0, AdBuffer);
		}
		TRACE_EXIT();
		return FALSE;
	}

	// Stash the value that worked here
	g_GaaBufLast = BufLen;

	//
	// Now obtain the information about this adapter
	//
	for (TmpAddr=AdBuffer; TmpAddr != NULL; TmpAddr = TmpAddr->Next)
	{
		// If the adapter matches, add it to the list.
		if(_stricmp(TmpAddr->AdapterName, AdapterGuid) == 0)
		{
			PacketAddAdapterNPF(TmpAddr);
			found = TRUE;
			break;
		}
	}

#ifdef HAVE_AIRPCAP_API
	if (!found)
	{
		if (g_PAirpcapGetDeviceList != NULL)
		{
			PacketGetAdaptersAirpcap();
			found = (PacketFindAdInfo(AdapterName) != NULL);
		}
		else
		{
			TRACE_PRINT("AirPcap extension not available");
		}
	}
#endif
	if (AdBuffer)
	{
		HeapFree(GetProcessHeap(), 0, AdBuffer);
	}
	TRACE_EXIT();
	return found;
}

/*!
  \brief Populates the list of the adapters.

  This function populates the list of adapter descriptions, invoking PacketGetAdapters*()
*/
void PacketPopulateAdaptersInfoList()
{
	//this function should acquire the g_AdaptersInfoMutex, since it's NOT called with an ADAPTER_INFO as parameter
	PADAPTER_INFO TAdInfo;
	PVOID Mem2;

	TRACE_ENTER();

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	if(g_AdaptersInfoList)
	{
		// Free the old list
		TAdInfo = g_AdaptersInfoList;
		while(TAdInfo != NULL)
		{
			PNPF_IF_ADDRESS_ITEM pItem, pCursor;
			Mem2 = TAdInfo;
			
			pCursor = TAdInfo->pNetworkAddresses;
			TAdInfo = TAdInfo->Next;
			
			while(pCursor != NULL)
			{
				pItem = pCursor->Next;
				HeapFree(GetProcessHeap(), 0, pCursor);
				pCursor = pItem;
			}
			HeapFree(GetProcessHeap(), 0, Mem2);
		}
		
		g_AdaptersInfoList = NULL;
	}

	//
	// Fill the new list
	//
	if(!PacketGetAdaptersNPF())
	{
		// No info about adapters in the registry. (NDIS adapters, i.e. exported by NPF)
		TRACE_PRINT("PacketPopulateAdaptersInfoList: registry scan for adapters failed!");
	}

#ifdef HAVE_AIRPCAP_API
	if(g_PAirpcapGetDeviceList)	// Ensure that the airpcap dll is present
	{
		if(!PacketGetAdaptersAirpcap())
		{
			TRACE_PRINT("PacketPopulateAdaptersInfoList: lookup of airpcap adapters failed!");
		}
	}
#endif // HAVE_AIRPCAP_API

	ReleaseMutex(g_AdaptersInfoMutex);
	TRACE_EXIT();
}
