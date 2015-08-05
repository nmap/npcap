/*
* Copyright (c) 1997 - 2015
* Nmap.org (U.S.)
* All rights reserved.
*
* Loopback.c
*
* Abstract:
* This file declares common functions used
* throughout loopback packets capturing.
*
* This code is based on Microsoft WFP Network Inspect sample.
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

#include "Loopback.h"
#include "packet.h"
#include "debug.h"

#define NPCAP_CALLOUT_DRIVER_TAG (UINT32) 'NPCA'

#define IPPROTO_NPCAP_LOOPBACK		250

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
typedef struct _IPV6_HEADER
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
} IPV6_HEADER, *PIPV6_HEADER;

/*
* The length of the IPv6 header.
*/
#define	IPV6_HDR_LEN		sizeof(IPV6_HEADER)

// 
// Global variables
//
extern POPEN_INSTANCE g_LoopbackOpenGroupHead; // Loopback adapter open_instance group head, this pointer points to one item in g_arrOpen list.

// 
// Callout and sublayer GUIDs
//

// 2D605B3E-C244-4364-86E8-BD81E6C91B6D
DEFINE_GUID(
	NPF_OUTBOUND_IPPACKET_CALLOUT_V4,
	0x2d605b3e,
	0xc244,
	0x4364,
	0x86, 0xe8, 0xbd, 0x81, 0xe6, 0xc9, 0x1b, 0x6d
	);
// F935E4CD-9499-4934-824D-8E3726BA4A93
DEFINE_GUID(
	NPF_OUTBOUND_IPPACKET_CALLOUT_V6,
	0xf935e4cd,
	0x9499,
	0x4934,
	0x82, 0x4d, 0x8e, 0x37, 0x26, 0xba, 0x4a, 0x93
	);
// ED7E5EB2-6B09-4783-961C-5495EAAD361E
DEFINE_GUID(
	NPF_INBOUND_IPPACKET_CALLOUT_V4,
	0xed7e5eb2,
	0x6b09,
	0x4783,
	0x96, 0x1c, 0x54, 0x95, 0xea, 0xad, 0x36, 0x1e
	);
// 21022F40-9578-4C39-98A5-C97B8D834E27
DEFINE_GUID(
	NPF_INBOUND_IPPACKET_CALLOUT_V6,
	0x21022f40,
	0x9578,
	0x4c39,
	0x98, 0xa5, 0xc9, 0x7b, 0x8d, 0x83, 0x4e, 0x27
	);

// 2F32C254-A054-469B-B99B-3E8810275A71
DEFINE_GUID(
	NPF_SUBLAYER,
	0x2f32c254,
	0xa054,
	0x469b,
	0xb9, 0x9b, 0x3e, 0x88, 0x10, 0x27, 0x5a, 0x71
	);


// 
// Callout driver global variables
//

HANDLE g_WFPEngineHandle = INVALID_HANDLE_VALUE;
UINT32 g_OutboundIPPacketV4 = 0;
UINT32 g_OutboundIPPacketV6 = 0;
UINT32 g_InboundIPPacketV4 = 0;
UINT32 g_InboundIPPacketV6 = 0;
HANDLE g_InjectionHandle_IPv4 = INVALID_HANDLE_VALUE;
HANDLE g_InjectionHandle_IPv6 = INVALID_HANDLE_VALUE;


BOOLEAN
NPF_IsPacketSelfSent(
	_In_ PNET_BUFFER_LIST pNetBufferList,
	_In_ BOOLEAN bIPv4
	)
{
	NTSTATUS			status = STATUS_SUCCESS;
	NET_BUFFER*			pNetBuffer = 0;
	PVOID				pContiguousData = NULL;
	UCHAR				pPacketData[IPV6_HDR_LEN];
	UCHAR				iProtocol;

	TRACE_ENTER();

	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
	while (pNetBuffer)
	{
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			bIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			pPacketData,
			1,
			0);
		if (!pContiguousData)
		{
			status = STATUS_UNSUCCESSFUL;

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_IsPacketSelfSent: NdisGetDataBuffer() [status: %#x]\n",
				status);

			TRACE_EXIT();
			return FALSE;
		}
		else
		{
			iProtocol = bIPv4 ? ((PIP_HEADER) pContiguousData)->ip_Protocol : ((PIPV6_HEADER) pContiguousData)->ip6_CTL.ip6_HeaderCtl.ip6_NextHeader;
			if (iProtocol == IPPROTO_NPCAP_LOOPBACK)
			{
				TRACE_EXIT();
				return TRUE;
			}
			else
			{
				TRACE_EXIT();
				return FALSE;
			}
		}

		pNetBuffer = pNetBuffer->Next;
	}

	TRACE_EXIT();
	return FALSE;
}

VOID
NPF_NetworkInjectionComplete(
	_In_ VOID* pContext,
	_Inout_ NET_BUFFER_LIST* pNetBufferList,
	_In_ BOOLEAN dispatchLevel
	)
{
	UNREFERENCED_PARAMETER(dispatchLevel);

	TRACE_ENTER();

	if (pNetBufferList->Status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkInjectionComplete: pNetBufferList->Status [status: %#x]\n",
			pNetBufferList->Status);
	}

	FwpsFreeCloneNetBufferList(pNetBufferList, 0);

	TRACE_EXIT();
	return;
}

// 
// Callout driver functions
//

#if(NTDDI_VERSION >= NTDDI_WIN7)

/* ++

This is the classifyFn function for the Transport (v4 and v6) callout.
packets (inbound or outbound) are ueued to the packet queue to be processed
by the worker thread.

-- */
void
NPF_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
	)

#else

void
NPF_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
	)

#endif

{
	POPEN_INSTANCE		GroupOpen;
	POPEN_INSTANCE		TempOpen;
	NTSTATUS			status = STATUS_SUCCESS;
	UINT32				ipHeaderSize = 0;
	UINT32				bytesRetreated = 0;
	UINT32				bytesRetreatedEthernet = 0;
	INT32				iIPv4 = -1;
	INT32				iDrection = -1;
	BOOLEAN				bSelfSent = FALSE;
	PETHER_HEADER		pContiguousData = NULL;
	NET_BUFFER*			pNetBuffer = 0;
	UCHAR				pPacketData[ETHER_HDR_LEN];
	PNET_BUFFER_LIST	pNetBufferList = (NET_BUFFER_LIST*) layerData;
	COMPARTMENT_ID		compartmentID = UNSPECIFIED_COMPARTMENT_ID;
	FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_INJECTION_STATE_MAX;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
		classifyOut->actionType = FWP_ACTION_CONTINUE;

	// Filter out fragment packets and reassembled packets.
	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FRAGMENT_DATA)
	{
		return;
	}
	if (inMetaValues->currentMetadataValues & FWP_CONDITION_FLAG_IS_REASSEMBLED)
	{
		return;
	}

	TRACE_ENTER();

	// Get the packet protocol (IPv4 or IPv6) and the direction (Inbound or Outbound).
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4)
	{
		iIPv4 = 1;
	}
	else // if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6)
	{
		iIPv4 = 0;
	}
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6)
	{
		iDrection = 0;
	}
	else // if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6)
	{
		iDrection = 1;
	}

	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE)
	{
		ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	injectionState = FwpsQueryPacketInjectionState(iIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
		pNetBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassify: this packet is injected by ourself, let it go\n");

		TRACE_EXIT();
		return;
	}

	// Inbound: Initial offset is at the Transport Header, so retreat the size of the Ethernet Header and IP Header.
	// Outbound: Initial offset is at the IP Header, so just retreat the size of the Ethernet Header.
	// We retreated the packet in two phases: 1) retreat the IP Header (if has), 2) clone the packet and retreat the Ethernet Header.
	// We must NOT retreat the Ethernet Header on the original packet, or this will lead to BAD_POOL_CALLER Bluescreen.
	bytesRetreated = iDrection ? ipHeaderSize : 0;

	status = NdisRetreatNetBufferListDataStart(pNetBufferList,
		bytesRetreated,
		0,
		NULL,
		NULL);

	if (status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassify: NdisRetreatNetBufferListDataStart(bytesRetreated) [status: %#x]\n",
			status);

		TRACE_EXIT();
		return;
	}

	//bSelfSent = NPF_IsPacketSelfSent(pNetBufferList, (BOOLEAN)iIPv4);
	bSelfSent = (iDrection == 0) ? FALSE : NPF_IsPacketSelfSent(pNetBufferList, (BOOLEAN) iIPv4);
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
		"NPF_NetworkClassify: NPF_IsPacketSelfSent() [bSelfSent: %#x]\n",
		bSelfSent);

	if (bSelfSent)
	{
		NdisAdvanceNetBufferListDataStart(pNetBufferList,
			iIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			FALSE,
			0);
	}

	// Here if this NBL is sent by ourself, we will clone it starting from IP header and inject it into Network Layer send path.
	if (bSelfSent)
	{
		PNET_BUFFER_LIST pClonedNetBufferList_Injection;
		status = FwpsAllocateCloneNetBufferList(pNetBufferList, NULL, NULL, 0, &pClonedNetBufferList_Injection);
		if (status != STATUS_SUCCESS)
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassify: FwpsAllocateCloneNetBufferList(pClonedNetBufferList_Injection) [status: %#x]\n",
				status);

			goto Exit_WSK_IP_Retreated;
		}

		if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
			FWPS_METADATA_FIELD_COMPARTMENT_ID))
			compartmentID = (COMPARTMENT_ID)inMetaValues->compartmentId;

		// This cloned NBL will be freed in NPF_NetworkInjectionComplete function.
		status = FwpsInjectNetworkSendAsync(iIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
			NULL,
			0,
			compartmentID,
			pClonedNetBufferList_Injection,
			NPF_NetworkInjectionComplete,
			NULL);
		if (status != STATUS_SUCCESS)
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassify: FwpsInjectNetworkSendAsync() [status: %#x]\n",
				status);

			FwpsFreeCloneNetBufferList(pClonedNetBufferList_Injection, 0);
			goto Exit_WSK_IP_Retreated;
		}

		// We have successfully re-inject the cloned NBL, so remove this one.
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		classifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;
	}

	// We clone this NBL again, for packet reading operation.
	PNET_BUFFER_LIST pClonedNetBufferList;
	status = FwpsAllocateCloneNetBufferList(pNetBufferList, NULL, NULL, 0, &pClonedNetBufferList);
	if (status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassify: FwpsAllocateCloneNetBufferList() [status: %#x]\n",
			status);

		goto Exit_WSK_IP_Retreated;
	}

	bytesRetreatedEthernet = ETHER_HDR_LEN;
	status = NdisRetreatNetBufferListDataStart(pClonedNetBufferList,
		bytesRetreatedEthernet,
		0,
		0,
		0);
	if (status != STATUS_SUCCESS)
	{
		bytesRetreatedEthernet = 0;

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassify: NdisRetreatNetBufferListDataStart(bytesRetreatedEthernet) [status: %#x]\n",
			status);

		goto Exit_Packet_Cloned;
	}

	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pClonedNetBufferList);
	while (pNetBuffer)
	{
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			ETHER_HDR_LEN,
			pPacketData,
			1,
			0);
		if (!pContiguousData)
		{
			status = STATUS_UNSUCCESSFUL;

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassify: NdisGetDataBuffer() [status: %#x]\n",
				status);

			goto Exit_Ethernet_Retreated;
		}
		else
		{
			RtlZeroMemory(pContiguousData, ETHER_ADDR_LEN * 2);
			pContiguousData->ether_type = iIPv4 ? RtlUshortByteSwap(ETHERTYPE_IP) : RtlUshortByteSwap(ETHERTYPE_IPV6);
		}

		pNetBuffer = pNetBuffer->Next;
	}

	// Send the loopback packets data to the user-mode code.
	if (g_LoopbackOpenGroupHead)
	{
		//get the 1st group adapter child
		GroupOpen = g_LoopbackOpenGroupHead->GroupNext;
	}
	else
	{
		// Should not come here
		GroupOpen = NULL;
	}

	while (GroupOpen != NULL)
	{
		TempOpen = GroupOpen;
		if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
		{
			//let every group adapter receive the packets
			NPF_TapExForEachOpen(TempOpen, pClonedNetBufferList);
		}

		GroupOpen = TempOpen->GroupNext;
	}

Exit_Ethernet_Retreated:
	// Advance the offset back to the original position.
	NdisAdvanceNetBufferListDataStart(pClonedNetBufferList,
		bytesRetreatedEthernet,
		FALSE,
		0);

Exit_Packet_Cloned:
	FwpsFreeCloneNetBufferList(pClonedNetBufferList, 0);

Exit_WSK_IP_Retreated:
	if (bSelfSent)
	{
		status = NdisRetreatNetBufferListDataStart(pNetBufferList,
			iIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			0,
			NULL,
			NULL);

// 		if (status != STATUS_SUCCESS)
// 		{
// 			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
// 				"NPF_NetworkClassify: NdisRetreatNetBufferListDataStart(IP_HDR_LEN) [status: %#x]\n",
// 				status);
//
// 			goto Exit_IP_Retreated;
// 		}
	}

/*Exit_IP_Retreated:*/
	NdisAdvanceNetBufferListDataStart(pNetBufferList,
		bytesRetreated,
		FALSE,
		0);

// 	// print "protocol, direction, fragment, reassembled" info for the current packet.
// 
// 	int iFragment = -1;
// 	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FRAGMENT_DATA)
// 	{
// 		iFragment = 1;
// 	}
// 	else
// 	{
// 		iFragment = 0;
// 	}
// 
// 	int iReassembled = -1;
// 	if (inMetaValues->currentMetadataValues & FWP_CONDITION_FLAG_IS_REASSEMBLED)
// 	{
// 		iReassembled = 1;
// 	}
// 	else
// 	{
// 		iReassembled = 0;
// 	}
// 	IF_LOUD(DbgPrint("\n\nNPF_NetworkClassify: Loopback packet found !!! protocol=[%d] (ipv4=0, ipv6=1), direction=[%d] (out=0, in=1), fragment=[%d], reassembled=[%d]\n", iProtocol, iDrection, iFragment, iReassembled);)


	TRACE_EXIT();
	return;
}

NTSTATUS
NPF_NetworkNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter
	)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	TRACE_ENTER();

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

// 
// Callout driver implementation
//

NTSTATUS
NPF_AddFilter(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey,
	_In_ const int iFlag
	)
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[1] = { 0 };
	UINT conditionIndex;

	filter.layerKey = *layerKey;
	filter.displayData.name = L"Network Npcap Filter (Outbound)";
	filter.displayData.description = L"Npcap inbound/outbound network traffic";

	filter.action.calloutKey = *calloutKey;
	filter.filterCondition = filterConditions;
	filter.subLayerKey = NPF_SUBLAYER;
	filter.rawContext = 0;
	conditionIndex = 0;

	if (iFlag == 0)
	{
		filter.action.type = FWP_ACTION_PERMIT;
		filter.weight.type = FWP_UINT8;
		filter.weight.uint8 = 0x5;
		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_NONE_SET;
		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
		filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
		conditionIndex++;
	}
	else if (iFlag == 1)
	{
		filter.action.type = FWP_ACTION_PERMIT;
		filter.weight.type = FWP_UINT8;
		filter.weight.uint8 = 0x4;
		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_ALL_SET;
		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
		filterConditions[conditionIndex].conditionValue.uint32 = FWPS_METADATA_FIELD_FRAGMENT_DATA;
		conditionIndex++;
	}
	else if (iFlag == 2)
	{
		filter.action.type = FWP_ACTION_PERMIT;
		filter.weight.type = FWP_UINT8;
		filter.weight.uint8 = 0x3;
		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_ALL_SET;
		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
		filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_REASSEMBLED;
		conditionIndex++;
	}
	else if (iFlag == 3)
	{
		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
		filter.weight.type = FWP_UINT8;
		filter.weight.uint8 = 0x2;
		filter.filterCondition = NULL;
	}
	// 	else if (iFlag == 1)
	// 	{
	// 		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	// 		filter.weight.type = FWP_UINT8;
	// 		filter.weight.uint8 = 0x4;
	// 		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
	// 		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_NONE_SET;
	// 		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
	// 		filterConditions[conditionIndex].conditionValue.uint32 = FWPS_METADATA_FIELD_FRAGMENT_DATA | FWP_CONDITION_FLAG_IS_REASSEMBLED;
	// 		conditionIndex++;
	// 	}

	filter.numFilterConditions = conditionIndex;

	status = FwpmFilterAdd(
		g_WFPEngineHandle,
		&filter,
		NULL,
		NULL);

	TRACE_EXIT();
	return status;
}

NTSTATUS
NPF_RegisterCallout(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey,
	_Inout_ void* deviceObject,
	_Out_ UINT32* calloutId
	)
/* ++

This function registers callouts and filters that intercept transport
traffic at the following layers --

FWPM_LAYER_INBOUND_IPPACKET_V4
FWPM_LAYER_INBOUND_IPPACKET_V6
FWPM_LAYER_OUTBOUND_IPPACKET_V4
FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD

-- */
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = NPF_NetworkClassify;
	sCallout.notifyFn = NPF_NetworkNotify;

	status = FwpsCalloutRegister(
		deviceObject,
		&sCallout,
		calloutId
		);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = L"Npcap Network Callout";
	displayData.description = L"Npcap inbound/outbound network traffic";

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd(
		g_WFPEngineHandle,
		&mCallout,
		NULL,
		NULL
		);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 0);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 1);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 2);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 3);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit:

	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("NPF_RegisterCallout: failed to register callout\n");)
			if (calloutRegistered)
			{
				FwpsCalloutUnregisterById(*calloutId);
				*calloutId = 0;
			}
	}

	TRACE_EXIT();
	return status;
}

NTSTATUS
NPF_RegisterCallouts(
_Inout_ void* deviceObject
)
/* ++

This function registers dynamic callouts and filters that intercept
transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and
INBOUND/OUTBOUND transport layers.

Callouts and filters will be removed during DriverUnload.

-- */
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER NPFSubLayer;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;

	FWPM_SESSION session = { 0 };

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&g_WFPEngineHandle
		);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	engineOpened = TRUE;

	status = FwpmTransactionBegin(g_WFPEngineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	inTransaction = TRUE;

	RtlZeroMemory(&NPFSubLayer, sizeof(FWPM_SUBLAYER));

	NPFSubLayer.subLayerKey = NPF_SUBLAYER;
	NPFSubLayer.displayData.name = L"Npcap Loopback Sub-Layer";
	NPFSubLayer.displayData.description = L"Sub-Layer for use by Npcap Loopback callouts";
	NPFSubLayer.flags = 0;
	NPFSubLayer.weight = 0; // must be less than the weight of 
	// FWPM_SUBLAYER_UNIVERSAL to be
	// compatible with Vista's IpSec
	// implementation.

	status = FwpmSubLayerAdd(g_WFPEngineHandle, &NPFSubLayer, NULL);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	//if (isV4)
	{
		status = NPF_RegisterCallout(
			&FWPM_LAYER_OUTBOUND_IPPACKET_V4,
			&NPF_OUTBOUND_IPPACKET_CALLOUT_V4,
			deviceObject,
			&g_OutboundIPPacketV4
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		status = NPF_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V4,
			&NPF_INBOUND_IPPACKET_CALLOUT_V4,
			deviceObject,
			&g_InboundIPPacketV4
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}
	}
	//else
	{
		status = NPF_RegisterCallout(
			&FWPM_LAYER_OUTBOUND_IPPACKET_V6,
			&NPF_OUTBOUND_IPPACKET_CALLOUT_V6,
			deviceObject,
			&g_OutboundIPPacketV6
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		status = NPF_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V6,
			&NPF_INBOUND_IPPACKET_CALLOUT_V6,
			deviceObject,
			&g_InboundIPPacketV6
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}
	}

	status = FwpmTransactionCommit(g_WFPEngineHandle);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	inTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("NPF_RegisterCallouts: failed to register callouts\n");)
			if (inTransaction)
			{
				FwpmTransactionAbort(g_WFPEngineHandle);
				_Analysis_assume_lock_not_held_(g_WFPEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
			}
		if (engineOpened)
		{
			FwpmEngineClose(g_WFPEngineHandle);
			g_WFPEngineHandle = INVALID_HANDLE_VALUE;
		}
	}

	TRACE_EXIT();
	return status;
}

void
NPF_UnregisterCallouts(
	)
{
	TRACE_ENTER();

	if (g_WFPEngineHandle != INVALID_HANDLE_VALUE)
	{
		FwpmEngineClose(g_WFPEngineHandle);
		g_WFPEngineHandle = INVALID_HANDLE_VALUE;

		if (g_OutboundIPPacketV4)
		{
			FwpsCalloutUnregisterById(g_OutboundIPPacketV4);
		}
		if (g_OutboundIPPacketV6)
		{
			FwpsCalloutUnregisterById(g_OutboundIPPacketV6);
		}
		if (g_InboundIPPacketV4)
		{
			FwpsCalloutUnregisterById(g_InboundIPPacketV4);
		}
		if (g_InboundIPPacketV6)
		{
			FwpsCalloutUnregisterById(g_InboundIPPacketV6);
		}
	}

	TRACE_EXIT();
}

NTSTATUS
NPF_InitInjectionHandles(
)
/* ++

Open injection handles (IPv4 and IPv6) for use with the various injection APIs.

injection handles will be removed during DriverUnload.

-- */
{
	NTSTATUS status = STATUS_SUCCESS;

	TRACE_ENTER();

	status = FwpsInjectionHandleCreate(AF_INET,
		FWPS_INJECTION_TYPE_NETWORK,
		&g_InjectionHandle_IPv4);

	if (status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_InitInjectionHandles: FwpsInjectionHandleCreate(AF_INET) [status: %#x]\n",
			status);

		TRACE_EXIT();
		return status;
	}

	status = FwpsInjectionHandleCreate(AF_INET6,
		FWPS_INJECTION_TYPE_NETWORK,
		&g_InjectionHandle_IPv6);

	if (status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_InitInjectionHandles: FwpsInjectionHandleCreate(AF_INET6) [status: %#x]\n",
			status);

		TRACE_EXIT();
		return status;
	}

	TRACE_EXIT();
	return status;
}

NTSTATUS
NPF_FreeInjectionHandles(
	)
/* ++

Free injection handles (IPv4 and IPv6).

-- */
{
	NTSTATUS status = STATUS_SUCCESS;

	TRACE_ENTER();

	if (g_InjectionHandle_IPv4 != INVALID_HANDLE_VALUE)
	{
		status = FwpsInjectionHandleDestroy(g_InjectionHandle_IPv4);

		if (status != STATUS_SUCCESS)
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_InitInjectionHandles: FwpsInjectionHandleDestroy(AF_INET) [status: %#x]\n",
				status);

			TRACE_EXIT();
			return status;
		}

		g_InjectionHandle_IPv4 = INVALID_HANDLE_VALUE;
	}

	if (g_InjectionHandle_IPv6 != INVALID_HANDLE_VALUE)
	{
		status = FwpsInjectionHandleDestroy(g_InjectionHandle_IPv6);

		if (status != STATUS_SUCCESS)
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_InitInjectionHandles: FwpsInjectionHandleDestroy(AF_INET6) [status: %#x]\n",
				status);

			TRACE_EXIT();
			return status;
		}

		g_InjectionHandle_IPv6 = INVALID_HANDLE_VALUE;
	}

	TRACE_EXIT();
	return status;
}

#endif
