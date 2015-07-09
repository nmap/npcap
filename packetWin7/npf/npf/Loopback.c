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

#include "stdafx.h"

#include "Loopback.h"
#include "packet.h"
#include "debug.h"

#define NPCAP_CALLOUT_DRIVER_TAG (UINT32) 'NPCA'

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

HANDLE gWFPEngineHandle;
UINT32 gOutboundIPPacketV4 = 0;
UINT32 gOutboundIPPacketV6 = 0;
UINT32 gInboundIPPacketV4 = 0;
UINT32 gInboundIPPacketV6 = 0;

typedef struct CLASSIFY_DATA_
{
	const FWPS_INCOMING_VALUES*          pClassifyValues;
	const FWPS_INCOMING_METADATA_VALUES* pMetadataValues;
	VOID*                                pPacket;               /// NET_BUFFER_LIST | FWPS_STREAM_CALLOUT_IO_PACKET
	const VOID*                          pClassifyContext;
	const FWPS_FILTER*                   pFilter;
	UINT64                               flowContext;
	FWPS_CLASSIFY_OUT*                   pClassifyOut;
	UINT64                               classifyContextHandle;
	BOOLEAN                              chainedNBL;
	UINT32                               numChainedNBLs;
}CLASSIFY_DATA, *PCLASSIFY_DATA;


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
	INT32				iProtocol = -1;
	INT32				iDrection = -1;
	PETHER_HEADER		pContiguousData = NULL;
	NET_BUFFER*			pNetBuffer = 0;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

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

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
		classifyOut->actionType = FWP_ACTION_CONTINUE;

	// Get the packet protocol (IPv4 or IPv6) and the direction (Inbound or Outbound).
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4)
	{
		iProtocol = 0;
	}
	else // if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6)
	{
		iProtocol = 1;
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

	// Inbound: Initial offset is at the Transport Header, so retreat the size of the Ethernet Header and IP Header.
	// Outbound: Initial offset is at the IP Header, so just retreat the size of the Ethernet Header.
	bytesRetreated = iDrection ? ETHER_HDR_LEN + ipHeaderSize : ETHER_HDR_LEN;
	status = NdisRetreatNetBufferListDataStart((NET_BUFFER_LIST*) layerData,
		bytesRetreated,
		0,
		0,
		0);
	if (status != STATUS_SUCCESS)
	{
		bytesRetreated = 0;

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassify: NdisRetreatNetBufferListDataStart() [status: %#x]\n",
			status);

		TRACE_EXIT();
		return;
	}

	pNetBuffer = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*) layerData);
	while (pNetBuffer)
	{
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			NET_BUFFER_DATA_LENGTH(pNetBuffer),
			0,
			1,
			0);
		if (!pContiguousData)
		{
			status = STATUS_UNSUCCESSFUL;

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassify: NdisGetDataBuffer() [status: %#x]\n",
				status);

			TRACE_EXIT();
			return;
		}
		else
		{
			pContiguousData->ether_type = iProtocol ? RtlUshortByteSwap(ETHERTYPE_IPV6) : RtlUshortByteSwap(ETHERTYPE_IP);
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
			NPF_TapExForEachOpen(TempOpen, (PNET_BUFFER_LIST) layerData);
		}

		GroupOpen = TempOpen->GroupNext;
	}

	// Advance the offset back to the original position.
	NdisAdvanceNetBufferListDataStart((NET_BUFFER_LIST*) layerData,
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
		gWFPEngineHandle,
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
		gWFPEngineHandle,
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
		&gWFPEngineHandle
		);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	engineOpened = TRUE;

	status = FwpmTransactionBegin(gWFPEngineHandle, 0);
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

	status = FwpmSubLayerAdd(gWFPEngineHandle, &NPFSubLayer, NULL);
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
			&gOutboundIPPacketV4
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		status = NPF_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V4,
			&NPF_INBOUND_IPPACKET_CALLOUT_V4,
			deviceObject,
			&gInboundIPPacketV4
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
			&gOutboundIPPacketV6
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		status = NPF_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V6,
			&NPF_INBOUND_IPPACKET_CALLOUT_V6,
			deviceObject,
			&gInboundIPPacketV6
			);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}
	}

	status = FwpmTransactionCommit(gWFPEngineHandle);
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
				FwpmTransactionAbort(gWFPEngineHandle);
				_Analysis_assume_lock_not_held_(gWFPEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
			}
		if (engineOpened)
		{
			FwpmEngineClose(gWFPEngineHandle);
			gWFPEngineHandle = NULL;
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

	if (gWFPEngineHandle)
	{
		FwpmEngineClose(gWFPEngineHandle);
		gWFPEngineHandle = NULL;
	}

	if (gOutboundIPPacketV4)
	{
		FwpsCalloutUnregisterById(gOutboundIPPacketV4);
	}
	if (gOutboundIPPacketV6)
	{
		FwpsCalloutUnregisterById(gOutboundIPPacketV6);
	}
	if (gInboundIPPacketV4)
	{
		FwpsCalloutUnregisterById(gInboundIPPacketV4);
	}
	if (gInboundIPPacketV6)
	{
		FwpsCalloutUnregisterById(gInboundIPPacketV6);
	}

	TRACE_EXIT();
}