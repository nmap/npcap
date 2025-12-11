/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2025 by Nmap Software LLC ("The Nmap Project").  All
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
* Loopback.c
*
* Abstract:
* This file declares common functions used
* throughout loopback packets capturing.
*
* This code is based on Microsoft WFP Network Inspect sample.
*
*/

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#include "stdafx.h"

#include "Loopback.h"
#include "Packet.h"
#include "..\..\..\Common\WpcapNames.h"
#include "..\..\..\version.h"

#include <fwpsk.h>
#include <fwpmk.h>

#define INITGUID
#include <guiddef.h>

// 
// Global variables
//
extern PNPCAP_DRIVER_EXTENSION g_pDriverExtension;

// 
// Callout and sublayer GUIDs
//

// af617412-ce10-4058-8996-abc79fd805ff
DEFINE_GUID(
	NPF_FWPM_PROVIDER_GUID,
	0xaf617412,
	0xce10,
	0x4058,
	0x89, 0x96, 0xab, 0xc7, 0x9f, 0xd8, 0x05, 0xff
);

// ED7E5EB2-6B09-4783-961C-5495EAAD361F
DEFINE_GUID(
	NPF_INBOUND_IPPACKET_CALLOUT_V4,
	0xed7e5eb2,
	0x6b09,
	0x4783,
	0x96, 0x1c, 0x54, 0x95, 0xea, 0xad, 0x36, 0x1f
);
// 21022F40-9578-4C39-98A5-C97B8D834E28
DEFINE_GUID(
	NPF_INBOUND_IPPACKET_CALLOUT_V6,
	0x21022f40,
	0x9578,
	0x4c39,
	0x98, 0xa5, 0xc9, 0x7b, 0x8d, 0x83, 0x4e, 0x28
);

// 2F32C254-A054-469B-B99B-3E8810275A72
DEFINE_GUID(
	NPF_SUBLAYER,
	0x2f32c254,
	0xa054,
	0x469b,
	0xb9, 0x9b, 0x3e, 0x88, 0x10, 0x27, 0x5a, 0x72
);


// Send the loopback packets data to the user-mode code.
VOID
NPF_TapLoopback(
        _In_ PNPCAP_FILTER_MODULE pLoopbackFilter,
        _In_ BOOLEAN bIPv4,
        _In_ PNET_BUFFER_LIST pNetBufferList
        )
{
	UCHAR pPacketData[ETHER_HDR_LEN] = {0};
	UINT numBytes = 0;
    PUCHAR npBuff = NULL;
    PNET_BUFFER_LIST pFakeNbl = NULL;
    PNET_BUFFER pFakeNetBuffer = NULL;
    PNET_BUFFER pNetBuffer = NULL;
    ULONG Offset = 0;
    PUCHAR pOrigBuf = NULL;
    ULONG OrigLen = 0;
    ULONG FirstMDLLen = 0;
    PUCHAR pTmpBuf = NULL;
    PMDL pMdl = NULL;

	NT_ASSERT(pLoopbackFilter != NULL);
	do {
		/* Quick check to avoid extra work.
		 * Won't lock because we're not actually traversing. */
		if (NULL == pLoopbackFilter->OpenInstances.Next) {
			break;
		}
		if (g_pDriverExtension->bDltNullMode)
		{
			((PDLT_NULL_HEADER) pPacketData)->null_type = bIPv4 ? DLTNULLTYPE_IP : DLTNULLTYPE_IPV6;
			numBytes = DLT_NULL_HDR_LEN;
		}
		else
		{
			/* Addresses zero-initialized */
			((PETHER_HEADER) pPacketData)->ether_type = bIPv4 ? RtlUshortByteSwap(ETHERTYPE_IP) : RtlUshortByteSwap(ETHERTYPE_IPV6);
			numBytes = ETHER_HDR_LEN;
		}
		// TODO: use a lookahead list for npBuffs
		npBuff = (PUCHAR) NdisAllocateMemoryWithTagPriority(
				pLoopbackFilter->AdapterHandle, numBytes, NPF_LOOPBACK_COPY_TAG, NormalPoolPriority);
		if (npBuff == NULL)
		{
			WARNING_DBG("Failed to allocate buffer.\n");
			break;
		}
		RtlCopyMemory(npBuff, pPacketData, numBytes);

		pFakeNbl = NdisAllocateNetBufferAndNetBufferList(
				pLoopbackFilter->PacketPool, 0, 0, NULL, 0, 0);
		if (pFakeNbl == NULL)
		{
			WARNING_DBG("Failed to allocate NBL.\n");
			break;
		}
		pFakeNetBuffer = NET_BUFFER_LIST_FIRST_NB(pFakeNbl);
		/* Now loop through the original NBL, creating NBs in our fake NBL for each one. */
		pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
		while (pNetBuffer)
		{
			Offset = NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuffer);
			if (Offset >= numBytes) {
				QueryMdl(NET_BUFFER_CURRENT_MDL(pNetBuffer),
						&pOrigBuf,
						&OrigLen,
						NormalPagePriority);
				if (pOrigBuf == NULL) {
					WARNING_DBG("Failed to query MDL\n");
					break;
				}
				RtlCopyMemory(pOrigBuf + Offset - numBytes, pPacketData, numBytes);
				NET_BUFFER_FIRST_MDL(pFakeNetBuffer) =
					NET_BUFFER_CURRENT_MDL(pFakeNetBuffer) = NET_BUFFER_CURRENT_MDL(pNetBuffer);
				NET_BUFFER_DATA_OFFSET(pFakeNetBuffer) = 
					NET_BUFFER_CURRENT_MDL_OFFSET(pFakeNetBuffer) = Offset - numBytes;
				NET_BUFFER_DATA_LENGTH(pFakeNetBuffer) = numBytes + NET_BUFFER_DATA_LENGTH(pNetBuffer);
				// We didn't allocate a MDL, so make sure we don't free it.
				NET_BUFFER_PROTOCOL_RESERVED(pFakeNetBuffer)[0] = NULL;
			}
			else {
				if (Offset > 0) {
					/* Need to eliminate empty data prior to offset in our fake copy. */
					QueryMdl(NET_BUFFER_CURRENT_MDL(pNetBuffer),
							&pOrigBuf,
							&OrigLen,
							NormalPagePriority);
					if (pOrigBuf == NULL) {
						WARNING_DBG("Failed to query MDL\n");
						break;
					}
					/* Make a buffer big enough for our fake DLT header plus used
					 * data of first MDL */
					FirstMDLLen = numBytes + OrigLen - Offset;
					pTmpBuf = NdisAllocateMemoryWithTagPriority(
							pLoopbackFilter->AdapterHandle, FirstMDLLen, NPF_LOOPBACK_COPY_TAG, NormalPoolPriority);
					if (pTmpBuf == NULL)
					{
						WARNING_DBG("Failed to allocate buffer.\n");
						break;
					}
					RtlCopyMemory(pTmpBuf, pPacketData, numBytes);
					RtlCopyMemory(pTmpBuf + numBytes, pOrigBuf + Offset, OrigLen - Offset);
					pMdl = NdisAllocateMdl(pLoopbackFilter->AdapterHandle, pTmpBuf, FirstMDLLen);
					if (pMdl == NULL) {
						NdisFreeMemory(pTmpBuf, FirstMDLLen, 0);
						WARNING_DBG("Failed to allocate MDL.\n");
						break;
					}
					// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the buffer address
					// is stored in the MDL and we retrieve it (via QueryMdl) in the cleanup block below.
					// Therefore, it is not leaking after this point.
					NPF_AnalysisAssumeAliased(pTmpBuf);

					pMdl->Next = NET_BUFFER_CURRENT_MDL(pNetBuffer)->Next;
				}
				else {
					/* Allocate a MDL for the remainder and chain to theirs */
					pMdl = NdisAllocateMdl(pLoopbackFilter->AdapterHandle, npBuff, numBytes);
					if (pMdl == NULL)
					{
						WARNING_DBG("Failed to allocate MDL.\n");
						break;
					}
					// No NPF_AnalysisAssumeAliased here because there is only one npBuff, and we keep it around until we free it below.
					FirstMDLLen = numBytes;
					pMdl->Next = NET_BUFFER_CURRENT_MDL(pNetBuffer);
				}
				NET_BUFFER_FIRST_MDL(pFakeNetBuffer) = pMdl;
				NET_BUFFER_DATA_LENGTH(pFakeNetBuffer) = numBytes + NET_BUFFER_DATA_LENGTH(pNetBuffer);
				NET_BUFFER_DATA_OFFSET(pFakeNetBuffer) = 0;
				NET_BUFFER_CURRENT_MDL(pFakeNetBuffer) = pMdl;
				NET_BUFFER_CURRENT_MDL_OFFSET(pFakeNetBuffer) = 0;
				// We use the ProtocolReserved field to indicate that the MDL needs to be freed.
				NET_BUFFER_PROTOCOL_RESERVED(pFakeNetBuffer)[0] = pMdl;
			}
			/* Move down the chain! */
			pNetBuffer = pNetBuffer->Next;
			if (pNetBuffer) {
				NET_BUFFER_NEXT_NB(pFakeNetBuffer) = NdisAllocateNetBuffer(
						pLoopbackFilter->PacketPool, NULL, 0, 0);
				pFakeNetBuffer = NET_BUFFER_NEXT_NB(pFakeNetBuffer);
				if (pFakeNetBuffer == NULL)
				{
					WARNING_DBG("Failed to allocate NB.\n");
					break;
				}
			}
		}


		// TODO: handle SkipSentPackets?
		NPF_DoTap(pLoopbackFilter, pFakeNbl, NULL, TRUE);
	} while (0);

	if (pFakeNbl != NULL) {
		/* cleanup */
		pFakeNetBuffer = NET_BUFFER_LIST_FIRST_NB(pFakeNbl);
		while (pFakeNetBuffer != NULL)
		{
			// If this field is not NULL, it points to the MDL we need to free
			pMdl = (PMDL)(NET_BUFFER_PROTOCOL_RESERVED(pFakeNetBuffer)[0]);

			if (pMdl != NULL) {
				/* If it's npBuff, we'll free it later.
				 * Otherwise it's unique and we should free it now. */
				QueryMdl(pMdl, &pTmpBuf, &FirstMDLLen, HighPagePriority|MdlMappingNoExecute);
				if (pTmpBuf != npBuff)
				{
					// See NPF_FreeNBCopies for TODO item related to this assert and
					// justification for HighPagePriority above.
					if (NT_VERIFY(pTmpBuf != NULL)) {
						NdisFreeMemory(pTmpBuf, FirstMDLLen, 0);
					}
					// else? No good way to recover, we've leaked the memory.
				}

				/* Regardless, free the MDL */
				NdisFreeMdl(pMdl);
			}

			/* Now stash the next NB and free this one. */
			pNetBuffer = NET_BUFFER_NEXT_NB(pFakeNetBuffer);
			/* First NB is pre-allocated, so we don't have to free it. */
			if (pFakeNetBuffer != NET_BUFFER_LIST_FIRST_NB(pFakeNbl)) {
				NdisFreeNetBuffer(pFakeNetBuffer);
			}
			pFakeNetBuffer = pNetBuffer;
		}

		NdisFreeNetBufferList(pFakeNbl);
	}

	if (npBuff != NULL) {
		NdisFreeMemory(npBuff, numBytes, 0);
	}
}

_Must_inspect_result_
BOOL NPF_ShouldProcess(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Out_ PUCHAR puIPv4
		)
{
	UNREFERENCED_PARAMETER(inMetaValues);
	UINT32 layerFlags = 0;

	// Get the packet protocol (IPv4 or IPv6)
	switch (inFixedValues->layerId) {
		case FWPS_LAYER_INBOUND_IPPACKET_V4:
			*puIPv4 = NPF_INJECT_IPV4;
			layerFlags = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS].value.uint32;
			break;
		case FWPS_LAYER_INBOUND_IPPACKET_V6:
			*puIPv4 = NPF_INJECT_IPV6;
			layerFlags = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS].value.uint32;
			break;
		default:
			// This is not our layer! Bail.
			ERROR_DBG("uIPv4 cannot be determined, inFixedValues->layerId = %u\n", inFixedValues->layerId);
			*puIPv4 = 0;
			return FALSE;
			break;
	}

	// Filter out fragment packets and reassembled packets.
	if (layerFlags & FWP_CONDITION_FLAG_IS_FRAGMENT
			|| layerFlags & FWP_CONDITION_FLAG_IS_REASSEMBLED)
	{
		return FALSE;
	}
	return TRUE;
}

#if(NTDDI_VERSION < NTDDI_WIN7)
#error This version of Npcap is not supported on Windows versions older than Windows 7
#endif

/* ++

This is the classifyFn function for the Transport (v4 and v6) callout.
packets (inbound) are queued to the packet queue to be processed
by the worker thread.

-- */
#if(NTDDI_VERSION >= NTDDI_WIN8)
// FWPS_CALLOUT_CLASSIFY_FN2
_IRQL_requires_max_(DISPATCH_LEVEL)
void NPF_NetworkClassifyInbound(
	_In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
	_Inout_opt_ void *layerData,
	_In_opt_ const void *classifyContext,
	_In_ const FWPS_FILTER2 *filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0 *classifyOut
	)
#elif(NTDDI_VERSION >= NTDDI_WIN7)
// FWPS_CALLOUT_CLASSIFY_FN1
_IRQL_requires_max_(DISPATCH_LEVEL)
void
NPF_NetworkClassifyInbound(
	_In_ const FWPS_INCOMING_VALUES0* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER1* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT0* classifyOut
	)
#endif
{
	PNPCAP_DRIVER_EXTENSION pDrvExt = (PNPCAP_DRIVER_EXTENSION)filter->context;
	PNPCAP_FILTER_MODULE pLoopbackFilter = pDrvExt->pLoopbackFilter;
	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	UINT32				ipHeaderSize = 0;
	UINT32				bytesRetreated = 0;
	UCHAR uIPv4;
	PNET_BUFFER_LIST	pNetBufferList = (NET_BUFFER_LIST*) layerData;
	FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_INJECTION_STATE_MAX;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
		classifyOut->actionType = FWP_ACTION_CONTINUE;

	TRACE_ENTER();

	if (pLoopbackFilter == NULL || pLoopbackFilter->AdapterBindingStatus != FilterRunning)
	{
		WARNING_DBG("pLoopbackFilter invalid: %p (AdapterBindingStatus: %d)\n",
				pLoopbackFilter, pLoopbackFilter ? pLoopbackFilter->AdapterBindingStatus : 0);
		return;
	}

	if (pNetBufferList == NULL || !NPF_ShouldProcess(inFixedValues, inMetaValues, &uIPv4))
	{
		return;
	}

	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE)
	{
		ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	injectionState = FwpsQueryPacketInjectionState(pDrvExt->hInject[uIPv4],
		pNetBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		INFO_DBG("this packet is injected by ourself, let it go\n");

		TRACE_EXIT();
		return;
	}

	INFO_DBG("inFixedValues->layerId = %u, inMetaValues->currentMetadataValues = 0x%x, inMetaValues->ipHeaderSize = %u, inMetaValues->compartmentId = 0x%x\n",
		inFixedValues->layerId, inMetaValues->currentMetadataValues, inMetaValues->ipHeaderSize, inMetaValues->compartmentId);

	// Inbound: Initial offset is at the Transport Header, so retreat the size of the IP Header.
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/data-offset-positions
	status = NdisRetreatNetBufferListDataStart(pNetBufferList,
			ipHeaderSize,
			0,
			NULL,
			NULL);
	bytesRetreated = ipHeaderSize;

	if (status != NDIS_STATUS_SUCCESS)
	{
		INFO_DBG("NdisRetreatNetBufferListDataStart(bytesRetreated) [status: %#x]\n", status);

		TRACE_EXIT();
		return;
	}

	NPF_TapLoopback(pLoopbackFilter, uIPv4 == NPF_INJECT_IPV4, pNetBufferList);

	if (bytesRetreated > 0)
	{
		NdisAdvanceNetBufferListDataStart(pNetBufferList,
				bytesRetreated,
				FALSE,
				0);
		bytesRetreated = 0;
	}

	TRACE_EXIT();
	return;
}

NTSTATUS
NPF_NetworkNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ FWPS_FILTER* filter
	)
{
	UNREFERENCED_PARAMETER(filterKey);

	TRACE_ENTER();

	switch (notifyType)
	{
		case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
			filter->context = (UINT64)g_pDriverExtension;
			INFO_DBG("ADD filter, context: %p\n", (PVOID)filter->context);
			break;
		case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
			INFO_DBG("REMOVE filter, context: %p\n", (PVOID)filter->context);
			break;
		default:
			INFO_DBG("Other notifyType: %d\n", notifyType);
			break;
	}

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

// 
// Callout driver implementation
//
#define IF_ERR_LOG_AND_DO(_Func, _Do) \
	if (!NT_SUCCESS(status)) { \
		ERROR_DBG(#_Func "failed: %08x\n", status); \
		_Do; \
	}

#define IF_ERR_LOG_AND_SKIP(_Func, _Label) IF_ERR_LOG_AND_DO(_Func, goto _Label)

#define IF_ERR_LOG(_Func) IF_ERR_LOG_AND_DO(_Func, do {} while(0))

#define EXIT_IF_ERR(_Func) IF_ERR_LOG_AND_SKIP(_Func, Exit)

#define EXISTS_OR_EXIT_IF_ERR(_Func) \
	if (status == STATUS_FWP_ALREADY_EXISTS) { \
		WARNING_DBG(#_Func " returned STATUS_FWP_ALREADY_EXISTS\n"); \
	} else EXIT_IF_ERR(_Func)


NTSTATUS
NPF_AddFilter(
	_In_ HANDLE WFPEngineHandle,
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey
	)
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[1] = { 0 };
	UINT conditionIndex;

	// Identify this filter so we don't add it multiple times.
	// At the moment, each FWPM callout has only 1 filter. If we add more, make each one unique.
	filter.filterKey = *calloutKey; // GUID matches our callout, but...
	filter.filterKey.Data4[7] = 1; // ...last byte is the ordinal number for this filter.

	filter.layerKey = *layerKey;
	filter.displayData.name = L"Network Npcap Filter (Loopback)";

	filter.action.calloutKey = *calloutKey;
	filter.filterCondition = filterConditions;
	filter.subLayerKey = NPF_SUBLAYER;
	filter.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
	filter.rawContext = 0;
	conditionIndex = 0;

		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
		filter.weight.type = FWP_EMPTY;
		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_ALL_SET;
		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
		filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
		conditionIndex++;

	filter.numFilterConditions = conditionIndex;

	status = FwpmFilterAdd(
		WFPEngineHandle,
		&filter,
		NULL,
		NULL);
	EXISTS_OR_EXIT_IF_ERR(FwpmFilterAdd);

Exit:
	TRACE_EXIT();
	return status;
}

/*
This function adds callout objects and filters that reference the callout driver
*/
NTSTATUS
NPF_AddCallout(
	_In_ HANDLE WFPEngineHandle,
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_CALLOUT mCallout = { 0 };
	FWPM_DISPLAY_DATA displayData = { 0 };

	displayData.name = L"Npcap Network Callout";
	displayData.description = L"Npcap loopback network traffic";

	mCallout.calloutKey = *calloutKey;
	mCallout.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd(
		WFPEngineHandle,
		&mCallout,
		NULL,
		NULL
		);
	EXISTS_OR_EXIT_IF_ERR(FwpmCalloutAdd);

	status = NPF_AddFilter(WFPEngineHandle, layerKey, calloutKey);
	EXISTS_OR_EXIT_IF_ERR(NPF_AddFilter);

Exit:
	TRACE_EXIT();
	return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NPF_AddCalloutsAndFilters()
/* ++

This function registers dynamic callouts and filters that intercept
transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and
INBOUND/OUTBOUND transport layers.

Callouts and filters will be removed during DriverUnload.

-- */
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;
	NTSTATUS err = STATUS_SUCCESS;
	HANDLE WFPEngineHandle = NULL;
	FWPM_SUBLAYER NPFSubLayer = {0};

	FWPM_SESSION session = { 0 };
	FWPM_PROVIDER provider = { 0 };

	session.displayData.name = L"Npcap AddCalloutsAndFilters session";

	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&WFPEngineHandle
		);
	EXIT_IF_ERR(FwpmEngineOpen);

	status = FwpmTransactionBegin(WFPEngineHandle, 0);
	EXIT_IF_ERR(FwpmTransactionBegin);

#define _WIDE(X) _WIDE2(X)
#define _WIDE2(X) L ## X
#define NPCAP_COMPANY_NAME_W _WIDE(WINPCAP_COMPANY_NAME)
	provider.providerKey = NPF_FWPM_PROVIDER_GUID;
	provider.displayData.name = NPCAP_COMPANY_NAME_W;
	provider.displayData.description = NPF_DRIVER_NAME_NORMAL_WIDECHAR;
	provider.serviceName = NPF_DRIVER_NAME_SMALL_WIDECHAR;
	status = FwpmProviderAdd(WFPEngineHandle, &provider, NULL);
	EXISTS_OR_EXIT_IF_ERR(FwpmProviderAdd);

	NPFSubLayer.subLayerKey = NPF_SUBLAYER;
	NPFSubLayer.displayData.name = L"Npcap Loopback Sub-Layer";
	NPFSubLayer.displayData.description = L"Sub-Layer for use by Npcap Loopback callouts";
	NPFSubLayer.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
	NPFSubLayer.flags = 0;
	NPFSubLayer.weight = 0; // must be less than the weight of 
	// FWPM_SUBLAYER_UNIVERSAL to be
	// compatible with Vista's IpSec
	// implementation.

	status = FwpmSubLayerAdd(WFPEngineHandle, &NPFSubLayer, NULL);
	EXISTS_OR_EXIT_IF_ERR(FwpmSubLayerAdd);


	status = NPF_AddCallout( WFPEngineHandle,
			&FWPM_LAYER_INBOUND_IPPACKET_V4,
			&NPF_INBOUND_IPPACKET_CALLOUT_V4
			);
	EXISTS_OR_EXIT_IF_ERR(NPF_AddCallout);


	status = NPF_AddCallout( WFPEngineHandle,
			&FWPM_LAYER_INBOUND_IPPACKET_V6,
			&NPF_INBOUND_IPPACKET_CALLOUT_V6
			);
	EXISTS_OR_EXIT_IF_ERR(NPF_AddCallout);

	status = FwpmTransactionCommit(WFPEngineHandle);
	EXIT_IF_ERR(FwpmTransactionCommit);

Exit:
	/* "If this function is called with a transaction in progress, the transaction will be aborted."
	 */
	err = FwpmEngineClose(WFPEngineHandle);
	if (!NT_SUCCESS(err)) {
		ERROR_DBG("FwpmEngineClose: %#08x\n", err);
	}
	_Analysis_assume_lock_not_held_(WFPEngineHandle);

	TRACE_EXIT();
	return status;
}


// Unlike other functions, this one needs to continue even if it gets an error, in order to clean up any remaining items.
void NPF_DeleteFiltersForLayer(
		_In_ HANDLE WFPEngineHandle,
		_In_ const GUID *pLayerKey
		)
{
	// Enumerate and delete all filters
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFilterEnum;
	FWPM_FILTER_ENUM_TEMPLATE tmplEnum = {0};
#define NUM_FILTERS_REQ 16
	UINT32 numFilters = 0;
	FWPM_FILTER **filterEntries = NULL;

	tmplEnum.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
	tmplEnum.actionMask = 0xffffffff;
	tmplEnum.layerKey = *pLayerKey;

	status = FwpmFilterCreateEnumHandle(WFPEngineHandle, &tmplEnum, &hFilterEnum);
	EXIT_IF_ERR(FwpmFilterCreateEnumHandle);

	do {
		status = FwpmFilterEnum(WFPEngineHandle, hFilterEnum, NUM_FILTERS_REQ, &filterEntries, &numFilters);
		IF_ERR_LOG_AND_DO(FwpmFilterEnum, break);

		for (UINT32 i=0; i < numFilters; i++)
		{
			status = FwpmFilterDeleteByKey(WFPEngineHandle, &filterEntries[i]->filterKey);
			IF_ERR_LOG_AND_DO(FwpmFilterDeleteByKey, continue);
		}

		FwpmFreeMemory((VOID **)&filterEntries);
	} while (numFilters == NUM_FILTERS_REQ);

	status = FwpmFilterDestroyEnumHandle(WFPEngineHandle, hFilterEnum);
	IF_ERR_LOG(FwpmFilterDestroyEnumHandle);
Exit:
	return;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NPF_DeleteCalloutsAndFilters(
	_In_ BOOLEAN bUnload
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	NTSTATUS err = STATUS_SUCCESS;
	HANDLE WFPEngineHandle;
	TRACE_ENTER();

	FWPM_SESSION session = { 0 };
	session.displayData.name = L"Npcap DeleteCalloutsAndFilters session";
	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&WFPEngineHandle
		);
	EXIT_IF_ERR(FwpmEngineOpen);

	status = FwpmTransactionBegin(WFPEngineHandle, 0);
	EXIT_IF_ERR(FwpmTransactionBegin);

	NPF_DeleteFiltersForLayer(WFPEngineHandle, &FWPM_LAYER_INBOUND_IPPACKET_V4);
	NPF_DeleteFiltersForLayer(WFPEngineHandle, &FWPM_LAYER_INBOUND_IPPACKET_V6);

	// Now all the filters are gone, we can delete the callouts

	status = FwpmCalloutDeleteByKey(WFPEngineHandle,
			&NPF_INBOUND_IPPACKET_CALLOUT_V4);
	IF_ERR_LOG(FwpmCalloutDeleteByKey);

	status = FwpmCalloutDeleteByKey(WFPEngineHandle,
			&NPF_INBOUND_IPPACKET_CALLOUT_V6);
	IF_ERR_LOG(FwpmCalloutDeleteByKey);

	// Provider and sublayer can persist and only have to be cleaned up at driver unload.
	if (bUnload)
	{
		status = FwpmSubLayerDeleteByKey(WFPEngineHandle, &NPF_SUBLAYER);
		IF_ERR_LOG(FwpmSubLayerDeleteByKey);

		status = FwpmProviderDeleteByKey(WFPEngineHandle, &NPF_FWPM_PROVIDER_GUID);
		IF_ERR_LOG(FwpmProviderDeleteByKey);
	}

	status = FwpmTransactionCommit(WFPEngineHandle);
	EXIT_IF_ERR(FwpmTransactionCommit);

Exit:
	err = FwpmEngineClose(WFPEngineHandle);
	if (!NT_SUCCESS(err)) {
		ERROR_DBG("FwpmEngineClose: %#08x\n", err);
	}
	_Analysis_assume_lock_not_held_(WFPEngineHandle);

	TRACE_EXIT();
	return status;
}

NTSTATUS
NPF_WFPCalloutRegister()
/* ++

Open injection handles (IPv4 and IPv6) for use with the various injection APIs.

injection handles will be removed during DriverUnload.

-- */
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT sCallout = { 0 };

	TRACE_ENTER();

	status = FwpsInjectionHandleCreate(AF_INET,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_pDriverExtension->hInject[NPF_INJECT_IPV4]);
	EXIT_IF_ERR(FwpsInjectionHandleCreate_V4);

	status = FwpsInjectionHandleCreate(AF_INET6,
			FWPS_INJECTION_TYPE_NETWORK,
			&g_pDriverExtension->hInject[NPF_INJECT_IPV6]);
	EXIT_IF_ERR(FwpsInjectionHandleCreate_V6);

	// These are the same for all callouts
	sCallout.notifyFn = NPF_NetworkNotify;
	sCallout.flags = FWP_CALLOUT_FLAG_ALLOW_OFFLOAD
#if(NTDDI_VERSION >= NTDDI_WIN8)
		| FWP_CALLOUT_FLAG_ALLOW_RSC
#if (NTDDI_VERSION >= NTDDI_WIN10_19H1)
		| FWP_CALLOUT_FLAG_ALLOW_USO
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
		| FWP_CALLOUT_FLAG_ALLOW_URO
#endif
#endif
#endif
		;

	// Inbound
	sCallout.classifyFn = NPF_NetworkClassifyInbound;
	// - IPv4
	sCallout.calloutKey = NPF_INBOUND_IPPACKET_CALLOUT_V4;
	status = FwpsCalloutRegister(
		g_pDriverExtension->pNpcapDeviceObject,
		&sCallout,
		&g_pDriverExtension->uCalloutInboundV4
		);
	EXISTS_OR_EXIT_IF_ERR(FwpsCalloutRegister);
	// - IPv6
	sCallout.calloutKey = NPF_INBOUND_IPPACKET_CALLOUT_V6;
	status = FwpsCalloutRegister(
		g_pDriverExtension->pNpcapDeviceObject,
		&sCallout,
		&g_pDriverExtension->uCalloutInboundV6
		);
	EXISTS_OR_EXIT_IF_ERR(FwpsCalloutRegister);

Exit:
	if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
		NPF_WFPCalloutUnregister();
	}

	TRACE_EXIT();
	return status;
}

VOID
NPF_WFPCalloutUnregister()
{
	NTSTATUS status = STATUS_SUCCESS;

	TRACE_ENTER();
#define _DESTROY_FWPS_OBJ(_Obj, _Dtor) \
	if (_Obj) { \
		status = _Dtor(_Obj); \
		INFO_DBG(#_Dtor "(" #_Obj "): %#08x\n", status); \
		_Obj = 0; \
	}

	_DESTROY_FWPS_OBJ(g_pDriverExtension->hInject[NPF_INJECT_IPV6], FwpsInjectionHandleDestroy);
	_DESTROY_FWPS_OBJ(g_pDriverExtension->hInject[NPF_INJECT_IPV4], FwpsInjectionHandleDestroy);
	_DESTROY_FWPS_OBJ(g_pDriverExtension->uCalloutInboundV4, FwpsCalloutUnregisterById);
	_DESTROY_FWPS_OBJ(g_pDriverExtension->uCalloutInboundV6, FwpsCalloutUnregisterById);

	TRACE_EXIT();
}

_Use_decl_annotations_
NTSTATUS
NPF_InitWFP()
{
	NTSTATUS status = KeWaitForMutexObject(&g_pDriverExtension->WFPInitMutex, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_SUCCESS)
	{
		ERROR_DBG("Failed to get WFPInitMutex: %#08x\n", status);
		// Failed to get the mutex. Report exact error unless it's a "success" value
		_Analysis_assume_lock_not_held_(g_pDriverExtension->WFPInitMutex);
		return NT_SUCCESS(status) ? STATUS_LOCK_NOT_GRANTED : status;
	}
	INFO_DBG("bWFPInit %u -> 1\n", g_pDriverExtension->bWFPInit);
	if (g_pDriverExtension->bWFPInit)
	{
		goto Exit;
	}

	status = NPF_AddCalloutsAndFilters();
	EXISTS_OR_EXIT_IF_ERR(NPF_AddCalloutsAndFilters);

	g_pDriverExtension->bWFPInit = 1;

Exit:
	KeReleaseMutex(&g_pDriverExtension->WFPInitMutex, FALSE);

	return status;
}

_Use_decl_annotations_
VOID
NPF_ReleaseWFP(BOOLEAN bUnload)
{
	NTSTATUS status = KeWaitForMutexObject(&g_pDriverExtension->WFPInitMutex, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_SUCCESS)
	{
		ERROR_DBG("Failed to get WFPInitMutex: %#08x\n", status);
		// Failed to get the mutex.
		_Analysis_assume_lock_not_held_(g_pDriverExtension->WFPInitMutex);
		return;
	}
	INFO_DBG("bWFPInit %u -> 0\n", g_pDriverExtension->bWFPInit);
	if (!g_pDriverExtension->bWFPInit)
	{
		goto Exit;
	}

	status = NPF_DeleteCalloutsAndFilters(bUnload);
	EXIT_IF_ERR(NPF_DeleteCalloutsAndFilters);

	g_pDriverExtension->bWFPInit = 0;

Exit:
	KeReleaseMutex(&g_pDriverExtension->WFPInitMutex, FALSE);

	return;
}

#endif // HAVE_WFP_LOOPBACK_SUPPORT
