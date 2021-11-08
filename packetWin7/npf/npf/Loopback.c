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
#include "packet.h"
#include "..\..\..\Common\WpcapNames.h"
#include "..\..\..\version.h"

// 
// Global variables
//
extern ULONG g_DltNullMode;

// 
// Callout and sublayer GUIDs
//

// f99c911e-90ce-41a3-8022-c3e078b8f7a2
DEFINE_GUID(
	NPF_FWPM_SESSION_GUID,
	0xf99c911e,
	0x90ce,
	0x41a3,
	0x80, 0x22, 0xc3, 0xe0, 0x78, 0xb8, 0xf7, 0xa2
);

// af617412-ce10-4058-8996-abc79fd805ff
DEFINE_GUID(
	NPF_FWPM_PROVIDER_GUID,
	0xaf617412,
	0xce10,
	0x4058,
	0x89, 0x96, 0xab, 0xc7, 0x9f, 0xd8, 0x05, 0xff
);

// 2D605B3E-C244-4364-86E8-BD81E6C91B6E
DEFINE_GUID(
	NPF_OUTBOUND_IPPACKET_CALLOUT_V4,
	0x2d605b3e,
	0xc244,
	0x4364,
	0x86, 0xe8, 0xbd, 0x81, 0xe6, 0xc9, 0x1b, 0x6e
);
// F935E4CD-9499-4934-824D-8E3726BA4A94
DEFINE_GUID(
	NPF_OUTBOUND_IPPACKET_CALLOUT_V6,
	0xf935e4cd,
	0x9499,
	0x4934,
	0x82, 0x4d, 0x8e, 0x37, 0x26, 0xba, 0x4a, 0x94
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

// 
// Callout driver functions
//


// Send the loopback packets data to the user-mode code.
VOID
NPF_TapLoopback(
        _In_ BOOLEAN bIPv4,
        _In_ PNET_BUFFER_LIST pNetBufferList
        )
{
	PNPCAP_FILTER_MODULE pLoopbackFilter = NULL;
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

	pLoopbackFilter = NPF_GetLoopbackFilterModule();
	if (pLoopbackFilter && NPF_StartUsingBinding(pLoopbackFilter, TRUE)) {
		do {
			/* Quick check to avoid extra work.
			 * Won't lock because we're not actually traversing. */
			if (NULL == pLoopbackFilter->OpenInstances.Next) {
				break;
			}
			if (g_DltNullMode)
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
			npBuff = (PUCHAR) NdisAllocateMemoryWithTagPriority(
					pLoopbackFilter->AdapterHandle, numBytes, NPF_LOOPBACK_COPY_TAG, NormalPoolPriority);
			if (npBuff == NULL)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD,
						"NPF_TapLoopback: Failed to allocate buffer.");
				break;
			}
			RtlCopyMemory(npBuff, pPacketData, numBytes);

			pFakeNbl = NdisAllocateNetBufferAndNetBufferList(
					pLoopbackFilter->PacketPool, 0, 0, NULL, 0, 0);
			if (pFakeNbl == NULL)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD,
						"NPF_TapLoopback: Failed to allocate NBL.");
				break;
			}
			pFakeNetBuffer = NET_BUFFER_LIST_FIRST_NB(pFakeNbl);
			/* Now loop through the original NBL, creating NBs in our fake NBL for each one. */
			pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
			while (pNetBuffer)
			{
				Offset = NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuffer);
				if (Offset >= numBytes) {
					NdisQueryMdl(NET_BUFFER_CURRENT_MDL(pNetBuffer),
							&pOrigBuf,
							&OrigLen,
							NormalPagePriority);
					if (pOrigBuf == NULL) {
						TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NPF_TapLoopback: Failed to query MDL");
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
						NdisQueryMdl(NET_BUFFER_CURRENT_MDL(pNetBuffer),
								&pOrigBuf,
								&OrigLen,
								NormalPagePriority);
						if (pOrigBuf == NULL) {
							TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NPF_TapLoopback: Failed to query MDL");
							break;
						}
						/* Make a buffer big enough for our fake DLT header plus used
						 * data of first MDL */
						FirstMDLLen = numBytes + OrigLen - Offset;
						pTmpBuf = NdisAllocateMemoryWithTagPriority(
								pLoopbackFilter->AdapterHandle, FirstMDLLen, NPF_LOOPBACK_COPY_TAG, NormalPoolPriority);
						if (pTmpBuf == NULL)
						{
							TRACE_MESSAGE(PACKET_DEBUG_LOUD,
									"NPF_TapLoopback: Failed to allocate buffer.");
							break;
						}
						RtlCopyMemory(pTmpBuf, pPacketData, numBytes);
						RtlCopyMemory(pTmpBuf + numBytes, pOrigBuf + Offset, OrigLen - Offset);
						pMdl = NdisAllocateMdl(pLoopbackFilter->AdapterHandle, pTmpBuf, FirstMDLLen);
						if (pMdl == NULL) {
							NdisFreeMemory(pTmpBuf, FirstMDLLen, 0);
							TRACE_MESSAGE(PACKET_DEBUG_LOUD,
									"NPF_TapLoopback: Failed to allocate MDL.");
							break;
						}
						// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the buffer address
						// is stored in the MDL and we retrieve it (via NdisQueryMdl) in the cleanup block below.
						// Therefore, it is not leaking after this point.
						NPF_AnalysisAssumeAliased(pTmpBuf);

						pMdl->Next = NET_BUFFER_CURRENT_MDL(pNetBuffer)->Next;
					}
					else {
						/* Allocate a MDL for the remainder and chain to theirs */
						pMdl = NdisAllocateMdl(pLoopbackFilter->AdapterHandle, npBuff, numBytes);
						if (pMdl == NULL)
						{
							TRACE_MESSAGE(PACKET_DEBUG_LOUD,
									"NPF_TapLoopback: Failed to allocate MDL.");
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
						TRACE_MESSAGE(PACKET_DEBUG_LOUD,
								"NPF_TapLoopback: Failed to allocate NB.");
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
					NdisQueryMdl(pMdl, &pTmpBuf, &FirstMDLLen, HighPagePriority|MdlMappingNoExecute);
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

		NPF_StopUsingBinding(pLoopbackFilter, TRUE);
	}
}

_Must_inspect_result_
BOOL NPF_ShouldProcess(
		_In_ const FWPS_INCOMING_VALUES* inFixedValues,
		_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Out_ PBOOLEAN pbIPv4
		)
{
	UNREFERENCED_PARAMETER(inMetaValues);
	UINT32 layerFlags = 0;

	// Get the packet protocol (IPv4 or IPv6)
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4)
	{
		*pbIPv4 = TRUE;
		layerFlags = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS].value.uint32;
	}
	else if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6)
	{
		*pbIPv4 = FALSE;
		layerFlags = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V6_FLAGS].value.uint32;
	}
	if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4)
	{
		*pbIPv4 = TRUE;
		layerFlags = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS].value.uint32;
	}
	else if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6)
	{
		*pbIPv4 = FALSE;
		layerFlags = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS].value.uint32;
	}
	else
	{
		// This is not our layer! Bail.
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassifyOutbound: bIPv4 cannot be determined, inFixedValues->layerId = %u\n", inFixedValues->layerId);
		*pbIPv4 = FALSE;
		return FALSE;
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
packets (outbound) are queued to the packet queue to be processed
by the worker thread.

-- */
#if(NTDDI_VERSION >= NTDDI_WIN8)
// FWPS_CALLOUT_CLASSIFY_FN2
_IRQL_requires_max_(DISPATCH_LEVEL)
void NPF_NetworkClassifyOutbound(
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
NPF_NetworkClassifyOutbound(
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
	BOOLEAN				bIPv4;
	PNET_BUFFER_LIST	pNetBufferList = (NET_BUFFER_LIST*) layerData;
	FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_INJECTION_STATE_MAX;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
		classifyOut->actionType = FWP_ACTION_CONTINUE;

	TRACE_ENTER();

	if (pNetBufferList == NULL || !NPF_ShouldProcess(inFixedValues, inMetaValues, &bIPv4))
	{
		return;
	}

	injectionState = FwpsQueryPacketInjectionState(bIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
		pNetBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassifyOutbound: this packet is injected by ourself, let it go\n");

		TRACE_EXIT();
		return;
	}

	TRACE_MESSAGE4(PACKET_DEBUG_LOUD, "NPF_NetworkClassifyOutbound: inFixedValues->layerId = %u, inMetaValues->currentMetadataValues = 0x%x, inMetaValues->ipHeaderSize = %u, inMetaValues->compartmentId = 0x%x\n",
		inFixedValues->layerId, inMetaValues->currentMetadataValues, inMetaValues->ipHeaderSize, inMetaValues->compartmentId);

	// Outbound: Initial offset is already at the IP Header

    NPF_TapLoopback(bIPv4, pNetBufferList);

	TRACE_EXIT();
	return;
}

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
	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	UINT32				ipHeaderSize = 0;
	UINT32				bytesRetreated = 0;
	BOOLEAN				bIPv4;
	PNET_BUFFER_LIST	pNetBufferList = (NET_BUFFER_LIST*) layerData;
	FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_INJECTION_STATE_MAX;

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
		classifyOut->actionType = FWP_ACTION_CONTINUE;

	TRACE_ENTER();

	if (pNetBufferList == NULL || !NPF_ShouldProcess(inFixedValues, inMetaValues, &bIPv4))
	{
		return;
	}

	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE)
	{
		ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	injectionState = FwpsQueryPacketInjectionState(bIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
		pNetBufferList,
		NULL);
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD,
			"NPF_NetworkClassifyInbound: this packet is injected by ourself, let it go\n");

		TRACE_EXIT();
		return;
	}

	TRACE_MESSAGE4(PACKET_DEBUG_LOUD, "NPF_NetworkClassifyInbound: inFixedValues->layerId = %u, inMetaValues->currentMetadataValues = 0x%x, inMetaValues->ipHeaderSize = %u, inMetaValues->compartmentId = 0x%x\n",
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
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"NPF_NetworkClassifyInbound: NdisRetreatNetBufferListDataStart(bytesRetreated) [status: %#x]\n",
				status);

		TRACE_EXIT();
		return;
	}

		NPF_TapLoopback(bIPv4, pNetBufferList);

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
	filter.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
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
		filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_FRAGMENT;
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
	else
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_AddFilter: invalid iFlag, iFlag = %d\n",
			iFlag);
		TRACE_EXIT();
		return STATUS_INVALID_PARAMETER;
	}

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
    _In_ FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	_Inout_ void* deviceObject,
	_Out_ UINT32* calloutId
	)
/* ++

This function registers callouts and filters that intercept transport
traffic at the layers defined in NPF_RegisterCallouts
*/
{
	TRACE_ENTER();
	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.notifyFn = NPF_NetworkNotify;
	sCallout.flags = FWP_CALLOUT_FLAG_ALLOW_OFFLOAD
#if(NTDDI_VERSION >= NTDDI_WIN8)
		| FWP_CALLOUT_FLAG_ALLOW_RSC
#endif
		;

	status = FwpsCalloutRegister(
		deviceObject,
		&sCallout,
		calloutId
		);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: FwpsCalloutRegister() [status: %#x]\n",
			status);
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = L"Npcap Network Callout";
	displayData.description = L"Npcap inbound/outbound network traffic";

	mCallout.calloutKey = *calloutKey;
	mCallout.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
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
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: FwpmCalloutAdd() [status: %#x]\n",
			status);
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 0);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: NPF_AddFilter() [status: %#x]\n",
			status);
		goto Exit;
	}

	status = NPF_AddFilter(layerKey, calloutKey, 1);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: NPF_AddFilter() [status: %#x]\n",
			status);
		goto Exit;
	}
	status = NPF_AddFilter(layerKey, calloutKey, 2);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: NPF_AddFilter() [status: %#x]\n",
			status);
		goto Exit;
	}
	status = NPF_AddFilter(layerKey, calloutKey, 3);
	if (!NT_SUCCESS(status))
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_RegisterCallout: NPF_AddFilter() [status: %#x]\n",
			status);
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

_Use_decl_annotations_
NTSTATUS
NPF_RegisterCallouts(
void* deviceObject
)
/* ++

This function registers dynamic callouts and filters that intercept
transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and
INBOUND/OUTBOUND transport layers.

Callouts and filters will be removed during DriverUnload.

-- */
{
	TRACE_ENTER();
	DWORD status = STATUS_SUCCESS;
	FWPM_SUBLAYER NPFSubLayer;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;

	FWPM_SESSION session = { 0 };
	FWPM_PROVIDER provider = { 0 };

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.displayData.name = L"Npcap RegisterCallouts session";

	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&g_WFPEngineHandle
		);

	if (!NT_SUCCESS(status) || !g_WFPEngineHandle || g_WFPEngineHandle == INVALID_HANDLE_VALUE)
	{
		g_WFPEngineHandle = INVALID_HANDLE_VALUE;
		goto Exit;
	}
	engineOpened = TRUE;

	status = FwpmTransactionBegin(g_WFPEngineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	inTransaction = TRUE;

#define _WIDE(X) _WIDE2(X)
#define _WIDE2(X) L ## X
#define NPCAP_COMPANY_NAME_W _WIDE(WINPCAP_COMPANY_NAME)
	RtlZeroMemory(&provider, sizeof(FWPM_PROVIDER));
	provider.providerKey = NPF_FWPM_PROVIDER_GUID;
	provider.displayData.name = NPCAP_COMPANY_NAME_W;
	provider.displayData.description = NPF_DRIVER_NAME_NORMAL_WIDECHAR;
	provider.serviceName = NPF_DRIVER_NAME_SMALL_WIDECHAR;
	status = FwpmProviderAdd(g_WFPEngineHandle, &provider, NULL);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	RtlZeroMemory(&NPFSubLayer, sizeof(FWPM_SUBLAYER));

	NPFSubLayer.subLayerKey = NPF_SUBLAYER;
	NPFSubLayer.displayData.name = L"Npcap Loopback Sub-Layer";
	NPFSubLayer.displayData.description = L"Sub-Layer for use by Npcap Loopback callouts";
	NPFSubLayer.providerKey = (GUID *)&NPF_FWPM_PROVIDER_GUID;
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
            NPF_NetworkClassifyOutbound,
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
            NPF_NetworkClassifyInbound,
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
            NPF_NetworkClassifyOutbound,
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
            NPF_NetworkClassifyInbound,
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


_Use_decl_annotations_
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

_Use_decl_annotations_
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

_Use_decl_annotations_
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

#endif // HAVE_WFP_LOOPBACK_SUPPORT
