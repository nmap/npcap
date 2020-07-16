/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2020 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and may not be redistributed or incorporated   *
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
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
 * Copyright (c) 2010 - 2013 Riverbed Technology, San Francisco (California), Yang Luo (China)
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

#include "stdafx.h"

#include "packet.h"
#include "win_bpf.h"
#include "time_calls.h"

 //
 // Global variables
 //
extern ULONG	g_VlanSupportMode;
extern ULONG	g_DltNullMode;

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_Read(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	POPEN_INSTANCE			Open;
	PIO_STACK_LOCATION		IrpSp;
	PUCHAR					packp;
	PUCHAR					CurrBuff;
	struct bpf_hdr*			header;
	ULONG					copied, plen, available;
	LOCK_STATE_EX lockState;
	NTSTATUS Status = STATUS_SUCCESS;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	Open = IrpSp->FileObject->FsContext;

	do /* Validate */
	{
		if (!NPF_IsOpenInstance(Open))
		{
			Status = STATUS_INVALID_HANDLE;
			break;
		}
		if (!NPF_StartUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN))
		{
			// Instance is being closed
			Status = STATUS_CANCELLED;
			break;
		}

		if (Open->Size == 0)
		{
			NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

#ifdef NPCAP_KDUMP
		if (Open->mode & MODE_DUMP && Open->DumpFileHandle == NULL)
		{
			// this instance is in dump mode, but the dump file has still not been opened
			NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
#endif

	} while (FALSE);

	if (Status != STATUS_SUCCESS)
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return Status;
	}

	//See if the buffer is full enough to be copied
	if (Open->Size - Open->Free <= Open->MinToCopy || Open->mode & MODE_DUMP)
	{
		if (Open->ReadEvent != NULL)
		{
			//wait until some packets arrive or the timeout expires
			if (Open->OpenStatus == OpenRunning && Open->TimeOut.QuadPart != (LONGLONG)IMMEDIATE)
#pragma warning (disable: 28118)
				KeWaitForSingleObject(Open->ReadEvent,
				UserRequest,
				KernelMode,
				TRUE,
				(Open->TimeOut.QuadPart == (LONGLONG)0) ? NULL : &(Open->TimeOut));

			KeClearEvent(Open->ReadEvent);
		}

		if (Open->mode & MODE_STAT)
		{
			//this capture instance is in statistics mode
			CurrBuff = (PUCHAR) MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

			if (CurrBuff == NULL)
			{
				NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
				TRACE_EXIT();
				EXIT_FAILURE(0);
			}

			if (Open->mode & MODE_DUMP)
			{
				if (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr) + 24)
				{
					NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
					Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					TRACE_EXIT();
					return STATUS_BUFFER_TOO_SMALL;
				}
			}
			else
			{
				if (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr) + 16)
				{
					NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
					Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					TRACE_EXIT();
					return STATUS_BUFFER_TOO_SMALL;
				}
			}

			//fill the bpf header for this packet
			header = (struct bpf_hdr *)CurrBuff;
			GET_TIME(&header->bh_tstamp, &Open->start, Open->TimestampMode);

#ifdef NPCAP_KDUMP
			if (Open->mode & MODE_DUMP)
			{
				*(LONGLONG *)(CurrBuff + sizeof(struct bpf_hdr) + 16) = Open->DumpOffset.QuadPart;
				header->bh_caplen = 24;
				header->bh_datalen = 24;
				Irp->IoStatus.Information = 24 + sizeof(struct bpf_hdr);
			}
			else
#endif
			{
				header->bh_caplen = 16;
				header->bh_datalen = 16;
				header->bh_hdrlen = sizeof(struct bpf_hdr);
				Irp->IoStatus.Information = 16 + sizeof(struct bpf_hdr);
			}

			*(LONGLONG *) (CurrBuff + sizeof(struct bpf_hdr)) = Open->Npackets.QuadPart;
			*(LONGLONG *) (CurrBuff + sizeof(struct bpf_hdr) + 8) = Open->Nbytes.QuadPart;

			//reset the countetrs
			FILTER_ACQUIRE_LOCK(&Open->CountersLock, NPF_IRQL_UNKNOWN);
			Open->Npackets.QuadPart = 0;
			Open->Nbytes.QuadPart = 0;
			FILTER_RELEASE_LOCK(&Open->CountersLock, NPF_IRQL_UNKNOWN);

			NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);

			Irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);

			TRACE_EXIT();
			return STATUS_SUCCESS;
		}

		//
		// The MONITOR_MODE (aka TME extensions) is not supported on
		// 64 bit architectures
		//
		if (Open->mode == MODE_MON)   //this capture instance is in monitor mode
		{
			NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
			TRACE_EXIT();
			EXIT_FAILURE(0);
		}
	}



	//------------------------------------------------------------------------------
	copied = 0;
	available = IrpSp->Parameters.Read.Length;

	if (Irp->MdlAddress == 0x0)
	{
		NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	packp = (PUCHAR) MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);


	if (packp == NULL)
	{
		NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	if (Open->ReadEvent != NULL)
		KeClearEvent(Open->ReadEvent);

	// "NdisAcquireRWLockRead always raises the IRQL to IRQL = DISPATCH_LEVEL"
	NdisAcquireRWLockRead(Open->BufferLock, &lockState, 0);

	while (available > copied && Open->Free < Open->Size)
	{
		//there are some packets in the buffer
		PLIST_ENTRY pCapDataEntry = ExInterlockedRemoveHeadList(&Open->PacketQueue, &Open->PacketQueueLock);
		if (pCapDataEntry == NULL)
		{
			/* No packets in queue. Maybe someone else is calling NPF_Read?
			* This was reported as a crash (null ptr deref) 2 lines down, but I can't see a reason for it
			* unless compiler is reordering calls such that Open->Free is decremented before the packet is
			* put in the queue down in TEFEO.  We could continue here to try to get more packets, but if
			* it's an actual accounting bug, we'd get infite loop hangs. I'd rather break and see Read calls
			* returning no or few packets and eventually unexplained packet drops.
			*/
			break;
		}
		PNPF_CAP_DATA pCapData = CONTAINING_RECORD(pCapDataEntry, NPF_CAP_DATA, PacketQueueEntry);

#ifdef HAVE_DOT11_SUPPORT
		PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) pCapData->pNBCopy->pNBLCopy->Dot11RadiotapHeader;
#else
		PVOID pRadiotapHeader = NULL;
#endif
		plen = pCapData->BpfHeader.bh_caplen;

		if (NPF_CAP_SIZE(pCapData, pRadiotapHeader) > available - copied)
		{
			//if the packet does not fit into the user buffer, we've ended copying packets
			// Put this packet back.
			ExInterlockedInsertHeadList(&Open->PacketQueue, pCapDataEntry, &Open->PacketQueueLock);
			break;
		}

		header = (struct bpf_hdr *) (packp + copied);
		*header = pCapData->BpfHeader;

		copied += sizeof(struct bpf_hdr);

#ifdef HAVE_DOT11_SUPPORT
		if (pRadiotapHeader != NULL)
		{
			RtlCopyMemory(packp + copied, pRadiotapHeader, pRadiotapHeader->it_len);
			header->bh_caplen += pRadiotapHeader->it_len;
			copied += pRadiotapHeader->it_len;
		}
#endif

		PNET_BUFFER pNetBuf = pCapData->pNBCopy->pNetBuffer;
		// NetBuffers that we create for copy don't use offsets and
		// begin right at the beginning of FirstMdl
		PMDL pMdl = NET_BUFFER_FIRST_MDL(pNetBuf);
		while (pMdl != NULL && plen > 0)
		{
			UINT CopyLengthForMDL = 0;
			PUCHAR pDataLinkBuffer = NULL;
			ULONG BufferLength = 0;
			NdisQueryMdl(
					pMdl,
					&pDataLinkBuffer,
					&BufferLength,
					NormalPagePriority);

			CopyLengthForMDL = min(plen, BufferLength);

			RtlCopyMemory(packp + copied, pDataLinkBuffer, CopyLengthForMDL);
			copied += CopyLengthForMDL;
			plen -= CopyLengthForMDL;

			NdisGetNextMdl(pMdl, &pMdl);
		}

		if (pMdl == NULL && plen > 0) {
			IF_LOUD(DbgPrint("NetBuffer missing %lu bytes", plen);)
			header->bh_caplen -= plen;
		}

		// Fix up alignment
		copied -= header->bh_caplen;
		copied += Packet_WORDALIGN(header->bh_caplen);

		// Increase free space by the amount that it was reduced before
		InterlockedExchangeAdd(&Open->Free, NPF_CAP_SIZE(pCapData, pRadiotapHeader));

		// Return this capture data
		NPF_ObjectPoolReturn(pCapData, NPF_FreeCapData, TRUE);

		ASSERT(Open->Free <= Open->Size);
	}

	NdisReleaseRWLock(Open->BufferLock, &lockState);
	NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);

	if (copied == 0 && Open->OpenStatus == OpenDetached)
	{
		// Filter module is detached and there are no more packets in the buffer
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_DEVICE_REMOVED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return Status;
	}

	TRACE_EXIT();
	EXIT_SUCCESS(copied);
}

//-------------------------------------------------------------------
VOID
NPF_TapExForEachOpen(
	_In_ POPEN_INSTANCE Open,
	_In_ PNET_BUFFER_LIST pNetBufferLists,
	_Inout_ PSINGLE_LIST_ENTRY NBLCopyHead,
	_Inout_ struct timeval *tstamp,
	_In_ BOOLEAN AtDispatchLevel
	);

_Use_decl_annotations_
VOID
NPF_DoTap(
	PNPCAP_FILTER_MODULE pFiltMod,
	PNET_BUFFER_LIST NetBufferLists,
	POPEN_INSTANCE pOpenOriginating,
	BOOLEAN AtDispatchLevel
	)
{
	PSINGLE_LIST_ENTRY Curr;
	POPEN_INSTANCE TempOpen;
	LOCK_STATE_EX lockState;
	PNPF_NBL_COPY pNBLCopy = NULL;
	SINGLE_LIST_ENTRY NBLCopiesHead;
	struct timeval tstamp = {0, 0};
	NBLCopiesHead.Next = NULL;

	/* Lock the group */
	// Read-only lock since list is not being modified.
	NdisAcquireRWLockRead(pFiltMod->OpenInstancesLock, &lockState,
			AtDispatchLevel ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);

	for (Curr = pFiltMod->OpenInstances.Next; Curr != NULL; Curr = Curr->Next)
	{
		TempOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
		if (TempOpen->OpenStatus == OpenRunning)
		{
			// If this instance originated the packet and doesn't want to see it, don't capture.
			if (!(TempOpen == pOpenOriginating && TempOpen->SkipSentPackets))
			{
				// NdisAcquireRWLockRead above raised to DISPATCH_LEVEL
				NPF_TapExForEachOpen(TempOpen, NetBufferLists, &NBLCopiesHead, &tstamp, TRUE);
			}
		}
	}
	/* Release the spin lock no matter what. */
	NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);

	for (Curr = NBLCopiesHead.Next; Curr != NULL; Curr = Curr->Next)
	{
		pNBLCopy = CONTAINING_RECORD(Curr, NPF_NBL_COPY, NBLCopyEntry); 
		NPF_ObjectPoolReturn(pNBLCopy, NPF_FreeNBLCopy, AtDispatchLevel);
	}

	return;
}

_Use_decl_annotations_
VOID
NPF_SendEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	NDIS_PORT_NUMBER    PortNumber,
	ULONG               SendFlags
	)
{
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// Do not capture the normal NDIS send traffic, if this is our loopback adapter.
	if (pFiltMod->Loopback == FALSE)
	{
#endif
		NPF_DoTap(pFiltMod, NetBufferLists, NULL, NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags));
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	}
#endif

	NdisFSendNetBufferLists(pFiltMod->AdapterHandle, NetBufferLists, PortNumber, SendFlags);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_TapEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	NDIS_PORT_NUMBER    PortNumber,
	ULONG               NumberOfNetBufferLists,
	ULONG               ReceiveFlags
	)
{

	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	ULONG				ReturnFlags = 0;

	TRACE_ENTER();

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	if (
		// If this is a Npcap-sent packet being looped back, then it has already been captured.
		!(NdisTestNblFlag(NetBufferLists, NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET)
		 && NetBufferLists->SourceHandle == pFiltMod->AdapterHandle)

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		// Do not capture the normal NDIS receive traffic, if this is our loopback adapter.
		&& pFiltMod->Loopback == FALSE
#endif
	   )
	{
		NPF_DoTap(pFiltMod, NetBufferLists, NULL, NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags));
	}

#ifdef HAVE_RX_SUPPORT
	if (pFiltMod->BlockRxPath)
	{
		if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
		{
			// no NDIS_RECEIVE_FLAGS_RESOURCES in ReceiveFlags
			NdisFReturnNetBufferLists(
				pFiltMod->AdapterHandle,
				NetBufferLists,
				ReturnFlags);
		}
	}
	else
#endif
	{
		//return the packets immediately
		NdisFIndicateReceiveNetBufferLists(
			pFiltMod->AdapterHandle,
			NetBufferLists,
			PortNumber,
			NumberOfNetBufferLists,
			ReceiveFlags);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

VOID
NPF_AlignProtocolField(
	IN UINT Alignment,
	IN PUINT pCur
)
{
	*pCur = (*pCur + Alignment - 1);
	*pCur = *pCur - *pCur % Alignment;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_TapExForEachOpen(
	POPEN_INSTANCE Open,
	PNET_BUFFER_LIST pNetBufferLists,
	PSINGLE_LIST_ENTRY NBLCopyHead,
	struct timeval *tstamp,
	BOOLEAN AtDispatchLevel
	)
{
	UINT					fres;
	UINT					TotalPacketSize;
	UINT received = 0, dropped = 0;

	PNET_BUFFER_LIST		pNetBufList;
	PNET_BUFFER_LIST		pNextNetBufList;
	PNET_BUFFER				pNetBuf = NULL;
	PNET_BUFFER				pNextNetBuf;
	LOCK_STATE_EX lockState;

	PNPF_NB_COPIES pNBCopy = NULL;
	PNPF_NBL_COPY pNBLCopy = NULL;
	PSINGLE_LIST_ENTRY pNBLCopyPrev = NBLCopyHead;
	PSINGLE_LIST_ENTRY pNBCopiesPrev = NULL;
	ASSERT(tstamp != NULL);
	
	//TRACE_ENTER();

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning, AtDispatchLevel))
 	{
 		// The adapter is in use or even released, stop the tapping.
 		return;
 	}

	pNetBufList = pNetBufferLists;
	while (pNetBufList != NULL)
	{
		BOOLEAN withVlanTag = FALSE;
		UCHAR pVlanTag[2];
#ifdef HAVE_DOT11_SUPPORT
		PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = NULL;
#else
		PVOID pRadiotapHeader = NULL;
#endif

		if (pNBLCopyPrev->Next == NULL)
		{
			// Add another NBL copy to the chain
			pNBLCopy = (PNPF_NBL_COPY) NPF_ObjectPoolGet(Open->DeviceExtension->NBLCopyPool, AtDispatchLevel);
			if (pNBLCopy == NULL)
			{
				//Insufficient resources.
				// We can't continue traversing or the NBCopies
				// and actual NBs won't line up.
				goto TEFEO_done_with_NBs;
			}
			pNBLCopyPrev->Next = &pNBLCopy->NBLCopyEntry;
		}
		else
		{
			pNBLCopy = CONTAINING_RECORD(pNBLCopyPrev->Next, NPF_NBL_COPY, NBLCopyEntry);
		}
		pNBLCopyPrev = pNBLCopyPrev->Next;

		// Informational headers
		// Only bother with these if we are capturing, i.e. not MODE_STAT
		if (Open->mode & MODE_DUMP || !(Open->mode & MODE_STAT))
		{
			// Handle IEEE802.1Q VLAN tag here, the tag in OOB field will be copied to the packet data, currently only Ethernet supported.
			// This code refers to Win10Pcap at https://github.com/SoftEtherVPN/Win10Pcap.
			if (g_VlanSupportMode && (NET_BUFFER_LIST_INFO(pNetBufList, Ieee8021QNetBufferListInfo) != 0))
			{
				NDIS_NET_BUFFER_LIST_8021Q_INFO qInfo;
				qInfo.Value = NET_BUFFER_LIST_INFO(pNetBufList, Ieee8021QNetBufferListInfo);
				if (qInfo.TagHeader.VlanId != 0)
				{
					USHORT pTmpVlanTag;
					withVlanTag = TRUE;

					pTmpVlanTag = ((qInfo.TagHeader.UserPriority & 0x07) << 13) |
						((qInfo.TagHeader.CanonicalFormatId & 0x01) << 12) |
						(qInfo.TagHeader.VlanId & 0x0FFF);

					pVlanTag[0] = ((UCHAR *)(&pTmpVlanTag))[1];
					pVlanTag[1] = ((UCHAR *)(&pTmpVlanTag))[0];
				}
			}

#ifdef HAVE_DOT11_SUPPORT
			// Handle native 802.11 media specific OOB data here.
			// This code will help provide the radiotap header for 802.11 packets, see http://www.radiotap.org for details.
			if (Open->pFiltMod->Dot11 && (NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation) != 0))
			{
				PDOT11_EXTSTA_RECV_CONTEXT  pwInfo;

				UINT cur = 0;

				pwInfo = NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation);
				if (pwInfo->Header.Type != NDIS_OBJECT_TYPE_DEFAULT
					|| pwInfo->Header.Revision != DOT11_EXTSTA_RECV_CONTEXT_REVISION_1
					|| pwInfo->Header.Size != sizeof(DOT11_EXTSTA_RECV_CONTEXT)) {
					// This isn't the information we're looking for. Move along.
					goto RadiotapDone;
				}

				pNBLCopy->Dot11RadiotapHeader = (PUCHAR) NPF_ObjectPoolGet(Open->DeviceExtension->Dot11HeaderPool, AtDispatchLevel);
				if (pNBLCopy->Dot11RadiotapHeader == NULL)
				{
					// Insufficient memory
					// TODO: Count this as a drop?
					goto RadiotapDone;
				}
				pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) pNBLCopy->Dot11RadiotapHeader;

				// The radiotap header is also placed in the buffer.
				cur += sizeof(IEEE80211_RADIOTAP_HEADER) / sizeof(UCHAR);

				// [Radiotap] "TSFT" field.
				// Size: 8 bytes, Alignment: 8 bytes.
				if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET_TIMESTAMP) == DOT11_RECV_FLAG_RAW_PACKET_TIMESTAMP)
				{
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_TSFT);
					RtlCopyMemory((PUCHAR)pRadiotapHeader + cur, &pwInfo->ullTimestamp, sizeof(INT64) / sizeof(UCHAR));
					cur += sizeof(INT64) / sizeof(UCHAR);
				}

				// [Radiotap] "Flags" field.
				// Size: 1 byte, Alignment: 1 byte.
				if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET) != DOT11_RECV_FLAG_RAW_PACKET) // The packet doesn't have FCS. We always have no FCS for all packets currently.
				{
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_FLAGS);
					*((PUCHAR)pRadiotapHeader + cur) = 0x0; // 0x0: none
					cur += sizeof(UCHAR) / sizeof(UCHAR);
				}
				else // The packet has FCS.
				{
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_FLAGS);
					*((PUCHAR)pRadiotapHeader + cur) = IEEE80211_RADIOTAP_F_FCS; // 0x10: frame includes FCS

					// FCS check fails.
					if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET_FCS_FAILURE) == DOT11_RECV_FLAG_RAW_PACKET_FCS_FAILURE)
					{
						*((PUCHAR)pRadiotapHeader + cur) |= IEEE80211_RADIOTAP_F_BADFCS; // 0x40: frame failed FCS check
					}

					cur += sizeof(UCHAR) / sizeof(UCHAR);
				}

				// [Radiotap] "Rate" field.
				// Size: 1 byte, Alignment: 1 byte.
				// Looking up the ucDataRate field's value in the data rate mapping table.
				// If not found, return 0.
				IF_LOUD(DbgPrint("pwInfo->ucDataRate = %d\n", pwInfo->ucDataRate);)
				USHORT usDataRateValue = NPF_LookUpDataRateMappingTable(Open->pFiltMod, pwInfo->ucDataRate);
				if (usDataRateValue != 0) {
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_RATE);
					// The miniport might be providing data rate values > 127.5 Mb/s, but radiotap's "Rate" field is only 8 bits,
					// so we at least make it the maximum value instead of overflowing it.
					if (usDataRateValue > 255)
					{
						usDataRateValue = 255;
					}
					*((PUCHAR)pRadiotapHeader + cur) = (UCHAR) usDataRateValue;
					cur += sizeof(UCHAR) / sizeof(UCHAR);
				}

				if (pwInfo->uPhyId || pwInfo->uChCenterFrequency)
				{
					USHORT flags = 0;
					NPF_AlignProtocolField(2, &cur);
					// [Radiotap] "Channel" field.
					// Size: 2 bytes + 2 bytes, Alignment: 2 bytes.
					IF_LOUD(DbgPrint("pwInfo->uPhyId = %x\n", pwInfo->uPhyId);)
					if (pwInfo->uPhyId == dot11_phy_type_fhss)
					{
						flags = IEEE80211_CHAN_GFSK; // 0x0800
					}
					else if (pwInfo->uPhyId == dot11_phy_type_ofdm)
					{
						flags = IEEE80211_CHAN_OFDM; // 0x0040
					}
					else if (pwInfo->uPhyId == dot11_phy_type_hrdsss)
					{
						flags = IEEE80211_CHAN_CCK; // 0x0020
					}
					else if (pwInfo->uPhyId == dot11_phy_type_erp)
					{
						flags = IEEE80211_CHAN_OFDM; // 0x0040
					}
					else if (pwInfo->uPhyId != dot11_phy_type_irbaseband)
					{
						// 2484 is cutoff value used by Wireshark for CommView files, we follow this design here.
						if (pwInfo->uChCenterFrequency > 2484) // 5 GHz
						{
							flags = IEEE80211_CHAN_5GHZ; // 0x0100
						}
						else // 2.4 GHz
						{
							flags = IEEE80211_CHAN_2GHZ; // 0x0080
						}
					}

					// If the frequency is higher than 65535, radiotap can't hold this value because "Frequency" field is only 16 bits, we just leave it the maximum value 65535.
					IF_LOUD(DbgPrint("pwInfo->uChCenterFrequency = %d\n", pwInfo->uChCenterFrequency);)
					if (pwInfo->uChCenterFrequency <= 65535)
					{
						*((USHORT*)pRadiotapHeader + cur) = (USHORT) pwInfo->uChCenterFrequency;
					}
					else
					{
						*((USHORT*)pRadiotapHeader + cur) = 65535;
					}
					cur += sizeof(USHORT) / sizeof(UCHAR);

					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_CHANNEL);
					*((USHORT*)pRadiotapHeader + cur) = flags;
					cur += sizeof(USHORT) / sizeof(UCHAR);
				}

				// [Radiotap] "Antenna signal" field, 1 byte.
				// Size: 1 byte, Alignment: 1 byte.
				if (TRUE)
				{
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
					// We don't need to worry about that lRSSI value doesn't fit in 8 bits based on practical use.
					*((UCHAR*)pRadiotapHeader + cur) = (UCHAR) pwInfo->lRSSI;
					cur += sizeof(UCHAR) / sizeof(UCHAR);
				}

				// [Radiotap] "MCS" field.
				// Size: 1 byte + 1 byte + 1 byte, Alignment: 1 byte.
				if (pwInfo->uPhyId == dot11_phy_type_ht)
				{
					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_MCS);
					RtlZeroMemory((PUCHAR)pRadiotapHeader + cur, 3 * sizeof(UCHAR) / sizeof(UCHAR));
					cur += 3 * sizeof(UCHAR) / sizeof(UCHAR);
				}
				// [Radiotap] "VHT" field, 12 bytes.
				// Size: 2 bytes + 1 byte + 1 byte + 4 * 1 byte + 1 byte + 1 byte + 2 bytes, Alignment: 2 bytes.
				else if (pwInfo->uPhyId == dot11_phy_type_vht)
				{
					// Before putting the VHT field into the packet, because the VHT field has to be aligned on a 2-byte boundary,
					// and the antenna field is on a 2-byte boundary but is only 1 byte long.
					// (The MCS field, however, doesn't have to be aligned on a 2-byte boundary, so you *don't* need to pad anything for HT frames.)
					// cur += sizeof(UCHAR) / sizeof(UCHAR);
					NPF_AlignProtocolField(2, &cur);

					pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_VHT);
					RtlZeroMemory((PUCHAR)pRadiotapHeader + cur, 12 * sizeof(UCHAR) / sizeof(UCHAR));
					cur += 12 * sizeof(UCHAR) / sizeof(UCHAR);
				}

				pRadiotapHeader->it_version = 0x0;
				pRadiotapHeader->it_len = (USHORT) cur;
			}
		RadiotapDone:;
#endif
		} // end of informational headers

		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);

		pNetBuf = pNetBufList->FirstNetBuffer;
		pNBCopiesPrev = &pNBLCopy->NBCopiesHead;
		while (pNetBuf != NULL)
		{
			if (pNBCopiesPrev->Next == NULL)
			{
				// Add another copy to the chain
				pNBCopy = (PNPF_NB_COPIES) NPF_ObjectPoolGet(Open->DeviceExtension->NBCopiesPool, AtDispatchLevel);
				if (pNBCopy == NULL)
				{
					//Insufficient resources.
					// We can't continue traversing or the NBCopies
					// and actual NBs won't line up.
					goto TEFEO_done_with_NBs;
				}
				pNBCopiesPrev->Next = &pNBCopy->CopiesEntry;
				pNBCopy->pNBLCopy = pNBLCopy;
			}
			else
			{
				pNBCopy = CONTAINING_RECORD(pNBCopiesPrev->Next, NPF_NB_COPIES, CopiesEntry);
			}
			pNBCopiesPrev = pNBCopiesPrev->Next;
			pNextNetBuf = NET_BUFFER_NEXT_NB(pNetBuf);

			received++;

			// Lock BPF engine for reading.
			NdisAcquireRWLockRead(Open->MachineLock, &lockState,
					AtDispatchLevel ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);

			// Get the whole packet length.
			TotalPacketSize = NET_BUFFER_DATA_LENGTH(pNetBuf);

			fres = bpf_filter((struct bpf_insn *)(Open->bpfprogram),
					NET_BUFFER_CURRENT_MDL(pNetBuf),
					NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf),
					TotalPacketSize);
			IF_LOUD(DbgPrint("\nCurrent MDL length = %d, Packet Size = %d, fres = %d\n", MmGetMdlByteCount(NET_BUFFER_CURRENT_MDL(pNetBuf)), TotalPacketSize, fres);)

			NdisReleaseRWLock(Open->MachineLock, &lockState);

			if (fres == 0)
			{
				// Packet not accepted by the filter, ignore it.
				// return NDIS_STATUS_NOT_ACCEPTED;
				goto TEFEO_next_NB;
			}

			//if the filter returns -1 the whole packet must be accepted
			if (fres > TotalPacketSize || fres == -1)
				fres = TotalPacketSize;

			if (Open->mode & MODE_STAT)
			{
				// we are in statistics mode
				FILTER_ACQUIRE_LOCK(&Open->CountersLock, AtDispatchLevel);

				Open->Npackets.QuadPart++;

				if (TotalPacketSize < 60)
					Open->Nbytes.QuadPart += 60;
				else
					Open->Nbytes.QuadPart += TotalPacketSize;
				// add preamble+SFD+FCS to the packet
				// these values must be considered because are not part of the packet received from NDIS
				Open->Nbytes.QuadPart += 12;

				FILTER_RELEASE_LOCK(&Open->CountersLock, AtDispatchLevel);

				if (!(Open->mode & MODE_DUMP))
				{
					//return NDIS_STATUS_NOT_ACCEPTED;
					goto TEFEO_next_NB;
				}
			}

#ifdef NPCAP_KDUMP
			if (Open->mode & MODE_DUMP && Open->MaxDumpPacks)
			{
				if (Open->Accepted > Open->MaxDumpPacks)
				{
					// Reached the max number of packets to save in the dump file. Discard the packet and stop the dump thread.
					Open->DumpLimitReached = TRUE; // This stops the thread
												   // Awake the dump thread
					NdisSetEvent(&Open->DumpEvent);

					// Awake the application
					if (Open->ReadEvent != NULL)
						KeSetEvent(Open->ReadEvent, 0, FALSE);

					//return NDIS_STATUS_NOT_ACCEPTED;
					goto TEFEO_next_NB;
				}
			}
#endif
			// Lock "buffer" whenever checking Size/Free
			NdisAcquireRWLockRead(Open->BufferLock, &lockState,
					AtDispatchLevel ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);
			if (Open->Size == 0)
			{
				dropped++;
				//return NDIS_STATUS_NOT_ACCEPTED;
				goto TEFEO_release_BufferLock;
			}

			if (fres + sizeof(struct bpf_hdr)
#ifdef HAVE_DOT11_SUPPORT
					+ (pRadiotapHeader != NULL ? pRadiotapHeader->it_len : 0)
#endif
					> Open->Free)
			{
				dropped++;
				IF_LOUD(DbgPrint("Dropped++, fres = %d, Open->Free = %d\n", fres, Open->Free);)
				// May as well tell the application, even if MinToCopy is not met,
				// to avoid dropping further packets
				if (Open->ReadEvent != NULL)
					KeSetEvent(Open->ReadEvent, 0, FALSE);

				goto TEFEO_release_BufferLock;
			}

			// Packet accepted and must be written to buffer.
			// Make a copy of the data so we can return the original quickly,
			if (pNBCopy->pNetBuffer == NULL)
			{
				pNBCopy->pNetBuffer = NdisAllocateNetBufferMdlAndData(Open->pFiltMod->TapNBPool);
				if (pNBCopy->pNetBuffer == NULL)
				{
					// Insufficient memory
					dropped++;
					goto TEFEO_release_BufferLock;
				}
				pNBCopy->ulSize = NPF_NBCOPY_INITIAL_DATA_SIZE;
				NET_BUFFER_DATA_OFFSET(pNBCopy->pNetBuffer) = 0;
				NET_BUFFER_DATA_LENGTH(pNBCopy->pNetBuffer) = 0;
				NdisAdjustNetBufferCurrentMdl(pNBCopy->pNetBuffer);
			}
			ULONG OldLength = NET_BUFFER_DATA_LENGTH(pNBCopy->pNetBuffer);

			// If this instance wants more data than was copied previously,
			if (fres > OldLength)
			{
				PMDL pMdl = NULL;
				// Check if there's enough space for the data requested
				if (fres > pNBCopy->ulSize) {
					// Allocate some more space.
					// Round up to our data size increment, but:
					// no more than TotalPacketSize, AND
					// no less than what is requested.
					ULONG toAlloc = min(TotalPacketSize, max(NPF_NBCOPY_INITIAL_DATA_SIZE, fres - pNBCopy->ulSize));
					PUCHAR pBuff = (PUCHAR) NdisAllocateMemoryWithTagPriority(
						Open->pFiltMod->AdapterHandle,
						toAlloc,
						NPF_ALLOC_TAG,
						NormalPoolPriority);
					if (pBuff == NULL)
					{
						dropped++;
						goto TEFEO_release_BufferLock;
					}
					// Find the end of the MDL chain,
					for (pMdl = NET_BUFFER_CURRENT_MDL(pNBCopy->pNetBuffer);
							pMdl->Next != NULL; pMdl = pMdl->Next);

					// and tag on another MDL to describe the new buffer.
					pMdl->Next = NdisAllocateMdl(Open->pFiltMod->AdapterHandle, pBuff, toAlloc);
					if (pMdl->Next == NULL)
					{
						NdisFreeMemory(pBuff, toAlloc, 0);
						dropped++;
						goto TEFEO_release_BufferLock;
					}
					pNBCopy->ulSize += toAlloc;
				}
				// Now the NB has enough space.
				ULONG BytesCopied = 0;
				NdisCopyFromNetBufferToNetBuffer(
						pNBCopy->pNetBuffer,
						OldLength,
						fres - OldLength,
						pNetBuf,
						OldLength,
						&BytesCopied);
				NET_BUFFER_DATA_LENGTH(pNBCopy->pNetBuffer) = fres;
			}

			// While BufferLock is held we are at DISPATCH_LEVEL
			PNPF_CAP_DATA pCapData = (PNPF_CAP_DATA) NPF_ObjectPoolGet(Open->CapturePool, TRUE);
			if (pCapData == NULL)
			{
				// Insufficient memory
				// Don't free pNBCopy; that's done later
				dropped++;
				goto TEFEO_release_BufferLock;
			}
			// Increment refcounts on relevant structures
			pCapData->pNBCopy = pNBCopy;
			NPF_ReferenceObject(pNBCopy);
			NPF_ReferenceObject(pNBLCopy);

			if (tstamp->tv_sec == 0)
			{
				// We only get the timestamp once for all packets in this set of NBLs
				// since they were all delivered at the same time.
				GET_TIME(tstamp, &Open->start, Open->TimestampMode);
			}
			pCapData->BpfHeader.bh_tstamp = *tstamp;
			pCapData->BpfHeader.bh_caplen = fres;
			pCapData->BpfHeader.bh_datalen = TotalPacketSize;
			pCapData->BpfHeader.bh_hdrlen = sizeof(struct bpf_hdr);
			ExInterlockedInsertTailList(&Open->PacketQueue, &pCapData->PacketQueueEntry, &Open->PacketQueueLock);

			InterlockedExchangeAdd(&Open->Free, -(LONG)NPF_CAP_SIZE(pCapData, pRadiotapHeader));
			InterlockedIncrement(&Open->Accepted);
			if (Open->Size - Open->Free >= Open->MinToCopy)
			{
#ifdef NPCAP_KDUMP
				if (Open->mode & MODE_DUMP)
					NdisSetEvent(&Open->DumpEvent);
				else
#endif
				{
					if (Open->ReadEvent != NULL)
					{
						KeSetEvent(Open->ReadEvent, 0, FALSE);
					}
				}
			}

TEFEO_release_BufferLock:
			NdisReleaseRWLock(Open->BufferLock, &lockState);

TEFEO_next_NB:
			pNetBuf = pNextNetBuf;
		} // while (pNetBuf != NULL)

		pNetBufList = pNextNetBufList;
	} // while (pNetBufList != NULL)
	
TEFEO_done_with_NBs:
	// If we bailed out and didn't finish traversing,
	// count remaining packets as received.
	for(; pNetBufList != NULL; pNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList)) {
		for (; pNetBuf != NULL; pNetBuf = NET_BUFFER_NEXT_NB(pNetBuf)) {
			received++;
		}
	}

	InterlockedExchangeAdd(&Open->Dropped, dropped);
	InterlockedExchangeAdd(&Open->Received, received);
	NPF_StopUsingOpenInstance(Open, OpenRunning, AtDispatchLevel);
	//TRACE_EXIT();
}
