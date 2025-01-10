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

#include "Packet.h"
#include "win_bpf.h"
#include "time_calls.h"
#if DBG
#include <limits.h> // MAX_LONG
#endif

 //
 // Global variables
 //
extern PNPCAP_DRIVER_EXTENSION g_pDriverExtension;

_Must_inspect_result_
_Success_(return == ulDesiredLen)
ULONG
NPF_CopyFromNBCopyToBuffer(
		_In_ PNPF_NB_COPIES pNBCopy,
		_Out_writes_(ulDesiredLen) PUCHAR __restrict pDstBuf,
		_In_ ULONG ulDesiredLen
		)
{
	if (!NT_VERIFY(ulDesiredLen <= pNBCopy->ulSize))
	{
		return 0;
	}
	RtlCopyMemory(pDstBuf, pNBCopy->Buffer, ulDesiredLen);

	return ulDesiredLen;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_Read(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE			Open;
	PUCHAR packp = NULL;
	struct bpf_hdr*			header;
	ULONG copied=0;
	ULONG plen, available;
	LOCK_STATE_EX lockState;
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	TRACE_ENTER();

	/* Validate */
	Status = NPF_ValidateIoIrp(Irp, &Open, &packp, &available);
	if (Status != STATUS_SUCCESS)
	{
		goto NPF_Read_End;
	}

	// Note a pending IRP at OpenDetached state
	if (!NPF_StartUsingOpenInstance(Open, OpenDetached, FALSE))
	{
		// Instance is being closed
		Status = STATUS_CANCELLED;
		goto NPF_Read_End;
	}

	// Failures after this point must call NPF_StopUsingOpenInstance
	do
	{
		if (Open->Size == 0)
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (packp == NULL)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// Capture mode: need at least a bpf_hdr
		plen = sizeof(struct bpf_hdr);

		// Stat mode needs 2 LONGLONGs
		if (!Open->bModeCapt)
		{
			plen += 2 * sizeof(LONGLONG);
		}

		if (available < plen)
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			copied = plen; // report how much we need.
			break;
		}
	} while (FALSE);

	if (Status != STATUS_SUCCESS)
	{
		NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);
		goto NPF_Read_End;
	}

	// Reset the event; all paths forward are STATUS_SUCCESS
	if (Open->ReadEvent != NULL)
		KeClearEvent(Open->ReadEvent);

	// Stats mode returns and resets stats every time it is called.
	// Packet.dll uses ReadEvent to time the read calls so they happen at
	// regular intervals. bModeCapt prevents TapExForEachOpen from setting
	// the event, so it's strictly a timed wait.
	if (!Open->bModeCapt)
	{
		//this capture instance is in statistics mode
		LONGLONG *Stats = (LONGLONG *)(packp + sizeof(struct bpf_hdr));
		copied = plen; // Set above during size validation
		plen -= sizeof(struct bpf_hdr);

		//fill the bpf header for this packet
		header = (struct bpf_hdr *)packp;
		GET_TIME(&header->bh_tstamp, &Open->start, Open->TimestampMode);
		header->bh_caplen = plen;
		header->bh_datalen = plen;
		header->bh_hdrlen = sizeof(struct bpf_hdr);

		Stats[0] = Open->Npackets.QuadPart;
		Stats[1] = Open->Nbytes.QuadPart;

		//reset the countetrs
		FILTER_ACQUIRE_LOCK(&Open->CountersLock, NPF_IRQL_UNKNOWN);
		Open->Npackets.QuadPart = 0;
		Open->Nbytes.QuadPart = 0;
		FILTER_RELEASE_LOCK(&Open->CountersLock, NPF_IRQL_UNKNOWN);

		NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);

		Status = STATUS_SUCCESS;
		goto NPF_Read_End;
	}

	//------------------------------------------------------------------------------
	copied = 0;

	// Lock this so we don't increment Free during a buffer reset
	NdisAcquireRWLockRead(Open->BufferLock, &lockState, 0);

	// Ensure we have enough space left for at least a bpf_hdr
	while (available > copied + NPF_CAP_SIZE(0))
	{
		//there are some packets in the buffer
		PLIST_ENTRY pCapDataEntry = ExInterlockedRemoveHeadList(&Open->PacketQueue, &Open->PacketQueueLock);
		if (pCapDataEntry == NULL)
		{
			// Done (empty buffer)
			break;
		}
		PNPF_CAP_DATA pCapData = CONTAINING_RECORD(pCapDataEntry, NPF_CAP_DATA, PacketQueueEntry);

		/* Any NPF_CAP_DATA in the queue must be initialized and point to valid data. */
		NT_ASSERT(pCapData->pNBCopy);
		NT_ASSERT(pCapData->pNBCopy->pNBLCopy);
		NT_ASSERT(pCapData->pNBCopy->ulPacketSize < 0xffffffff);

#ifdef HAVE_DOT11_SUPPORT
		PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) pCapData->pNBCopy->pNBLCopy->Dot11RadiotapHeader;
#else
		PVOID pRadiotapHeader = NULL;
#endif
		ULONG ulCapSize = NPF_CAP_OBJ_SIZE(pCapData, pRadiotapHeader);
		if (ulCapSize > available - copied)
		{
			//if the packet does not fit into the user buffer, we've ended copying packets
			if (copied == 0)
			{
				// This packet is too large for the entire buffer. Truncate it.
				plen = available - (ulCapSize - pCapData->ulCaplen);
			}
			else
			{
				// Put this packet back.
				ExInterlockedInsertHeadList(&Open->PacketQueue, pCapDataEntry, &Open->PacketQueueLock);
				break;
			}
		}
		else
		{
			plen = pCapData->ulCaplen;
		}

		header = (struct bpf_hdr *) (packp + copied);
		switch (Open->TimestampMode)
		{
			case TIMESTAMPMODE_QUERYSYSTEMTIME:
			case TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE:
				NT_ASSERT(pCapData->pNBCopy->pNBLCopy->SystemTime.QuadPart > 0);
				GetTimevalFromSystemTime(&header->bh_tstamp, pCapData->pNBCopy->pNBLCopy->SystemTime);
				break;
			default:
				NT_ASSERT(Open->TimestampMode == TIMESTAMPMODE_SINGLE_SYNCHRONIZATION);
				NT_ASSERT(pCapData->pNBCopy->pNBLCopy->PerfCount.QuadPart > 0);
				GetTimevalFromPerfCount(&header->bh_tstamp, &Open->start, pCapData->pNBCopy->pNBLCopy->PerfCount);
				break;
		}
		NT_ASSERT(header->bh_tstamp.tv_sec > 0 || header->bh_tstamp.tv_usec > 0);
		header->bh_caplen = 0;
		header->bh_datalen = pCapData->pNBCopy->ulPacketSize;
		header->bh_hdrlen = sizeof(struct bpf_hdr);

		copied += sizeof(struct bpf_hdr);

#ifdef HAVE_DOT11_SUPPORT
		if (pRadiotapHeader != NULL)
		{
			RtlCopyMemory(packp + copied, pRadiotapHeader, pRadiotapHeader->it_len);
			header->bh_caplen += pRadiotapHeader->it_len;
			header->bh_datalen += pRadiotapHeader->it_len;
			copied += pRadiotapHeader->it_len;
		}
#endif

		ULONG ulCopied = NPF_CopyFromNBCopyToBuffer(pCapData->pNBCopy, packp + copied, plen);
		if (ulCopied < plen) {
			INFO_DBG("NetBuffer missing %lu bytes\n", plen - ulCopied);
		}
		header->bh_caplen += ulCopied;

		// Fix up alignment
		copied += ulCopied;
		copied = Packet_WORDALIGN(copied);

		// Return this capture data
		// MUST be done BEFORE incrementing free space, otherwise we risk runaway allocations while this is stalled.
		NPF_ReturnCapData(pCapData);

		// Increase free space by the amount that it was reduced before
		NpfInterlockedExchangeAdd(&Open->Free, ulCapSize);
		NT_ASSERT(Open->Free <= Open->Size);
	}

	NdisReleaseRWLock(Open->BufferLock, &lockState);
	NPF_StopUsingOpenInstance(Open, OpenDetached, NPF_IRQL_UNKNOWN);

	if (copied == 0 && Open->OpenStatus == OpenDetached)
	{
		// Filter module is detached and there are no more packets in the buffer
		Status = STATUS_DEVICE_REMOVED;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}

NPF_Read_End:
	Irp->IoStatus.Information = copied;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	TRACE_EXIT();
	return Status;
}

VOID
NPF_AlignProtocolField(
	_In_ UINT Alignment,
	_Inout_ PUINT pCur
)
{
	*pCur = (*pCur + Alignment - 1);
	*pCur = *pCur - *pCur % Alignment;
}

/* Returns the number of NET_BUFFERs that couldn't be processed because of
 * insufficient resources (resdropped)
 */
ULONG NPF_GetMetadata(
	_In_ const PNET_BUFFER_LIST pNetBufferLists,
	_Inout_ PSINGLE_LIST_ENTRY NBLCopyHead,
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ LARGE_INTEGER SystemTime,
	_In_ LARGE_INTEGER PerfCount
	)
{
	PNPF_NBL_COPY pNBLCopy = NULL;
	PSINGLE_LIST_ENTRY pNBLCopyPrev = NBLCopyHead;
	ULONG resdropped = 0;
	for (PNET_BUFFER_LIST pNetBufList = pNetBufferLists;
			pNetBufList != NULL;
			pNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList))
	{
#ifdef HAVE_DOT11_SUPPORT
		PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = NULL;
#else
		PVOID pRadiotapHeader = NULL;
#endif

		NT_ASSERT(pNBLCopyPrev);
		NT_ASSERT(pNBLCopyPrev->Next == NULL);
		// Add another NBL copy to the chain
		pNBLCopy = (PNPF_NBL_COPY) ExAllocateFromLookasideListEx(&g_pDriverExtension->NBLCopyPool);
		if (pNBLCopy == NULL)
		{
			//Insufficient resources.
			for (PNET_BUFFER pNetBuf = pNetBufList->FirstNetBuffer;
					pNetBuf != NULL;
					pNetBuf = NET_BUFFER_NEXT_NB(pNetBuf))
			{
				resdropped++;
			}
			continue;
		}
		RtlZeroMemory(pNBLCopy, sizeof(NPF_NBL_COPY));
		pNBLCopy->refcount = 1;
		pNBLCopy->SystemTime = SystemTime;
		pNBLCopy->PerfCount = PerfCount;
		PSINGLE_LIST_ENTRY pSrcNBPrev = &pNBLCopy->NBCopiesHead;


		for (PNET_BUFFER pNetBuf = pNetBufList->FirstNetBuffer;
				pNetBuf != NULL;
				pNetBuf = NET_BUFFER_NEXT_NB(pNetBuf))
		{
			// Some checks for malformed packets that we've seen other drivers produce.
			// If Npcap is implicated in crashes, use the debug build to turn these into assertion failures.
			// DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1) referencing addr 000a indicates null ptr deref.
			if (!NT_VERIFY(NULL != NET_BUFFER_CURRENT_MDL(pNetBuf))
					|| !NT_VERIFY(NULL != NET_BUFFER_FIRST_MDL(pNetBuf)))
			{
				// Skip this one, let someone else crash.
				// We could drop it, but it's not our job to police the NDIS stack.
				continue;
			}
			// Add another copy to the chain
			PNPF_SRC_NB pSrcNB = (PNPF_SRC_NB) ExAllocateFromLookasideListEx(&g_pDriverExtension->SrcNBPool);
			if (pSrcNB == NULL)
			{
				//Insufficient resources.
				resdropped++;
				continue;
			}
			RtlZeroMemory(pSrcNB, sizeof(NPF_SRC_NB));
			pSrcNB->pNBCopy = (PNPF_NB_COPIES) ExAllocateFromLookasideListEx(&g_pDriverExtension->NBCopiesPool);
			if (pSrcNB->pNBCopy == NULL)
			{
				// Out of resources
				resdropped++;
				ExFreeToLookasideListEx(&g_pDriverExtension->SrcNBPool, pSrcNB);
				continue;
			}
			RtlZeroMemory(pSrcNB->pNBCopy, sizeof(NPF_NB_COPIES));
			// OK, all allocations succeeded; now fill out the info.
			pSrcNBPrev->Next = &pSrcNB->CopiesEntry;
			pSrcNBPrev = pSrcNBPrev->Next;
			pSrcNB->pNetBuffer = pNetBuf;
			pSrcNB->pNBCopy->pNBLCopy = pNBLCopy;
			pSrcNB->pNBCopy->ulPacketSize = NET_BUFFER_DATA_LENGTH(pNetBuf);
			pSrcNB->pNBCopy->refcount = 1;
		}

		// If no NBCopies were added, drop this NBLCopy also.
		if (pNBLCopy->NBCopiesHead.Next == NULL) {
			ExFreeToLookasideListEx(&g_pDriverExtension->NBLCopyPool, pNBLCopy);
			continue;
		}

		// Otherwise, gather the appropriate metadata
#ifdef HAVE_DOT11_SUPPORT
			// Handle native 802.11 media specific OOB data here.
			// This code will help provide the radiotap header for 802.11 packets, see http://www.radiotap.org for details.
			if (pFiltMod->Dot11 && (NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation) != 0))
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

				pNBLCopy->Dot11RadiotapHeader = (PUCHAR) ExAllocateFromLookasideListEx(&g_pDriverExtension->Dot11HeaderPool);
				if (pNBLCopy->Dot11RadiotapHeader == NULL)
				{
					// Insufficient memory
					// TODO: Count this as a drop?
					goto RadiotapDone;
				}
				RtlZeroMemory(pNBLCopy->Dot11RadiotapHeader, SIZEOF_RADIOTAP_BUFFER);
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
				INFO_DBG("pwInfo->ucDataRate = %u\n", pwInfo->ucDataRate);
				USHORT usDataRateValue = NPF_LookUpDataRateMappingTable(pFiltMod, pwInfo->ucDataRate);
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
					INFO_DBG("pwInfo->uPhyId = %x\n", pwInfo->uPhyId);
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
					INFO_DBG("pwInfo->uChCenterFrequency = %lu\n", pwInfo->uChCenterFrequency);
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

		NT_ASSERT(pNBLCopy->NBLCopyEntry.Next == NULL);
		pNBLCopyPrev->Next = &pNBLCopy->NBLCopyEntry;
		pNBLCopyPrev = pNBLCopyPrev->Next;
	}
	return resdropped;
}

//-------------------------------------------------------------------
_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
BOOLEAN
NPF_TapExForEachOpen(
	_Inout_ POPEN_INSTANCE Open,
	_Inout_ PNPF_CAP_DATA pCapData,
	_In_ BOOLEAN AtDispatchLevel
	);

_Must_inspect_result_
_Success_(return != 0)
BOOLEAN
NPF_CopyFromNetBufferToNBCopy(
	_Inout_ PNPF_SRC_NB pSrcNB
);

_Must_inspect_result_
_Success_(return != NULL)
__drv_allocatesMem(mem)
__declspec(restrict) PNPF_CAP_DATA
NPF_GetCapData(
	_Inout_ PLOOKASIDE_LIST_EX pPool,
	_Inout_ PNPF_NB_COPIES pNBCopy,
	_In_ PNPF_NBL_COPY pNBLCopy,
	_In_range_(1, 0xffffffff) UINT uCapLen
);

_Use_decl_annotations_
VOID
NPF_DoTap(
	PNPCAP_FILTER_MODULE pFiltMod,
	const PNET_BUFFER_LIST NetBufferLists,
	POPEN_INSTANCE pOpenOriginating,
	BOOLEAN AtDispatchLevel
	)
{
	PSINGLE_LIST_ENTRY Curr;
	LOCK_STATE_EX lockState;
	PNPF_NBL_COPY pNBLCopy = NULL;
	SINGLE_LIST_ENTRY NBLCopiesHead;
	NBLCopiesHead.Next = NULL;
	PNPF_SRC_NB pSrcNB = NULL;
	LARGE_INTEGER SystemTime = { 0 }, PerfCount = { 0 };
	PLIST_ENTRY CurrFilter;
	PNPF_CAP_DATA pCaptures = NULL;

	/* Get relevant timestamps */
	if (pFiltMod->nTimestampQPC == 0 && pFiltMod->nTimestampQST == 0 && pFiltMod->nTimestampQST_Precise == 0)
	{
		// No instances at OpenRunning
		return;
	}
	// Any instances need performance counter?
	if (pFiltMod->nTimestampQPC > 0)
	{
		PerfCount = KeQueryPerformanceCounter(NULL);
	}
	// Any instances need system time? All can use precise if any need it.
	if (pFiltMod->nTimestampQST_Precise > 0)
	{
		BestQuerySystemTime(&SystemTime);
	}
	else if (pFiltMod->nTimestampQST > 0)
	{
		// If none need QST_Precise, we can make do with just QST
		KeQuerySystemTime(&SystemTime);
	}

	/* If we got this far, there is at least 1 instance at OpenRunning,
	 * so gather metadata before locking the list. */
	ULONG resdropped = NPF_GetMetadata(NetBufferLists, &NBLCopiesHead, pFiltMod, SystemTime, PerfCount);
	BOOLEAN firstpass = resdropped > 0;
	/* Lock the filter programs */
	// Read-only lock since list is not being modified.
	NdisAcquireRWLockRead(pFiltMod->BpfProgramsLock, &lockState,
			AtDispatchLevel ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);

	if (NBLCopiesHead.Next == NULL) {
		// No packets, all resdropped!
		// Have to deal with this here, since otherwise the next loop won't be entered.
		for (CurrFilter = pFiltMod->BpfPrograms.Flink; CurrFilter != &pFiltMod->BpfPrograms; CurrFilter = CurrFilter->Flink)
		{
			PNPCAP_BPF_PROGRAM pBpf = CONTAINING_RECORD(CurrFilter, NPCAP_BPF_PROGRAM, BpfProgramsEntry);
			POPEN_INSTANCE pOpen = CONTAINING_RECORD(pBpf, OPEN_INSTANCE, BpfProgram);
			// If this instance originated the packet and doesn't want to see it, don't capture.
			if (pOpen == pOpenOriginating && pOpen->SkipSentPackets)
			{
				continue;
			}
			// Account for packets lost due to inadequate resources earlier
			NpfInterlockedExchangeAdd(&(LONG)pOpen->ResourceDropped, resdropped);
		}
		NdisReleaseRWLock(pFiltMod->BpfProgramsLock, &lockState);
		return;
	}

	PNPF_CAP_DATA pCapPrev = pCaptures;
	for (Curr = NBLCopiesHead.Next; Curr != NULL; Curr = Curr->Next)
	{
		pNBLCopy = CONTAINING_RECORD(Curr, NPF_NBL_COPY, NBLCopyEntry);
		PSINGLE_LIST_ENTRY CurrSrcNB = pNBLCopy->NBCopiesHead.Next;
		for (; CurrSrcNB != NULL; CurrSrcNB = CurrSrcNB->Next)
		{
			pSrcNB = CONTAINING_RECORD(CurrSrcNB, NPF_SRC_NB, CopiesEntry);
			ULONG maxFres = 0;
			for (CurrFilter = pFiltMod->BpfPrograms.Flink; CurrFilter != &pFiltMod->BpfPrograms; CurrFilter = CurrFilter->Flink)
			{
				PNPCAP_BPF_PROGRAM pBpf = CONTAINING_RECORD(CurrFilter, NPCAP_BPF_PROGRAM, BpfProgramsEntry);
				POPEN_INSTANCE pOpen = CONTAINING_RECORD(pBpf, OPEN_INSTANCE, BpfProgram);
				// If this instance originated the packet and doesn't want to see it, don't capture.
				if (pOpen == pOpenOriginating && pOpen->SkipSentPackets)
				{
					continue;
				}
				if (firstpass)
				{
					// Account for packets lost due to inadequate resources earlier
					NpfInterlockedExchangeAdd(&(LONG)pOpen->ResourceDropped, resdropped);
				}

				ULONG TotalPacketSize = pSrcNB->pNBCopy->ulPacketSize;
				UINT fres = bpf_filter(pBpf->bpf_program, pSrcNB->pNetBuffer);
				if (fres == 0)
				{
					// Packet not accepted by the filter, ignore it.
					continue;
				}
				// We have a packet to record. OpenDetached is the highest needed level here.
				if (!NPF_StartUsingOpenInstance(pOpen, OpenDetached, TRUE))
				{
					continue;
				}

				NpfInterlockedIncrement(&(LONG)pOpen->Received);

				//if the filter returns -1 the whole packet must be accepted
				if (fres > TotalPacketSize || fres == -1)
					fres = TotalPacketSize;

				if (fres > maxFres)
					maxFres = fres;

				PNPF_CAP_DATA pCapData = NPF_GetCapData(&g_pDriverExtension->CapturePool, pSrcNB->pNBCopy, pNBLCopy, fres);
				if (pCapData == NULL)
				{
					// Insufficient memory
					// Don't free pNBCopy; that's done later
					NpfInterlockedIncrement(&(LONG)pOpen->ResourceDropped);
					NPF_StopUsingOpenInstance(pOpen, OpenDetached, TRUE);
					continue;
				}

				// Stash this cap data to process later
				if (pCaptures == NULL)
				{
					pCaptures = pCapData;
				}
				else
				{
					pCapPrev->Next = pCapData;
				}
				pCapData->pOpen = pOpen;
				pCapData->pSrcNB = pSrcNB;
				pCapData->Next = NULL;
				pCapPrev = pCapData;
			}
			// Copy maxFres of data from the packet
			pSrcNB->ulDesired = maxFres;
			firstpass = FALSE;
		}
	}
	/* Release the spin lock no matter what. */
	NdisReleaseRWLock(pFiltMod->BpfProgramsLock, &lockState);

	// Now go through all the captures and dispatch them.
	PNPF_CAP_DATA pCapData = NULL;
	while (NULL != (pCapData = pCaptures)) {
		pCaptures = pCapData->Next;
		if (pCapData->pSrcNB->pNBCopy->ulSize < pCapData->pSrcNB->ulDesired)
		{
			// The data hasn't been copied yet
			if (!NPF_CopyFromNetBufferToNBCopy(pCapData->pSrcNB))
			{
				// Failed to copy. Drop it!
				NpfInterlockedIncrement(&(LONG)pCapData->pOpen->ResourceDropped);
				NPF_ReturnCapData(pCapData);
				continue;
			}
		}

		// Have to cache this value; it may be overwritten by NPF_TapExForEachOpen.
		POPEN_INSTANCE pOpen = pCapData->pOpen;
		BOOLEAN accepted = NPF_TapExForEachOpen(pOpen, pCapData, AtDispatchLevel);
		NPF_StopUsingOpenInstance(pOpen, OpenDetached, AtDispatchLevel);
		if (!accepted)
		{
			// Didn't accept it. Clean up!
			NPF_ReturnCapData(pCapData);
		}
	}

	// Now release/return the copies
	Curr = NBLCopiesHead.Next;
	while (Curr != NULL)
	{
		pNBLCopy = CONTAINING_RECORD(Curr, NPF_NBL_COPY, NBLCopyEntry); 
		Curr = Curr->Next;

		PSINGLE_LIST_ENTRY pNBCopiesEntry = pNBLCopy->NBCopiesHead.Next;
		while (pNBCopiesEntry != NULL)
		{
			pSrcNB = CONTAINING_RECORD(pNBCopiesEntry, NPF_SRC_NB, CopiesEntry);
			pNBCopiesEntry = pNBCopiesEntry->Next;

			if (pSrcNB->pNBCopy)
			{
				NPF_ReturnNBCopies(pSrcNB->pNBCopy);
			}
			ExFreeToLookasideListEx(&g_pDriverExtension->SrcNBPool, pSrcNB);
		}

		NPF_ReturnNBLCopy(pNBLCopy);
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

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

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

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	if (
		// If this is a Npcap-sent packet being looped back, then it has already been captured.
		!(NdisTestNblFlag(NetBufferLists, NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET)
		 && NetBufferLists->SourceHandle == pFiltMod->AdapterHandle)

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

_Use_decl_annotations_
PNPF_CAP_DATA NPF_GetCapData(
		PLOOKASIDE_LIST_EX pPool,
		PNPF_NB_COPIES pNBCopy,
		PNPF_NBL_COPY pNBLCopy,
		UINT uCapLen
		)
{
	NT_ASSERT(pNBLCopy);
	NT_ASSERT(pNBCopy->pNBLCopy == pNBLCopy);
	NT_ASSERT(pNBCopy->ulPacketSize < 0xffffffff);

	PNPF_CAP_DATA pCapData = (PNPF_CAP_DATA) ExAllocateFromLookasideListEx(pPool);
	if (pCapData == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(pCapData, sizeof(NPF_CAP_DATA));

	// Increment refcounts on relevant structures
	pCapData->pNBCopy = pNBCopy;
	NpfInterlockedIncrement(&pNBCopy->refcount);
	NpfInterlockedIncrement(&pNBLCopy->refcount);

	pCapData->ulCaplen = uCapLen;

	return pCapData;
}

_Use_decl_annotations_
BOOLEAN
NPF_CopyFromNetBufferToNBCopy(
		PNPF_SRC_NB pSrcNB
		)
{
	PVOID pSrcBuf = NULL;
	ULONG ulDesired = pSrcNB->ulDesired;

	PNPF_NB_COPIES pNBCopy = pSrcNB->pNBCopy;

	// pNBCopy must be set up correctly
	NT_ASSERT(pNBCopy->ulSize == 0);
	NT_ASSERT(pNBCopy->Buffer == NULL);
	NT_ASSERT(ulDesired > 0);

	pNBCopy->Buffer = NPF_AllocateZeroNonpaged(ulDesired, NPF_PACKET_DATA_TAG);
	if (pNBCopy->Buffer == NULL)
	{
		INFO_DBG("Failed to allocate Buffer\n");
		return FALSE;
	}

	// Map or copy a contiguous buffer
	pSrcBuf = NdisGetDataBuffer(pSrcNB->pNetBuffer, ulDesired, pNBCopy->Buffer, 1, 0);
	if (pSrcBuf == NULL)
	{
		INFO_DBG("Failed to map NET_BUFFER\n");
		ExFreePoolWithTag(pNBCopy->Buffer, NPF_PACKET_DATA_TAG);
		pNBCopy->Buffer = NULL;
		return FALSE;
	}
	else if (pSrcBuf != pNBCopy->Buffer)
	{
		// Data was contiguous; we are responsible for copying it
		RtlCopyMemory(pNBCopy->Buffer, pSrcBuf, ulDesired);
	}

	pNBCopy->ulSize = ulDesired;
	return TRUE;
}

_Use_decl_annotations_
BOOLEAN
NPF_TapExForEachOpen(
	POPEN_INSTANCE Open,
	PNPF_CAP_DATA pCapData,
	BOOLEAN AtDispatchLevel
)
{
	LOCK_STATE_EX lockState;

	PNPF_NB_COPIES pNBCopy = pCapData->pNBCopy;
	PNPF_NBL_COPY pNBLCopy = pNBCopy->pNBLCopy;
	ULONG TotalPacketSize = pNBCopy->ulPacketSize;
	ULONG fres = pCapData->ulCaplen;
	BOOLEAN bEnqueued = FALSE;

	NT_ASSERT((Open->TimestampMode == TIMESTAMPMODE_SINGLE_SYNCHRONIZATION && pNBLCopy->PerfCount.QuadPart > 0)
			|| ((Open->TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME
					|| Open->TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE)
				&& pNBLCopy->SystemTime.QuadPart > 0));

	if (!Open->bModeCapt)
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

		goto TEFEO_next_NB;
	}

	// Special case: zero-length buffer or negative free space can be checked without locking buffer
	if (Open->Size <= 0)
	{
		NpfInterlockedIncrement(&(LONG)Open->Dropped);
		goto TEFEO_next_NB;
	}

	// Special case: negative free space can be checked without locking buffer
	if (Open->Free <= 0)
	{
		NpfInterlockedIncrement(&(LONG)Open->Dropped);
		// Wake the application
		if (Open->ReadEvent != NULL)
			KeSetEvent(Open->ReadEvent, 0, FALSE);
		goto TEFEO_next_NB;
	}

#ifdef HAVE_DOT11_SUPPORT
	PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) pNBLCopy->Dot11RadiotapHeader;
#else
	PVOID pRadiotapHeader = NULL;
#endif

	LONG lCapSize = NPF_CAP_SIZE(fres)
#ifdef HAVE_DOT11_SUPPORT
		+ (pRadiotapHeader != NULL ? pRadiotapHeader->it_len : 0)
#endif
		;
	NT_ASSERT(lCapSize > 0);
	if (lCapSize < 0)
	{
		// Overflow; this is an impossibly large packet
		NpfInterlockedIncrement(&(LONG)Open->Dropped);
		goto TEFEO_next_NB;
	}

	// Lock "buffer" whenever checking Size/Free
	NdisAcquireRWLockRead(Open->BufferLock, &lockState,
			AtDispatchLevel ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);
	do {
		// Subtract capture size from Free; if it's less than 0, we didn't have enough space.
		if (0 > NpfInterlockedExchangeAdd(&Open->Free, -lCapSize))
		{
			NpfInterlockedIncrement(&(LONG)Open->Dropped);
			INFO_DBG("Dropped++, fres = %lu, Open->Free = %d\n", fres, Open->Free);
			// May as well tell the application, even if MinToCopy is not met,
			// to avoid dropping further packets
			if (Open->ReadEvent != NULL)
				KeSetEvent(Open->ReadEvent, 0, FALSE);

			break;
		}

		/* Any NPF_CAP_DATA in the queue must be initialized and point to valid data. */
		NT_ASSERT(pCapData->pNBCopy);
		NT_ASSERT(pCapData->pNBCopy->pNBLCopy);
		/* This should never happen, but has happened due to
		 * bugs in NPF_CopyFromNetBufferToNBCopy. Handle the
		 * consequences here, but bail if we're debugging
		 * because this is a big deal. */
		if (!NT_VERIFY(NPF_CAP_OBJ_SIZE(pCapData, pRadiotapHeader) == lCapSize))
		{
			// Add the difference back, otherwise we never recover it.
			NpfInterlockedExchangeAdd(&Open->Free, lCapSize - NPF_CAP_OBJ_SIZE(pCapData, pRadiotapHeader));
		}
		ExInterlockedInsertTailList(&Open->PacketQueue, &pCapData->PacketQueueEntry, &Open->PacketQueueLock);
		// We successfully put this into the queue
		bEnqueued = TRUE;
		lCapSize = 0;
		NpfInterlockedIncrement(&(LONG)Open->Accepted);

		if (Open->Size - Open->Free >= (LONG) Open->MinToCopy
				&& Open->ReadEvent != NULL)
		{
			KeSetEvent(Open->ReadEvent, 0, FALSE);
		}

	} while (0);
	if (!bEnqueued && lCapSize > 0)
	{
		// something went wrong and we didn't enqueue this, so reverse it.
		NpfInterlockedExchangeAdd(&Open->Free, lCapSize);
	}
	NdisReleaseRWLock(Open->BufferLock, &lockState);

TEFEO_next_NB:


	return bEnqueued;
	//TRACE_EXIT();
}
