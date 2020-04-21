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

#include <ntddk.h>
#include <ndis.h>

#include "debug.h"
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
	ULONG					copied, plen, ToCopy, available;
	LOCK_STATE lockState;
	NDIS_STATUS Status = STATUS_SUCCESS;

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
		if (NPF_StartUsingOpenInstance(Open) == FALSE)
		{
			// Filter module is detached.
			Status = STATUS_CANCELLED;
			break;
		}

		/* TODO: Allow the read to continue if the filter module is
		 * detached (NPF_StartUsingOpenInstance above returned false)
		 * but we have packet data in the buffer that can still be
		 * delivered. */

		if (Open->Size == 0)
		{
			NPF_StopUsingOpenInstance(Open);
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

#ifdef NPCAP_KDUMP
		if (Open->mode & MODE_DUMP && Open->DumpFileHandle == NULL)
		{
			// this instance is in dump mode, but the dump file has still not been opened
			NPF_StopUsingOpenInstance(Open);
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
			if (Open->TimeOut.QuadPart != (LONGLONG)IMMEDIATE)
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
				NPF_StopUsingOpenInstance(Open);
				TRACE_EXIT();
				EXIT_FAILURE(0);
			}

			if (Open->mode & MODE_DUMP)
			{
				if (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr) + 24)
				{
					NPF_StopUsingOpenInstance(Open);
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
					NPF_StopUsingOpenInstance(Open);
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
			NdisAcquireSpinLock(&Open->CountersLock);
			Open->Npackets.QuadPart = 0;
			Open->Nbytes.QuadPart = 0;
			NdisReleaseSpinLock(&Open->CountersLock);

			NPF_StopUsingOpenInstance(Open);

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
			NPF_StopUsingOpenInstance(Open);
			TRACE_EXIT();
			EXIT_FAILURE(0);
		}
	}



	//------------------------------------------------------------------------------
	copied = 0;
	available = IrpSp->Parameters.Read.Length;

	if (Irp->MdlAddress == 0x0)
	{
		NPF_StopUsingOpenInstance(Open);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	packp = (PUCHAR) MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);


	if (packp == NULL)
	{
		NPF_StopUsingOpenInstance(Open);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	if (Open->ReadEvent != NULL)
		KeClearEvent(Open->ReadEvent);

	NdisAcquireReadWriteLock(&Open->BufferLock, FALSE, &lockState);

	while (available > copied && Open->Free < Open->Size)
	{
		//there are some packets in the buffer
		header = (struct bpf_hdr*)(Open->Buffer + Open->C);

		plen = header->bh_caplen;
		if (plen + sizeof(struct bpf_hdr) > available - copied)
		{
			//if the packet does not fit into the user buffer, we've ended copying packets
			break;
		}

		*((struct bpf_hdr *) (&packp[copied])) = *header;

		copied += sizeof(struct bpf_hdr);
		Open->C += sizeof(struct bpf_hdr);
		InterlockedExchangeAdd(&Open->Free, sizeof(struct bpf_hdr));

		if (Open->C == Open->Size)
		{
			Open->C = 0;
		}

		if (Open->Size - Open->C < plen)
		{
			//the packet is fragmented in the buffer (i.e. it skips the buffer boundary)
			ToCopy = Open->Size - Open->C;
			RtlCopyMemory(packp + copied, Open->Buffer + Open->C, ToCopy);
			RtlCopyMemory(packp + copied + ToCopy, Open->Buffer, plen - ToCopy);
			Open->C = plen - ToCopy;
		}
		else
		{
			//the packet is not fragmented
			RtlCopyMemory(packp + copied, Open->Buffer + Open->C, plen);
			Open->C += plen;
		}
		InterlockedExchangeAdd(&Open->Free, plen);

		copied += Packet_WORDALIGN(plen);

		if (Open->Size - Open->C < sizeof(struct bpf_hdr))
		{
			//the next packet would be saved at the end of the buffer, but the bpf_hdr would be fragmented
			//so the producer (--> the consumer) skips to the beginning of the buffer
			// Update free space accordingly
			InterlockedExchangeAdd(&Open->Free, Open->Size - Open->C);
			Open->C = 0;
		}
		ASSERT(Open->Free <= Open->Size);
	}

	NdisReleaseReadWriteLock(&Open->BufferLock, &lockState);
	NPF_StopUsingOpenInstance(Open);
	TRACE_EXIT();
	EXIT_SUCCESS(copied);
}

//-------------------------------------------------------------------
VOID
NPF_TapExForEachOpen(
	IN POPEN_INSTANCE Open,
	IN PNET_BUFFER_LIST pNetBufferLists
	);

VOID
NPF_DoTap(
	PNPCAP_FILTER_MODULE pFiltMod,
	PNET_BUFFER_LIST NetBufferLists,
	POPEN_INSTANCE pOpenOriginating
	)
{
	PSINGLE_LIST_ENTRY Curr;
	POPEN_INSTANCE TempOpen;

	// If this is a Npcap-sent packet being looped back, then it has already been captured.
	if (NdisTestNblFlag(NetBufferLists, NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET)
			&& NetBufferLists->NdisPoolHandle == pFiltMod->PacketPool)
	{
		return;
	}

	/* Lock the group */
	NdisAcquireSpinLock(&pFiltMod->OpenInstancesLock);

	for (Curr = pFiltMod->OpenInstances.Next; Curr != NULL; Curr = Curr->Next)
	{
		TempOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
		if (TempOpen->OpenStatus == OpenRunning)
		{
			// If this instance originated the packet and doesn't want to see it, don't capture.
			if (!(TempOpen == pOpenOriginating && TempOpen->SkipSentPackets))
			{
				NPF_TapExForEachOpen(TempOpen, NetBufferLists);
			}
		}
	}
	/* Release the spin lock no matter what. */
	NdisReleaseSpinLock(&pFiltMod->OpenInstancesLock);
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
		NPF_DoTap(pFiltMod, NetBufferLists, NULL);
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
	PNET_BUFFER_LIST pClonedNBL = NULL;
	PNET_BUFFER_LIST pWorkingNBL = NULL;
	PSINGLE_LIST_ENTRY Curr;
	POPEN_INSTANCE		TempOpen;
	ULONG				ReturnFlags = 0;

	TRACE_ENTER();

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags))
	{
		pClonedNBL = NdisAllocateCloneNetBufferList(NetBufferLists, pFiltMod->PacketPool, NULL, 0);
		NdisFReturnNetBufferLists(
				pFiltMod->AdapterHandle,
				NetBufferLists,
				ReturnFlags);
		if (pClonedNBL == NULL)
		{
			// Insufficient resources
			return;
		}
	}
	pWorkingNBL = pClonedNBL ? pClonedNBL : NetBufferLists;

	// Do not capture the normal NDIS receive traffic, if this is our loopback adapter.
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (pFiltMod->Loopback == FALSE)
	{
#endif
		NPF_DoTap(pFiltMod, pWorkingNBL, NULL);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	}
#endif

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
			pWorkingNBL,
			PortNumber,
			NumberOfNetBufferLists,
			ReceiveFlags);
		if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags))
		{
			// We retained this, so free it up right away
			NPF_ReturnEx(FilterModuleContext, 
					pWorkingNBL,
					ReturnFlags);
		}
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

VOID
NPF_TapExForEachOpen(
	IN POPEN_INSTANCE Open,
	IN PNET_BUFFER_LIST pNetBufferLists
	)
{
	UINT					fres;
	UINT					TotalPacketSize;

	PNET_BUFFER_LIST		pNetBufList;
	PNET_BUFFER_LIST		pNextNetBufList;
	PNET_BUFFER				pNetBuf;
	PNET_BUFFER				pNextNetBuf;
	PNPF_WRITER_REQUEST pReq = NULL;

#ifdef HAVE_DOT11_SUPPORT
	PUCHAR					Dot11RadiotapHeader = NULL;
	UINT					Dot11RadiotapHeaderSize = 0;
#endif

	//TRACE_ENTER();

 	if (!NPF_StartUsingOpenInstance(Open))
 	{
 		// The adapter is in use or even released, stop the tapping.
 		return;
 	}

	pNetBufList = pNetBufferLists;
	while (pNetBufList != NULL)
	{
		BOOLEAN withVlanTag = FALSE;
		UCHAR pVlanTag[2];

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
			PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = NULL;

			UINT cur = 0;

			pwInfo = NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation);
			if (pwInfo->Header.Type != NDIS_OBJECT_TYPE_DEFAULT
				|| pwInfo->Header.Revision != DOT11_EXTSTA_RECV_CONTEXT_REVISION_1
				|| pwInfo->Header.Size != sizeof(DOT11_EXTSTA_RECV_CONTEXT)) {
				// This isn't the information we're looking for. Move along.
				goto RadiotapDone;
			}

			Dot11RadiotapHeader = NdisAllocateMemoryWithTagPriority(Open->pFiltMod->AdapterHandle, SIZEOF_RADIOTAP_BUFFER, '0OWA', NormalPoolPriority);
			if (Dot11RadiotapHeader == NULL)
			{
				// Insufficient memory
				// TODO: Count this as a drop?
				goto RadiotapDone;
			}
			pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) Dot11RadiotapHeader;

			// The radiotap header is also placed in the buffer.
			cur += sizeof(IEEE80211_RADIOTAP_HEADER) / sizeof(UCHAR);

			// [Radiotap] "TSFT" field.
			// Size: 8 bytes, Alignment: 8 bytes.
			if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET_TIMESTAMP) == DOT11_RECV_FLAG_RAW_PACKET_TIMESTAMP)
			{
				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_TSFT);
				RtlCopyMemory(Dot11RadiotapHeader + cur, &pwInfo->ullTimestamp, sizeof(INT64) / sizeof(UCHAR));
				cur += sizeof(INT64) / sizeof(UCHAR);
			}

			// [Radiotap] "Flags" field.
			// Size: 1 byte, Alignment: 1 byte.
			if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET) != DOT11_RECV_FLAG_RAW_PACKET) // The packet doesn't have FCS. We always have no FCS for all packets currently.
			{
				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_FLAGS);
				*((UCHAR*)Dot11RadiotapHeader + cur) = 0x0; // 0x0: none
				cur += sizeof(UCHAR) / sizeof(UCHAR);
			}
			else // The packet has FCS.
			{
				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_FLAGS);
				*((UCHAR*)Dot11RadiotapHeader + cur) = IEEE80211_RADIOTAP_F_FCS; // 0x10: frame includes FCS

				// FCS check fails.
				if ((pwInfo->uReceiveFlags & DOT11_RECV_FLAG_RAW_PACKET_FCS_FAILURE) == DOT11_RECV_FLAG_RAW_PACKET_FCS_FAILURE)
				{
					*((UCHAR*)Dot11RadiotapHeader + cur) |= IEEE80211_RADIOTAP_F_BADFCS; // 0x40: frame failed FCS check
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
				*((UCHAR*)Dot11RadiotapHeader + cur) = (UCHAR) usDataRateValue;
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
					*((USHORT*)Dot11RadiotapHeader + cur) = (USHORT) pwInfo->uChCenterFrequency;
				}
				else
				{
					*((USHORT*)Dot11RadiotapHeader + cur) = 65535;
				}
				cur += sizeof(USHORT) / sizeof(UCHAR);

				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_CHANNEL);
				*((USHORT*)Dot11RadiotapHeader + cur) = flags;
				cur += sizeof(USHORT) / sizeof(UCHAR);
			}

			// [Radiotap] "Antenna signal" field, 1 byte.
			// Size: 1 byte, Alignment: 1 byte.
			if (TRUE)
			{
				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
				// We don't need to worry about that lRSSI value doesn't fit in 8 bits based on practical use.
				*((UCHAR*)Dot11RadiotapHeader + cur) = (UCHAR) pwInfo->lRSSI;
				cur += sizeof(UCHAR) / sizeof(UCHAR);
			}

			// [Radiotap] "MCS" field.
			// Size: 1 byte + 1 byte + 1 byte, Alignment: 1 byte.
			if (pwInfo->uPhyId == dot11_phy_type_ht)
			{
				pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_MCS);
				RtlZeroMemory(Dot11RadiotapHeader + cur, 3 * sizeof(UCHAR) / sizeof(UCHAR));
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
				RtlZeroMemory(Dot11RadiotapHeader + cur, 12 * sizeof(UCHAR) / sizeof(UCHAR));
				cur += 12 * sizeof(UCHAR) / sizeof(UCHAR);
			}

			Dot11RadiotapHeaderSize = cur;
			pRadiotapHeader->it_version = 0x0;
			pRadiotapHeader->it_len = (USHORT) Dot11RadiotapHeaderSize;
		}
	RadiotapDone:;
#endif

		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);

		pNetBuf = pNetBufList->FirstNetBuffer;
		while (pNetBuf != NULL)
		{
			pNextNetBuf = NET_BUFFER_NEXT_NB(pNetBuf);

			InterlockedIncrement(&Open->Received);

			NdisAcquireSpinLock(&Open->MachineLock);

			// Get the whole packet length.
			TotalPacketSize = NET_BUFFER_DATA_LENGTH(pNetBuf);

			fres = bpf_filter((struct bpf_insn *)(Open->bpfprogram),
					NET_BUFFER_FIRST_MDL(pNetBuf),
					NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf),
					TotalPacketSize);
			IF_LOUD(DbgPrint("\nFirst MDL length = %d, Packet Size = %d, fres = %d\n", MmGetMdlByteCount(NET_BUFFER_FIRST_MDL(pNetBuf)), TotalPacketSize, fres);)


			NdisReleaseSpinLock(&Open->MachineLock);

			if (fres == 0)
			{
				// Packet not accepted by the filter, ignore it.
				// return NDIS_STATUS_NOT_ACCEPTED;
				goto NPF_TapExForEachOpen_End;
			}

			//if the filter returns -1 the whole packet must be accepted
			if (fres > TotalPacketSize || fres == -1)
				fres = TotalPacketSize;

			if (Open->mode & MODE_STAT)
			{
				// we are in statistics mode
				NdisAcquireSpinLock(&Open->CountersLock);

				Open->Npackets.QuadPart++;

				if (TotalPacketSize < 60)
					Open->Nbytes.QuadPart += 60;
				else
					Open->Nbytes.QuadPart += TotalPacketSize;
				// add preamble+SFD+FCS to the packet
				// these values must be considered because are not part of the packet received from NDIS
				Open->Nbytes.QuadPart += 12;

				NdisReleaseSpinLock(&Open->CountersLock);

				if (!(Open->mode & MODE_DUMP))
				{
					//return NDIS_STATUS_NOT_ACCEPTED;
					goto NPF_TapExForEachOpen_End;
				}
			}

			if (Open->Size == 0)
			{
				InterlockedIncrement(&Open->Dropped);
				//return NDIS_STATUS_NOT_ACCEPTED;
				goto NPF_TapExForEachOpen_End;
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
					goto NPF_TapExForEachOpen_End;
				}
			}
#endif
			pReq = NdisAllocateMemoryWithTagPriority(Open->pFiltMod->AdapterHandle, sizeof(NPF_WRITER_REQUEST), '0OWA', NormalPoolPriority);
			if (pReq == NULL)
			{
				// Insufficient memory
				InterlockedIncrement(&Open->Dropped);
				goto NPF_TapExForEachOpen_End;
			}
			pReq->pOpen = Open;
			pReq->pNBL = pNetBufList;
			pReq->pNetBuffer = pNetBuf;
			GET_TIME(&pReq->BpfHeader.bh_tstamp, &Open->start, Open->TimestampMode);
			pReq->BpfHeader.bh_caplen = fres;
			pReq->BpfHeader.bh_datalen = TotalPacketSize;
			pReq->BpfHeader.bh_hdrlen = sizeof(struct bpf_hdr);
#ifdef HAVE_DOT11_SUPPORT
			pReq->pRadiotapHeader = Dot11RadiotapHeader;
#endif

			pReq->FunctionCode = NPF_WRITER_WRITE;
			NPF_QueueRequest(Open->pFiltMod, pReq);

NPF_TapExForEachOpen_End:;

			pNetBuf = pNextNetBuf;
		} // while (pNetBuf != NULL)

#ifdef HAVE_DOT11_SUPPORT
		// Free the radiotap header
		pReq = NdisAllocateMemoryWithTagPriority(Open->pFiltMod->AdapterHandle, sizeof(NPF_WRITER_REQUEST), '0OWA', NormalPoolPriority);
		if (pReq == NULL)
		{
			// Insufficient memory
			// Can't free it yet or writer will BSOD accessing it.
			NPF_PurgeRequests(Open->pFiltMod, NULL, &Dot11RadiotapHeader, NULL);
			NdisFreeMemory(Dot11RadiotapHeader, SIZEOF_RADIOTAP_BUFFER, 0);
		}
		else
		{
			pReq->pRadiotapHeader = Dot11RadiotapHeader;
			pReq->FunctionCode = NPF_WRITER_FREE_RADIOTAP;
			NPF_QueueRequest(Open->pFiltMod, pReq);
		}
#endif

		pNetBufList = pNextNetBufList;
	} // while (pNetBufList != NULL)

	NPF_StopUsingOpenInstance(Open);
	//TRACE_EXIT();
}
			//////////////////////////////COPIA.C//////////////////////////////////////////77
__inline VOID NPF_CircularFill( POPEN_INSTANCE pOpen, PUCHAR pSrc, ULONG Len )
{
	ULONG ToCopy = 0;
	if (pOpen->Size - pOpen->P < Len)
	{
		ToCopy = pOpen->Size - pOpen->P;
		NdisMoveMappedMemory(pOpen->Buffer + pOpen->P, pSrc, ToCopy);
		NdisMoveMappedMemory(pOpen->Buffer + 0, pSrc + ToCopy, Len - ToCopy);
		pOpen->P = Len - ToCopy;
	}
	else
	{
		NdisMoveMappedMemory(pOpen->Buffer + pOpen->P, pSrc, Len);
		pOpen->P += Len;
	}

	if (pOpen->P == pOpen->Size)
	{
		pOpen->P = 0;
	}
}

VOID
NPF_FillBuffer( POPEN_INSTANCE pOpen,
	       	PNET_BUFFER pNetBuf,
	       	struct bpf_hdr *pBpfHeader,
	       	PUCHAR pDot11Data)
{

	UINT iFres = pBpfHeader->bh_caplen;
	struct bpf_hdr *pBufferHeader = NULL;
	ULONG Offset;
	LOCK_STATE lockState;
#ifdef HAVE_DOT11_SUPPORT
	PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) pDot11Data;
#endif

	NdisAcquireReadWriteLock(&pOpen->BufferLock, FALSE, &lockState);
	do
	{


		if (pBpfHeader->bh_caplen + sizeof(struct bpf_hdr)
#ifdef HAVE_DOT11_SUPPORT
				+ (pRadiotapHeader != NULL ? pRadiotapHeader->it_len : 0)
#endif
				> pOpen->Free)
		{
			// Not enough room in this buffer segment. Drop the packet.
			IF_LOUD(DbgPrint("Dropped++, iFres = %d, pOpen->Free = %d\n", iFres, pOpen->Free);)
			// May as well tell the application, even if MinToCopy is not met,
			// to avoid dropping further packets
			if (pOpen->ReadEvent != NULL)
				KeSetEvent(pOpen->ReadEvent, 0, FALSE);
			break;
		}

		// Disable the IEEE802.1Q VLAN feature for now.
		// 					if (withVlanTag)
		// 					{
		// 						// Insert a tag in the case of IEEE802.1Q packet
		// 						pHeaderBuffer = ExAllocatePoolWithTag(NonPagedPool, fres + 4, 'NPCA');
		// 						NdisMoveMappedMemory(pHeaderBuffer, HeaderBuffer, 12);
		// 						pHeaderBuffer[12] = 0x81;
		// 						pHeaderBuffer[13] = 0x00;
		// 						NdisMoveMappedMemory(&pHeaderBuffer[14], pVlanTag, 2);
		// 						NdisMoveMappedMemory(&pHeaderBuffer[16], &HeaderBuffer[12], fres - 12);
		// 						iFres += 4;
		// 					}

		ULONG oldP = pOpen->P;
		ULONG ulSize = 0;

		InterlockedIncrement(&pOpen->Accepted);

		pBufferHeader = (struct bpf_hdr *)(pOpen->Buffer + pOpen->P);
		// We won't wrap this because of earlier checks
		NPF_CircularFill(pOpen, (PUCHAR) pBpfHeader, sizeof(struct bpf_hdr));

#ifdef HAVE_DOT11_SUPPORT
		if (pRadiotapHeader != NULL)
		{
			ulSize = pRadiotapHeader->it_len;
			pBufferHeader->bh_caplen += ulSize;
			pBufferHeader->bh_caplen += ulSize;
			NPF_CircularFill(pOpen, pDot11Data, ulSize);
		}
#endif


		// Disable the IEEE802.1Q VLAN feature for now.
		// 					if (withVlanTag)
		// 					{
		// 						if (pHeaderBuffer)
		// 						{
		// 							ExFreePool(pHeaderBuffer);
		// 							pHeaderBuffer = NULL;
		// 						}
		// 					}

		// Add MDLs
		PMDL pMdl = NET_BUFFER_CURRENT_MDL(pNetBuf);
		Offset = NET_BUFFER_CURRENT_MDL_OFFSET(pNetBuf);
		while (pMdl != NULL && iFres > 0)
		{
			UINT CopyLengthForMDL = 0;
			PUCHAR pDataLinkBuffer = NULL;
			ULONG BufferLength = 0;
			NdisQueryMdl(
					pMdl,
					&pDataLinkBuffer,
					&BufferLength,
					NormalPagePriority);

			BufferLength -= Offset;
			pDataLinkBuffer += Offset;

			CopyLengthForMDL = min(iFres, BufferLength);

			if (pOpen->P == pOpen->Size)
			{
				pOpen->P = 0;
			}

			NPF_CircularFill(pOpen, pDataLinkBuffer, CopyLengthForMDL);
			iFres -= CopyLengthForMDL;

			/* Offset only matters for first MDL. */
			Offset = 0;
			NdisGetNextMdl(pMdl, &pMdl);
		}

		if (pMdl == NULL && iFres > 0) {
			IF_LOUD(DbgPrint("NetBuffer missing %lu bytes", iFres);)
			pBufferHeader->bh_caplen -= iFres;
		}


		InterlockedExchangeAdd(&pOpen->Free, -(LONG)(sizeof(struct bpf_hdr) + pBufferHeader->bh_caplen));
		// Check our accounting.
		ASSERT((pOpen->Size + (pOpen->P - oldP)) % pOpen->Size == sizeof(struct bpf_hdr) + pBufferHeader->bh_caplen);

		if (pOpen->Size - pOpen->P < sizeof(struct bpf_hdr))  //we check that the available, AND contiguous, space in the buffer will fit
		{
			//the NewHeader structure, at least, otherwise we skip the producer
			InterlockedExchangeAdd(&pOpen->Free, -(LONG)(pOpen->Size - pOpen->P));
			pOpen->P = 0;
		}

		if (pOpen->Size - pOpen->Free >= pOpen->MinToCopy)
		{
#ifdef NPCAP_KDUMP
			if (pOpen->mode & MODE_DUMP)
				NdisSetEvent(&pOpen->DumpEvent);
			else
#endif
			{
				if (pOpen->ReadEvent != NULL)
				{
					KeSetEvent(pOpen->ReadEvent, 0, FALSE);
				}
			}
		}
	} while (FALSE);

	NdisReleaseReadWriteLock(&pOpen->BufferLock, &lockState);

}
