/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and my not be redistributed or incorporated    *
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

#ifdef HAVE_DOT11_SUPPORT
#include "ieee80211_radiotap.h"
#endif

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "tme.h"
#endif //HAVE_BUGGY_TME_SUPPORT

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
	ULONG					Input_Buffer_Length;
	UINT					Thead;
	UINT					Ttail;
	UINT					TLastByte;
	PUCHAR					CurrBuff;
	LARGE_INTEGER			CapTime;
	LARGE_INTEGER			TimeFreq;
	struct bpf_hdr*			header;
	KIRQL					Irql;
	PUCHAR					UserPointer;
	ULONG					bytecopy;
	UINT					SizeToCopy;
	UINT					PktLen;
	ULONG					copied, count, current_cpu, av, plen, increment, ToCopy, available;
	CpuPrivateData*			LocalData;
	ULONG					i;
	ULONG					Occupation;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	Open = IrpSp->FileObject->FsContext;


	if (NPF_StartUsingOpenInstance(Open) == FALSE)
	{
		//
		// an IRP_MJ_CLEANUP was received, just fail the request
		//
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_CANCELLED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_CANCELLED;
	}


	//
	// we need to test if the device is still bound to the Network adapter,
	// so we perform a start/stop using binding.
	// This is not critical, since we just want to have a quick way to have the
	// dispatch read fail in case the adapter has been unbound

	if (!Open->GroupHead || NPF_StartUsingBinding(Open->GroupHead) == FALSE)
	{
		NPF_StopUsingOpenInstance(Open);
		// The Network adapter has been removed or diasabled
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}
	NPF_StopUsingBinding(Open->GroupHead);

	if (Open->Size == 0)
	{
		NPF_StopUsingOpenInstance(Open);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	if (Open->mode & MODE_DUMP && Open->DumpFileHandle == NULL)
	{
		// this instance is in dump mode, but the dump file has still not been opened
		NPF_StopUsingOpenInstance(Open);
		TRACE_EXIT();
		EXIT_FAILURE(0);
	}

	Occupation = 0;

	for (i = 0; i < g_NCpu; i++)
	{
		Occupation += (Open->Size - Open->CpuData[i].Free);
	}

	//See if the buffer is full enough to be copied
	if (Occupation <= Open->MinToCopy * g_NCpu || Open->mode & MODE_DUMP)
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
			GET_TIME(&header->bh_tstamp, &G_Start_Time);

			if (Open->mode & MODE_DUMP)
			{
				*(LONGLONG *)(CurrBuff + sizeof(struct bpf_hdr) + 16) = Open->DumpOffset.QuadPart;
				header->bh_caplen = 24;
				header->bh_datalen = 24;
				Irp->IoStatus.Information = 24 + sizeof(struct bpf_hdr);
			}
			else
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
#ifdef HAVE_BUGGY_TME_SUPPORT

		if (Open->mode == MODE_MON)   //this capture instance is in monitor mode
		{
			PTME_DATA data;
			ULONG cnt;
			ULONG block_size;
			PUCHAR tmp;

#ifdef NDIS50
			UserPointer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
#else
			UserPointer = MmGetSystemAddressForMdl(Irp->MdlAddress);
#endif

			if (UserPointer == NULL)
			{
				NPF_StopUsingOpenInstance(Open);
				TRACE_EXIT();
				EXIT_FAILURE(0);
			}

			if ((!IS_VALIDATED(Open->tme.validated_blocks, Open->tme.active_read)) || (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr)))
			{
				NPF_StopUsingOpenInstance(Open);
				TRACE_EXIT();
				EXIT_FAILURE(0);
			}

			header = (struct bpf_hdr *)UserPointer;

			GET_TIME(&header->bh_tstamp, &G_Start_Time);


			header->bh_hdrlen = sizeof(struct bpf_hdr);


			//moves user memory pointer
			UserPointer += sizeof(struct bpf_hdr);

			//calculus of data to be copied
			//if the user buffer is smaller than data to be copied,
			//only some data will be copied
			data = &Open->tme.block_data[Open->tme.active_read];

			if (data->last_read.tv_sec != 0)
				data->last_read = header->bh_tstamp;


			bytecopy = data->block_size * data->filled_blocks;

			if ((IrpSp->Parameters.Read.Length - sizeof(struct bpf_hdr)) < bytecopy)
				bytecopy = (IrpSp->Parameters.Read.Length - sizeof(struct bpf_hdr)) / data->block_size;
			else
				bytecopy = data->filled_blocks;

			tmp = data->shared_memory_base_address;
			block_size = data->block_size;

			for (cnt = 0; cnt < bytecopy; cnt++)
			{
				NdisAcquireSpinLock(&Open->MachineLock);
				RtlCopyMemory(UserPointer, tmp, block_size);
				NdisReleaseSpinLock(&Open->MachineLock);
				tmp += block_size;
				UserPointer += block_size;
			}

			bytecopy *= block_size;

			header->bh_caplen = bytecopy;
			header->bh_datalen = header->bh_caplen;

			NPF_StopUsingOpenInstance(Open);
			TRACE_EXIT();
			EXIT_SUCCESS(bytecopy + sizeof(struct bpf_hdr));
		}

		Occupation = 0;

		for (i = 0; i < g_NCpu; i++)
			Occupation += (Open->Size - Open->CpuData[i].Free);


		if (Occupation == 0 || Open->mode & MODE_DUMP)
							// The timeout has expired, but the buffer is still empty (or the packets must be written to file).
							// We must awake the application, returning an empty buffer.
		{
			NPF_StopUsingOpenInstance(Open);
			TRACE_EXIT();
			EXIT_SUCCESS(0);
		}

#else // not HAVE_BUGGY_TME_SUPPORT
		if (Open->mode == MODE_MON)   //this capture instance is in monitor mode
		{
			NPF_StopUsingOpenInstance(Open);
			TRACE_EXIT();
			EXIT_FAILURE(0);
		}
#endif // HAVE_BUGGY_TME_SUPPORT
	}



	//------------------------------------------------------------------------------
	copied = 0;
	count = 0;
	current_cpu = 0;
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

	while (count < g_NCpu) //round robin on the CPUs, if count = NCpu there are no packets left to be copied
	{
		if (available == copied)
		{
			NPF_StopUsingOpenInstance(Open);
			TRACE_EXIT();
			EXIT_SUCCESS(copied);
		}

		LocalData = &Open->CpuData[current_cpu];

		if (LocalData->Free < Open->Size)
		{
			//there are some packets in the selected (aka LocalData) buffer
			struct PacketHeader* Header = (struct PacketHeader*)(LocalData->Buffer + LocalData->C);

			if (Header->SN == Open->ReaderSN)
			{
				//check if it the next one to be copied
				plen = Header->header.bh_caplen;
				if (plen + sizeof(struct bpf_hdr) > available - copied)
				{
					//if the packet does not fit into the user buffer, we've ended copying packets
					NPF_StopUsingOpenInstance(Open);
					TRACE_EXIT();
					EXIT_SUCCESS(copied);
				}

				// FIX_TIMESTAMPS(&Header->header.bh_tstamp);

				*((struct bpf_hdr *) (&packp[copied])) = Header->header;

				copied += sizeof(struct bpf_hdr);
				LocalData->C += sizeof(struct PacketHeader);

				if (LocalData->C == Open->Size)
				{
					LocalData->C = 0;
				}

				if (Open->Size - LocalData->C < plen)
				{
					//the packet is fragmented in the buffer (i.e. it skips the buffer boundary)
					ToCopy = Open->Size - LocalData->C;
					RtlCopyMemory(packp + copied, LocalData->Buffer + LocalData->C, ToCopy);
					RtlCopyMemory(packp + copied + ToCopy, LocalData->Buffer, plen - ToCopy);
					LocalData->C = plen - ToCopy;
				}
				else
				{
					//the packet is not fragmented
					RtlCopyMemory(packp + copied, LocalData->Buffer + LocalData->C, plen);
					LocalData->C += plen;
					//if (c==size)  inutile, contemplato nell "header atomico"
					//c=0;
				}

				Open->ReaderSN++;
				copied += Packet_WORDALIGN(plen);

				increment = plen + sizeof(struct PacketHeader);
				if (Open->Size - LocalData->C < sizeof(struct PacketHeader))
				{
					//the next packet would be saved at the end of the buffer, but the NewHeader struct would be fragmented
					//so the producer (--> the consumer) skips to the beginning of the buffer
					increment += Open->Size - LocalData->C;
					LocalData->C = 0;
				}
				InterlockedExchangeAdd(&Open->CpuData[current_cpu].Free, increment);
				count = 0;
			}
			else
			{
				current_cpu = (current_cpu + 1) % g_NCpu;
				count++;
			}
		}
		else
		{
			current_cpu = (current_cpu + 1) % g_NCpu;
			count++;
		}
	}
	{
		NPF_StopUsingOpenInstance(Open);
		TRACE_EXIT();
		EXIT_SUCCESS(copied);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_SendEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	NDIS_PORT_NUMBER    PortNumber,
	ULONG               SendFlags
	)
{
	POPEN_INSTANCE		Open = (POPEN_INSTANCE) FilterModuleContext;
	POPEN_INSTANCE GroupOpen;
	POPEN_INSTANCE		TempOpen;
	PVOID i = 0;
	PVOID j = 0;

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// Do not capture the normal NDIS send traffic, if this is our loopback adapter.
	if (Open->Loopback == FALSE)
	{
#endif
		/* Lock the group */
		NdisAcquireSpinLock(&Open->GroupLock);

		ASSERT(Open->GroupHead == NULL);
		if (Open->GroupHead != NULL)
		{
			// Should not come here, because Open called by NDIS will always be a group head itself, so its GroupHead member is NULL.
			IF_LOUD(DbgPrint("NPF_SendEx: Open->GroupHead != NULL\n");)
				GroupOpen = Open->GroupHead->GroupNext;
		}
		else
		{
			//get the 1st group adapter child
			GroupOpen = Open->GroupNext;
		}

		while (GroupOpen != NULL)
		{
			TempOpen = GroupOpen;
			if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
			{
				NPF_TapExForEachOpen(TempOpen, NetBufferLists);
			}

			GroupOpen = TempOpen->GroupNext;
		}
		/* Release the spin lock no matter what. */
		NdisReleaseSpinLock(&Open->GroupLock);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	}
#endif

	NdisFSendNetBufferLists(Open->AdapterHandle, NetBufferLists, PortNumber, SendFlags);

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

	POPEN_INSTANCE      Open = (POPEN_INSTANCE) FilterModuleContext;
	POPEN_INSTANCE		GroupOpen;
	POPEN_INSTANCE		TempOpen;
	ULONG				ReturnFlags = 0;

	TRACE_ENTER();

	UNREFERENCED_PARAMETER(PortNumber);
	UNREFERENCED_PARAMETER(NumberOfNetBufferLists);

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	// Do not capture the normal NDIS receive traffic, if this is our loopback adapter.
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (Open->Loopback == FALSE)
	{
#endif
		/* Lock the group */
		NdisAcquireSpinLock(&Open->GroupLock);
		ASSERT(Open->GroupHead == NULL);
		if (Open->GroupHead != NULL)
		{
			// Should not come here, because Open called by NDIS will always be a group head itself, so its GroupHead member is NULL.
			GroupOpen = Open->GroupHead->GroupNext;
		}
		else
		{
			//get the 1st group adapter child
			GroupOpen = Open->GroupNext;
		}

		while (GroupOpen != NULL)
		{
			TempOpen = GroupOpen;
				if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
				{
					//let every group adapter receive the packets
					NPF_TapExForEachOpen(TempOpen, NetBufferLists);
				}
				GroupOpen = TempOpen->GroupNext;
		}
		/* Release the spin lock no matter what. */
		NdisReleaseSpinLock(&Open->GroupLock);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	}
#endif

#ifdef HAVE_RX_SUPPORT
	if (Open->BlockRxPath)
	{
		if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
		{
			// no NDIS_RECEIVE_FLAGS_RESOURCES in ReceiveFlags
			NdisFReturnNetBufferLists(
				Open->AdapterHandle,
				NetBufferLists,
				ReturnFlags);
		}
	}
	else
#endif
	{
		//return the packets immediately
		NdisFIndicateReceiveNetBufferLists(
			Open->AdapterHandle,
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

VOID
NPF_TapExForEachOpen(
	IN POPEN_INSTANCE Open,
	IN PNET_BUFFER_LIST pNetBufferLists
	)
{
	ULONG					SizeToTransfer;
	NDIS_STATUS				Status;
	UINT					BytesTransfered;
	PMDL					pMdl1, pMdl2;
	LARGE_INTEGER			CapTime;
	LARGE_INTEGER			TimeFreq;
	UINT					fres;
	USHORT					NPFHdrSize;

	CpuPrivateData*			LocalData;
	ULONG					Cpu;
	struct PacketHeader*	Header;
	ULONG					ToCopy;
	ULONG					increment;
	ULONG					i;
	BOOLEAN					ShouldReleaseBufferLock;

	PUCHAR					TmpBuffer = NULL;
	PUCHAR					HeaderBuffer;
	UINT					HeaderBufferSize;
	PUCHAR					LookaheadBuffer;
	UINT					LookaheadBufferSize;
	UINT					PacketSize;
	ULONG					TotalLength;
	UINT					TotalPacketSize;

	PMDL					pMdl = NULL;
	UINT					BufferLength;
	PUCHAR					pDataLinkBuffer = NULL;
	PNET_BUFFER_LIST		pNetBufList;
	PNET_BUFFER_LIST		pNextNetBufList;
	PNET_BUFFER				pNetBuf;
	PNET_BUFFER				pNextNetBuf;
	ULONG					Offset;

	UINT					DataLinkHeaderSize;

#ifdef HAVE_DOT11_SUPPORT
	UCHAR					Dot11RadiotapHeader[256] = { 0 };
	UINT					Dot11RadiotapHeaderSize = 0;
#endif

	//TRACE_ENTER();

// 	if (NPF_StartUsingOpenInstance(Open) == FALSE)
// 	{
// 		// The adapter is in use or even released, stop the tapping.
// 		return;
// 	}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (Open->Loopback && g_DltNullMode)
	{
		DataLinkHeaderSize = DLT_NULL_HDR_LEN;
	}
	else
#endif
	{
		DataLinkHeaderSize = ETHER_HDR_LEN;
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

				pTmpVlanTag = (qInfo.TagHeader.UserPriority & 0x07 << 13) |
					(qInfo.TagHeader.CanonicalFormatId & 0x01 << 12) |
					(qInfo.TagHeader.VlanId & 0x0FFF);

				pVlanTag[0] = ((UCHAR *)(&pTmpVlanTag))[1];
				pVlanTag[1] = ((UCHAR *)(&pTmpVlanTag))[0];
			}
		}

#ifdef HAVE_DOT11_SUPPORT
		// Handle native 802.11 media specific OOB data here.
		// This code will help provide the radiotap header for 802.11 packets, see http://www.radiotap.org for details.
		if (Open->Dot11 && (NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation) != 0))
		{
			PDOT11_EXTSTA_RECV_CONTEXT  pwInfo;
			PIEEE80211_RADIOTAP_HEADER pRadiotapHeader = (PIEEE80211_RADIOTAP_HEADER) Dot11RadiotapHeader;
			UINT cur = 0;

			// The radiotap header is also placed in the buffer.
			cur += sizeof(IEEE80211_RADIOTAP_HEADER) / sizeof(UCHAR);

			pwInfo = NET_BUFFER_LIST_INFO(pNetBufList, MediaSpecificInformation);

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
			USHORT usDataRateValue = NPF_LookUpDataRateMappingTable(Open, pwInfo->ucDataRate);
			pRadiotapHeader->it_present |= BIT(IEEE80211_RADIOTAP_RATE);
			// The miniport might be providing data rate values > 127.5 Mb/s, but radiotap's "Rate" field is only 8 bits,
			// so we at least make it the maximum value instead of overflowing it.
			if (usDataRateValue > 255)
			{
				usDataRateValue = 255;
			}
			*((UCHAR*)Dot11RadiotapHeader + cur) = (UCHAR) usDataRateValue;
			cur += sizeof(UCHAR) / sizeof(UCHAR);

			NPF_AlignProtocolField(2, &cur);
			// [Radiotap] "Channel" field.
			// Size: 2 bytes + 2 bytes, Alignment: 2 bytes.
			if (TRUE)
			{
				USHORT flags = 0;
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
#endif

		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);

		pNetBuf = pNetBufList->FirstNetBuffer;
		while (pNetBuf != NULL)
		{
			pNextNetBuf = NET_BUFFER_NEXT_NB(pNetBuf);

			Cpu = My_KeGetCurrentProcessorNumber();
			LocalData = &Open->CpuData[Cpu];

			LocalData->Received++;

			IF_LOUD(DbgPrint("Received on CPU %d \t%d\n", Cpu, LocalData->Received);)

				NdisAcquireSpinLock(&Open->MachineLock);

			//
			// Get first MDL and data length in the list
			//
			pMdl = pNetBuf->CurrentMdl;
			TotalLength = pNetBuf->DataLength;
			Offset = pNetBuf->CurrentMdlOffset;
			BufferLength = 0;

			do
			{
				if (pMdl)
				{
					NdisQueryMdl(
						pMdl,
						&pDataLinkBuffer,
						&BufferLength,
						NormalPagePriority);
				}

				if (pDataLinkBuffer == NULL)
				{
					//
					//  The system is low on resources. Set up to handle failure
					//  below.
					//
					BufferLength = 0;
					NdisReleaseSpinLock(&Open->MachineLock);
					break;
				}

				if (BufferLength == 0)
				{
					NdisReleaseSpinLock(&Open->MachineLock);
					break;
				}

				BufferLength -= Offset;
				pDataLinkBuffer += Offset;

				// As for single MDL (as we assume) condition, we always have BufferLength == TotalLength
				if (BufferLength > TotalLength)
					BufferLength = TotalLength;

				// Handle multiple MDLs situation here, if there's only 20 bytes in the first MDL, then the IP header is in the second MDL.
				if (BufferLength == DataLinkHeaderSize && pMdl->Next != NULL)
				{
					TmpBuffer = ExAllocatePoolWithTag(NonPagedPool, pNetBuf->DataLength, 'NPCA');
					pDataLinkBuffer = NdisGetDataBuffer(pNetBuf,
						pNetBuf->DataLength,
						TmpBuffer,
						1,
						0);
					if (!pDataLinkBuffer)
					{
						TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
							"NPF_TapExForEachOpen: NdisGetDataBuffer() [status: %#x]\n",
							STATUS_UNSUCCESSFUL);

						NdisReleaseSpinLock(&Open->MachineLock);
						break;
					}
					else
					{
						BufferLength = pNetBuf->DataLength;
					}
				}

				// 			if (BufferLength < sizeof(NDISPROT_ETH_HEADER))
				// 			{
				// 				IF_LOUD(DbgPrint("ReceiveNetBufferList: Open %p, runt nbl %p, first buffer length %d\n",
				// 					Open, pNetBufList, BufferLength);)
				// 				NdisReleaseSpinLock(&Open->MachineLock);
				// 				break;
				// 			}

				//bAcceptedReceive = TRUE;
				//IF_LOUD(DbgPrint("ReceiveNetBufferList: Open %p, interesting nbl %p\n",
				//	Open, pNetBufList);)

				//
				//  If the miniport is out of resources, we can't queue
				//  this list of net buffer list - make a copy if this is so.
				//
				//DispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);

				HeaderBuffer = pDataLinkBuffer;
				HeaderBufferSize = DataLinkHeaderSize;
				LookaheadBuffer = pDataLinkBuffer + HeaderBufferSize;
				LookaheadBufferSize = BufferLength - HeaderBufferSize;
				PacketSize = LookaheadBufferSize;

				//
				// the jit filter is available on x86 (32 bit) only
				//
#ifdef _X86_

				if (Open->Filter != NULL)
				{
					if (Open->bpfprogram != NULL && Open->Filter->Function != NULL)
					{
						fres = Open->Filter->Function(
							(PVOID)HeaderBuffer,
							PacketSize + HeaderBufferSize,
							LookaheadBufferSize + HeaderBufferSize);
					}
					else
					{
						fres = -1;
					}
				}
				else
#endif //_X86_
				{
					fres = bpf_filter((struct bpf_insn *)(Open->bpfprogram),
						HeaderBuffer,
						PacketSize + HeaderBufferSize,
						LookaheadBufferSize + HeaderBufferSize);
					IF_LOUD(DbgPrint("\n");)
					IF_LOUD(DbgPrint("HeaderBufferSize = %d, LookaheadBufferSize (PacketSize) = %d, fres = %d\n", HeaderBufferSize, LookaheadBufferSize, fres);)
				}


				NdisReleaseSpinLock(&Open->MachineLock);

				//
				// The MONITOR_MODE (aka TME extensions) is not supported on
				// 64 bit architectures
				//

				if (fres == 0)
				{
					// Packet not accepted by the filter, ignore it.
					// return NDIS_STATUS_NOT_ACCEPTED;
					goto NPF_TapExForEachOpen_End;
				}

				//if the filter returns -1 the whole packet must be accepted
				// if (fres == -1 || fres > PacketSize + HeaderBufferSize)
				//	fres = PacketSize + HeaderBufferSize;

				if (Open->mode & MODE_STAT)
				{
					// we are in statistics mode
					NdisAcquireSpinLock(&Open->CountersLock);

					Open->Npackets.QuadPart++;

					if (PacketSize + HeaderBufferSize < 60)
						Open->Nbytes.QuadPart += 60;
					else
						Open->Nbytes.QuadPart += PacketSize + HeaderBufferSize;
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
					LocalData->Dropped++;
					//return NDIS_STATUS_NOT_ACCEPTED;
					goto NPF_TapExForEachOpen_End;
				}

				if (Open->mode & MODE_DUMP && Open->MaxDumpPacks)
				{
					ULONG Accepted = 0;
					for (i = 0; i < g_NCpu; i++)
						Accepted += Open->CpuData[i].Accepted;

					if (Accepted > Open->MaxDumpPacks)
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

				//////////////////////////////COPIA.C//////////////////////////////////////////77

				ShouldReleaseBufferLock = TRUE;
				//NdisDprAcquireSpinLock(&LocalData->BufferLock);
				NdisAcquireSpinLock(&LocalData->BufferLock);

				do
				{
					// Get the whole packet length.
					TotalPacketSize = PacketSize + HeaderBufferSize;
					PMDL pCurMdl = pMdl;
					PMDL pPreMdl;
					while (TRUE)
					{
						pPreMdl = pCurMdl;
						NdisGetNextMdl(pPreMdl, &pCurMdl);

						if (pCurMdl)
						{
							NdisQueryMdl(
								pCurMdl,
								&pDataLinkBuffer,
								&BufferLength,
								NormalPagePriority);
							TotalPacketSize += BufferLength;
						}
						else
						{
							break;
						}
					}

					if (fres > TotalPacketSize)
						fres = TotalPacketSize;

					if (fres + sizeof(struct PacketHeader) > LocalData->Free)
					{
						LocalData->Dropped++;
						IF_LOUD(DbgPrint("LocalData->Dropped++, fres = %d, LocalData->Free = %d\n", fres, LocalData->Free);)
						break;
					}

					if (LocalData->TransferMdl1 != NULL)
					{
						//
						//if TransferMdl is not NULL, there is some TransferData pending (i.e. not having called TransferDataComplete, yet)
						//in order to avoid buffer corruption, we drop the packet
						//
						LocalData->Dropped++;
						IF_LOUD(DbgPrint("LocalData->Dropped++, LocalData->TransferMdl1 = %d\n", LocalData->TransferMdl1);)
						break;
					}

					PUCHAR pHeaderBuffer = HeaderBuffer;
					UINT iFres = fres;

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

					Header = (struct PacketHeader *)(LocalData->Buffer + LocalData->P);
					LocalData->Accepted++;
					GET_TIME(&Header->header.bh_tstamp, &G_Start_Time);
					Header->SN = InterlockedIncrement(&Open->WriterSN) - 1;

					// DbgPrint("MDL %d\n", BufferLength);

					Header->header.bh_caplen = 0;
					Header->header.bh_datalen = TotalPacketSize;
					Header->header.bh_hdrlen = sizeof(struct bpf_hdr);

					LocalData->P += sizeof(struct PacketHeader);
					if (LocalData->P == Open->Size)
						LocalData->P = 0;

					increment = sizeof(struct PacketHeader);

#ifdef HAVE_DOT11_SUPPORT
					if (Dot11RadiotapHeaderSize)
					{
						Header->header.bh_caplen += Dot11RadiotapHeaderSize;
						Header->header.bh_datalen += Dot11RadiotapHeaderSize;

						if (Open->Size - LocalData->P < Dot11RadiotapHeaderSize) //we check that the available, AND contiguous, space in the buffer will fit
						{
							// the NewHeader structure, at least, otherwise we skip the producer
							increment += Open->Size - LocalData->P; // at the beginning of the buffer (p = 0), and decrement the free bytes appropriately
							LocalData->P = 0;
						}

						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, Dot11RadiotapHeader, Dot11RadiotapHeaderSize);
						LocalData->P += Dot11RadiotapHeaderSize;
						if (LocalData->P == Open->Size)
							LocalData->P = 0;
						increment += Dot11RadiotapHeaderSize;
					}
#endif

					//
					//we can consider the buffer contiguous, either because we use only the data
					//present in the HeaderBuffer, or because HeaderBuffer and LookaheadBuffer are contiguous
					// ;-))))))
					//
// 					if (Open->Size - LocalData->P < iFres)
// 					{
// 						//the packet will be fragmented in the buffer (aka, it will skip the buffer boundary)
// 						//two copies!!
// 						ToCopy = Open->Size - LocalData->P;
// 						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, pHeaderBuffer, ToCopy);
// 						NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)pHeaderBuffer + ToCopy, iFres - ToCopy);
// 						LocalData->P = iFres - ToCopy;
// 					}
// 					else
// 					{
// 						//the packet does not need to be fragmented in the buffer (aka, it doesn't skip the buffer boundary)
// 						// ;-)))))) only ONE copy
// 						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, pHeaderBuffer, iFres);
// 						LocalData->P += iFres;
// 					}	

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
					pCurMdl = pMdl;
					pPreMdl;
					while (iFres > 0 || iFres == -1)
					{
						UINT CopyLengthForMDL = 0;
						if (pCurMdl)
						{
							NdisQueryMdl(
								pCurMdl,
								&pDataLinkBuffer,
								&BufferLength,
								NormalPagePriority);

							// The first MDL, need to handle the offset.
							if (pCurMdl == pMdl)
							{
								IF_LOUD(DbgPrint("The 1st MDL, (Original) MdlSize = %d, Offset = %d\n", BufferLength, Offset);)
								BufferLength -= Offset;
								pDataLinkBuffer += Offset;
							}

							if (iFres != -1)
								CopyLengthForMDL = min(iFres, BufferLength);
							else
								CopyLengthForMDL = BufferLength;

							if (LocalData->P == Open->Size)
							{
								LocalData->P = 0;
							}

							if (Open->Size - LocalData->P < CopyLengthForMDL)
							{
								//the MDL data will be fragmented in the buffer (aka, it will skip the buffer boundary)
								//two copies!!
								ToCopy = Open->Size - LocalData->P;
								NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, pDataLinkBuffer, ToCopy);
								NdisMoveMappedMemory(LocalData->Buffer + 0, pDataLinkBuffer + ToCopy, CopyLengthForMDL - ToCopy);
								LocalData->P = CopyLengthForMDL - ToCopy;

								IF_LOUD(DbgPrint("iFres = %d, MdlSize = %d, CopyLengthForMDL = %d (two copies)\n", iFres, BufferLength, CopyLengthForMDL);)
							}
							else
							{
								NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, pDataLinkBuffer, CopyLengthForMDL);
								LocalData->P += CopyLengthForMDL;

								IF_LOUD(DbgPrint("iFres = %d, MdlSize = %d, CopyLengthForMDL = %d\n", iFres, BufferLength, CopyLengthForMDL);)
							}

							increment += CopyLengthForMDL;
							Header->header.bh_caplen += CopyLengthForMDL;
							if (iFres != -1)
								iFres -= CopyLengthForMDL;
						}
						else
						{
							break;
						}

						pPreMdl = pCurMdl;
						NdisGetNextMdl(pPreMdl, &pCurMdl);
					}

					IF_LOUD(DbgPrint("Packet Header: bh_caplen = %d, bh_datalen = %d\n", Header->header.bh_caplen, Header->header.bh_datalen);)

					if (Open->Size - LocalData->P < sizeof(struct PacketHeader))  //we check that the available, AND contiguous, space in the buffer will fit
					{
						//the NewHeader structure, at least, otherwise we skip the producer
						increment += Open->Size - LocalData->P;				   //at the beginning of the buffer (p = 0), and decrement the free bytes appropriately
						LocalData->P = 0;
					}

					InterlockedExchangeAdd(&LocalData->Free, (ULONG)(-(LONG)increment));
					if (Open->Size - LocalData->Free >= Open->MinToCopy)
					{
						if (Open->mode & MODE_DUMP)
							NdisSetEvent(&Open->DumpEvent);
						else
						{
							if (Open->ReadEvent != NULL)
							{
								KeSetEvent(Open->ReadEvent, 0, FALSE);
							}
						}
					}
				} while (FALSE);

				if (ShouldReleaseBufferLock)
				{
					//NdisDprReleaseSpinLock(&LocalData->BufferLock);
					NdisReleaseSpinLock(&LocalData->BufferLock);
				}

			} while (FALSE);

NPF_TapExForEachOpen_End:;
			if (TmpBuffer)
			{
				ExFreePool(TmpBuffer);
				TmpBuffer = NULL;
			}

			pNetBuf = pNextNetBuf;
		} // while (pNetBuf != NULL)

		pNetBufList = pNextNetBufList;
	} // while (pNetBufList != NULL)

	//NPF_StopUsingOpenInstance(Open);
	//TRACE_EXIT();
}
