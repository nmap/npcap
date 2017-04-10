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

#include "Lo_send.h"
#include "debug.h"
#include "packet.h"

//-------------------------------------------------------------------

NTSTATUS
NPF_Write(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	POPEN_INSTANCE		Open;
	POPEN_INSTANCE		GroupOpen;
	POPEN_INSTANCE		TempOpen;
	PIO_STACK_LOCATION	IrpSp;
	ULONG				SendFlags = 0;
	PNET_BUFFER_LIST	pNetBufferList = NULL;
	NDIS_STATUS			Status;
	ULONG				NumSends;
	ULONG				numSentPackets;

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

	NumSends = Open->Nwrites;

	//
	// validate the send parameters set by the IOCTL
	//
	if (NumSends == 0)
	{
		NPF_StopUsingOpenInstance(Open);
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();
		return STATUS_SUCCESS;
	}

	//
	// Validate input parameters: 
	// 1. The packet size should be greater than 0,
	// 2. less-equal than max frame size for the link layer and
	// 3. the maximum frame size of the link layer should not be zero.
	//
	if (IrpSp->Parameters.Write.Length == 0 || 	// Check that the buffer provided by the user is not empty
		Open->MaxFrameSize == 0 ||	// Check that the MaxFrameSize is correctly initialized
		Irp->MdlAddress == NULL ||
		IrpSp->Parameters.Write.Length > Open->MaxFrameSize) // Check that the fame size is smaller that the MTU
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Frame size out of range, or maxFrameSize = 0. Send aborted");

		NPF_StopUsingOpenInstance(Open);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}

	// 
	// Increment the ref counter of the binding handle, if possible
	//
	if (!Open->GroupHead || NPF_StartUsingBinding(Open->GroupHead) == FALSE)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Adapter is probably unbinding, cannot send packets");

		NPF_StopUsingOpenInstance(Open);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	NdisAcquireSpinLock(&Open->WriteLock);
	if (Open->WriteInProgress)
	{
		// Another write operation is currently in progress
		NdisReleaseSpinLock(&Open->WriteLock);

		NPF_StopUsingBinding(Open->GroupHead);

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Another Send operation is in progress, aborting.");

		NPF_StopUsingOpenInstance(Open);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();

		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		Open->WriteInProgress = TRUE;
		NdisResetEvent(&Open->NdisWriteCompleteEvent);
	}

	NdisReleaseSpinLock(&Open->WriteLock);

	TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
		"Max frame size = %u, packet size = %u",
		Open->MaxFrameSize,
		IrpSp->Parameters.Write.Length);

	//
	// reset the number of packets pending the SendComplete
	//
	Open->TransmitPendingPackets = 0;

	NdisResetEvent(&Open->WriteEvent);

	numSentPackets = 0;

	while (numSentPackets < NumSends)
	{
		pNetBufferList = NdisAllocateNetBufferAndNetBufferList(Open->PacketPool,
			0,
			0,
			Irp->MdlAddress,
			0,
			Irp->MdlAddress->ByteCount);

		if (pNetBufferList != NULL)
		{
			//
			// packet is available, prepare it and send it with NdisSend.
			//

			//
			// If asked, set the flags for this packet.
			// Currently, the only situation in which we set the flags is to disable the reception of loopback
			// packets, i.e. of the packets sent by us.
			//
			//if (Open->SkipSentPackets)
			//{
			//	NPFSetNBLFlags(pNetBufferList, g_SendPacketFlags);
			//}


			// The packet hasn't a buffer that needs not to be freed after every single write
			RESERVED(pNetBufferList)->FreeBufAfterWrite = FALSE;

			// Save the IRP associated with the packet
			// RESERVED(pPacket)->Irp=Irp;

			// Attach the writes buffer to the packet

			ASSERT(Open->GroupHead != NULL);

			NdisAcquireSpinLock(&Open->OpenInUseLock);
			if (Open->GroupHead->PausePending)
			{
				Status = NDIS_STATUS_PAUSED;
			}
			else
			{
				Status = NDIS_STATUS_SUCCESS;
				InterlockedIncrement(&Open->TransmitPendingPackets);
			}
			NdisReleaseSpinLock(&Open->OpenInUseLock);

			if (Status == NDIS_STATUS_PAUSED)
			{
				// The adapter is pending to pause, so we don't send the packets.
				TRACE_MESSAGE(PACKET_DEBUG_LOUD, "The adapter is pending to pause, unable to send the packets.");

				NPF_FreePackets(pNetBufferList);
				NPF_StopUsingBinding(Open->GroupHead);
				NPF_StopUsingOpenInstance(Open);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				TRACE_EXIT();
				return STATUS_UNSUCCESSFUL;
			}
			

			NdisResetEvent(&Open->NdisWriteCompleteEvent);

			//receive the packets before sending them

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			// Do not capture the send traffic we send, if this is our loopback adapter.
			if (Open->Loopback == FALSE)
			{
#endif
				/* Lock the group */
				NdisAcquireSpinLock(&Open->GroupHead->GroupLock);
				GroupOpen = Open->GroupHead->GroupNext;
				while (GroupOpen != NULL)
				{
					TempOpen = GroupOpen;
					if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND && TempOpen->SkipSentPackets == FALSE)
					{
						NPF_TapExForEachOpen(TempOpen, pNetBufferList);
					}

					GroupOpen = TempOpen->GroupNext;
				}
				/* Release the spin lock no matter what. */
				NdisReleaseSpinLock(&Open->GroupHead->GroupLock);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			}
#endif

			pNetBufferList->SourceHandle = Open->AdapterHandle;
			NPFSetNBLChildOpen(pNetBufferList, Open); //save the child open object in the packets
			//SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;

			// Recognize IEEE802.1Q tagged packet, as no many adapters support VLAN tag packet sending, no much use for end users,
			// and this code examines the data which lacks efficiency, so I left it commented, the sending part is also unfinished.
			// This code refers to Win10Pcap at https://github.com/SoftEtherVPN/Win10Pcap.
// 			if (Open->Loopback == FALSE)
// 			{
// 				PUCHAR pHeaderBuffer;
// 				UINT iFres;
//
// 				BOOLEAN withVlanTag = FALSE;
// 				UINT VlanID = 0;
// 				UINT VlanUserPriority = 0;
// 				UINT VlanCanFormatID = 0;
//
// 				NdisQueryMdl(
// 					Irp->MdlAddress,
// 					&pHeaderBuffer,
// 					&iFres,
// 					NormalPagePriority);
//
// 				// Determine if the packet is IEEE802.1Q tagged packet.
// 				if (iFres >= 18)
// 				{
// 					if (pHeaderBuffer[12] == 0x81 && pHeaderBuffer[13] == 0x00)
// 					{
// 						USHORT pTmpVlanTag = 0;
//
// 						((UCHAR *)(&pTmpVlanTag))[0] = pHeaderBuffer[15];
// 						((UCHAR *)(&pTmpVlanTag))[1] = pHeaderBuffer[14];
//
// 						VlanID = pTmpVlanTag & 0x0FFF;
// 						VlanUserPriority = (pTmpVlanTag >> 13) & 0x07;
// 						VlanCanFormatID = (pTmpVlanTag >> 12) & 0x01;
//
// 						if (VlanID != 0)
// 						{
// 							withVlanTag = TRUE;
// 						}
// 					}
// 				}
// 			}

			//
			//  Call the MAC
			//
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			if (Open->Loopback == TRUE)
			{
				NPF_LoopbackSendNetBufferLists(Open->GroupHead,
					pNetBufferList);
			}
			else
#endif
#ifdef HAVE_RX_SUPPORT
				if (Open->SendToRxPath == TRUE)
				{
					IF_LOUD(DbgPrint("NPF_Write::SendToRxPath, Open->AdapterHandle=%p, pNetBufferList=%u\n", Open->AdapterHandle, pNetBufferList);)
					// pretend to receive these packets from network and indicate them to upper layers
					NdisFIndicateReceiveNetBufferLists(
						Open->AdapterHandle,
						pNetBufferList,
						NDIS_DEFAULT_PORT_NUMBER,
						1,
						NDIS_RECEIVE_FLAGS_RESOURCES);
				}
				else
#endif
				{
					NdisFSendNetBufferLists(Open->AdapterHandle,
						pNetBufferList,
						NDIS_DEFAULT_PORT_NUMBER,
						SendFlags);
				}

			numSentPackets ++;
		}
		else
		{
			//
			// no packets are available in the Transmit pool, wait some time. The 
			// event gets signalled when at least half of the TX packet pool packets
			// are available
			//
			NdisWaitEvent(&Open->WriteEvent, 1);
		}
	}

	//
	// when we reach this point, all the packets have been enqueued to NdisSend,
	// we just need to wait for all the packets to be completed by the SendComplete
	// (if any of the NdisSend requests returned STATUS_PENDING)
	//
	
#ifdef HAVE_RX_SUPPORT
	if (Open->SendToRxPath && pNetBufferList)
	{
		NPF_FreePackets(pNetBufferList);
	}
	else
#endif
		NdisWaitEvent(&Open->NdisWriteCompleteEvent, 0);

	//
	// all the packets have been transmitted, release the use of the adapter binding
	//
	NPF_StopUsingBinding(Open->GroupHead);

	//
	// no more writes are in progress
	//
	NdisAcquireSpinLock(&Open->WriteLock);
	Open->WriteInProgress = FALSE;
	NdisReleaseSpinLock(&Open->WriteLock);

	NPF_StopUsingOpenInstance(Open);

	//
	// Complete the Irp and return success
	//
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = IrpSp->Parameters.Write.Length;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

INT
NPF_BufferedWrite(
	IN PIRP Irp,
	IN PCHAR UserBuff,
	IN ULONG UserBuffSize,
	BOOLEAN Sync)
{
	POPEN_INSTANCE			Open;
	POPEN_INSTANCE			GroupOpen;
	POPEN_INSTANCE			TempOpen;
	PIO_STACK_LOCATION		IrpSp;
	PNET_BUFFER_LIST		pNetBufferList = NULL;
	PNET_BUFFER				pNetBuffer;
	ULONG					SendFlags = 0;
	UINT					i;
	NDIS_STATUS				Status;
	LARGE_INTEGER			StartTicks, CurTicks, TargetTicks;
	LARGE_INTEGER			TimeFreq;
	struct timeval			BufStartTime;
	struct sf_pkthdr*		pWinpcapHdr;
	PMDL					TmpMdl;
	ULONG					Pos = 0;
	//	PCHAR				CurPos;
	//	PCHAR				EndOfUserBuff = UserBuff + UserBuffSize;
	INT						result;

	TRACE_ENTER();

	IF_LOUD(DbgPrint("NPF: BufferedWrite, UserBuff=%p, Size=%u\n", UserBuff, UserBuffSize);)

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	Open = (POPEN_INSTANCE) IrpSp->FileObject->FsContext;

	if (!Open->GroupHead || NPF_StartUsingBinding(Open->GroupHead) == FALSE)
	{
		// The Network adapter was removed. 
		TRACE_EXIT();
		return 0;
	}

	// Sanity check on the user buffer
	if (UserBuff == NULL)
	{
		// 
		// release ownership of the NdisAdapter binding
		//
		NPF_StopUsingBinding(Open->GroupHead);
		TRACE_EXIT();
		return 0;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->MaxFrameSize == 0)
	{
		IF_LOUD(DbgPrint("NPF_BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");)

		// 
		// release ownership of the NdisAdapter binding
		//
		NPF_StopUsingBinding(Open->GroupHead);
		TRACE_EXIT();
		return 0;
	}

	// Reset the event used to synchronize packet allocation
	NdisResetEvent(&Open->WriteEvent);

	// Reset the pending packets counter
	Open->Multiple_Write_Counter = 0;

	// Save the current time stamp counter
	CurTicks = KeQueryPerformanceCounter(&TimeFreq);

	//
	// Main loop: send the buffer to the wire
	//
	while (TRUE)
	{
		if (Pos == UserBuffSize)
		{
			//
			// end of buffer
			//
			result = Pos;
			break;
		}

		if (UserBuffSize - Pos < sizeof(*pWinpcapHdr))
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			result = -1;
			break;
		}

		pWinpcapHdr = (struct sf_pkthdr *)(UserBuff + Pos);

		if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->MaxFrameSize)
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			result = -1;
			break;
		}

		if (Pos == 0)
		{
			// Retrieve the time references
			StartTicks = KeQueryPerformanceCounter(&TimeFreq);
			BufStartTime.tv_sec = pWinpcapHdr->ts.tv_sec;
			BufStartTime.tv_usec = pWinpcapHdr->ts.tv_usec;
		}

		Pos += sizeof(*pWinpcapHdr);

		if (pWinpcapHdr->caplen > UserBuffSize - Pos)
		{
			//
			// the packet is missing!!
			//
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			result = -1;
			break;
		}

		// Allocate an MDL to map the packet data
		TmpMdl = IoAllocateMdl(UserBuff + Pos, pWinpcapHdr->caplen, FALSE, FALSE, NULL);

		if (TmpMdl == NULL)
		{
			// Unable to map the memory: packet lost
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate the MDL.\n");)

			result = -1;
			break;
		}

		MmBuildMdlForNonPagedPool(TmpMdl);	// XXX can this line be removed?

		Pos += pWinpcapHdr->caplen;

		// Allocate a packet from our free list
		pNetBufferList = NdisAllocateNetBufferAndNetBufferList(
			Open->PacketPool,
			0,
			0,
			TmpMdl,
			0,
			pWinpcapHdr->caplen);

		if (pNetBufferList == NULL)
		{
			//  No more free packets
			IF_LOUD(DbgPrint("NPF_BufferedWrite: no more free packets, returning.\n");)

			NdisResetEvent(&Open->WriteEvent);

			NdisWaitEvent(&Open->WriteEvent, 1000);  

			// Try again to allocate a packet
			pNetBufferList = NdisAllocateNetBufferAndNetBufferList(
				Open->PacketPool,
				0,
				0,
				TmpMdl,
				0,
				pWinpcapHdr->caplen);

			if (pNetBufferList == NULL)
			{
				// Second failure, report an error
				IoFreeMdl(TmpMdl);

				result = -1;
				break;
			}
		}

		// If asked, set the flags for this packet.
		// Currently, the only situation in which we set the flags is to disable the reception of loopback
		// packets, i.e. of the packets sent by us.
		//if (Open->SkipSentPackets)
		//{
		//	NPFSetNBLFlags(pNetBufferList, g_SendPacketFlags);
		//}

		// The packet has a buffer that needs to be freed after every single write
		RESERVED(pNetBufferList)->FreeBufAfterWrite = TRUE;

		TmpMdl->Next = NULL;

		ASSERT(Open->GroupHead != NULL);

		NdisAcquireSpinLock(&Open->OpenInUseLock);
		if (Open->GroupHead->PausePending)
		{
			Status = NDIS_STATUS_PAUSED;
		}
		else
		{
			Status = NDIS_STATUS_SUCCESS;
			// Increment the number of pending sends
			InterlockedIncrement(&Open->Multiple_Write_Counter);
		}
		NdisReleaseSpinLock(&Open->OpenInUseLock);

		if (Status == NDIS_STATUS_PAUSED)
		{
			// The adapter is pending to pause, so we don't send the packets.
			IF_LOUD(DbgPrint("NPF_BufferedWrite: the adapter is pending to pause, unable to send the packets.\n");)

			result = -1;
			break;
		}

		//receive the packets before sending them
		/* Lock the group */
		NdisAcquireSpinLock(&Open->GroupHead->GroupLock);
		GroupOpen = Open->GroupHead->GroupNext;

		while (GroupOpen != NULL)
		{
			TempOpen = GroupOpen;
			if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND && TempOpen->SkipSentPackets == FALSE)
			{
				NPF_TapExForEachOpen(TempOpen, pNetBufferList);
			}

			GroupOpen = TempOpen->GroupNext;
		}
		/* Release the spin lock no matter what. */
		NdisReleaseSpinLock(&Open->GroupHead->GroupLock);

		pNetBufferList->SourceHandle = Open->AdapterHandle;
		NPFSetNBLChildOpen(pNetBufferList, Open); //save the child open object in the packets
		//SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;

		//
		// Call the MAC
		//
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (Open->Loopback == TRUE)
		{
			NPF_LoopbackSendNetBufferLists(Open->GroupHead,
				pNetBufferList);
		}
		else
#endif
#ifdef HAVE_RX_SUPPORT
			if (Open->SendToRxPath == TRUE)
			{
				IF_LOUD(DbgPrint("NPF_BufferedWrite::SendToRxPath, Open->AdapterHandle=%p, pNetBufferList=%u\n", Open->AdapterHandle, pNetBufferList);)
				// pretend to receive these packets from network and indicate them to upper layers
				NdisFIndicateReceiveNetBufferLists(
					Open->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					1,
					NDIS_RECEIVE_FLAGS_RESOURCES);
			}
			else
#endif
			{
				NdisFSendNetBufferLists(Open->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					SendFlags);
			}

		if (Sync)
		{
			if (Pos == UserBuffSize)
			{
				result = Pos;
				break;
			}

			if ((UserBuffSize - Pos) < sizeof(*pWinpcapHdr))
			{
				// Malformed header
				IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

				result = -1;
				break;
			}

			pWinpcapHdr = (struct sf_pkthdr *)(UserBuff + Pos);

			if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->MaxFrameSize || pWinpcapHdr->caplen > (UserBuffSize - Pos - sizeof(*pWinpcapHdr)))
			{
				// Malformed header
				IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

				result = -1;
				break;
			}

			// Release the application if it has been blocked for approximately more than 1 seconds
			if (pWinpcapHdr->ts.tv_sec - BufStartTime.tv_sec > 1)
			{
				IF_LOUD(DbgPrint("NPF_BufferedWrite: timestamp elapsed, returning.\n");)

				result = Pos;
				break;
			}

			// Calculate the time interval to wait before sending the next packet
			TargetTicks.QuadPart = StartTicks.QuadPart + (LONGLONG)((pWinpcapHdr->ts.tv_sec - BufStartTime.tv_sec) * 1000000 + pWinpcapHdr->ts.tv_usec - BufStartTime.tv_usec) * (TimeFreq.QuadPart) / 1000000;

			// Wait until the time interval has elapsed
			while (CurTicks.QuadPart <= TargetTicks.QuadPart)
				CurTicks = KeQueryPerformanceCounter(NULL);
		}
	}

	// Wait the completion of pending sends
#ifdef HAVE_RX_SUPPORT
	if (Open->SendToRxPath && pNetBufferList)
	{
		NPF_FreePackets(pNetBufferList);
	}
	else
#endif
		NPF_WaitEndOfBufferedWrite(Open);

	// 
	// release ownership of the NdisAdapter binding
	//
	NPF_StopUsingBinding(Open->GroupHead);

	TRACE_EXIT();
	return result;
}

//-------------------------------------------------------------------

VOID
NPF_WaitEndOfBufferedWrite(
	POPEN_INSTANCE Open
	)
{
	UINT i;

	TRACE_ENTER();

	NdisResetEvent(&Open->WriteEvent);

	for (i = 0; Open->Multiple_Write_Counter > 0 && i < TRANSMIT_PACKETS; i++)
	{
		NdisWaitEvent(&Open->WriteEvent, 100);  
		NdisResetEvent(&Open->WriteEvent);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

VOID
NPF_FreePackets(
	PNET_BUFFER_LIST    NetBufferLists
	)
	/*++

	Routine Description:

	Free our own initiated Net Buffer Lists.

	Arguments:

	NetBufferLists          - a chain of NBLs that are being freed

	Return Value:

	NONE

	--*/
{
	BOOLEAN				FreeBufAfterWrite;
	PNET_BUFFER_LIST    pNetBufList = NetBufferLists;
	PNET_BUFFER         Currbuff;
	PMDL                pMdl;

/*	TRACE_ENTER();*/

	FreeBufAfterWrite = RESERVED(pNetBufList)->FreeBufAfterWrite;

	if (FreeBufAfterWrite)
	{
		//
		// Packet sent by NPF_BufferedWrite()
		//

		//Free the NBL allocate by myself
		Currbuff = NET_BUFFER_LIST_FIRST_NB(pNetBufList);
		while (Currbuff)
		{
			pMdl = NET_BUFFER_FIRST_MDL(Currbuff);
			NdisFreeMdl(pMdl); //Free MDL
			Currbuff = NET_BUFFER_NEXT_NB(Currbuff);
		}
		NdisFreeNetBufferList(pNetBufList); //Free NBL
	}
	else
	{
		//
		// Packet sent by NPF_Write()
		//

		//Free the NBL allocate by myself
		NdisFreeNetBufferList(pNetBufList); //Free NBL
	}

/*	TRACE_EXIT();*/
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_SendCompleteEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	ULONG               SendCompleteFlags
	)
/*++

Routine Description:

	Send complete handler

	This routine is invoked whenever the lower layer is finished processing 
	sent NET_BUFFER_LISTs.  If the filter does not need to be involved in the
	send path, you should remove this routine and the FilterSendNetBufferLists
	routine.  NDIS will pass along send packets on behalf of your filter more 
	efficiently than the filter can.

Arguments:

	FilterModuleContext     - our filter context
	NetBufferLists          - a chain of NBLs that are being returned to you
	SendCompleteFlags       - flags (see documentation)

Return Value:

	 NONE

--*/
{
	POPEN_INSTANCE		ChildOpen;
	POPEN_INSTANCE		GroupOpen;
	POPEN_INSTANCE		TempOpen;
	BOOLEAN				FreeBufAfterWrite;
	PNET_BUFFER_LIST    pNetBufList;
	PNET_BUFFER_LIST    pNextNetBufList;
	PNET_BUFFER         Currbuff;
	PMDL                pMdl;
	POPEN_INSTANCE		Open = (POPEN_INSTANCE) FilterModuleContext;

	TRACE_ENTER();

	//
	// If your filter injected any send packets into the datapath to be sent,
	// you must identify their NBLs here and remove them from the chain.  Do not
	// attempt to send-complete your NBLs up to the higher layer.
	//

	pNetBufList = NetBufferLists;

	while (pNetBufList != NULL)
	{
		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);
		NET_BUFFER_LIST_NEXT_NBL(pNetBufList) = NULL;

		if (pNetBufList->SourceHandle == Open->AdapterHandle) //this is our self-sent packets
		{
			ChildOpen = NPFGetNBLChildOpen(pNetBufList); //get the child open object that sends these packets
			FreeBufAfterWrite = RESERVED(pNetBufList)->FreeBufAfterWrite;

			NPF_FreePackets(pNetBufList);

			/* Lock the group */
			NdisAcquireSpinLock(&Open->GroupLock);
			// this if should always be false, as Open is always the GroupHead itself, only GroupHead is known by NDIS and get invoked in NPF_SendCompleteEx() function.
			ASSERT(Open->GroupHead == NULL);
			if (Open->GroupHead != NULL)
			{
				GroupOpen = Open->GroupHead->GroupNext;
			}
			else
			{
				GroupOpen = Open->GroupNext;
			}

			while (GroupOpen != NULL)
			{
				TempOpen = GroupOpen;
				if (ChildOpen == TempOpen) //only indicate the specific child open object
				{
					NPF_SendCompleteExForEachOpen(TempOpen, FreeBufAfterWrite);
					break;
				}

				GroupOpen = TempOpen->GroupNext;

			}
			/* Release the spin lock no matter what. */
			NdisReleaseSpinLock(&Open->GroupLock);
		}
		else
		{
			// Send complete the NBLs.  If you removed any NBLs from the chain, make
			// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
			NdisFSendNetBufferListsComplete(Open->AdapterHandle, pNetBufList, SendCompleteFlags);
		}

		pNetBufList = pNextNetBufList;
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

VOID
NPF_SendCompleteExForEachOpen(
	IN POPEN_INSTANCE Open,
	IN BOOLEAN FreeBufAfterWrite
	)
{
	BOOLEAN CompletePause = FALSE;
	//TRACE_ENTER();

	NdisAcquireSpinLock(&Open->OpenInUseLock);

	if (FreeBufAfterWrite)
	{
		// Increment the number of pending sends
		InterlockedDecrement(&Open->Multiple_Write_Counter);

		NdisSetEvent(&Open->WriteEvent);

		//TRACE_EXIT();
	}
	else
	{
		//
		// Packet sent by NPF_Write()
		//

		ULONG stillPendingPackets = InterlockedDecrement(&Open->TransmitPendingPackets);

		//
		// if the number of packets submitted to NdisSend and not acknoledged is less than half the
		// packets in the TX pool, wake up any transmitter waiting for available packets in the TX
		// packet pool
		//
		if (stillPendingPackets < TRANSMIT_PACKETS/2)
		{
			NdisSetEvent(&Open->WriteEvent);
		}
		else
		{
			//
			// otherwise, reset the event, so that we are sure that the NPF_Write will eventually block to
			// wait for availability of packets in the TX packet pool
			//
			NdisResetEvent(&Open->WriteEvent);
		}

		if (stillPendingPackets == 0)
		{
			NdisSetEvent(&Open->NdisWriteCompleteEvent);
		}

		//TRACE_EXIT();
	}

	if (Open->Multiple_Write_Counter == 0 && Open->TransmitPendingPackets == 0 && Open->GroupHead->PausePending)
	{
		CompletePause = TRUE;
	}

	NdisReleaseSpinLock(&Open->OpenInUseLock);

	if (CompletePause)
	{
		NdisFPauseComplete(Open->AdapterHandle);
	}
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
VOID
NPF_LoopbackSendNetBufferLists(
	IN POPEN_INSTANCE Open,
	IN PNET_BUFFER_LIST NetBufferList
	)
{
	TRACE_ENTER();

	// Use Winsock Kernel to send this NBL.
	NPF_WSKSendPacket_NBL(NetBufferList);

	// Call complete function manually just like NDIS callback.
	NPF_SendCompleteEx(Open, NetBufferList, 0);

	TRACE_EXIT();
}
#endif
