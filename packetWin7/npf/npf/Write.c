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

#include "Lo_send.h"
#include "packet.h"

/*!
  \brief Function to free the Net Buffer Lists initiated by ourself.
*/
VOID
NPF_FreePackets(
	_In_ PNET_BUFFER_LIST    NetBufferLists
	);

/*!
  \brief Ends a send operation.
  \param pFiltMod Pointer to filter module context structure
  \param FreeBufAfterWrite Whether the buffer should be freed.

  Callback function associated with the NdisFSend() NDIS function. It is invoked by NPF_SendCompleteEx() when the NIC
  driver has finished an OID request operation that was previously started by NPF_Write().
*/
VOID
NPF_SendCompleteExForEachOpen(
	_In_ POPEN_INSTANCE Open,
	_In_ BOOLEAN FreeBufAfterWrite
	);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
/*!
  \brief Send a loopback NBL.
  \param NetBufferList Pointer to NBL.

  Alternative to NdisFSendNetBufferLists, use the same NBL parameter, but it calls Winsock Kernel to send packet instead
  of NDIS functions.
*/
VOID
NPF_LoopbackSendNetBufferLists(
	_In_ NDIS_HANDLE FilterModuleContext,
	_In_ PNET_BUFFER_LIST NetBufferList
	);
#endif

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_Write(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE		Open;
	PIO_STACK_LOCATION	IrpSp;
	ULONG				SendFlags = 0;
	PNET_BUFFER_LIST	pNetBufferList = NULL;
	ULONG				NumSends;
	ULONG				numSentPackets;
	NTSTATUS Status = STATUS_SUCCESS;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	Open = IrpSp->FileObject->FsContext;
	if (!NPF_IsOpenInstance(Open))
	{
		Irp->IoStatus.Status = STATUS_INVALID_HANDLE;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INVALID_HANDLE;
	}

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning))
	{
		// Write requires an attached adapter.
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = (Open->OpenStatus == OpenDetached
					? STATUS_DEVICE_REMOVED
					: STATUS_CANCELLED);
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
		NPF_StopUsingOpenInstance(Open, OpenRunning);
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
	// These we can check without bothering with the filter module:
	if (IrpSp->Parameters.Write.Length == 0 || 	// Check that the buffer provided by the user is not empty
		Irp->MdlAddress == NULL)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Write parameters empty. Send aborted");

		NPF_StopUsingOpenInstance(Open, OpenRunning);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}

	// 
	// Increment the ref counter of the binding handle, if possible
	//
	if (!Open->pFiltMod)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Adapter is probably unbinding, cannot send packets");

		NPF_StopUsingOpenInstance(Open, OpenRunning);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	// Now that we have a handle to the filter module, validate specifics:
	if (Open->pFiltMod->MaxFrameSize == 0 ||	// Check that the MaxFrameSize is correctly initialized
		IrpSp->Parameters.Write.Length > Open->pFiltMod->MaxFrameSize) // Check that the fame size is smaller that the MTU
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Frame size out of range, or maxFrameSize = 0. Send aborted");

		NPF_StopUsingOpenInstance(Open, OpenRunning);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();

		return STATUS_UNSUCCESSFUL;
	}

	NdisAcquireSpinLock(&Open->WriteLock);
	if (Open->WriteInProgress)
	{
		// Another write operation is currently in progress
		NdisReleaseSpinLock(&Open->WriteLock);

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Another Send operation is in progress, aborting.");

		NPF_StopUsingOpenInstance(Open, OpenRunning);

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_DEVICE_BUSY;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		TRACE_EXIT();

		return STATUS_DEVICE_BUSY;
	}
	else
	{
		Open->WriteInProgress = TRUE;
		NdisResetEvent(&Open->NdisWriteCompleteEvent);
	}

	NdisReleaseSpinLock(&Open->WriteLock);

	TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
		"Max frame size = %u, packet size = %u",
		Open->pFiltMod->MaxFrameSize,
		IrpSp->Parameters.Write.Length);

	// WinPcap emulation: loop back injected packets if anyone's listening.
	// Except when NPF_DISABLE_LOOPBACK is chosen, then don't loop back.
	if (!Open->SkipSentPackets)
	{
		SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;
	}

	//
	// reset the number of packets pending the SendComplete
	//
	Open->TransmitPendingPackets = 0;

	NdisResetEvent(&Open->WriteEvent);

	numSentPackets = 0;

	while (numSentPackets < NumSends)
	{
		/* Unlike NPF_BufferedWrite, we can directly allocate NBLs
		 * using the MDL in the IRP because the device was created with
		 * DO_DIRECT_IO. */
		pNetBufferList = NdisAllocateNetBufferAndNetBufferList(Open->pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
			0,
			Irp->MdlAddress,
			0,
			Irp->MdlAddress->ByteCount);

		if (pNetBufferList != NULL)
		{
			//
			// packet is available, prepare it and send it with NdisSend.
			//

			// The packet hasn't a buffer that needs not to be freed after every single write
			RESERVED(pNetBufferList)->FreeBufAfterWrite = FALSE;

			// Attach the writes buffer to the packet

			ASSERT(Open->pFiltMod != NULL);

			InterlockedIncrement(&Open->TransmitPendingPackets);

			NdisResetEvent(&Open->NdisWriteCompleteEvent);

			//receive the packets before sending them

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			// Do not capture the send traffic we send, if this is our loopback adapter.
			if (Open->pFiltMod->Loopback == FALSE)
			{
#endif
				NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, FALSE);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			}
#endif

			pNetBufferList->SourceHandle = Open->pFiltMod->AdapterHandle;
			RESERVED(pNetBufferList)->ChildOpen = Open; //save the child open object in the packets

			// Recognize IEEE802.1Q tagged packet, as no many adapters support VLAN tag packet sending, no much use for end users,
			// and this code examines the data which lacks efficiency, so I left it commented, the sending part is also unfinished.
			// This code refers to Win10Pcap at https://github.com/SoftEtherVPN/Win10Pcap.
// 			if (Open->pFiltMod->Loopback == FALSE)
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
			if (Open->pFiltMod->Loopback == TRUE)
			{
				NPF_LoopbackSendNetBufferLists(Open->pFiltMod,
					pNetBufferList);
			}
			else
#endif
#ifdef HAVE_RX_SUPPORT
				if (Open->pFiltMod->SendToRxPath == TRUE)
				{
					IF_LOUD(DbgPrint("NPF_Write::SendToRxPath, Open->pFiltMod->AdapterHandle=%p, pNetBufferList=%p\n", Open->pFiltMod->AdapterHandle, pNetBufferList);)
					// pretend to receive these packets from network and indicate them to upper layers
					NdisFIndicateReceiveNetBufferLists(
						Open->pFiltMod->AdapterHandle,
						pNetBufferList,
						NDIS_DEFAULT_PORT_NUMBER,
						1,
						NDIS_RECEIVE_FLAGS_RESOURCES);
				}
				else
#endif
				{
					NdisFSendNetBufferLists(Open->pFiltMod->AdapterHandle,
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
	if (Open->pFiltMod->SendToRxPath && pNetBufferList)
	{
		NPF_FreePackets(pNetBufferList);
	}
	else
#endif
		NdisWaitEvent(&Open->NdisWriteCompleteEvent, 0);

	//
	// no more writes are in progress
	//
	NdisAcquireSpinLock(&Open->WriteLock);
	Open->WriteInProgress = FALSE;
	NdisReleaseSpinLock(&Open->WriteLock);

	NPF_StopUsingOpenInstance(Open, OpenRunning);

	//
	// Complete the Irp and return success
	//
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = numSentPackets > 0 ? IrpSp->Parameters.Write.Length : 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

	return Status;
}

//-------------------------------------------------------------------

/*!
  \brief Waits the completion of all the sends performed by NPF_BufferedWrite.
  \param Open Pointer to open context structure.

  This function is used by NPF_BufferedWrite to wait the completion of
  all the sends before returning the control to the user.
*/
VOID
NPF_WaitEndOfBufferedWrite(
	_In_ POPEN_INSTANCE Open
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

_Use_decl_annotations_
INT
NPF_BufferedWrite(
	PIRP Irp,
	PCHAR UserBuff,
	ULONG UserBuffSize,
	BOOLEAN Sync)
{
	POPEN_INSTANCE			Open;
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
	PVOID npBuff = NULL;

	TRACE_ENTER();

	IF_LOUD(DbgPrint("NPF: BufferedWrite, UserBuff=%p, Size=%u\n", UserBuff, UserBuffSize);)

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	Open = (POPEN_INSTANCE) IrpSp->FileObject->FsContext;
	if (!NPF_IsOpenInstance(Open))
	{
		TRACE_EXIT();
		return -STATUS_INVALID_HANDLE;
	}

	if (!Open->pFiltMod)
	{
		// The Network adapter was removed. 
		TRACE_EXIT();
		return -STATUS_DEVICE_DOES_NOT_EXIST;
	}

	// Sanity check on the user buffer
	if (UserBuff == NULL)
	{
		TRACE_EXIT();
		return -STATUS_INVALID_PARAMETER;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->pFiltMod->MaxFrameSize == 0)
	{
		IF_LOUD(DbgPrint("NPF_BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");)

		TRACE_EXIT();
		return -STATUS_UNSUCCESSFUL;
	}

	// WinPcap emulation: loop back injected packets if anyone's listening.
	// Except when NPF_DISABLE_LOOPBACK is chosen, then don't loop back.
	if (!Open->SkipSentPackets)
	{
		SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;
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

			result = -STATUS_INVALID_PARAMETER;
			break;
		}

		pWinpcapHdr = (struct sf_pkthdr *)(UserBuff + Pos);

		if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->pFiltMod->MaxFrameSize)
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			result = -STATUS_INVALID_PARAMETER;
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

			result = -STATUS_INVALID_PARAMETER;
			break;
		}

		/* Copy packet data to non-paged memory, otherwise we induce
		 * page faults in NIC drivers: http://issues.nmap.org/1398
		 * Alternately, we could possibly use Direct I/O for the BIOCSENDPACKETS IoCtl? */
		npBuff = ExAllocatePoolWithTag(NonPagedPool, pWinpcapHdr->caplen, 'WBPN');
		if (npBuff == NULL)
		{
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate non-paged buffer.\n");)
			result = -STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlCopyMemory(npBuff, UserBuff + Pos, pWinpcapHdr->caplen);

		// Allocate an MDL to map the packet data
		TmpMdl = NdisAllocateMdl(Open->pFiltMod, npBuff, pWinpcapHdr->caplen);

		if (TmpMdl == NULL)
		{
			// Unable to map the memory: packet lost
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate the MDL.\n");)

			result = -STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		MmBuildMdlForNonPagedPool(TmpMdl);

		Pos += pWinpcapHdr->caplen;

		// Allocate a packet from our free list
		pNetBufferList = NdisAllocateNetBufferAndNetBufferList(
			Open->pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
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
				Open->pFiltMod->PacketPool,
				sizeof(PACKET_RESERVED),
				0,
				TmpMdl,
				0,
				pWinpcapHdr->caplen);

			if (pNetBufferList == NULL)
			{
				// Second failure, report an error
				NdisFreeMdl(TmpMdl);

				result = -STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
		}

		// The packet has a buffer that needs to be freed after every single write
		RESERVED(pNetBufferList)->FreeBufAfterWrite = TRUE;

		TmpMdl->Next = NULL;

		ASSERT(Open->pFiltMod != NULL);

		// Increment the number of pending sends
		InterlockedIncrement(&Open->Multiple_Write_Counter);

		//receive the packets before sending them
		// TODO: Should we check for loopback like we do in NPF_Write?
		NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, FALSE);

		pNetBufferList->SourceHandle = Open->pFiltMod->AdapterHandle;
		RESERVED(pNetBufferList)->ChildOpen = Open; //save the child open object in the packets

		//
		// Call the MAC
		//
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (Open->pFiltMod->Loopback == TRUE)
		{
			NPF_LoopbackSendNetBufferLists(Open->pFiltMod,
				pNetBufferList);
		}
		else
#endif
#ifdef HAVE_RX_SUPPORT
			if (Open->pFiltMod->SendToRxPath == TRUE)
			{
				IF_LOUD(DbgPrint("NPF_BufferedWrite::SendToRxPath, Open->pFiltMod->AdapterHandle=%p, pNetBufferList=%p\n", Open->pFiltMod->AdapterHandle, pNetBufferList);)
				// pretend to receive these packets from network and indicate them to upper layers
				NdisFIndicateReceiveNetBufferLists(
					Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					1,
					NDIS_RECEIVE_FLAGS_RESOURCES);
			}
			else
#endif
			{
				NdisFSendNetBufferLists(Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					SendFlags);
			}

		// We've sent the packet, so leave it up to SendComplete to free the buffer
		npBuff = NULL;

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

				result = -STATUS_INVALID_PARAMETER;
				break;
			}

			pWinpcapHdr = (struct sf_pkthdr *)(UserBuff + Pos);

			if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->pFiltMod->MaxFrameSize || pWinpcapHdr->caplen > (UserBuffSize - Pos - sizeof(*pWinpcapHdr)))
			{
				// Malformed header
				IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

				result = -STATUS_INVALID_PARAMETER;
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
	
	// Cleanup
	if (npBuff != NULL) {
		ExFreePoolWithTag(npBuff, 'WBPN');
	}

	// Wait the completion of pending sends
#ifdef HAVE_RX_SUPPORT
	if (Open->pFiltMod->SendToRxPath && pNetBufferList)
	{
		NPF_FreePackets(pNetBufferList);
	}
	else
#endif
		NPF_WaitEndOfBufferedWrite(Open);

	TRACE_EXIT();
	return result;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
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
	PVOID npBuff;

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
			npBuff = MmGetSystemAddressForMdlSafe(pMdl, LowPagePriority|MdlMappingNoExecute);
			if (npBuff != NULL) {
				ExFreePoolWithTag(npBuff, 'WBPN');
			}
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
	PSINGLE_LIST_ENTRY Curr;
	POPEN_INSTANCE		TempOpen;
	LOCK_STATE_EX lockState;
	BOOLEAN				FreeBufAfterWrite;
	PNET_BUFFER_LIST    pNetBufList;
	PNET_BUFFER_LIST    pNextNetBufList;
	PNET_BUFFER         Currbuff;
	PMDL                pMdl;
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

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

		if (pNetBufList->SourceHandle == pFiltMod->AdapterHandle) //this is our self-sent packets
		{
			ChildOpen = RESERVED(pNetBufList)->ChildOpen; //get the child open object that sends these packets
			FreeBufAfterWrite = RESERVED(pNetBufList)->FreeBufAfterWrite;

			NPF_FreePackets(pNetBufList);

			/* Lock the group */
			NdisAcquireRWLockRead(pFiltMod->OpenInstancesLock, &lockState, 0);

			for (Curr = pFiltMod->OpenInstances.Next; Curr != NULL; Curr = Curr->Next)
			{
				TempOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
				if (ChildOpen == TempOpen) //only indicate the specific child open object
				{
					NPF_SendCompleteExForEachOpen(TempOpen, FreeBufAfterWrite);
					break;
				}

			}
			/* Release the spin lock no matter what. */
			NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);
		}
		else
		{
			// Send complete the NBLs.  If you removed any NBLs from the chain, make
			// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
			NdisFSendNetBufferListsComplete(pFiltMod->AdapterHandle, pNetBufList, SendCompleteFlags);
		}

		pNetBufList = pNextNetBufList;
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_SendCompleteExForEachOpen(
	POPEN_INSTANCE Open,
	BOOLEAN FreeBufAfterWrite
	)
{
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

	NdisReleaseSpinLock(&Open->OpenInUseLock);
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
_Use_decl_annotations_
VOID
NPF_LoopbackSendNetBufferLists(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferList
	)
{
	TRACE_ENTER();

	// Use Winsock Kernel to send this NBL.
	NPF_WSKSendPacket_NBL(NetBufferList);

	// Call complete function manually just like NDIS callback.
	NPF_SendCompleteEx(FilterModuleContext, NetBufferList, 0);

	TRACE_EXIT();
}
#endif
