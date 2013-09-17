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
	PNET_BUFFER_LIST	pNetBufferList;
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
	if (NPF_StartUsingBinding(Open) == FALSE)
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

		NPF_StopUsingBinding(Open);

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

			InterlockedIncrement(&Open->TransmitPendingPackets);

			NdisResetEvent(&Open->NdisWriteCompleteEvent);

			//receive the packets before sending them
			ASSERT(Open->GroupHead != NULL);
			if (Open->GroupHead != NULL)
			{
				GroupOpen = Open->GroupHead->GroupNext;
			}
			else
			{
				//this is impossible
				GroupOpen = Open->GroupNext;
			}

			while (GroupOpen != NULL)
			{
				TempOpen = GroupOpen;
				if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
				{
					NPF_TapExForEachOpen(TempOpen, pNetBufferList);
				}

				GroupOpen = TempOpen->GroupNext;
			}

			pNetBufferList->SourceHandle = Open->AdapterHandle;
			NPFSetNBLChildOpen(pNetBufferList, Open); //save the child open object in the packets
			//SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;

			//
			//  Call the MAC
			//
			NdisFSendNetBufferLists(Open->AdapterHandle,
				pNetBufferList,
				NDIS_DEFAULT_PORT_NUMBER,
				SendFlags);

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
	NdisWaitEvent(&Open->NdisWriteCompleteEvent, 0);

	//
	// all the packets have been transmitted, release the use of the adapter binding
	//
	NPF_StopUsingBinding(Open);

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
	PNET_BUFFER_LIST		pNetBufferList;
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

	if (NPF_StartUsingBinding(Open) == FALSE)
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
		NPF_StopUsingBinding(Open);
		TRACE_EXIT();
		return 0;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->MaxFrameSize == 0)
	{
		IF_LOUD(DbgPrint("BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");)

		// 
		// release ownership of the NdisAdapter binding
		//
		NPF_StopUsingBinding(Open);
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

		// Increment the number of pending sends
		InterlockedIncrement(&Open->Multiple_Write_Counter);

		//receive the packets before sending them
		ASSERT(Open->GroupHead != NULL);
		if (Open->GroupHead != NULL)
		{
			GroupOpen = Open->GroupHead->GroupNext;
		}
		else
		{
			GroupOpen = Open->GroupNext;
		}
		
		GroupOpen = Open->GroupNext;
		while (GroupOpen != NULL)
		{
			TempOpen = GroupOpen;
			if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
			{
				NPF_TapExForEachOpen(TempOpen, pNetBufferList);
			}

			GroupOpen = TempOpen->GroupNext;
		}

		pNetBufferList->SourceHandle = Open->AdapterHandle;
		NPFSetNBLChildOpen(pNetBufferList, Open); //save the child open object in the packets
		//SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;

		//
		// Call the MAC
		//
		NdisFSendNetBufferLists(Open->AdapterHandle, pNetBufferList, NDIS_DEFAULT_PORT_NUMBER, SendFlags);

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
	NPF_WaitEndOfBufferedWrite(Open);

	// 
	// release ownership of the NdisAdapter binding
	//
	NPF_StopUsingBinding(Open);

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
	PNET_BUFFER_LIST    CurrNbl,nextNbl= NULL;
	PNET_BUFFER         Currbuff;
	PMDL                pMdl;
	int					Count = 0;

	POPEN_INSTANCE     Open = (POPEN_INSTANCE) FilterModuleContext;

	TRACE_ENTER();

	//
	// If your filter injected any send packets into the datapath to be sent,
	// you must identify their NBLs here and remove them from the chain.  Do not
	// attempt to send-complete your NBLs up to the higher layer.
	//

	pNetBufList = NetBufferLists;

	while (pNetBufList != NULL)
	{
		Count ++;
		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);
		NET_BUFFER_LIST_NEXT_NBL(pNetBufList) = NULL;

		if (pNetBufList->SourceHandle == Open->AdapterHandle) //this is our self-sent packets
		{
			ChildOpen = NPFGetNBLChildOpen(pNetBufList); //get the child open object that sends these packets
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

			GroupOpen = Open->GroupNext;
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
		}
		else
		{
			// Send complete the NBLs.  If you removed any NBLs from the chain, make
			// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
			NdisFSendNetBufferListsComplete(Open->AdapterHandle, pNetBufList, SendCompleteFlags);
		}

		pNetBufList = pNextNetBufList;
	}

//////////// this is another SendComplete handling method, view the buffer lists as a whole
// 	if (NetBufferLists->SourceHandle != NULL && NetBufferLists->SourceHandle == Open->AdapterHandle)
// 	{
// 		ChildOpen = NPFGetNBLChildOpen(NetBufferLists);
// 		FreeBufAfterWrite = RESERVED(NetBufferLists)->FreeBufAfterWrite;
// 
// 		if (FreeBufAfterWrite)
// 		{
// 			//
// 			// Packet sent by NPF_BufferedWrite()
// 			//
// 
// 			//Free all the NBLs allocate by myself
// 			CurrNbl = NetBufferLists;
// 			while (CurrNbl)
// 			{
// 				Currbuff = NET_BUFFER_LIST_FIRST_NB(CurrNbl);
// 				while (Currbuff)
// 				{
// 					pMdl = NET_BUFFER_FIRST_MDL(Currbuff);
// 					NdisFreeMdl(pMdl); //Free MDL
// 					Currbuff = NET_BUFFER_NEXT_NB(Currbuff);
// 				}
// 				nextNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl); //get Next MBL
// 				NdisFreeNetBufferList(CurrNbl); //Free CurrentNBL
// 				CurrNbl = nextNbl;
// 			}
// 		}
// 		else
// 		{
// 			//
// 			// Packet sent by NPF_Write()
// 			//
// 
// 			//Free all the NBLs allocate by myself
// 			CurrNbl = NetBufferLists;
// 			while (CurrNbl)
// 			{
// 				nextNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl); //get Next MBL
// 				NdisFreeNetBufferList(CurrNbl); //Free CurrentNBL
// 				CurrNbl = nextNbl;
// 			}
// 		}
// 
// 		GroupOpen = Open->GroupNext;
// 		while (GroupOpen != NULL)
// 		{
// 			TempOpen = GroupOpen;
// 			if (ChildOpen == TempOpen)
// 			{
// 				NPF_SendCompleteExForEachOpen(TempOpen, FreeBufAfterWrite);
// 				break;
// 			}
// 
// 			GroupOpen = TempOpen->GroupNext;
// 		}
// 	}
// 	else
// 	{
// 		// Send complete the NBLs.  If you removed any NBLs from the chain, make
// 		// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
// 		NdisFSendNetBufferListsComplete(Open->AdapterHandle, NetBufferLists, SendCompleteFlags);
// 	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

VOID
NPF_SendCompleteExForEachOpen(
	IN POPEN_INSTANCE Open,
	IN BOOLEAN FreeBufAfterWrite
	)
{
	//TRACE_ENTER();

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

}