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
#include <fwpsk.h>

extern ULONG g_DltNullMode;
extern HANDLE g_InjectionHandle_IPv4;
extern HANDLE g_InjectionHandle_IPv6;

/*!
  \brief Ends a send operation.
  \param pFiltMod Pointer to filter module context structure
  \param FreeBufAfterWrite Whether the buffer should be freed.

  Callback function associated with the NdisFSend() NDIS function. It is invoked by NPF_SendCompleteEx() when the NIC
  driver has finished an OID request operation that was previously started by NPF_Write().
*/
_IRQL_requires_min_(DISPATCH_LEVEL)
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
NTSTATUS
NPF_LoopbackSendNetBufferLists(
	_In_ NDIS_HANDLE FilterModuleContext,
	_In_ __drv_aliasesMem PNET_BUFFER_LIST NetBufferList
	);

#endif

inline
__drv_allocatesMem(mem)
PVOID
#pragma warning(suppress: 28195) // We aren't really allocating it here, but we know that it was allocated in some other un-annotated function.
NPF_AnalysisAssumeAllocated(_In_ PVOID *p)
{
	return *p;
}

NTSTATUS
_At_(*ppNBL, __drv_allocatesMem(mem))
NPF_AllocateNBL(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ __drv_aliasesMem PMDL pMdl,
	_In_ SIZE_T uDataLen,
	_Outptr_result_nullonfailure_ PNET_BUFFER_LIST *ppNBL
       )
{
	NTSTATUS Status = STATUS_SUCCESS;
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (pFiltMod->Loopback)
	{
		Status = FwpsAllocateNetBufferAndNetBufferList(pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
			0,
			pMdl,
			0,
			uDataLen,
			ppNBL);
		if (NT_SUCCESS(Status) && *ppNBL)
		{
			// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
			// FwpsAllocateNetBufferAndNetBufferList do not use __drv_aliasesMem for the 4th parameter,
			// even though it is just a wrapper for NdisAllocateNetBufferAndNetBufferList, which does alias the MDL.
			NPF_AnalysisAssumeAliased(pMdl);
			// WORKAROUND: FwpsAllocateNetBufferAndNetBufferList also does not have annotations for
			// allocating the NBL. This fake function will suppress the warning about it.
			*ppNBL = NPF_AnalysisAssumeAllocated(ppNBL);
		}
		else
		{
			// Can't indicate success if it didn't actually succeed.
			Status = NT_SUCCESS(Status) ? STATUS_INSUFFICIENT_RESOURCES : Status;
			*ppNBL = NULL;
		}
	}
	else
#endif
	{
		*ppNBL = NdisAllocateNetBufferAndNetBufferList(pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
			0,
			pMdl,
			0,
			uDataLen);
		Status = *ppNBL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
	}
	return Status;
}
//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_Write(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE		Open;
	ULONG				SendFlags = 0;
	PNET_BUFFER_LIST	pNetBufferList = NULL;
	ULONG				NumSends;
	ULONG numSentPackets = 0;
	ULONG buflen = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	TRACE_ENTER();

	/* Validate */
	Status = NPF_ValidateIoIrp(Irp, &Open);
	if (Status != STATUS_SUCCESS)
	{
		goto NPF_Write_End;
	}

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN))
	{
		// Write requires an attached adapter.
		Status = (Open->OpenStatus == OpenDetached
					? STATUS_DEVICE_REMOVED
					: STATUS_CANCELLED);
		goto NPF_Write_End;
	}

	NumSends = Open->Nwrites;
	if (NumSends == 0)
	{
		Status = STATUS_SUCCESS;
		NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);
		goto NPF_Write_End;
	}

	// Failures after this point must call NPF_StopUsingOpenInstance
	do
	{
		buflen = MmGetMdlByteCount(Irp->MdlAddress);
		if (buflen == 0)
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Check that the MaxFrameSize is correctly initialized
		if (Open->pFiltMod->MaxFrameSize == 0)
		{
			// TODO: better status code
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Check that the frame size is smaller than the MTU
		if (buflen > Open->pFiltMod->MaxFrameSize)
		{
			// TODO: better status code
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (InterlockedExchange(&Open->WriteInProgress, 1) == 1)
		{
			// Another write operation is currently in progress

			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Another Send operation is in progress, aborting.");

			NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);

			Status = STATUS_DEVICE_BUSY;
			break;
		}


	} while (FALSE);

	if (Status != STATUS_SUCCESS)
	{
		NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);
		goto NPF_Write_End;
	}

	TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
		"Max frame size = %u, packet size = %u",
		Open->pFiltMod->MaxFrameSize,
		buflen);

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
		Status = NPF_AllocateNBL(Open->pFiltMod,
				Irp->MdlAddress,
				buflen,
				&pNetBufferList);

		if (NT_SUCCESS(Status) && NT_VERIFY(pNetBufferList != NULL))
		{
			//
			// packet is available, prepare it and send it with NdisSend.
			//

			// The packet hasn't a buffer that needs not to be freed after every single write
			RESERVED(pNetBufferList)->FreeBufAfterWrite = FALSE;

			// Attach the writes buffer to the packet

			NT_ASSERT(Open->pFiltMod != NULL);

			NpfInterlockedIncrement(&(LONG)Open->TransmitPendingPackets);

			NdisResetEvent(&Open->NdisWriteCompleteEvent);

			//receive the packets before sending them

			// Used to avoid capturing loopback injected traffic here because it's captured later, but now I do it here and avoid capturing it later.
			NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, NPF_IRQL_UNKNOWN);

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
				Status = NPF_LoopbackSendNetBufferLists(Open->pFiltMod,
					pNetBufferList);
				if (!NT_SUCCESS(Status))
				{
					// Couldn't send this one. Don't wait for it!
					NpfInterlockedDecrement(&(LONG)Open->TransmitPendingPackets);
					NPF_FreePackets(pNetBufferList);
					break;
				}
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
						0); // If NDIS_RECEIVE_FLAGS_RESOURCES, would need to free pNetBufferList after this.
					// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
					// NdisFIndicateReceiveNetBufferLists do not use __drv_aliasesMem for the 2nd parameter.
					// When Flags (5th parameter) do *not* have NDIS_RECEIVE_FLAGS_RESOURCES set, the NBL is
					// owned by NDIS until it is returned via NPF_ReturnEx (FilterReturnNetBufferLists handler)
					// Therefore we must not free it, and it is not leaking here.
					NPF_AnalysisAssumeAliased(pNetBufferList);
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
	
	if (
#ifdef HAVE_RX_SUPPORT
		// SendToRxPath receive indications do not block or set an event when they are done.
		// Maybe they should, or maybe Send indications should not.
		// Either way, need to avoid waiting for something that won't happen.
		!Open->pFiltMod->SendToRxPath &&
#endif
		NT_SUCCESS(Status))
	{
		// TODO: Don't wait forever? Some sort of error would be good.
		NdisWaitEvent(&Open->NdisWriteCompleteEvent, 0);
	}

	//
	// no more writes are in progress
	//
	InterlockedExchange(&Open->WriteInProgress, 0);

	NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);

NPF_Write_End:
	//
	// Complete the Irp and return success
	//
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = numSentPackets > 0 ? MmGetMdlByteOffset(Irp->MdlAddress) : 0;
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
_IRQL_requires_(PASSIVE_LEVEL)
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
NTSTATUS NPF_BufferedWrite(
	POPEN_INSTANCE Open,
	PUCHAR UserBuff,
	ULONG UserBuffSize,
	BOOLEAN Sync,
	PULONG_PTR Written)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PNET_BUFFER_LIST		pNetBufferList = NULL;
	ULONG					SendFlags = 0;
	UINT					i;
	LARGE_INTEGER			StartTicks = { 0 }, CurTicks, TargetTicks;
	LARGE_INTEGER			TimeFreq;
	struct timeval			BufStartTime = { 0 };
	struct dump_bpf_hdr* pWinpcapHdr = NULL;
	PMDL					TmpMdl;
	ULONG					Pos = 0;
	//	PCHAR				CurPos;
	//	PCHAR				EndOfUserBuff = UserBuff + UserBuffSize;
	PVOID npBuff = NULL;
	NDIS_EVENT Event;

	TRACE_ENTER();

	IF_LOUD(DbgPrint("NPF: BufferedWrite, UserBuff=%p, Size=%u\n", UserBuff, UserBuffSize);)

	*Written = 0;

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN))
	{
		TRACE_EXIT();
		return STATUS_CANCELLED;
	}

	if (InterlockedExchange(&Open->WriteInProgress, 1) == 1)
	{
		//
		// Another write operation is currently in progress
		//
		NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);
		TRACE_EXIT();
		return STATUS_DEVICE_BUSY;
	}

	// Sanity check on the user buffer
	if (!NT_VERIFY(UserBuff != NULL))
	{
		Status = STATUS_INVALID_PARAMETER;
		goto NPF_BufferedWrite_End;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->pFiltMod->MaxFrameSize == 0)
	{
		IF_LOUD(DbgPrint("NPF_BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");)
		Status = STATUS_UNSUCCESSFUL;
		goto NPF_BufferedWrite_End;
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

	if (Sync)
	{
		// Initialize event used for synchronization
		NdisInitializeEvent(&Event);
		NdisResetEvent(&Event);
	}

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
			break;
		}

		if (UserBuffSize - Pos < sizeof(*pWinpcapHdr))
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		pWinpcapHdr = (struct dump_bpf_hdr *)(UserBuff + Pos);

		if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->pFiltMod->MaxFrameSize)
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

			Status = STATUS_INVALID_PARAMETER;
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

			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		/* Copy packet data to non-paged memory, otherwise we induce
		 * page faults in NIC drivers: http://issues.nmap.org/1398
		 * Alternately, we could possibly use Direct I/O for the BIOCSENDPACKETS IoCtl? */
		npBuff = ExAllocatePoolWithTag(NPF_NONPAGED, pWinpcapHdr->caplen, NPF_BUFFERED_WRITE_TAG);
		if (npBuff == NULL)
		{
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate non-paged buffer.\n");)
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlCopyMemory(npBuff, UserBuff + Pos, pWinpcapHdr->caplen);

		// Allocate an MDL to map the packet data
		TmpMdl = NdisAllocateMdl(Open->pFiltMod->AdapterHandle, npBuff, pWinpcapHdr->caplen);

		if (TmpMdl == NULL)
		{
			// Unable to map the memory: packet lost
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate the MDL.\n");)

			ExFreePoolWithTag(npBuff, NPF_BUFFERED_WRITE_TAG);

			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the buffer address
		// is stored in the MDL and we retrieve it (via NdisQueryMdl) in NPF_FreePackets called from NPF_ReturnEx.
		// Therefore, it is not leaking after this point.
		NPF_AnalysisAssumeAliased(npBuff);

		Pos += pWinpcapHdr->caplen;

		// Allocate a packet from our free list
		Status = NPF_AllocateNBL(Open->pFiltMod,
				TmpMdl,
				pWinpcapHdr->caplen,
				&pNetBufferList);
		if (!NT_SUCCESS(Status))
		{
			//  No more free packets
			
			NdisResetEvent(&Open->WriteEvent);

			NdisWaitEvent(&Open->WriteEvent, 1000);  

			// Try again to allocate a packet
			Status = NPF_AllocateNBL(Open->pFiltMod,
					TmpMdl,
					pWinpcapHdr->caplen,
					&pNetBufferList);

			if (!NT_SUCCESS(Status))
			{
				// Second failure, report an error
				IF_LOUD(DbgPrint("NPF_BufferedWrite: no more free packets, returning.\n");)

				NdisFreeMdl(TmpMdl);
				ExFreePoolWithTag(npBuff, NPF_BUFFERED_WRITE_TAG);

				// TODO: Should we reset Pos here? Is it the
				// amount sent or the place where we found a problem?
				break;
			}
		}
		NT_ASSERT(pNetBufferList != NULL);

		// The packet has a buffer that needs to be freed after every single write
		RESERVED(pNetBufferList)->FreeBufAfterWrite = TRUE;

		TmpMdl->Next = NULL;

		NT_ASSERT(Open->pFiltMod != NULL);

		// Increment the number of pending sends
		NpfInterlockedIncrement(&(LONG)Open->Multiple_Write_Counter);

		//receive the packets before sending them
		NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, NPF_IRQL_UNKNOWN);

		pNetBufferList->SourceHandle = Open->pFiltMod->AdapterHandle;
		RESERVED(pNetBufferList)->ChildOpen = Open; //save the child open object in the packets

		//
		// Call the MAC
		//
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (Open->pFiltMod->Loopback == TRUE)
		{
			Status = NPF_LoopbackSendNetBufferLists(Open->pFiltMod,
				pNetBufferList);
			if (!NT_SUCCESS(Status))
			{
				NpfInterlockedDecrement(&(LONG)Open->Multiple_Write_Counter);
				NPF_FreePackets(pNetBufferList);
				break;
			}
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
					0); // If NDIS_RECEIVE_FLAGS_RESOURCES, would need to free pNetBufferList after this.
				// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
				// NdisFIndicateReceiveNetBufferLists do not use __drv_aliasesMem for the 2nd parameter.
				// When Flags (5th parameter) do *not* have NDIS_RECEIVE_FLAGS_RESOURCES set, the NBL is
				// owned by NDIS until it is returned via NPF_ReturnEx (FilterReturnNetBufferLists handler)
				// Therefore we must not free it, and it is not leaking here.
				NPF_AnalysisAssumeAliased(pNetBufferList);
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
				break;
			}

			if ((UserBuffSize - Pos) < sizeof(*pWinpcapHdr))
			{
				// Malformed header
				IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			pWinpcapHdr = (struct dump_bpf_hdr *)(UserBuff + Pos);

			if (pWinpcapHdr->caplen == 0 || pWinpcapHdr->caplen > Open->pFiltMod->MaxFrameSize || pWinpcapHdr->caplen > (UserBuffSize - Pos - sizeof(*pWinpcapHdr)))
			{
				// Malformed header
				IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)

				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			// Release the application if it has been blocked for approximately more than 1 seconds
			if (pWinpcapHdr->ts.tv_sec - BufStartTime.tv_sec > 1)
			{
				IF_LOUD(DbgPrint("NPF_BufferedWrite: timestamp elapsed, returning.\n");)

				break;
			}

			// Calculate the time interval to wait before sending the next packet
			TargetTicks.QuadPart = StartTicks.QuadPart +
				((LONGLONG)pWinpcapHdr->ts.tv_sec - BufStartTime.tv_sec) * TimeFreq.QuadPart +
				((LONGLONG)pWinpcapHdr->ts.tv_usec - BufStartTime.tv_usec) * (TimeFreq.QuadPart) / 1000000;

			// Wait until the time interval has elapsed
			while (CurTicks.QuadPart < TargetTicks.QuadPart)
			{
				// whole milliseconds remaining.
				// Explicit cast ok since condition above ensures this will be at most 1000ms.
				i = (UINT)(((TargetTicks.QuadPart - CurTicks.QuadPart) * 1000) / TimeFreq.QuadPart);
				if (i >= 1)
				{
					// Sleep with millisecond resolution.
					NdisWaitEvent(&Event, i);
				}
				// else perform a busy wait.
				CurTicks = KeQueryPerformanceCounter(NULL);
			}
		}
	}

	// Wait the completion of pending sends
#ifdef HAVE_RX_SUPPORT
	// SendToRxPath receive indications do not block or set an event when they are done.
	// Maybe they should, or maybe Send indications should not.
	// Either way, need to avoid waiting for something that won't happen.
	if (!Open->pFiltMod->SendToRxPath)
#endif
		NPF_WaitEndOfBufferedWrite(Open);

	*Written = Pos;

NPF_BufferedWrite_End:
	InterlockedExchange(&Open->WriteInProgress, 0);
	NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);

	TRACE_EXIT();
	return Status;
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
	POPEN_INSTANCE pOpen = NULL;
	PNET_BUFFER         Currbuff;
	PMDL                pMdl;
	PVOID npBuff;

/*	TRACE_ENTER();*/

	FreeBufAfterWrite = RESERVED(pNetBufList)->FreeBufAfterWrite;
	pOpen = RESERVED(pNetBufList)->ChildOpen;

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
			npBuff = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority|MdlMappingNoExecute);
			if (npBuff != NULL) {
				ExFreePoolWithTag(npBuff, NPF_BUFFERED_WRITE_TAG);
			}
			NdisFreeMdl(pMdl); //Free MDL
			Currbuff = NET_BUFFER_NEXT_NB(Currbuff);
		}
	}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (pOpen && pOpen->pFiltMod && pOpen->pFiltMod->Loopback)
	{
		FwpsFreeNetBufferList(pNetBufList);
	}
	else
#endif
	{
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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

	TRACE_ENTER();
	/* This callback is used for NDIS LWF as well as WFP/loopback */

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
			NdisAcquireRWLockRead(pFiltMod->OpenInstancesLock, &lockState, 
				NDIS_TEST_SEND_COMPLETE_AT_DISPATCH_LEVEL(SendCompleteFlags)
			       	? NDIS_RWL_AT_DISPATCH_LEVEL
			       	: 0);

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

	FILTER_ACQUIRE_LOCK(&Open->OpenInUseLock, TRUE);

	if (FreeBufAfterWrite)
	{
		// Increment the number of pending sends
		NpfInterlockedDecrement(&(LONG)Open->Multiple_Write_Counter);

		NdisSetEvent(&Open->WriteEvent);

		//TRACE_EXIT();
	}
	else
	{
		//
		// Packet sent by NPF_Write()
		//

		ULONG stillPendingPackets = NpfInterlockedDecrement(&(LONG)Open->TransmitPendingPackets);

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

	FILTER_RELEASE_LOCK(&Open->OpenInUseLock, TRUE);
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
void NTAPI NPF_NetworkInjectionComplete(
	_In_ VOID* pContext,
	_Inout_ NET_BUFFER_LIST* pNetBufferList,
	_In_ BOOLEAN dispatchLevel
	)
{
	TRACE_ENTER();

	/* This method should only be used for Loopback (for now, though see #516) */
	NT_ASSERT(((PNPCAP_FILTER_MODULE) pContext)->Loopback);

	if (pNetBufferList->Status != STATUS_SUCCESS)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_NetworkInjectionComplete: pNetBufferList->Status [status: %#x]\n",
			pNetBufferList->Status);
	}

	// Don't need to Retreat the data offset since the completion/free functions ignore CurrentMdl
	// Call complete function manually just like NDIS callback.
	NPF_SendCompleteEx(pContext, pNetBufferList, dispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);

	TRACE_EXIT();
	return;
}

_Use_decl_annotations_
NTSTATUS
NPF_LoopbackSendNetBufferLists(
	NDIS_HANDLE FilterModuleContext,
	PNET_BUFFER_LIST NetBufferList
	)
{
	ULONG bytesAdvanced = 0;
	ULONG BuffSize = 0;
	PETHER_HEADER pEthernetHdr = NULL;
	PDLT_NULL_HEADER pDltNullHdr;
	HANDLE hInjectionHandle = INVALID_HANDLE_VALUE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();

	NdisQueryMdl(
		NET_BUFFER_CURRENT_MDL(NET_BUFFER_LIST_FIRST_NB(NetBufferList)),
		&pEthernetHdr,
		&BuffSize,
		NormalPagePriority);

	if (pEthernetHdr == NULL)
	{
		// allocation failed
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NPF_LoopbackSendNetBufferLists: Failed to query MDL\n");
		TRACE_EXIT();
		return status;
	}

	if (g_DltNullMode)
	{
		pDltNullHdr = (PDLT_NULL_HEADER) pEthernetHdr;
		bytesAdvanced = DLT_NULL_HDR_LEN;
		switch(pDltNullHdr->null_type)
		{
			case DLTNULLTYPE_IP:
				hInjectionHandle = g_InjectionHandle_IPv4;
				break;
			case DLTNULLTYPE_IPV6:
				hInjectionHandle = g_InjectionHandle_IPv6;
				break;
			default:
				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_LoopbackSendNetBufferLists: Invalid DLTNULLTYPE %u\n", pDltNullHdr->null_type);
				status = STATUS_PROTOCOL_NOT_SUPPORTED;
				break;
		}
	}
	else
	{
		bytesAdvanced = ETHER_HDR_LEN;
		switch(RtlUshortByteSwap(pEthernetHdr->ether_type))
		{
			case ETHERTYPE_IP:
				hInjectionHandle = g_InjectionHandle_IPv4;
				break;
			case ETHERTYPE_IPV6:
				hInjectionHandle = g_InjectionHandle_IPv6;
				break;
			default:
				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NPF_LoopbackSendNetBufferLists: Invalid ETHERTYPE %u\n", RtlUshortByteSwap(pEthernetHdr->ether_type));
				status = STATUS_PROTOCOL_NOT_SUPPORTED;
				break;
		}
	}

	if (hInjectionHandle == INVALID_HANDLE_VALUE)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NPF_LoopbackSendNetBufferLists: invalid injection handle");
		TRACE_EXIT();
		return status;
	}

	NdisAdvanceNetBufferListDataStart(NetBufferList, bytesAdvanced, FALSE, NULL);

	status = FwpsInjectNetworkSendAsync(hInjectionHandle,
			NULL,
			0,
			UNSPECIFIED_COMPARTMENT_ID,
			NetBufferList,
			NPF_NetworkInjectionComplete,
			FilterModuleContext);
	if (NT_SUCCESS(status))
	{
		// Fwps* functions don't have annotations about aliasing or freeing memory. Have to do it ourselves.
		NPF_AnalysisAssumeAliased(NetBufferList);
	}

	TRACE_EXIT();
	return status;
}
#endif
