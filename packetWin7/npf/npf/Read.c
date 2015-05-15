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

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "tme.h"
#endif //HAVE_BUGGY_TME_SUPPORT

//-------------------------------------------------------------------

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

	if (NPF_StartUsingBinding(Open) == FALSE)
	{
		NPF_StopUsingOpenInstance(Open);
		// The Network adapter has been removed or diasabled
		EXIT_FAILURE(0);
	}
	NPF_StopUsingBinding(Open);

	if (Open->Size == 0)
	{
		NPF_StopUsingOpenInstance(Open);
		EXIT_FAILURE(0);
	}

	if (Open->mode & MODE_DUMP && Open->DumpFileHandle == NULL)
	{
		// this instance is in dump mode, but the dump file has still not been opened
		NPF_StopUsingOpenInstance(Open);
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
			CurrBuff = (PUCHAR) MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

			if (CurrBuff == NULL)
			{
				NPF_StopUsingOpenInstance(Open);
				EXIT_FAILURE(0);
			}

			if (Open->mode & MODE_DUMP)
			{
				if (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr) + 24)
				{
					NPF_StopUsingOpenInstance(Open);
					Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
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
				EXIT_FAILURE(0);
			}

			if ((!IS_VALIDATED(Open->tme.validated_blocks, Open->tme.active_read)) || (IrpSp->Parameters.Read.Length < sizeof(struct bpf_hdr)))
			{
				NPF_StopUsingOpenInstance(Open);
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
			EXIT_SUCCESS(0);
		}

#else // not HAVE_BUGGY_TME_SUPPORT
		if (Open->mode == MODE_MON)   //this capture instance is in monitor mode
		{
			NPF_StopUsingOpenInstance(Open);
			EXIT_FAILURE(0);
		}
#endif // HAVE_BUGGY_TME_SUPPORT
	}



	//------------------------------------------------------------------------------
	copied = 0;
	count = 0;
	current_cpu = 0;
	available = IrpSp->Parameters.Read.Length;

	packp = (PUCHAR) MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);


	if (packp == NULL)
	{
		NPF_StopUsingOpenInstance(Open);
		EXIT_FAILURE(0);
	}

	if (Open->ReadEvent != NULL)
		KeClearEvent(Open->ReadEvent);

	while (count < g_NCpu) //round robin on the CPUs, if count = NCpu there are no packets left to be copied
	{
		if (available == copied)
		{
			NPF_StopUsingOpenInstance(Open);
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
	POPEN_INSTANCE		GroupOpen;
	POPEN_INSTANCE		TempOpen;
	PVOID i = 0;
	PVOID j = 0;

	TRACE_ENTER();

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
		if (TempOpen->AdapterBindingStatus == ADAPTER_BOUND)
		{
			NPF_TapExForEachOpen(TempOpen, NetBufferLists);
		}

		GroupOpen = TempOpen->GroupNext;
	}

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

	if (Open->GroupHead != NULL)
	{
		//this should be impossible
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

	//return the packets immediately
	NdisFIndicateReceiveNetBufferLists(
		Open->AdapterHandle,
		NetBufferLists,
		PortNumber,
		NumberOfNetBufferLists,
		ReceiveFlags);

	TRACE_EXIT();
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

	PUCHAR					HeaderBuffer;
	UINT					HeaderBufferSize;
	PUCHAR					LookaheadBuffer;
	UINT					LookaheadBufferSize;
	UINT					PacketSize;
	ULONG                   TotalLength;

	PMDL                    pMdl = NULL;
	UINT                    BufferLength;
	PNDISPROT_ETH_HEADER    pEthHeader = NULL;
	PNET_BUFFER_LIST        pNetBufList;
	PNET_BUFFER_LIST        pNextNetBufList;
	ULONG                   Offset;

	//TRACE_ENTER();

	pNetBufList = pNetBufferLists;

	while (pNetBufList != NULL)
	{
		pNextNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);

		Cpu = KeGetCurrentProcessorNumber();
		LocalData = &Open->CpuData[Cpu];

		LocalData->Received++;

		IF_LOUD(DbgPrint("Received on CPU %d \t%d\n", Cpu, LocalData->Received);)

		NdisAcquireSpinLock(&Open->MachineLock);

		//
		// Get first MDL and data length in the list
		//
		pMdl = pNetBufList->FirstNetBuffer->CurrentMdl;
		TotalLength = pNetBufList->FirstNetBuffer->DataLength;
		Offset = pNetBufList->FirstNetBuffer->CurrentMdlOffset;
		BufferLength = 0;

		do
		{
			if (pMdl)
			{
				NdisQueryMdl(
					pMdl,
					&pEthHeader,
					&BufferLength,
					NormalPagePriority);
			}

			if (pEthHeader == NULL)
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
			pEthHeader = (PNDISPROT_ETH_HEADER)((PUCHAR)pEthHeader + Offset);

			// As for single MDL (as we assume) condition, we always have BufferLength == TotalLength
			if (BufferLength > TotalLength)
				BufferLength = TotalLength;

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

			HeaderBuffer = (PUCHAR) pEthHeader;
			HeaderBufferSize = sizeof(NDISPROT_ETH_HEADER);
			LookaheadBuffer = (PUCHAR) pEthHeader + sizeof(NDISPROT_ETH_HEADER);
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
						(PVOID) HeaderBuffer,
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
				goto NPF_TapEx_ForEachOpen_End;
			}

			//if the filter returns -1 the whole packet must be accepted
			if (fres == -1 || fres > PacketSize + HeaderBufferSize)
				fres = PacketSize + HeaderBufferSize; 

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
					goto NPF_TapEx_ForEachOpen_End;
				}
			}

			if (Open->Size == 0)
			{
				LocalData->Dropped++;
				//return NDIS_STATUS_NOT_ACCEPTED;
				goto NPF_TapEx_ForEachOpen_End;
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
					goto NPF_TapEx_ForEachOpen_End;
				}
			}

			//////////////////////////////COPIA.C//////////////////////////////////////////77

			ShouldReleaseBufferLock = TRUE;
			//NdisDprAcquireSpinLock(&LocalData->BufferLock);
			NdisAcquireSpinLock(&LocalData->BufferLock);

			do
			{
				if (fres + sizeof(struct PacketHeader) > LocalData->Free)
				{
					LocalData->Dropped++;
					break;
				}

				if (LocalData->TransferMdl1 != NULL)
				{
					//
					//if TransferMdl is not NULL, there is some TransferData pending (i.e. not having called TransferDataComplete, yet)
					//in order to avoid buffer corruption, we drop the packet
					//
					LocalData->Dropped++;
					break;
				}

				/* always true */
				if (LookaheadBufferSize + HeaderBufferSize >= fres)
				{
					//
					// we do not need to call NdisTransferData, either because we need only the HeaderBuffer, or because the LookaheadBuffer
					// contains what we need
					//

					Header = (struct PacketHeader *)(LocalData->Buffer + LocalData->P);
					LocalData->Accepted++;
					GET_TIME(&Header->header.bh_tstamp, &G_Start_Time);
					Header->SN = InterlockedIncrement(&Open->WriterSN) - 1;

					DbgPrint("MDL %d\n", fres);

					Header->header.bh_caplen = fres;
					Header->header.bh_datalen = PacketSize + HeaderBufferSize;
					Header->header.bh_hdrlen = sizeof(struct bpf_hdr);

					LocalData->P += sizeof(struct PacketHeader);
					if (LocalData->P == Open->Size)
						LocalData->P = 0;

					//
					//we can consider the buffer contiguous, either because we use only the data 
					//present in the HeaderBuffer, or because HeaderBuffer and LookaheadBuffer are contiguous
					// ;-))))))
					//
					if (Open->Size - LocalData->P < fres)
					{
						//the packet will be fragmented in the buffer (aka, it will skip the buffer boundary)
						//two copies!!
						ToCopy = Open->Size - LocalData->P;
						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, ToCopy);
						NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)HeaderBuffer + ToCopy, fres - ToCopy);
						LocalData->P = fres - ToCopy;
					}
					else
					{
						//the packet does not need to be fragmented in the buffer (aka, it doesn't skip the buffer boundary)
						// ;-)))))) only ONE copy
						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, fres);
						LocalData->P += fres;
					}

					increment = fres + sizeof(struct PacketHeader);
					TotalLength -= fres;

					// add next MDLs
					while (TotalLength)
					{
						PMDL pNextMdl = NULL;

						NdisGetNextMdl(pMdl, &pNextMdl);

						if (pNextMdl)
						{
							NdisQueryMdl(
								pNextMdl,
								&pEthHeader,
								&BufferLength,
								NormalPagePriority);
							
							if (BufferLength >= TotalLength)
								BufferLength = TotalLength;
							
							if (Open->Size - LocalData->P >= BufferLength)
							{
								NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, pEthHeader, BufferLength);
								LocalData->P += BufferLength;
								
								increment += BufferLength;
								TotalLength -= BufferLength;
								
								Header->header.bh_caplen += BufferLength;
								Header->header.bh_datalen += BufferLength;
								
								DbgPrint("next MDL %d and added\n", BufferLength);
								
								pMdl = pNextMdl;
							}
							else
							{
								DbgPrint("next MDL %d not added\n", BufferLength);
								break;
							}
						}
						else
						{
							break;
						}
					}

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

					break;
				}
				else // never comes here.
				{
					IF_LOUD(DbgPrint("NPF_tapExForEachOpen: This is an error !!!!\n");)
					//ndisTransferData required
					//This is an error !!
					break;
				}
			}
			while (FALSE);

			if (ShouldReleaseBufferLock)
			{
				//NdisDprReleaseSpinLock(&LocalData->BufferLock);
				NdisReleaseSpinLock(&LocalData->BufferLock);
			}

		}
		while (FALSE);

NPF_TapEx_ForEachOpen_End:;
		pNetBufList = pNextNetBufList;
	} // end of the for loop

	//TRACE_EXIT();
}