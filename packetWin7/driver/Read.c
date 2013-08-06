/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
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

#include <ntddk.h>
#include <ndis.h>

#include "debug.h"
#include "packet.h"
#include "win_bpf.h"
#include "time_calls.h"

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "tme.h"
#endif //HAVE_BUGGY_TME_SUPPORT

NTSTATUS NPF_Read(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
    POPEN_INSTANCE      Open;
    PIO_STACK_LOCATION  IrpSp;
    PUCHAR				packp;
	ULONG				Input_Buffer_Length;
	UINT				Thead;
	UINT				Ttail;
	UINT				TLastByte;
	PUCHAR				CurrBuff;
	LARGE_INTEGER		CapTime;
	LARGE_INTEGER		TimeFreq;
	struct bpf_hdr		*header;
	KIRQL				Irql;
	PUCHAR				UserPointer;
	ULONG				bytecopy;
	UINT				SizeToCopy;
	UINT				PktLen;
	ULONG				copied,count,current_cpu,av,plen,increment,ToCopy,available;
	CpuPrivateData		*LocalData;
	ULONG				i;
	ULONG				Occupation;

	IF_LOUD(DbgPrint("NPF: Read\n");)

		
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
    Open=IrpSp->FileObject->FsContext;


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

	if(NPF_StartUsingBinding(Open) == FALSE)
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

	if( Open->mode & MODE_DUMP && Open->DumpFileHandle == NULL ){  
		// this instance is in dump mode, but the dump file has still not been opened
		NPF_StopUsingOpenInstance(Open);
		EXIT_FAILURE(0);
	}
	
	Occupation=0;

	for(i=0;i<g_NCpu;i++)
		Occupation += (Open->Size - Open->CpuData[i].Free);
	
	//See if the buffer is full enough to be copied
	if( Occupation <= Open->MinToCopy*g_NCpu || Open->mode & MODE_DUMP )
	{
		if (Open->ReadEvent != NULL)
		{
			//wait until some packets arrive or the timeout expires		
			if(Open->TimeOut.QuadPart != (LONGLONG)IMMEDIATE)
				KeWaitForSingleObject(Open->ReadEvent,
					UserRequest,
					KernelMode,
					TRUE,
					(Open->TimeOut.QuadPart == (LONGLONG)0)? NULL: &(Open->TimeOut));

			KeClearEvent(Open->ReadEvent);
		}		

		if(Open->mode & MODE_STAT)
		{   //this capture instance is in statistics mode
#ifdef NDIS50
			CurrBuff=(PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
#else
			CurrBuff=(PUCHAR)MmGetSystemAddressForMdl(Irp->MdlAddress);
#endif

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
			header=(struct bpf_hdr*)CurrBuff;
			GET_TIME(&header->bh_tstamp,&G_Start_Time);

			if(Open->mode & MODE_DUMP){
				*(LONGLONG*)(CurrBuff+sizeof(struct bpf_hdr)+16)=Open->DumpOffset.QuadPart;
				header->bh_caplen=24;
				header->bh_datalen=24;
				Irp->IoStatus.Information = 24 + sizeof(struct bpf_hdr);
			}
			else{
				header->bh_caplen=16;
				header->bh_datalen=16;
				header->bh_hdrlen=sizeof(struct bpf_hdr);
				Irp->IoStatus.Information = 16 + sizeof(struct bpf_hdr);
			}

			*(LONGLONG*)(CurrBuff+sizeof(struct bpf_hdr))=Open->Npackets.QuadPart;
			*(LONGLONG*)(CurrBuff+sizeof(struct bpf_hdr)+8)=Open->Nbytes.QuadPart;
			
			//reset the countetrs
			NdisAcquireSpinLock( &Open->CountersLock );
			Open->Npackets.QuadPart=0;
			Open->Nbytes.QuadPart=0;
			NdisReleaseSpinLock( &Open->CountersLock );
			
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

		if(Open->mode==MODE_MON)   //this capture instance is in monitor mode
		{   
			PTME_DATA data;
			ULONG cnt;
			ULONG block_size;
			PUCHAR tmp;

#ifdef NDIS50
			UserPointer=MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
#else
			UserPointer=MmGetSystemAddressForMdl(Irp->MdlAddress);
#endif

			if (UserPointer == NULL)
			{
				NPF_StopUsingOpenInstance(Open);
				EXIT_FAILURE(0);
			}

			if ((!IS_VALIDATED(Open->tme.validated_blocks,Open->tme.active_read))||(IrpSp->Parameters.Read.Length<sizeof(struct bpf_hdr)))
			{	
				NPF_StopUsingOpenInstance(Open);
				EXIT_FAILURE(0);
			}
			
			header=(struct bpf_hdr*)UserPointer;
	
			GET_TIME(&header->bh_tstamp,&G_Start_Time);

			
			header->bh_hdrlen=sizeof(struct bpf_hdr);
	

			//moves user memory pointer
			UserPointer+=sizeof(struct bpf_hdr);
			
			//calculus of data to be copied
			//if the user buffer is smaller than data to be copied,
			//only some data will be copied
			data=&Open->tme.block_data[Open->tme.active_read];

			if (data->last_read.tv_sec!=0)
				data->last_read=header->bh_tstamp;
			

			bytecopy=data->block_size*data->filled_blocks;
			
			if ((IrpSp->Parameters.Read.Length-sizeof(struct bpf_hdr))<bytecopy)
				bytecopy=(IrpSp->Parameters.Read.Length-sizeof(struct bpf_hdr))/ data->block_size;
			else 
				bytecopy=data->filled_blocks;

			tmp=data->shared_memory_base_address;
			block_size=data->block_size;
			
			for (cnt=0;cnt<bytecopy;cnt++)
			{
				NdisAcquireSpinLock(&Open->MachineLock);
				RtlCopyMemory(UserPointer,tmp,block_size);
				NdisReleaseSpinLock(&Open->MachineLock);
				tmp+=block_size;
				UserPointer+=block_size;
			}
						
			bytecopy*=block_size;

			header->bh_caplen=bytecopy;
			header->bh_datalen=header->bh_caplen;

			NPF_StopUsingOpenInstance(Open);
			EXIT_SUCCESS(bytecopy+sizeof(struct bpf_hdr));
		}

		Occupation=0;

		for(i=0;i<g_NCpu;i++)
			Occupation += (Open->Size - Open->CpuData[i].Free);


		if ( Occupation == 0 || Open->mode & MODE_DUMP)
			// The timeout has expired, but the buffer is still empty (or the packets must be written to file).
			// We must awake the application, returning an empty buffer.
		{
			NPF_StopUsingOpenInstance(Open);
			EXIT_SUCCESS(0);
		}
				
#else // not HAVE_BUGGY_TME_SUPPORT
		if(Open->mode==MODE_MON)   //this capture instance is in monitor mode
		{   
			NPF_StopUsingOpenInstance(Open);
			EXIT_FAILURE(0);
		}
#endif // HAVE_BUGGY_TME_SUPPORT

	}



//------------------------------------------------------------------------------
	copied=0;
	count=0;
	current_cpu=0;
	available = IrpSp->Parameters.Read.Length;
#ifdef NDIS50
	packp=(PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
#else
	packp=(PUCHAR)MmGetSystemAddressForMdl(Irp->MdlAddress);
#endif

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
		{  //there are some packets in the selected (aka LocalData) buffer
			struct PacketHeader *Header = (struct PacketHeader*)(LocalData->Buffer + LocalData->C);

			if ( Header->SN == Open->ReaderSN)
			{   //check if it the next one to be copied
				plen = Header->header.bh_caplen;
				if (plen + sizeof (struct bpf_hdr) > available - copied)  
				{  //if the packet does not fit into the user buffer, we've ended copying packets
					NPF_StopUsingOpenInstance(Open);
					EXIT_SUCCESS(copied);
				}
				
//				FIX_TIMESTAMPS(&Header->header.bh_tstamp);

				*((struct bpf_hdr*)(&packp[copied]))=Header->header;
				
				copied += sizeof(struct bpf_hdr);
				LocalData->C += sizeof(struct PacketHeader);

				if (LocalData->C == Open->Size)
					LocalData->C = 0;

				if (Open->Size - LocalData->C < plen)
				{
					//the packet is fragmented in the buffer (i.e. it skips the buffer boundary)
					ToCopy = Open->Size - LocalData->C;
					RtlCopyMemory(packp + copied,LocalData->Buffer + LocalData->C,ToCopy);
					RtlCopyMemory(packp + copied + ToCopy,LocalData->Buffer,plen-ToCopy);
					LocalData->C = plen-ToCopy;
				}
				else
				{
					//the packet is not fragmented
					RtlCopyMemory(packp + copied ,LocalData->Buffer + LocalData->C ,plen);
					LocalData->C += plen;
			//		if (c==size)  inutile, contemplato nell "header atomico"
			//			c=0;
				}

				Open->ReaderSN++;
				copied+=Packet_WORDALIGN(plen);

				increment = plen + sizeof(struct PacketHeader);
				if ( Open->Size - LocalData->C < sizeof(struct PacketHeader))
				{   //the next packet would be saved at the end of the buffer, but the NewHeader struct would be fragmented
					//so the producer (--> the consumer) skips to the beginning of the buffer
					increment += Open->Size-LocalData->C;
					LocalData->C=0;
				}
				InterlockedExchangeAdd(&Open->CpuData[current_cpu].Free,increment);
				count=0;
			}
			else
			{
				current_cpu=(current_cpu+1)%g_NCpu;
				count++;	
			}
		
		}
		else
		{
			current_cpu=(current_cpu+1)%g_NCpu;
			count++;	
		}
	}
		
	{
		NPF_StopUsingOpenInstance(Open);
		EXIT_SUCCESS(copied);
	}

//------------------------------------------------------------------------------

}

NDIS_STATUS NPF_tap (IN NDIS_HANDLE ProtocolBindingContext,IN NDIS_HANDLE MacReceiveContext,
                        IN PVOID HeaderBuffer,IN UINT HeaderBufferSize,IN PVOID LookaheadBuffer,
                        IN UINT LookaheadBufferSize,IN UINT PacketSize)
{
    POPEN_INSTANCE      Open;
    PNDIS_PACKET        pPacket;
    ULONG               SizeToTransfer;
    NDIS_STATUS         Status;
    UINT                BytesTransfered;
    ULONG               BufferLength;
    PMDL                pMdl1,pMdl2;
	LARGE_INTEGER		CapTime;
	LARGE_INTEGER		TimeFreq;
	UINT				fres;
	USHORT				NPFHdrSize;

	CpuPrivateData		*LocalData;
	ULONG				Cpu;
	struct PacketHeader	*Header;
	ULONG				ToCopy;
	ULONG				increment;
	ULONG				i;
	BOOLEAN				ShouldReleaseBufferLock;

    IF_VERY_LOUD(DbgPrint("NPF: tap\n");)
	IF_VERY_LOUD(DbgPrint("HeaderBufferSize=%u, LookAheadBuffer=%p, LookaheadBufferSize=%u, PacketSize=%u\n", 
	HeaderBufferSize,
	LookaheadBuffer,
	LookaheadBufferSize,
	PacketSize);)

	Open= (POPEN_INSTANCE)ProtocolBindingContext;
	
    Cpu = KeGetCurrentProcessorNumber();
	LocalData = &Open->CpuData[Cpu];

	LocalData->Received++;
	IF_LOUD(DbgPrint("Received on CPU %d \t%d\n",Cpu,LocalData->Received);)
//	Open->Received++;		// Number of packets received by filter ++


	NdisAcquireSpinLock(&Open->MachineLock);

	//
	//Check if the lookahead buffer follows the mac header.
	//If the data follow the header (i.e. there is only a buffer) a normal bpf_filter() is
	//executed on the packet.
	//Otherwise if there are 2 separate buffers (this could be the case of LAN emulation or
	//things like this) bpf_filter_with_2_buffers() is executed.
	//
	if((UINT)((PUCHAR)LookaheadBuffer-(PUCHAR)HeaderBuffer) != HeaderBufferSize)
	{
#ifdef  HAVE_BUGGY_TME_SUPPORT
		fres=bpf_filter_with_2_buffers((struct bpf_insn*)(Open->bpfprogram),
									   HeaderBuffer,
									   LookaheadBuffer,
									   HeaderBufferSize,
									   PacketSize+HeaderBufferSize,
									   LookaheadBufferSize+HeaderBufferSize,
									   &Open->mem_ex,
									   &Open->tme,
									   &G_Start_Time);
#else // HAVE_BUGGY_TME_SUPPORT
		fres=bpf_filter_with_2_buffers((struct bpf_insn*)(Open->bpfprogram),
									   HeaderBuffer,
									   LookaheadBuffer,
									   HeaderBufferSize,
									   PacketSize+HeaderBufferSize,
									   LookaheadBufferSize+HeaderBufferSize);
#endif // HAVE_BUGGY_TME_SUPPORT
	}	
	else 
//
// the jit filter is available on x86 (32 bit) only
//
#ifdef _X86_

		if(Open->Filter != NULL)
		{
			if (Open->bpfprogram != NULL)
			{
				fres=Open->Filter->Function(HeaderBuffer,
									PacketSize+HeaderBufferSize,
									LookaheadBufferSize+HeaderBufferSize);
			}
			else
				fres = -1;
		}
		else
#endif //_X86_
	
#ifdef HAVE_BUGGY_TME_SUPPORT
			fres=bpf_filter((struct bpf_insn*)(Open->bpfprogram),
 		                HeaderBuffer,
 						PacketSize+HeaderBufferSize,
						LookaheadBufferSize+HeaderBufferSize,
						&Open->mem_ex,
						&Open->tme,
						&G_Start_Time);
#else //HAVE_BUGGY_TME_SUPPORT
			fres=bpf_filter((struct bpf_insn*)(Open->bpfprogram),
 		                HeaderBuffer,
 						PacketSize+HeaderBufferSize,
						LookaheadBufferSize+HeaderBufferSize);
#endif //HAVE_BUGGY_TME_SUPPORT

	NdisReleaseSpinLock(&Open->MachineLock);

//
// The MONITOR_MODE (aka TME extensions) is not supported on 
// 64 bit architectures
//
#ifdef HAVE_BUGGY_TME_SUPPORT
	if(Open->mode==MODE_MON)
	// we are in monitor mode
	{
		if (fres==1) 
		{
			if (Open->ReadEvent != NULL)
			{
				KeSetEvent(Open->ReadEvent,0,FALSE);	
			}
		}
		return NDIS_STATUS_NOT_ACCEPTED;

	}
#endif //HAVE_BUGGY_TME_SUPPORT

	if(fres==0)
	{
		// Packet not accepted by the filter, ignore it.
		return NDIS_STATUS_NOT_ACCEPTED;
	}

	//if the filter returns -1 the whole packet must be accepted
	if(fres == -1 || fres > PacketSize+HeaderBufferSize)
		fres = PacketSize+HeaderBufferSize; 

	if(Open->mode & MODE_STAT)
	{
	// we are in statistics mode
		NdisAcquireSpinLock( &Open->CountersLock );

		Open->Npackets.QuadPart++;
		
		if(PacketSize+HeaderBufferSize<60)
			Open->Nbytes.QuadPart+=60;
		else
			Open->Nbytes.QuadPart+=PacketSize+HeaderBufferSize;
		// add preamble+SFD+FCS to the packet
		// these values must be considered because are not part of the packet received from NDIS
		Open->Nbytes.QuadPart+=12;

		NdisReleaseSpinLock( &Open->CountersLock );
		
		if(!(Open->mode & MODE_DUMP))
		{
 			return NDIS_STATUS_NOT_ACCEPTED;
		}
	}

	if(Open->Size == 0)
	{
		LocalData->Dropped++;
		return NDIS_STATUS_NOT_ACCEPTED;
	}

	if(Open->mode & MODE_DUMP && Open->MaxDumpPacks)
	{
		ULONG Accepted=0;
		for(i=0;i<g_NCpu;i++)
			Accepted+=Open->CpuData[i].Accepted;
		
		if(  Accepted > Open->MaxDumpPacks)
		{
			// Reached the max number of packets to save in the dump file. Discard the packet and stop the dump thread.
			Open->DumpLimitReached = TRUE; // This stops the thread
			// Awake the dump thread
			NdisSetEvent(&Open->DumpEvent);

			// Awake the application
			if (Open->ReadEvent != NULL)
				KeSetEvent(Open->ReadEvent,0,FALSE);

			return NDIS_STATUS_NOT_ACCEPTED;
		}
	}

	//////////////////////////////COPIA.C//////////////////////////////////////////77

	ShouldReleaseBufferLock = TRUE;
	NdisDprAcquireSpinLock(&LocalData->BufferLock);

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


		if (LookaheadBufferSize + HeaderBufferSize >= fres)
		{

			//
			// we do not need to call NdisTransferData, either because we need only the HeaderBuffer, or because the LookaheadBuffer
			// contains what we need
			//

			Header = (struct PacketHeader*)(LocalData->Buffer + LocalData->P);
			LocalData->Accepted++;
			GET_TIME(&Header->header.bh_tstamp,&G_Start_Time);
			Header->SN = InterlockedIncrement(&Open->WriterSN) - 1;

			Header->header.bh_caplen = fres;
			Header->header.bh_datalen = PacketSize + HeaderBufferSize;
			Header->header.bh_hdrlen=sizeof(struct bpf_hdr);

			LocalData->P +=sizeof(struct PacketHeader);
			if (LocalData->P == Open->Size)
				LocalData->P = 0;

			if ( fres <= HeaderBufferSize || (UINT)( (PUCHAR)LookaheadBuffer - (PUCHAR)HeaderBuffer ) == HeaderBufferSize )
			{
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
					NdisMoveMappedMemory(LocalData->Buffer + LocalData->P,HeaderBuffer, ToCopy);
					NdisMoveMappedMemory(LocalData->Buffer + 0 , (PUCHAR)HeaderBuffer + ToCopy, fres - ToCopy);
					LocalData->P = fres-ToCopy;
				}
				else
				{
					//the packet does not need to be fragmented in the buffer (aka, it doesn't skip the buffer boundary)
					// ;-)))))) only ONE copy
					NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, fres);
					LocalData->P += fres;
				}
			}
			else
			{
				//HeaderBuffer and LookAhead buffer are NOT contiguous,
				//AND, we need some bytes from the LookaheadBuffer, too
				if (Open->Size - LocalData->P < fres)
				{
					//the packet will be fragmented in the buffer (aka, it will skip the buffer boundary)
					if (Open->Size - LocalData->P >= HeaderBufferSize)
					{
						//HeaderBuffer is NOT fragmented
						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, HeaderBufferSize);
						LocalData->P += HeaderBufferSize;

						if (LocalData->P == Open->Size)
						{
							//the fragmentation of the packet in the buffer is the same fragmentation
							//in HeaderBuffer+LookaheadBuffer
							LocalData->P=0;	
							NdisMoveMappedMemory(LocalData->Buffer + 0, LookaheadBuffer, fres - HeaderBufferSize);
							LocalData->P += (fres - HeaderBufferSize);
						}
						else
						{
							//LookAheadBuffer is fragmented, two copies
							ToCopy = Open->Size - LocalData->P;
							NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, LookaheadBuffer, ToCopy);
							LocalData->P=0;
							NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)LookaheadBuffer+ ToCopy, fres - HeaderBufferSize - ToCopy);
							LocalData->P = fres - HeaderBufferSize - ToCopy;
						}
					}
					else
					{
						//HeaderBuffer is fragmented in the buffer (aka, it will skip the buffer boundary)
						//two copies to copy the HeaderBuffer
						ToCopy = Open->Size - LocalData->P;
						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, ToCopy);
						LocalData->P = 0;
						NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)HeaderBuffer + ToCopy, HeaderBufferSize - ToCopy);
						LocalData->P = HeaderBufferSize - ToCopy;

						//only one copy to copy the LookaheadBuffer
						NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, LookaheadBuffer, fres- HeaderBufferSize);
						LocalData->P += (fres - HeaderBufferSize);
					}
				}
				else
				{	
					//the packet won't be fragmented in the destination buffer (aka, it won't skip the buffer boundary)
					//two copies, the former to copy the HeaderBuffer, the latter to copy the LookaheadBuffer
					NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, HeaderBuffer, HeaderBufferSize);
					LocalData->P += HeaderBufferSize;
					NdisMoveMappedMemory(LocalData->Buffer + LocalData->P, LookaheadBuffer, fres - HeaderBufferSize);
					LocalData->P += (fres - HeaderBufferSize);
				}		 
			}		

			increment = fres + sizeof(struct PacketHeader);
			if (Open->Size - LocalData->P < sizeof(struct PacketHeader))  //we check that the available, AND contiguous, space in the buffer will fit
			{														   //the NewHeader structure, at least, otherwise we skip the producer
				increment += Open->Size-LocalData->P;				   //at the beginning of the buffer (p = 0), and decrement the free bytes appropriately
				LocalData->P = 0;
			}

			InterlockedExchangeAdd(&LocalData->Free, (ULONG)(-(LONG)increment));
			if(Open->Size - LocalData->Free >= Open->MinToCopy)
			{
				if(Open->mode & MODE_DUMP)
					NdisSetEvent(&Open->DumpEvent);
				else
				{		
					if (Open->ReadEvent != NULL)
					{
						KeSetEvent(Open->ReadEvent,0,FALSE);	
					}
				}
			}

			break;
		}
		else
		{
			IF_LOUD(DbgPrint("TransferData!!\n");)
				//ndisTransferData required
				LocalData->NewP = LocalData->P;

			LocalData->NewP +=sizeof(struct PacketHeader);
			if (LocalData->NewP == Open->Size)
				LocalData->NewP = 0;

			//first of all, surely the header must be copied
			if (Open->Size-LocalData->NewP >= HeaderBufferSize)
			{
				//1 copy!
				NdisMoveMappedMemory(LocalData->Buffer + LocalData->NewP, HeaderBuffer, HeaderBufferSize);
				LocalData->NewP += HeaderBufferSize;
				if (LocalData->NewP == Open->Size)
					LocalData->NewP = 0;
			}
			else
			{
				ToCopy = Open->Size - LocalData->NewP;
				NdisMoveMappedMemory(LocalData->Buffer + LocalData->NewP, HeaderBuffer, ToCopy);
				NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)HeaderBuffer + ToCopy, HeaderBufferSize - ToCopy);
				LocalData->NewP = HeaderBufferSize - ToCopy;
			}

			//then we copy the Lookahead buffer

			if (Open->Size-LocalData->NewP >= LookaheadBufferSize)
			{
				//1 copy!
				NdisMoveMappedMemory(LocalData->Buffer + LocalData->NewP, LookaheadBuffer, LookaheadBufferSize);
				LocalData->NewP += LookaheadBufferSize;
				if (LocalData->NewP == Open->Size)
					LocalData->NewP = 0;
			}
			else
			{
				ToCopy = Open->Size - LocalData->NewP;
				NdisMoveMappedMemory(LocalData->Buffer + LocalData->NewP, LookaheadBuffer, ToCopy);
				NdisMoveMappedMemory(LocalData->Buffer + 0, (PUCHAR)LookaheadBuffer + ToCopy, LookaheadBufferSize - ToCopy);
				LocalData->NewP = LookaheadBufferSize - ToCopy;
			}

			//Now we must prepare the buffer(s) for the NdisTransferData
			if ((Open->Size - LocalData->NewP) >= (fres - HeaderBufferSize - LookaheadBufferSize))
			{
				//only 1 buffer
				pMdl1 = IoAllocateMdl(
					LocalData->Buffer + LocalData->NewP, 
					fres - HeaderBufferSize - LookaheadBufferSize,
					FALSE,
					FALSE,
					NULL);

				if (pMdl1 == NULL)
				{
					IF_LOUD(DbgPrint("Error allocating Mdl1\n");)
						LocalData->Dropped++;
					break;
				}

				MmBuildMdlForNonPagedPool(pMdl1);
				pMdl2=NULL;
				LocalData->NewP += fres - HeaderBufferSize - LookaheadBufferSize;


			}
			else
			{
				//2 buffers
				pMdl1 = IoAllocateMdl(
					LocalData->Buffer + LocalData->NewP, 
					Open->Size - LocalData->NewP,
					FALSE,
					FALSE,
					NULL);

				if (pMdl1 == NULL)
				{
					IF_LOUD(DbgPrint("Error allocating Mdl1\n");)
						LocalData->Dropped++;
					break;
				}

				pMdl2 = IoAllocateMdl(
					LocalData->Buffer + 0, 
					fres - HeaderBufferSize - LookaheadBufferSize - (Open->Size - LocalData->NewP),
					FALSE,
					FALSE,
					NULL);

				if (pMdl2 == NULL)
				{
					IF_LOUD(DbgPrint("Error allocating Mdl2\n");)
						IoFreeMdl(pMdl1);
					LocalData->Dropped++;
					break;
				}

				LocalData->NewP = fres - HeaderBufferSize - LookaheadBufferSize - (Open->Size - LocalData->NewP);

				MmBuildMdlForNonPagedPool(pMdl1);
				MmBuildMdlForNonPagedPool(pMdl2);
			}


			NdisAllocatePacket(&Status, &pPacket, Open->PacketPool);

			if (Status != NDIS_STATUS_SUCCESS)
			{
				IF_LOUD(DbgPrint("NPF: Tap - No free packets\n");)
					IoFreeMdl(pMdl1);
				if (pMdl2 != NULL)
					IoFreeMdl(pMdl2);
				LocalData->Dropped++;
				break;
			}

			if (pMdl2 != NULL)
				NdisChainBufferAtFront(pPacket,pMdl2);

			NdisChainBufferAtFront(pPacket,pMdl1);

			RESERVED(pPacket)->Cpu = Cpu;

			LocalData->TransferMdl1 = pMdl1;	
			LocalData->TransferMdl2 = pMdl2;	


			Header = (struct PacketHeader*)(LocalData->Buffer + LocalData->P);
			Header->header.bh_caplen = fres;
			Header->header.bh_datalen = PacketSize + HeaderBufferSize;
			Header->header.bh_hdrlen=sizeof(struct bpf_hdr);

			NdisTransferData(
				&Status,
				Open->AdapterHandle,
				MacReceiveContext,
				LookaheadBufferSize,
				fres - HeaderBufferSize - LookaheadBufferSize,
				pPacket,
				&BytesTransfered);

			if (Status != NDIS_STATUS_PENDING)
			{
				IF_LOUD(DbgPrint("NdisTransferData, not pending!\n");)	
					LocalData->TransferMdl1 = NULL;
				LocalData->TransferMdl2 = NULL;

				IoFreeMdl(pMdl1);
				if ( pMdl2 != NULL )
					IoFreeMdl(pMdl2);

				NdisReinitializePacket(pPacket);
				// Put the packet on the free queue
				NdisFreePacket(pPacket);

				LocalData->P = LocalData->NewP;

				LocalData->Accepted++;
				GET_TIME(&Header->header.bh_tstamp,&G_Start_Time);
				Header->SN = InterlockedIncrement(&Open->WriterSN) - 1;

				increment = fres + sizeof(struct PacketHeader);
				if (Open->Size - LocalData->P < sizeof(struct PacketHeader))
				{
					increment += Open->Size-LocalData->P;
					LocalData->P = 0;
				}

				InterlockedExchangeAdd(&LocalData->Free, (ULONG)(-(LONG)increment));

				if(Open->Size - LocalData->Free >= Open->MinToCopy)
				{
					if(Open->mode & MODE_DUMP)
						NdisSetEvent(&Open->DumpEvent);
					else
					{
						if (Open->ReadEvent != NULL)
						{
							KeSetEvent(Open->ReadEvent,0,FALSE);	
						}
					}
				}

				break;
			}
			else
			{
				IF_LOUD(DbgPrint("NdisTransferData, pending!\n");)
					ShouldReleaseBufferLock = FALSE;
			}
		}
	}
	while(FALSE);

	if (ShouldReleaseBufferLock)
	{
		NdisDprReleaseSpinLock(&LocalData->BufferLock);
	}

	return NDIS_STATUS_NOT_ACCEPTED;

}

//-------------------------------------------------------------------

VOID NPF_TransferDataComplete (IN NDIS_HANDLE ProtocolBindingContext,IN PNDIS_PACKET pPacket,
                                 IN NDIS_STATUS Status,IN UINT BytesTransfered)
{
    POPEN_INSTANCE      Open;
	ULONG				Cpu;
    CpuPrivateData		*LocalData;
	struct PacketHeader*	Header;
	ULONG				increment;

	IF_LOUD(DbgPrint("NPF: TransferDataComplete\n");)
    
	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	Cpu = RESERVED(pPacket)->Cpu;

	LocalData = &Open->CpuData[Cpu];

	IoFreeMdl(LocalData->TransferMdl1);
	if ( LocalData->TransferMdl2 != NULL )
		IoFreeMdl(LocalData->TransferMdl2);

	NdisReinitializePacket(pPacket);
	// Put the packet on the free queue
	NdisFreePacket(pPacket);

	//the packet has been successfully copied to the kernel buffer, we can prepend it with the PacketHeader,
	//and obtain the sequence number and the timestamp

	LocalData->Accepted++;
	Header = (struct PacketHeader*)(LocalData->Buffer + LocalData->P);
	GET_TIME(&Header->header.bh_tstamp,&G_Start_Time);
	Header->SN = InterlockedIncrement(&Open->WriterSN) - 1;

	LocalData->P = LocalData->NewP;
	
	increment = Header->header.bh_caplen + sizeof(struct PacketHeader);
	if (Open->Size - LocalData->P < sizeof(struct PacketHeader))
	{
		increment += Open->Size-LocalData->P;
		LocalData->P = 0;
	}

	InterlockedExchangeAdd(&LocalData->Free, (ULONG)(-(LONG)increment));

	if(Open->Size - LocalData->Free >= Open->MinToCopy)
	{
		if(Open->mode & MODE_DUMP)
			NdisSetEvent(&Open->DumpEvent);
		else
		{
			if (Open->ReadEvent != NULL)
			{
				KeSetEvent(Open->ReadEvent,0,FALSE);	
			}
		}
	}

	LocalData->TransferMdl1 = NULL;
	LocalData->TransferMdl2 = NULL;

//
// NOTE: this is really bad practice.
// a better approach would be performing the entire copy here.
//
#pragma prefast(suppress:8107, "There's no Spinlock leak here, as it's acquired by the tap.")
	NdisDprReleaseSpinLock(&LocalData->BufferLock);

// Unfreeze the consumer
	if(Open->Size - LocalData->Free > Open->MinToCopy)
	{
 		if(Open->mode & MODE_DUMP)
 			NdisSetEvent(&Open->DumpEvent);
 		else
		{
			if (Open->ReadEvent != NULL)
			{
				KeSetEvent(Open->ReadEvent,0,FALSE);	
			}
		}
	}
	return;
}

//-------------------------------------------------------------------

VOID NPF_ReceiveComplete(IN NDIS_HANDLE ProtocolBindingContext)
{
    IF_VERY_LOUD(DbgPrint("NPF: NPF_ReceiveComplete\n");)
    return;
}
