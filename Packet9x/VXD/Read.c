/*
 * Copyright (c) 1999 - 2003
 * NetGroup, Politecnico di Torino (Italy)
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
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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


#include <basedef.h>
#include <vmm.h>
#include <vwin32.h>
#include <winerror.h>
#include <ndis.h>
#include "debug.h"
#include "packet.h"
#include <ntddpack.h>
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
DWORD _stdcall MyPageLock(DWORD, DWORD);
void  _stdcall MyPageUnlock(DWORD, DWORD);

/************************************************************
Allocates the space for a packet, extracting it from the 
buffer reserved for the driver
************************************************************/
VOID
PacketAllocatePacketBuffer(	PNDIS_STATUS	pStatus,
							POPEN_INSTANCE	pOpen,
							PNDIS_PACKET	*lplpPacket,
							PDIOCPARAMETERS	pDiocParms,
							DWORD			FunctionCode )
{
	PNDIS_BUFFER		pNdisBuffer;
	PPACKET_RESERVED	pReserved;


	TRACE_ENTER( "PacketAllocatePacket" );
	NdisAllocatePacket( pStatus, lplpPacket, pOpen->PacketPool );
	if ( *pStatus != NDIS_STATUS_SUCCESS ) 
	{
		IF_VERY_LOUD( "Read- No free packets" );
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		return;
	}
	InitializeListHead( &(RESERVED(*lplpPacket)->ListElement) );
	pReserved = RESERVED(*lplpPacket);
	switch ( FunctionCode )
	{
	case IOCTL_PROTOCOL_READ:
		pReserved->lpBuffer = (PVOID)PacketPageLock( (PVOID)pDiocParms->lpvOutBuffer, 
									 				 pDiocParms->cbOutBuffer );
		pReserved->cbBuffer = pDiocParms->cbOutBuffer;
		break;
	case IOCTL_PROTOCOL_WRITE:
		pReserved->lpBuffer = (PVOID)PacketPageLock( pDiocParms->lpvInBuffer, 
									 				 pDiocParms->cbInBuffer );
		pReserved->cbBuffer = pDiocParms->cbInBuffer;
		break;
	default:
		/*function not valid, free the resource*/
		IF_TRACE_MSG( "Allocate- Invalid FunctionCode %x", FunctionCode );
		NdisReinitializePacket( *lplpPacket );
		NdisFreePacket( *lplpPacket );
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		*pStatus = NDIS_STATUS_NOT_ACCEPTED;
		return;
	}
	pReserved->lpcbBytesReturned	= 
			(PVOID)PacketPageLock( (PVOID)pDiocParms->lpcbBytesReturned, sizeof(DWORD) );
	pReserved->lpoOverlapped		= 
	
			(PVOID)PacketPageLock( (PVOID)pDiocParms->lpoOverlapped, sizeof(OVERLAPPED) );
	
	NdisAllocateBuffer(	pStatus, 
						&pNdisBuffer, 
						pOpen->BufferPool, 
						(PVOID)pReserved->lpBuffer,
						pDiocParms->cbOutBuffer );
	if ( *pStatus != NDIS_STATUS_SUCCESS )
	{
		IF_TRACE( "Read- No free buffers" );
		NdisReinitializePacket(*lplpPacket);
		NdisFreePacket(*lplpPacket);
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		return;
	}
	NdisChainBufferAtFront( *lplpPacket, pNdisBuffer );
	IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) 
	{
		IF_TRACE_MSG( " lplpPacket : %lx", lplpPacket );		
		IF_TRACE_MSG( "   lpPacket : %lx", *lplpPacket );		
		IF_TRACE_MSG3( "pNdisBuffer : %lx  %lx  %lx", pNdisBuffer, (*lplpPacket)->Private.Head, (*lplpPacket)->Private.Tail );
		IF_TRACE_MSG( "   Reserved : %lx", pReserved );		
		IF_TRACE_MSG4( "   lpBuffer : %lx  %lx  %lx  %lx", pReserved->lpBuffer, pNdisBuffer->VirtualAddress, pDiocParms->lpvOutBuffer, pDiocParms->lpvInBuffer );
		IF_TRACE_MSG3( "   cbBuffer : %lx  %lx  %lx", pReserved->cbBuffer, pDiocParms->cbOutBuffer, pDiocParms->cbInBuffer );
		IF_TRACE_MSG2( " lpcbBytes  : %lx  %lx", pReserved->lpcbBytesReturned, pDiocParms->lpcbBytesReturned );
		IF_TRACE_MSG2( " lpoOverlap : %lx  %lx", pReserved->lpoOverlapped, pDiocParms->lpoOverlapped );
	}
	PACKETASSERT( pReserved->lpBuffer );
	PACKETASSERT( pReserved->cbBuffer );
	PACKETASSERT( pReserved->lpcbBytesReturned );
	PACKETASSERT( pReserved->lpoOverlapped );
	PACKETASSERT( pNdisBuffer == (*lplpPacket)->Private.Head );
	PACKETASSERT( pNdisBuffer->VirtualAddress == pReserved->lpBuffer );
	TRACE_LEAVE( "PacketAllocatePacket" );
	return;
}

/************************************************************
Move a portion of the circular buffer 
updating the head every 1024 bytes
************************************************************/

void PacketMoveMem(PVOID Destination,
				   PVOID Source, 
				   ULONG Length,
				   UINT	 *Bhead)
{
ULONG WordLength;
UINT n,i,NBlocks;

	WordLength=Length>>2;
	NBlocks=WordLength>>8;
	
	for(n=0;n<NBlocks;n++){
		for(i=0;i<256;i++){
			*((PULONG)Destination)++=*((PULONG)Source)++;
		}
	*Bhead+=1024;
	}

	n=WordLength-(NBlocks<<8);
	for(i=0;i<n;i++){
		*((PULONG)Destination)++=*((PULONG)Source)++;
	}
	*Bhead+=n<<2;
	
	n=Length-(WordLength<<2);
	for(i=0;i<n;i++){
		*((PUCHAR)Destination)++=*((PUCHAR)Source)++;
	}
	*Bhead+=n;
}

/************************************************************
Start a read
************************************************************/
DWORD
PacketRead( POPEN_INSTANCE	Open,
			DWORD  			dwDDB,
            DWORD  			hDevice,
		  	PDIOCPARAMETERS pDiocParms
	)
{
	NDIS_STATUS		Status;
	PNDIS_PACKET	pPacket;
    PUCHAR				packp;//buffer that maps the application memory
	UINT				i;
	ULONG				Input_Buffer_Length;
	UINT				Thead;
	UINT				Ttail;
	UINT				TLastByte;
	PUCHAR				CurrBuff;
	UINT				cplen;
	UINT				CpStart;
	DWORD				TEvent;
	
	
	TRACE_ENTER( "PacketRead" );
	if ( pDiocParms->cbOutBuffer < ETHERNET_HEADER_LENGTH ) 
	{
		/*the application's buffer if too small to contain the packet*/
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		IF_VERY_LOUD( "Read- Buffer too small" );
		TRACE_LEAVE( "ReadPacket" );
		return NDIS_STATUS_FAILURE;
	}
	
	/*See if there are packets in the buffer*/
	
	Thead=Open->Bhead;
	Ttail=Open->Btail;
	TLastByte=Open->BLastByte;
	
	if (Thead == Ttail)
	{
		
		/*there aren't buffered packet but there is no timeout */
		if(Open->TimeOut == -1){
			*(DWORD *)(pDiocParms->lpcbBytesReturned)=0;
			return(NDIS_STATUS_SUCCESS);
		}			
		
		/*there aren't buffered packet and there is a timeout: the application must wait*/	
		PacketAllocatePacketBuffer( &Status, Open, &pPacket, pDiocParms, IOCTL_PROTOCOL_READ );
		if ( Status == NDIS_STATUS_SUCCESS )
		{
			PACKETASSERT( Open != NULL );
			PACKETASSERT( pPacket != NULL );
			
			NdisAcquireSpinLock( &Open->RcvQSpinLock );
			InsertTailList( &Open->RcvList, &RESERVED(pPacket)->ListElement );
			NdisReleaseSpinLock( &Open->RcvQSpinLock );
			
			/*set the timeout on the read*/
			Open->ReadTimeoutTimer=SetReadTimeOut(ReadTimeout,Open->TimeOut,Open);
			
			IF_TRACE_MSG2( "RcvList Link : %lx  %lx", Open->RcvList.Blink, &RESERVED(pPacket)->ListElement );
			PACKETASSERT( Open->RcvList.Blink == &RESERVED(pPacket)->ListElement );
			PACKETASSERT( &(Open->RcvList) == RESERVED(pPacket)->ListElement.Flink );
		}
		
		TRACE_LEAVE( "PacketRead" );
		return(-1);	/*Communicate that the operation is asynchronous*/	
	}
	
	/*there is at least a buffered packet: the read call can be completed*/
	
	Input_Buffer_Length=pDiocParms->cbOutBuffer;
	packp=(PUCHAR)pDiocParms->lpvOutBuffer;
	i=0;
	/*get the address of the buffer*/
	CurrBuff=Open->Buffer;
	
	/*fill the application buffer*/
	
	/*first of all see if it we can copy all the buffer in one time*/
	if(Ttail>Thead){
		if((Ttail-Thead)<Input_Buffer_Length){
			PacketMoveMem(packp,CurrBuff+Thead,Ttail-Thead,&(Open->Bhead));
			*(DWORD *)(pDiocParms->lpcbBytesReturned)=Ttail-Thead;
			
			// The buffer is empty: reset the read event
			TEvent=Open->ReadEvent;
			_asm mov eax,TEvent;
			VxDCall(_VWIN32_ResetWin32Event);
			
			return(NDIS_STATUS_SUCCESS);
		}
	}
	else if((TLastByte-Thead)<Input_Buffer_Length){
		PacketMoveMem(packp,CurrBuff+Thead,TLastByte-Thead,&(Open->Bhead));
		Open->BLastByte=Ttail;
		Open->Bhead=0;
		*(DWORD *)(pDiocParms->lpcbBytesReturned)=TLastByte-Thead;
		return(NDIS_STATUS_SUCCESS);
	}
	
	/*scan the buffer*/
	CpStart=Thead;
	while(TRUE){
		if(Thead==Ttail)break;
		if(Thead==TLastByte){
			PacketMoveMem(packp,CurrBuff+CpStart,Thead-CpStart,&(Open->Bhead));
			packp+=(Thead-CpStart);
			Open->Bhead=0;
			Thead=0;
			CpStart=0;
		}
		cplen=((struct bpf_hdr*)(CurrBuff+Thead))->bh_caplen+sizeof(struct bpf_hdr);
		if((i+cplen > Input_Buffer_Length))break; //no more space in the application buffer
		cplen=Packet_WORDALIGN(cplen);
		i+=cplen;
		Thead+=cplen;
	}
	
	PacketMoveMem(packp,CurrBuff+CpStart,Thead-CpStart,&(Open->Bhead));
	
	*(DWORD *)(pDiocParms->lpcbBytesReturned)=i;
    return(NDIS_STATUS_SUCCESS);
	
}

/************************************************************
Callback routine called by NDIS when the adapter receives a
packet
************************************************************/
NDIS_STATUS NDIS_API
Packet_tap (	IN NDIS_HANDLE ProtocolBindingContext,
				IN NDIS_HANDLE MacReceiveContext,
				IN PVOID       pvHeaderBuffer,
				IN UINT        uiHeaderBufferSize,
				IN PVOID       pvLookAheadBuffer,
				IN UINT        uiLookaheadBufferSize,
				IN UINT        uiPacketSize
	)
#define pOpen	((POPEN_INSTANCE)ProtocolBindingContext)
{
	PLIST_ENTRY			PacketListEntry;
	PNDIS_PACKET   		pPacket;
	ULONG          		ulSizeToTransfer;
	NDIS_STATUS    		Status;
	UINT           		uiBytesTransferred;
	PPACKET_RESERVED	pReserved;
	PNDIS_BUFFER		pNdisBuffer;
	PVOID				pvActualVirtualAddress;
	UINT				uiActualLength;
	PUCHAR				CurrBuff;
	UINT				Thead;
	UINT				Ttail;
	UINT				TLastByte;
    PNDIS_PACKET        pPacketb;
	struct bpf_hdr		*header;
	LARGE_INTEGER		CapTime;
	__int64				lCapTime;
	UINT				fres; //filter result
	UINT				maxbufspace;
	UINT				to;
	DWORD				TEvent;

	TRACE_ENTER( "Packet_tap" );

	PACKETASSERT( (pOpen != NULL) );


	pOpen->Received++;		/*number of packets received by filter ++*/

	/*
	Check if the lookahead buffer follows the mac header.
	If the data follow the header (i.e. there is only a buffer) a normal bpf_filter() is
	executed on the packet.
	Otherwise if there are 2 separate buffers (this could be the case of LAN emulation or
	stuff like this) bpf_filter_with_2_buffers() is executed.
	*/

	if((int)pvLookAheadBuffer-(int)pvHeaderBuffer != uiHeaderBufferSize)
		fres=bpf_filter_with_2_buffers((struct bpf_insn*)(pOpen->bpfprogram),
									   pvHeaderBuffer,
									   pvLookAheadBuffer,
									   uiHeaderBufferSize,
									   uiPacketSize+uiHeaderBufferSize,
									   uiLookaheadBufferSize+uiHeaderBufferSize);
	else
		fres=bpf_filter((struct bpf_insn*)(pOpen->bpfprogram),
		                pvHeaderBuffer,
						uiPacketSize+uiHeaderBufferSize,
						uiLookaheadBufferSize+uiHeaderBufferSize);

	if(fres==0)return NDIS_STATUS_NOT_ACCEPTED;
	if( fres==-1)fres=uiPacketSize+uiHeaderBufferSize;	//if the filter returns -1 the whole packet must be accepted


	if(pOpen->mode==1){
	/*statistics mode*/
		NdisAcquireSpinLock( &pOpen->CountersLock );

		pOpen->Npackets++;
		
		if(uiPacketSize+uiHeaderBufferSize<60)
			pOpen->Nbytes+=60;
		else
			pOpen->Nbytes+=uiPacketSize+uiHeaderBufferSize;
		
		/*add preamble+SFD+FCS to the packet
		these values must be considered because are not part of the packet received from NDIS*/
		pOpen->Nbytes+=12;

		NdisReleaseSpinLock( &pOpen->CountersLock );
		
		return NDIS_STATUS_NOT_ACCEPTED; //it should be quicker
	}


	/*see if there are pending requests*/
	NdisAcquireSpinLock( &pOpen->RcvQSpinLock );
	PacketListEntry = PacketRemoveHeadList( &pOpen->RcvList );
	NdisReleaseSpinLock( &pOpen->RcvQSpinLock );

	if ( PacketListEntry == NULL )
	{
	/*no requests. This means that the application is not performing a read in this 
	  moment: the packet must go in the buffer*/

	TRACE_ENTER( "IndicateReceive" );

	if(pOpen->BufSize==0)return NDIS_STATUS_NOT_ACCEPTED;

	Thead=pOpen->Bhead;
	Ttail=pOpen->Btail;
	TLastByte=pOpen->BLastByte;


	maxbufspace=fres+sizeof(struct bpf_hdr);
	if(Ttail+maxbufspace>=pOpen->BufSize){
		if(Thead<=maxbufspace)
		{
			/*the buffer is full: the packet is lost*/
			pOpen->Dropped++;
			return NDIS_STATUS_NOT_ACCEPTED;
		}
		else{
			Ttail=0;
		}
	}

	if((Ttail<Thead)&&(Ttail+maxbufspace>=Thead))
	{
		/*the buffer is full: the packet is lost*/
		pOpen->Dropped++;
		return NDIS_STATUS_NOT_ACCEPTED;
	}
	CurrBuff=pOpen->Buffer+Ttail;


	/*allocate the ndis buffer*/
	NdisAllocateBuffer(	&Status, 
						&pNdisBuffer, 
						pOpen->BufferPool, 
						CurrBuff+sizeof(struct bpf_hdr),
						fres);

	if (Status != NDIS_STATUS_SUCCESS)
		{
			pOpen->Dropped++;
			return NDIS_STATUS_NOT_ACCEPTED;
		}

	/*allocate the packet from NDIS*/
	NdisAllocatePacket(&Status,&pPacketb,pOpen->PacketPool);
	    if (Status != NDIS_STATUS_SUCCESS)
		{
			NdisFreeBuffer( pNdisBuffer );
			pOpen->Dropped++;
			return NDIS_STATUS_NOT_ACCEPTED;
		}
	/*link the buffer to the packet*/
	NdisChainBufferAtFront(pPacketb,pNdisBuffer);

	if ( uiHeaderBufferSize > 0 ) 
	{
		if ( uiHeaderBufferSize > pNdisBuffer->Length )
			uiHeaderBufferSize = pNdisBuffer->Length;
		/*copy the header*/
		NdisMoveMemory(pNdisBuffer->VirtualAddress, pvHeaderBuffer, uiHeaderBufferSize );		
		uiBytesTransferred = uiHeaderBufferSize;
		(BYTE *)(pNdisBuffer->VirtualAddress) += uiHeaderBufferSize;
		pNdisBuffer->Length -= uiHeaderBufferSize;
	}
	
	ulSizeToTransfer = uiPacketSize;
	if ( ulSizeToTransfer > pNdisBuffer->Length )
		ulSizeToTransfer = pNdisBuffer->Length;

	/*Copy the remaining part of the packet*/
	NdisTransferData(	&Status,					
						pOpen->AdapterHandle,		
						MacReceiveContext,			
						0,		
						ulSizeToTransfer,			
						pPacketb,					
						&uiBytesTransferred );		

	uiBytesTransferred+=uiHeaderBufferSize;


	/*get the capture time*/
	lCapTime=QuerySystemTime();

 	/*fill the bpf header for this packet*/
	if( fres>uiBytesTransferred )fres=uiBytesTransferred;
	lCapTime+=pOpen->StartTime;
	header=(struct bpf_hdr*)CurrBuff;
	header->bh_tstamp.tv_usec=(long)((lCapTime%1193182)*1000000/1193182);
	header->bh_tstamp.tv_sec=(long)((lCapTime)/1193182);
	header->bh_caplen=(UINT)fres;
	header->bh_datalen=(UINT)uiPacketSize+uiHeaderBufferSize;
	header->bh_hdrlen=sizeof(struct bpf_hdr);

	/*update the buffer*/	
	Ttail+=Packet_WORDALIGN(fres+sizeof(struct bpf_hdr));
	if(Ttail>Thead)TLastByte=Ttail;
	pOpen->Btail=Ttail;
	pOpen->BLastByte=TLastByte;

	/*free the allocated buffer*/
	NdisFreeBuffer( pNdisBuffer );
	/*recylcle the packet*/
	NdisReinitializePacket(pPacketb);
	/*Put the packet on the free queue*/
	NdisFreePacket(pPacketb);

    TEvent=pOpen->ReadEvent;
	_asm mov eax,TEvent;
	VxDCall(_VWIN32_SetWin32Event);

	TRACE_LEAVE( "Packet_tap" );
    return NDIS_STATUS_SUCCESS;


	}

	/*cancel the timeout on this read call*/
	to=pOpen->ReadTimeoutTimer;
	_asm push esi;
	_asm mov esi,to;
	CancelReadTimeOut();
	_asm pop esi;
	pOpen->ReadTimeoutTimer=0;


	pReserved = CONTAINING_RECORD( PacketListEntry, PACKET_RESERVED, ListElement );
	pPacket   = CONTAINING_RECORD( pReserved, NDIS_PACKET, ProtocolReserved );
	IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) 
	{
		IF_TRACE_MSG( "   Reserved : %lx", pReserved );
		IF_TRACE_MSG( "    pPacket : %lx", pPacket );
		IF_TRACE_MSG2( "     Header : %lx  %lx", pvHeaderBuffer, uiHeaderBufferSize );
		IF_TRACE_MSG2( "  LookAhead : %lx  %lx", pvLookAheadBuffer, uiLookaheadBufferSize );
		IF_TRACE_MSG( " PacketSize : %lx", uiPacketSize );
	}
	PACKETASSERT( (pReserved != NULL) );
	PACKETASSERT( (pPacket != NULL) );

	pNdisBuffer = pPacket->Private.Head;
	/*virtual address of the buffer that will contain the packet*/
	pvActualVirtualAddress	= pNdisBuffer->VirtualAddress;
	uiActualLength			= pNdisBuffer->Length;
	
	CurrBuff=pNdisBuffer->VirtualAddress;
	(BYTE *)(pNdisBuffer->VirtualAddress) += sizeof(struct bpf_hdr);


	if ( uiHeaderBufferSize > 0 ) 
	{
		if ( uiHeaderBufferSize > pNdisBuffer->Length )
			uiHeaderBufferSize = pNdisBuffer->Length;
		/*copy the header*/
		NdisMoveMemory(pNdisBuffer->VirtualAddress, pvHeaderBuffer, uiHeaderBufferSize );		
		uiBytesTransferred = uiHeaderBufferSize;
		(BYTE *)(pNdisBuffer->VirtualAddress) += uiHeaderBufferSize;
		pNdisBuffer->Length -= uiHeaderBufferSize;
	}
	
	ulSizeToTransfer = uiPacketSize/*uiPacketSize - uiLookaheadBufferSize*/;
	if ( ulSizeToTransfer > pNdisBuffer->Length )
		ulSizeToTransfer = pNdisBuffer->Length;

	/*Copy the remaining part of the packet*/
	NdisTransferData(	&Status,					
						pOpen->AdapterHandle,		
						MacReceiveContext,			
						0,		
						ulSizeToTransfer,			
						pPacket,					
						&uiBytesTransferred );		

	uiBytesTransferred+=uiHeaderBufferSize;


	pNdisBuffer->VirtualAddress = pvActualVirtualAddress;
	pNdisBuffer->Length			= uiActualLength;
	if ( Status != NDIS_STATUS_PENDING ) 
	{

		/*store the capture time*/
		lCapTime=QuerySystemTime();

		/*fill the bpf header for this packet*/
		if( fres>uiBytesTransferred )fres=uiBytesTransferred;
			lCapTime+=pOpen->StartTime;
			header=(struct bpf_hdr*)CurrBuff;
			header->bh_tstamp.tv_usec=(long)((lCapTime%1193182)*1000000/1193182);
			header->bh_tstamp.tv_sec=(long)((lCapTime)/1193182);
			header->bh_caplen=(UINT)fres;
			header->bh_datalen=(UINT)uiPacketSize+uiHeaderBufferSize;
			header->bh_hdrlen=sizeof(struct bpf_hdr);
			/*call the completion routine*/
			PacketTransferDataComplete(	pOpen,				
										pPacket,			
										Status,				
										fres);

	}
	else
	{
		Status = NDIS_STATUS_SUCCESS;
		PacketTransferDataComplete(	pOpen,			
									pPacket,		
									Status,			
									0 );			
		
	}
	TRACE_LEAVE( "Packet_tap" );
	return NDIS_STATUS_SUCCESS;
}

/*Ends the transfer started with the Packet_tap function*/
VOID NDIS_API
PacketTransferDataComplete (	IN NDIS_HANDLE   ProtocolBindingContext,
								IN PNDIS_PACKET  pPacket,
								IN NDIS_STATUS   Status,
								IN UINT          uiBytesTransferred
   )
{
	PPACKET_RESERVED	pReserved;
	OVERLAPPED*			pOverlap;
	PNDIS_BUFFER		pNdisBuffer;
	TRACE_ENTER( "TransferDataComplete" );
	pReserved = (PPACKET_RESERVED) pPacket->ProtocolReserved;
	pOverlap  = (OVERLAPPED *) pReserved->lpoOverlapped;
	PACKETASSERT( (pOpen != NULL) );
	PACKETASSERT( (pReserved != NULL) );
	PACKETASSERT( (pOverlap != NULL) );
	
	IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) 
	{
		IF_TRACE_MSG( "     Status : %lx", Status );
		IF_TRACE_MSG( "BytesXfered : %lx", uiBytesTransferred );
		IF_TRACE_MSG( "Byte Offset : %lx", *(pReserved->lpcbBytesReturned) );
	}

	NdisUnchainBufferAtFront( pPacket, &pNdisBuffer );
	PACKETASSERT( (pNdisBuffer != NULL) );
	if ( pNdisBuffer )
		NdisFreeBuffer( pNdisBuffer );
	
	*(pReserved->lpcbBytesReturned) = uiBytesTransferred+sizeof(struct bpf_hdr);
	pOverlap->O_InternalHigh         = *(pReserved->lpcbBytesReturned);
	/*wakes the application process*/
	VWIN32_DIOCCompletionRoutine( pOverlap->O_Internal );
	
	PacketPageUnlock( pReserved->lpBuffer, pReserved->cbBuffer );
	PacketPageUnlock( pReserved->lpcbBytesReturned, sizeof(DWORD) );
	PacketPageUnlock( pReserved->lpoOverlapped, sizeof(OVERLAPPED) );
	
	NdisReinitializePacket( pPacket );
	
	NdisFreePacket( pPacket );
	TRACE_LEAVE( "TransferDataComplete" );
	return;
}

VOID NDIS_API
PacketReceiveComplete( IN NDIS_HANDLE  ProtocolBindingContext )
{
	IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) 
	{
		TRACE_ENTER( "ReceiveComplete" );
		TRACE_LEAVE( "ReceiveComplete" );
	}
	return;
}

/************************************************************
Routine called by the kernel when the timeout set in the 
PacketRead function expires
************************************************************/
void _cdecl ReadTimeout(void)
{
	POPEN_INSTANCE Open;
    PLIST_ENTRY         PacketListEntry;
    PNDIS_PACKET        pPacket;
	PPACKET_RESERVED	Reserved;
	OVERLAPPED*			pOverlap;
	PNDIS_BUFFER		pNdisBuffer;
	PUCHAR				CurrBuff;
	struct bpf_hdr		*header;
	UINT				to;
	__int64				lCapTime;

	//the parameter is in edx
	_asm{
		mov	Open,edx
	}

	NdisAcquireSpinLock( &Open->RcvQSpinLock );
	PacketListEntry = PacketRemoveHeadList( &Open->RcvList );
	NdisReleaseSpinLock( &Open->RcvQSpinLock );
	Open->ReadTimeoutTimer=0;

    if (PacketListEntry == NULL)
    {
		return;
	}

    Reserved=CONTAINING_RECORD(PacketListEntry,PACKET_RESERVED,ListElement);
    pPacket=CONTAINING_RECORD(Reserved,NDIS_PACKET,ProtocolReserved);

	Reserved = (PPACKET_RESERVED) pPacket->ProtocolReserved;
	pOverlap  = (OVERLAPPED *) Reserved->lpoOverlapped;

	if(Open->mode==1){
	//count mode
		pNdisBuffer = pPacket->Private.Head;
		CurrBuff=pNdisBuffer->VirtualAddress;

		/*get system time*/
		lCapTime=QuerySystemTime();
	 	/*fill the bpf header for this packet*/
		lCapTime+=Open->StartTime;
		header=(struct bpf_hdr*)CurrBuff;
		header->bh_tstamp.tv_usec=(long)((lCapTime%1193182)*1000000/1193182);
		header->bh_tstamp.tv_sec=(long)((lCapTime)/1193182);
		header->bh_caplen=(UINT)16;
		header->bh_datalen=(UINT)16;
		header->bh_hdrlen=sizeof(struct bpf_hdr);

		*(__int64*)(CurrBuff+sizeof(struct bpf_hdr))=Open->Npackets;
		*(__int64*)(CurrBuff+sizeof(struct bpf_hdr)+8)=Open->Nbytes;

		//reset the countetrs
		 Open->Npackets=0;
		 Open->Nbytes=0;

		NdisUnchainBufferAtFront( pPacket, &pNdisBuffer );
		if ( pNdisBuffer )
			NdisFreeBuffer( pNdisBuffer );

		*(Reserved->lpcbBytesReturned) = 16 + sizeof(struct bpf_hdr);
		pOverlap->O_InternalHigh = 16 + sizeof(struct bpf_hdr);
		VWIN32_DIOCCompletionRoutine( pOverlap->O_Internal );

		PacketPageUnlock( Reserved->lpBuffer, Reserved->cbBuffer );
		PacketPageUnlock( Reserved->lpcbBytesReturned, sizeof(DWORD) );
		PacketPageUnlock( Reserved->lpoOverlapped, sizeof(OVERLAPPED) );
	
		NdisReinitializePacket( pPacket );
	
		NdisFreePacket( pPacket );
		
		return;
	}

	NdisUnchainBufferAtFront( pPacket, &pNdisBuffer );
	if ( pNdisBuffer )
		NdisFreeBuffer( pNdisBuffer );

	//wakes the application process
	*(Reserved->lpcbBytesReturned) = 0;
	pOverlap->O_InternalHigh = *(Reserved->lpcbBytesReturned);

	VWIN32_DIOCCompletionRoutine( pOverlap->O_Internal );

	PacketPageUnlock( Reserved->lpBuffer, Reserved->cbBuffer );
	PacketPageUnlock( Reserved->lpcbBytesReturned, sizeof(DWORD) );
	PacketPageUnlock( Reserved->lpoOverlapped, sizeof(OVERLAPPED) );
	
	NdisReinitializePacket( pPacket );
	
	NdisFreePacket( pPacket );

	return;

}
