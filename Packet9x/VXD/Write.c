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
#include <ndis.h>
#include <vwin32.h>
#include "debug.h"
#include "packet.h"
#include <ntddpack.h>
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
DWORD _stdcall MyPageLock(DWORD, DWORD);
void  _stdcall MyPageUnlock(DWORD, DWORD);

/************************************************************
Start the sending of a packet
************************************************************/
DWORD
PacketWrite(POPEN_INSTANCE	Open,
			DWORD  			dwDDB,
			DWORD  			hDevice,
			PDIOCPARAMETERS	pDiocParms
	)
{
	PNDIS_PACKET	pPacket;
	PNDIS_BUFFER 	pNdisBuffer;
	NDIS_STATUS		Status;
	TRACE_ENTER( "SendPacket" );

	PacketAllocatePacketBuffer( &Status, Open, &pPacket, pDiocParms, IOCTL_PROTOCOL_WRITE );
	if ( Status != NDIS_STATUS_SUCCESS )
	{
		return 0;
	}
	NdisSend( &Status, Open->AdapterHandle, pPacket );
	if ( Status != NDIS_STATUS_PENDING ) 
	{
		PacketSendComplete( Open, pPacket, Status );
	}
	TRACE_LEAVE( "SendPacket" );
	return(-1);	
}

/************************************************************
Function called by NDIS to indicate that the data transfer
is finished
************************************************************/
VOID NDIS_API
PacketSendComplete(	IN NDIS_HANDLE	ProtocolBindingContext,
					IN PNDIS_PACKET	pPacket,
					IN NDIS_STATUS	Status
   )
{
	PNDIS_BUFFER 		pNdisBuffer;
	PPACKET_RESERVED	Reserved = (PPACKET_RESERVED) pPacket->ProtocolReserved;

	TRACE_ENTER( "SendComplete" );
	
	NdisUnchainBufferAtFront( pPacket, &pNdisBuffer );
	if ( pNdisBuffer )
		NdisFreeBuffer( pNdisBuffer );
		
	VWIN32_DIOCCompletionRoutine( Reserved->lpoOverlapped->O_Internal );
		
	PacketPageUnlock( Reserved->lpBuffer, Reserved->cbBuffer );
	PacketPageUnlock( Reserved->lpcbBytesReturned, sizeof(DWORD) );
	PacketPageUnlock( Reserved->lpoOverlapped, sizeof(OVERLAPPED) );
	
	NdisReinitializePacket(pPacket);
		
	NdisFreePacket(pPacket);

	TRACE_LEAVE( "SendComplete" );
	return;
}
