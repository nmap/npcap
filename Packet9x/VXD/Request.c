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

/************************************************************
Function that allows to perform a query on a network driver
or to set the parameters of an adapter.
************************************************************/
DWORD
PacketRequest(	POPEN_INSTANCE		Open,
				DWORD  				FunctionCode,
				DWORD  				dwDDB,
				DWORD				hDevice,
				PDIOCPARAMETERS 	pDiocParms )
{
	PLIST_ENTRY       RequestListEntry;
	PINTERNAL_REQUEST	pRequest;
	PPACKET_RESERVED  pReserved;
	PPACKET_OID_DATA	OidData;
	NDIS_STATUS			Status;
	TRACE_ENTER( "Request Packet" );
	/*extract a request from the list*/
	NdisAcquireSpinLock( &Open->RequestSpinLock );
	RequestListEntry = PacketRemoveHeadList(&Open->RequestList);
	NdisReleaseSpinLock( &Open->RequestSpinLock );
	if ( RequestListEntry == NULL ) 
	{
		IF_TRACE( "Request List Error" );
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		TRACE_LEAVE( "Request Packet" );
		return NDIS_STATUS_FAILURE/*NDIS_STATUS_SUCCESS*/;
	}
	pReserved = CONTAINING_RECORD( RequestListEntry, PACKET_RESERVED, ListElement );
	pRequest  = CONTAINING_RECORD( pReserved, INTERNAL_REQUEST, Reserved );
	OidData   = (PPACKET_OID_DATA)(pDiocParms->lpvInBuffer);
	if ( ( pDiocParms->cbInBuffer == pDiocParms->cbOutBuffer )	&&
	( pDiocParms->cbInBuffer >= sizeof(PACKET_OID_DATA) - 1 + OidData->Length) ) 
	{
		pReserved->lpBuffer			= (PVOID)PacketPageLock( pDiocParms->lpvInBuffer, 
									 					 pDiocParms->cbInBuffer );
		pReserved->lpcbBytesReturned= (PVOID)PacketPageLock( (PVOID)pDiocParms->lpcbBytesReturned,
													 sizeof(DWORD) );
		pReserved->lpoOverlapped	= (PVOID)PacketPageLock( (PVOID)pDiocParms->lpoOverlapped,
													 sizeof(OVERLAPPED) );
		pReserved->cbBuffer			= pDiocParms->cbInBuffer;
		if ( FunctionCode == BIOCSETOID ) 
		{
			pRequest->Request.RequestType              						= NdisRequestSetInformation;
			pRequest->Request.DATA.SET_INFORMATION.Oid 						= OidData->Oid;
			pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength	= OidData->Length;
			pRequest->Request.DATA.SET_INFORMATION.InformationBuffer 	  	= OidData->Data;
			IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )
			{
				IF_TRACE_MSG2( "Request Set: Oid=%08lx, Length=%08lx",
								OidData->Oid,
								OidData->Length );
			}
		} 
		else if ( FunctionCode == BIOCQUERYOID )
		{
			pRequest->Request.RequestType									= NdisRequestQueryInformation;
			pRequest->Request.DATA.QUERY_INFORMATION.Oid					= OidData->Oid;
			pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength= OidData->Length;
			pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer     	= OidData->Data;
			IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )		
			{
				IF_TRACE_MSG3( "Request Query: Type:%d Oid=%08lx, Length=%08lx",
								NdisRequestQueryInformation,
								OidData->Oid,
								OidData->Length );
			}
		}
		else
		{
			pRequest->Request.RequestType									= NdisRequestGeneric1;
			pRequest->Request.DATA.QUERY_INFORMATION.Oid					= OidData->Oid;
			pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength= OidData->Length;
			pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer     	= OidData->Data;
			IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )		
			{
				IF_TRACE_MSG3( "Request Statistic: Type:%d Oid=%08lx, Length=%08lx",
								NdisRequestGeneric1,
								OidData->Oid,
								OidData->Length );
			}
		}
		
		NdisRequest( &Status, Open->AdapterHandle, &pRequest->Request );

		if ( Status != NDIS_STATUS_PENDING )
		{
			PacketRequestComplete( Open, &pRequest->Request, Status );
			TRACE_LEAVE( "Request Packet" );
			return /*NDIS_STATUS_FAILURE*/NDIS_STATUS_SUCCESS;
		}
		TRACE_LEAVE( "Request Packet" );
		return (-1);	/*Return ERROR_IO_PENDING and block the application*/
	}
	else
	{
		IF_TRACE_MSG4( "Request Buffer Error: In=%lx Out=%lx Size=%lx Length=%lx",
						pDiocParms->cbInBuffer,
						pDiocParms->cbOutBuffer,
						sizeof( PACKET_OID_DATA ),
						OidData->Length
						);
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
	}
	TRACE_LEAVE( "Request Packet" );
	return NDIS_STATUS_FAILURE/*NDIS_STATUS_SUCCESS*/;
}


/************************************************************
Function called by NDIS to complete asynchornously a 
request
INPUT:	ProtocolBindingContext - Structure describing the 
		current adapter
		NdisRequest - Queue of NDIS internal requests
		Status - Status of the operation reported by NDIS
************************************************************/
VOID NDIS_API
PacketRequestComplete( IN NDIS_HANDLE		ProtocolBindingContext,
							  IN PNDIS_REQUEST	NdisRequest,
							  IN NDIS_STATUS		Status )
{
	POPEN_INSTANCE		Open;
	PINTERNAL_REQUEST	pRequest;
	PPACKET_RESERVED	pReserved;
	OVERLAPPED*			pOverlap;
	PPACKET_OID_DATA	oidData;

	TRACE_ENTER( "RequestComplete" );
	Open		= (POPEN_INSTANCE)ProtocolBindingContext;
	pRequest	= CONTAINING_RECORD( NdisRequest, INTERNAL_REQUEST, Request );
	pReserved 	= &pRequest->Reserved;
	pOverlap	= (OVERLAPPED *) pReserved->lpoOverlapped;
	oidData		= (PPACKET_OID_DATA)(pReserved->lpBuffer);
	#if DEBUG
		IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )		
		{
			ULONG		i;
			UCHAR*	pcData = oidData->Data;
			DbgPrint( "Packet: OID=%lx Status=%lx Buffer Length=%ld Buffer=%lx", 
			oidData->Oid, Status, oidData->Length, pcData );
			for ( i=0; i<oidData->Length; i++, pcData++ )
			{
				if ( i%16 == 0 )
					DbgPrint( "\r\nPacket: " );
				DbgPrint( "%02x ", *pcData );
			}
			DbgPrint( "\r\n" );
			IF_BREAK_SET;
		}
	#endif
	if ( Status == NDIS_STATUS_SUCCESS )
	{
		/*if the operation was succesful*/
		*(pReserved->lpcbBytesReturned)	= oidData->Length + sizeof(PACKET_OID_DATA) - 1;
		pOverlap->O_InternalHigh		= *(pReserved->lpcbBytesReturned);
	}
	else
	{
		/*if there is an error length contains the type of error*/
		*(pReserved->lpcbBytesReturned)	= 0;
		pOverlap->O_InternalHigh		= 0;
		oidData->Length = Status;
	}
	/*wakes the suspended process */
	VWIN32_DIOCCompletionRoutine( pOverlap->O_Internal );
	PacketPageUnlock( pReserved->lpBuffer, pReserved->cbBuffer );
	PacketPageUnlock( pReserved->lpcbBytesReturned, sizeof(DWORD) );
	PacketPageUnlock( pReserved->lpoOverlapped, sizeof(OVERLAPPED) );
	/*reinsert the request in the queue*/
	NdisAcquireSpinLock( &Open->RequestSpinLock );
	InsertTailList( &Open->RequestList, &pReserved->ListElement );
	NdisReleaseSpinLock( &Open->RequestSpinLock );
	TRACE_LEAVE( "RequestComplete" );
	return;
}
