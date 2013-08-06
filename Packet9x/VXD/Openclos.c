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
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG


void YieldExecution( void )
{
	VMMCall(Release_Time_Slice);
	VMMCall(Begin_Nest_Exec);
	VMMCall(Resume_Exec);
	VMMCall(End_Nest_Exec);
}

/************************************************************
Function called when the user level application performs a open
IOCTL. Opens the adapter.
************************************************************/

static NDIS_MEDIUM MediumArray[] = {
    NdisMedium802_3,
    NdisMediumWan,
    NdisMediumFddi,
    NdisMediumArcnet878_2,
    NdisMedium802_5
};

#define NUM_NDIS_MEDIA  (sizeof MediumArray / sizeof MediumArray[0])

DWORD PacketOpen(PNDIS_STRING AdapterName,DWORD dwDDB,DWORD hDevice,PDIOCPARAMETERS pDiocParms)
{

	LARGE_INTEGER		SystemTime;
	__int64				ltime1;
	PDEVICE_EXTENSION	pde;
	POPEN_INSTANCE 		oiNew;
	NDIS_STATUS			nsErrorStatus, nsOpenStatus;
	UINT           	i;
	UINT           	uiMedium;
	NDIS_STRING		NameStr;
	NDIS_STATUS	Status;


	pde = GlobalDeviceExtension;
	/*Allocate an element that describe an adapter*/
	NdisAllocateMemory( (PVOID *)&oiNew, sizeof( OPEN_INSTANCE ), 0, -1 );
	if ( oiNew == NULL ) 
	{
		return NDIS_STATUS_FAILURE;
	}
	NdisZeroMemory( (PVOID)oiNew, sizeof( OPEN_INSTANCE ) );
	/*allocate a pool for the packet headers*/

	NdisAllocatePacketPool( &nsErrorStatus,
							&(oiNew->PacketPool),
							TRANSMIT_PACKETS,
							sizeof(PACKET_RESERVED) );

	IF_TRACE_MSG( "PACKET_RESERVED_a :%lx",sizeof(PACKET_RESERVED));
	if ( nsErrorStatus != NDIS_STATUS_SUCCESS ) 
	{
		IF_TRACE_MSG( "Failed to allocate packet pool AllocStatus=%x", nsErrorStatus );
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		TRACE_LEAVE( "BindAdapter" );
		return NDIS_STATUS_FAILURE;
	}


	/*allocate a buffer pool for the packet data*/
	NdisAllocateBufferPool( &nsErrorStatus,
							&(oiNew->BufferPool),
							TRANSMIT_PACKETS );
	if ( nsErrorStatus != NDIS_STATUS_SUCCESS )
	{
		IF_TRACE_MSG( "Failed to allocate packet pool AllocStatus=%x", nsErrorStatus );
		NdisFreePacketPool( oiNew->PacketPool );
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		TRACE_LEAVE( "BindAdapter" );
		return NDIS_STATUS_FAILURE;
	}
	NdisAllocateSpinLock( &(oiNew->ResetSpinLock) );
	InitializeListHead( &(oiNew->ResetIrpList) );
	NdisAllocateSpinLock( &(oiNew->RcvQSpinLock) );
	InitializeListHead( &(oiNew->RcvList) );
	NdisAllocateSpinLock( &(oiNew->RequestSpinLock) );
	InitializeListHead( &(oiNew->RequestList) );

	for ( i=0;i<MAX_REQUESTS;i++ ) 
	{
		InsertTailList( &(oiNew->RequestList), &(oiNew->Requests[i].Reserved.ListElement) );
	}

	oiNew->Status = NDIS_STATUS_PENDING;

	/*initialize the timer variables for this session*/

	SystemTime=GetDate();	

	ltime1=((__int64)SystemTime.HighPart*86400);
	ltime1+=(__int64)(SystemTime.LowPart/1000);	//current time from 1980 in seconds
	ltime1+=(__int64)315532800;	//current time from 1970 (Unix format) in seconds
	ltime1*=1193182;
	ltime1+=(SystemTime.LowPart%1000)*1193182/1000; //current time from 1970 in ticks
	ltime1-=QuerySystemTime();	//boot time from 1970 in ticks
	oiNew->StartTime=ltime1;


	oiNew->Dropped=0;		//reset the dropped packets counter
	oiNew->Received=0;		//reset the received packets counter
	oiNew->bpfprogram=NULL;	//set an accept-all filter
	oiNew->bpfprogramlen=0;
	oiNew->BufSize=0;		//set an empty buffer
	oiNew->Buffer=NULL;		//reset the buffer
	oiNew->Bhead=0;
	oiNew->Btail=0;
	oiNew->BLastByte=0;
	oiNew->TimeOut=0;		//reset the timeouts
	oiNew->ReadTimeoutTimer=0;
	oiNew->mode=0;			//set capture mode
	oiNew->Nbytes=0;		//reset the counters
	oiNew->Npackets=0;
	oiNew->hDevice=hDevice;
	oiNew->tagProcess=pDiocParms->tagProcess;
	oiNew->ReadEvent=0;		//reset the read event

	NdisAllocateSpinLock( &(oiNew->CountersLock) );
	/*open the MAC driver calling NDIS*/
	NdisOpenAdapter( &nsOpenStatus,
					 &nsErrorStatus,
					 &oiNew->AdapterHandle,
					 &uiMedium,
					 MediumArray,
					 NUM_NDIS_MEDIA,
					 pde->NdisProtocolHandle,
					 oiNew,
					 AdapterName,
					 0,
					 NULL );

	IF_TRACE_MSG( "Open Status                   : %lx", nsOpenStatus );
	IF_TRACE_MSG( "Error Status                  : %lx", nsErrorStatus );
	IF_TRACE_MSG( "Completion Status             : %lx", oiNew->Status );

	if ( nsOpenStatus == NDIS_STATUS_PENDING )
	{
		while ( oiNew->Status == NDIS_STATUS_PENDING )
			YieldExecution();
	}
	else
	{
		PacketOpenAdapterComplete( oiNew, nsOpenStatus, nsErrorStatus );
	}

	Status = oiNew->Status;
	if ( Status != NDIS_STATUS_SUCCESS ) 
	{
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		return NDIS_STATUS_FAILURE;
	}
	else
	{

	}

	TRACE_LEAVE( "BindAdapter" );

	/*return succesfully*/
	return STATUS_SUCCESS;

}

/************************************************************
Function called when the user level application performs a Close
IOCTL. Closes the adapter and free the reources associated with it
************************************************************/

DWORD PacketClose(POPEN_INSTANCE Open,DWORD dwDDB,DWORD hDevice,PDIOCPARAMETERS pDiocParms)
{
	
	NDIS_STATUS			Status;
	NDIS_STATUS			nsErrorStatus;
	UINT				to;
	DWORD				TEvent;

	TRACE_ENTER( "PacketClose" );

	Open->BufSize=0;
	
	to=Open->ReadTimeoutTimer;
	Open->ReadTimeoutTimer=0;
	if(to!=0){
		_asm push esi;
		_asm mov esi,to;
		CancelReadTimeOut();
		_asm pop esi;
	}
	
	// Free the read event
	TEvent=Open->ReadEvent;
	_asm mov eax,TEvent;
	VxDCall(_VWIN32_CloseVxDHandle);
	
	//close the adapter
	NdisCloseAdapter(&nsErrorStatus,Open->AdapterHandle);
	if ( nsErrorStatus == NDIS_STATUS_PENDING )
	{
		while ( Open->Status == NDIS_STATUS_PENDING )
			YieldExecution();
		
		if(Open->Status!=NDIS_STATUS_SUCCESS){
			TRACE_LEAVE( "PacketClose" );
			return NDIS_STATUS_FAILURE;
		}
	}
	else
	{
		PacketUnbindAdapterComplete( Open, nsErrorStatus );
		if(nsErrorStatus!=NDIS_STATUS_SUCCESS){
			TRACE_LEAVE( "PacketClose" );
			return NDIS_STATUS_FAILURE;
		}
	}

	Status = Open->Status;
	
	if(Open->Buffer!=NULL)NdisFreeMemory(Open->Buffer,Open->BufSize,0);
	Open->Buffer=NULL;
	if(Open->bpfprogram!=NULL)NdisFreeMemory(Open->bpfprogram,Open->bpfprogramlen,0);
	
	//remove this adapter from the list of open adapters
	NdisAcquireSpinLock( &GlobalDeviceExtension->OpenSpinLock );
	RemoveEntryList(&(Open->ListElement));
	NdisReleaseSpinLock( &GlobalDeviceExtension->OpenSpinLock );

	NdisFreeMemory( Open, sizeof( OPEN_INSTANCE ) ,  0 );

	if(pDiocParms!=NULL)
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
	
	TRACE_LEAVE( "PacketClose" );
	return Status;
	
}

/************************************************************
Function used by NDIS to update the VXD when a new MAC driver
is added
************************************************************/
VOID NDIS_API PacketBindAdapter( OUT PNDIS_STATUS Status,
						 IN  NDIS_HANDLE  BindAdapterContext,
						 IN  PNDIS_STRING AdapterName,
						 IN  PVOID        SystemSpecific1,
						 IN  PVOID        SystemSpecific2 )
{
	PDEVICE_EXTENSION	pde;
	POPEN_INSTANCE		oiNew;
	NDIS_STATUS			nsErrorStatus, nsOpenStatus;
	UINT           		uiMedium;
	UINT           		i;
	PWRAPPER_PROTOCOL_BLOCK				pWPBlock;
	PNDIS_PROTOCOL_CHARACTERISTICS	pNPChar;
	PADAPTER_NAME		AName;
	PWRAPPER_MAC_BLOCK	pWMBlock;
	PNDIS_MAC_CHARACTERISTICS	  pNMChar;
    BYTE                *lpzName;


	TRACE_ENTER( "BindAdapter" );
	pde = GlobalDeviceExtension;
	/*Allocate an element that describe an adapter*/
	NdisAllocateMemory( (PVOID *)&AName, sizeof(ADAPTER_NAME), 0, -1 );
	if ( AName == NULL ) 
	{
		*Status = NDIS_STATUS_RESOURCES;
		return;
	}

	NdisAllocateMemory( (PVOID *)&oiNew, sizeof( OPEN_INSTANCE ), 0, -1 );
	if ( oiNew == NULL ) 
	{
		*Status = NDIS_STATUS_RESOURCES;
		return;
	}
	NdisZeroMemory( (PVOID)oiNew, sizeof( OPEN_INSTANCE ) );

	/*Save Binding Context*/
	oiNew->BindAdapterContext = BindAdapterContext;

    /*Save the device handle*/
    
    oiNew->hDevice = (DWORD) SystemSpecific1;

	/*allocate a pool for the packet headers*/

	NdisAllocatePacketPool( &nsErrorStatus,
							&(oiNew->PacketPool),
							TRANSMIT_PACKETS,
							sizeof(PACKET_RESERVED) );

	IF_TRACE_MSG( "PACKET_RESERVED_b :%lx",sizeof(PACKET_RESERVED));
	if ( nsErrorStatus != NDIS_STATUS_SUCCESS ) 
	{
		IF_TRACE_MSG( "Failed to allocate packet pool AllocStatus=%x", nsErrorStatus );
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		*Status = NDIS_STATUS_RESOURCES;
		TRACE_LEAVE( "BindAdapter" );
		return;
	}


	/*allocate a pool for the packet data*/

	NdisAllocateBufferPool( &nsErrorStatus,
							&(oiNew->BufferPool),
							TRANSMIT_PACKETS );
	if ( nsErrorStatus != NDIS_STATUS_SUCCESS )
	{
		IF_TRACE_MSG( "Failed to allocate packet pool AllocStatus=%x", nsErrorStatus );
		NdisFreePacketPool( oiNew->PacketPool );
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		*Status = NDIS_STATUS_RESOURCES;
		TRACE_LEAVE( "BindAdapter" );
		return;
	}
	NdisAllocateSpinLock( &(oiNew->ResetSpinLock) );
	InitializeListHead( &(oiNew->ResetIrpList) );
	NdisAllocateSpinLock( &(oiNew->RcvQSpinLock) );
	InitializeListHead( &(oiNew->RcvList) );
	NdisAllocateSpinLock( &(oiNew->RequestSpinLock) );
	InitializeListHead( &(oiNew->RequestList) );

	for ( i=0;i<MAX_REQUESTS;i++ ) 
	{
		InsertTailList( &(oiNew->RequestList), &(oiNew->Requests[i].Reserved.ListElement) );
	}
	oiNew->Status = NDIS_STATUS_PENDING;
	oiNew->BindAdapterContext = BindAdapterContext;

	/*open the MAC driver calling NDIS*/

	oiNew->hDevice=0;
	oiNew->tagProcess=0;

	NdisOpenAdapter( &nsOpenStatus,
					 &nsErrorStatus,
					 &oiNew->AdapterHandle,
					 &uiMedium,
					 MediumArray,
					 NUM_NDIS_MEDIA,
					 pde->NdisProtocolHandle,
					 oiNew,
					 AdapterName,
					 0,
					 NULL );
	IF_TRACE_MSG( "Open Status                   : %lx", nsOpenStatus );
	IF_TRACE_MSG( "Error Status                  : %lx", nsErrorStatus );
	IF_TRACE_MSG( "Completion Status             : %lx", oiNew->Status );
	if ( nsOpenStatus == NDIS_STATUS_PENDING )
	{
		while ( oiNew->Status == NDIS_STATUS_PENDING )
			YieldExecution();
	}
	else
	{
		PacketOpenAdapterComplete( oiNew, nsOpenStatus, nsErrorStatus );
	}

	pWPBlock = ((PWRAPPER_OPEN_BLOCK)(oiNew->AdapterHandle))->ProtocolHandle;
	pNPChar  = &pWPBlock->ProtocolCharacteristics;
	IF_TRACE_MSG( "Protocol                      : %s",  pNPChar->Name.Buffer );
	IF_TRACE_MSG( "Protocol Handle               : %lx", pde->NdisProtocolHandle );
	IF_TRACE_MSG( "PWRAPPER_OPEN_BLOCK           : %lx", oiNew->AdapterHandle );
	IF_TRACE_MSG( "PWRAPPER_PROTOCOL_BLOCK       : %lx", pWPBlock );
	IF_TRACE_MSG( "NDIS_PROTOCOL_CHARACTERISTICS : %lx", pNPChar );
	IF_TRACE_MSG( "Name                          : %lx", &pNPChar->Name );
	IF_TRACE_MSG( "Adapter Name                  : %s",  AdapterName->Buffer );
	*Status = oiNew->Status;

	if ( *Status != NDIS_STATUS_SUCCESS ) 
	{
		NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		IF_TRACE( "Bind Operation FAILED!" );
	}
	else
	{
		AName->realnamestr.Length=AdapterName->Length;
		AName->realnamestr.MaximumLength=AdapterName->MaximumLength;
		AName->realnamestr.Buffer=AName->realname;
		for(i=0;i<32;i++)AName->realname[i]=AdapterName->Buffer[i];

		pWMBlock = ((PWRAPPER_OPEN_BLOCK)(oiNew->AdapterHandle))->MacHandle;
		pNMChar  = &pWMBlock->MacCharacteristics;
		lpzName  = pNMChar->Name.Buffer;
		for(i=0;i<32;i++)AName->devicename[i]=lpzName[i];
		InsertTailList( &GlobalDeviceExtension->AdapterNames, &AName->ListElement);

		//close the adapter
		NdisCloseAdapter(&nsErrorStatus,oiNew->AdapterHandle);
		
		if ( nsErrorStatus == NDIS_STATUS_PENDING )
		{
			while ( oiNew->Status == NDIS_STATUS_PENDING )
				YieldExecution();
		}
		else
		{
			PacketUnbindAdapterComplete( oiNew, nsErrorStatus );
		}
		*Status = oiNew->Status;
		if ( *Status == NDIS_STATUS_SUCCESS )
		{
			//remove this adapter from the list of open adapters
			RemoveEntryList(&(oiNew->ListElement)); 
			//free the memory
			NdisFreeMemory( oiNew, sizeof( OPEN_INSTANCE ) ,  0 );
		}
		else
		{
			IF_TRACE( "Close Operation FAILED!" );
		}
	
	}

	TRACE_LEAVE( "BindAdapter" );
	return;
}

/************************************************************
Function called by NDIS to indicate the completion of a bind
************************************************************/
VOID NDIS_API
PacketOpenAdapterComplete(
   IN NDIS_HANDLE  ProtocolBindingContext,
   IN NDIS_STATUS  Status,
   IN NDIS_STATUS  OpenErrorStatus )
{
	POPEN_INSTANCE	Open;

	TRACE_ENTER( "BindAdapterComplete" );
	IF_TRACE_MSG2( "ErrorStatus=%x Status=%x", OpenErrorStatus, Status );
	Open = (POPEN_INSTANCE)ProtocolBindingContext;
	if ( Status == NDIS_STATUS_SUCCESS ) 
	{
		/*Insert the just opened NIC in the list of initialized NICs*/
		NdisAcquireSpinLock( &GlobalDeviceExtension->OpenSpinLock );
		InsertHeadList( &GlobalDeviceExtension->OpenList, &Open->ListElement );
		NdisReleaseSpinLock( &GlobalDeviceExtension->OpenSpinLock );
	}
	else
	{
		/*free resources.*/
		PacketFreeResources( Open );
		return;
	}
	Open->Status = Status;
	/*complete the binding*/
	NdisCompleteBindAdapter( Open->BindAdapterContext, Status, OpenErrorStatus );
	TRACE_LEAVE( "BindAdapterComplete" );
	return;
}

/************************************************************
Start the unbind of a network driver from the protocol driver
************************************************************/
VOID NDIS_API
PacketUnbindAdapter( OUT PNDIS_STATUS	Status,
					 IN  NDIS_HANDLE	ProtocolBindingContext,
					 IN  NDIS_HANDLE	UnbindContext )
{
	POPEN_INSTANCE	Open;
	NDIS_STATUS		nsCloseStatus;

	TRACE_ENTER( "UnbindAdapter" );


	Open = (POPEN_INSTANCE)ProtocolBindingContext;
	Open->BindAdapterContext = UnbindContext;
	/*clean the pending requests*/
	PacketCleanUp( Status, Open );
	Open->Status = NDIS_STATUS_PENDING;
	/*Calls NDIS to close the selected adapter*/

	NdisCloseAdapter( &nsCloseStatus, Open->AdapterHandle );
	if ( nsCloseStatus == NDIS_STATUS_PENDING )
	{
		while ( Open->Status == NDIS_STATUS_PENDING )
			YieldExecution();
	}
	else
	{
		PacketUnbindAdapterComplete( Open, nsCloseStatus );
	}
	*Status = Open->Status;
	if ( *Status == NDIS_STATUS_SUCCESS )
	{
		NdisFreeMemory( Open, sizeof( OPEN_INSTANCE ) ,  0 );
	}
	else
	{
		IF_TRACE( "Unbind Operation FAILED!" );
	}
	TRACE_LEAVE( "CloseAdapter" );

	return;
}

/************************************************************
Complete the unbind of a network driver from the protocol driver
************************************************************/
VOID NDIS_API 
PacketUnbindAdapterComplete( IN NDIS_HANDLE ProtocolBindingContext,
							 IN NDIS_STATUS Status	)
{
	POPEN_INSTANCE Open;

	TRACE_ENTER( "UnbindAdapterComplete" );
	Open = (POPEN_INSTANCE)ProtocolBindingContext;
	if ( Status == NDIS_STATUS_SUCCESS )
	{
		PacketFreeResources( Open );
	}
	Open->Status = Status;

	TRACE_LEAVE( "UnbindAdapterComplete" );
	return;
}

/************************************************************
free the resources allocated by an adapter
************************************************************/
VOID PacketFreeResources( POPEN_INSTANCE Open )
{
	NdisFreeSpinLock( &Open->RequestSpinLock );
	NdisFreeSpinLock( &Open->RcvQSpinLock );
	NdisFreeSpinLock( &Open->ResetSpinLock );
	NdisFreeBufferPool( Open->BufferPool );
	NdisFreePacketPool( Open->PacketPool );
}

/************************************************************
Function that frees the pending requests  
************************************************************/
VOID
PacketCleanUp(	PNDIS_STATUS	Status,
				POPEN_INSTANCE	Open )
{
	PLIST_ENTRY			PacketListEntry;
	PNDIS_PACKET   	pPacket;
	PPACKET_RESERVED  Reserved;

	TRACE_ENTER( "Cleanup" );
	/*clean all the pending requests*/
	NdisAcquireSpinLock( &(Open->RcvQSpinLock) );
	while( (PacketListEntry = PacketRemoveHeadList( &(Open->RcvList) )) != NULL )
	{
		IF_VERY_LOUD( "CleanUp - Completing read" );
		Reserved = CONTAINING_RECORD( PacketListEntry, PACKET_RESERVED, ListElement );
		pPacket  = CONTAINING_RECORD( Reserved, NDIS_PACKET, ProtocolReserved );
		/*emulate the end of a transfer to wake the processes that 
		are waiting on a request */
		PacketTransferDataComplete( Open, pPacket, NDIS_STATUS_SUCCESS, 0 );
	}
	NdisReleaseSpinLock( &(Open->RcvQSpinLock) );
	TRACE_LEAVE( "Cleanup" );
	return;
}

/************************************************************
Start the reset of a instance of the driver
************************************************************/
VOID
PacketReset( PNDIS_STATUS	pStatus,
			 POPEN_INSTANCE	pOpen )
{
	PLIST_ENTRY	ResetListEntry;

	TRACE_ENTER( "PacketReset" );

	NdisAcquireSpinLock( &pOpen->RequestSpinLock );
	ResetListEntry = PacketRemoveHeadList( &pOpen->RequestList );
	NdisReleaseSpinLock( &pOpen->RequestSpinLock );
	if ( ResetListEntry == NULL ) 
	{
		*pStatus = NDIS_STATUS_RESOURCES;
		TRACE_LEAVE( "PacketReset" );
		return;
	}
	NdisAcquireSpinLock( &pOpen->ResetSpinLock );
	InsertTailList( &pOpen->ResetIrpList, ResetListEntry );
	NdisReleaseSpinLock( &pOpen->ResetSpinLock );

	/*Call NDIS to reset the adapter*/
	NdisReset( pStatus, pOpen->AdapterHandle );
	if ( *pStatus != NDIS_STATUS_PENDING ) 
	{
		/*synchronous reset of the adapter*/
		PacketResetComplete( pOpen, *pStatus );
	}
	TRACE_LEAVE( "PacketReset" );
	return;
}
	
/************************************************************
complete the reset of a instance of the driver
************************************************************/
VOID NDIS_API
PacketResetComplete( IN NDIS_HANDLE	ProtocolBindingContext,
					 IN NDIS_STATUS	Status   )
{
	POPEN_INSTANCE		Open;
	PLIST_ENTRY			ResetListEntry;

	TRACE_ENTER( "PacketResetComplete" );
	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	NdisAcquireSpinLock( &Open->ResetSpinLock );
	ResetListEntry = PacketRemoveHeadList( &Open->ResetIrpList );
	NdisReleaseSpinLock( &Open->ResetSpinLock );
	if ( ResetListEntry == NULL ) 
	{
		IF_VERY_LOUD( "Reset List Empty Error" );
		TRACE_LEAVE( "PacketResetComplete" );
		return;
	}

	NdisAcquireSpinLock( &Open->RequestSpinLock );
	InsertTailList( &Open->RequestList, ResetListEntry );
	NdisReleaseSpinLock( &Open->RequestSpinLock );
	TRACE_LEAVE( "PacketResetComplete" );
	return;
}
