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
#include <vmmreg.h>
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG

/*head of the open instances*/
PDEVICE_EXTENSION GlobalDeviceExtension = 0;
UINT nOpen = 0;
POPEN_INSTANCE InstToClose[128];

/*number of processes attached to this driver*/
int Instances=0;


/************************************************************
    This routine initializes the Packet driver.
Arguments:
    DriverObject - Pointer to driver object created by system.
    RegistryPath - Pointer to the Unicode name of the registry path
        for this driver.
Return Value:
    The function value is the final status from the initialization operation.
************************************************************/
NTSTATUS
DriverEntry( IN PDRIVER_OBJECT	DriverObject,
				 IN PUNICODE_STRING	RegistryPath
	)
{
	NDIS_PROTOCOL_CHARACTERISTICS	ProtocolChar;
	NDIS_STRING	ProtoName = NDIS_STRING_CONST("PACKET");
   	NDIS_HANDLE NdisProtocolHandle;
	NDIS_STATUS	Status;
	TRACE_ENTER( "DriverEntry" );


	NdisAllocateMemory( (PVOID *)&GlobalDeviceExtension, sizeof( DEVICE_EXTENSION ), 0, -1 );
	if ( GlobalDeviceExtension != NULL )
	{
		NdisZeroMemory( (UCHAR*)GlobalDeviceExtension, sizeof(DEVICE_EXTENSION) );
		NdisZeroMemory( (UCHAR*)&ProtocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS) );
   		ProtocolChar.MajorNdisVersion            = 0x03;
		ProtocolChar.MinorNdisVersion            = 0x0A;
   		ProtocolChar.Reserved                    = 0;
		ProtocolChar.OpenAdapterCompleteHandler  = PacketOpenAdapterComplete;
   		ProtocolChar.CloseAdapterCompleteHandler = PacketUnbindAdapterComplete;
		ProtocolChar.SendCompleteHandler         = PacketSendComplete;
   		ProtocolChar.TransferDataCompleteHandler = PacketTransferDataComplete;
		ProtocolChar.ResetCompleteHandler        = PacketResetComplete;
   		ProtocolChar.RequestCompleteHandler      = PacketRequestComplete;
		ProtocolChar.ReceiveHandler              = Packet_tap;
   		ProtocolChar.ReceiveCompleteHandler      = PacketReceiveComplete;
		ProtocolChar.StatusHandler               = PacketStatus;
   		ProtocolChar.StatusCompleteHandler       = PacketStatusComplete;
   		ProtocolChar.BindAdapterHandler			 = PacketBindAdapter;
   		ProtocolChar.UnbindAdapterHandler        = PacketUnbindAdapter;
   		ProtocolChar.UnloadProtocolHandler       = PacketUnload;
		ProtocolChar.Name                        = ProtoName;
		NdisRegisterProtocol( &Status,
									 &GlobalDeviceExtension->NdisProtocolHandle,
									 &ProtocolChar,
									 sizeof(NDIS_PROTOCOL_CHARACTERISTICS) );
		if (Status != NDIS_STATUS_SUCCESS) 
   		{
			NdisFreeMemory( GlobalDeviceExtension, sizeof( DEVICE_EXTENSION ) ,  0 );
	   		IF_TRACE( "Failed to register protocol with NDIS" );
			INIT_LEAVE( "DriverEntry" );
			return Status;
   		}
		/*initializes the list of the open instances*/
		NdisAllocateSpinLock( &(GlobalDeviceExtension->OpenSpinLock) );
		InitializeListHead( &GlobalDeviceExtension->OpenList );
		GlobalDeviceExtension->DriverObject = DriverObject;

		if(Bind_Names() != NDIS_STATUS_SUCCESS)	return NDIS_STATUS_FAILURE;

  		IF_TRACE( "protocol registered with NDIS!!!" );
		INIT_LEAVE( "DriverEntry" );
		return Status;
	}
	IF_TRACE( "Memory Failure" );
	
	TRACE_LEAVE( "DriverEntry" );

	return NDIS_STATUS_RESOURCES;

}

/************************************************************
Function used to associate the names of the network devices 
with the internal NDIS names 
INPUT:
OUTPUT: NDIS_STATUS_SUCCESS if succesful, otherwise NDIS_STATUS_FAILURE
************************************************************/
DWORD Bind_Names(void){
	DWORD res;
	VMMHKEY Key,Key1;
	DWORD Klen,Klen1;
	char NdisName[64];
	char DevName[64];
	int i=0;
	PADAPTER_NAME AName;

	TRACE_ENTER( "Bind_Names" );

	// initialize the list of adapter names
	InitializeListHead( &GlobalDeviceExtension->AdapterNames);
	
	// change to HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Class\Net
	res=VMM_RegOpenKey(HKEY_LOCAL_MACHINE,"SYSTEM",&Key);
	res=VMM_RegOpenKey(Key,"CURRENTCONTROLSET",&Key);
	res=VMM_RegOpenKey(Key,"SERVICES",&Key);
	res=VMM_RegOpenKey(Key,"CLASS",&Key);
	res=VMM_RegOpenKey(Key,"NET",&Key);
	
	if(res!=ERROR_SUCCESS) return NDIS_STATUS_FAILURE;

	Klen=64;
	// Scan the list of the adapters
	while(VMM_RegEnumKey(Key,i,NdisName,Klen)==ERROR_SUCCESS)
	{
		res=VMM_RegOpenKey(Key,NdisName,&Key1);
		res=VMM_RegOpenKey(Key1,"NDIS",&Key1);
		Klen1=64;
		res=VMM_RegQueryValueEx(Key1,"LOGDRIVERNAME",NULL,NULL, DevName,&Klen1);
		if(res!=ERROR_SUCCESS){
			Klen=64;
			i++;
			continue;
		}
		
		NdisAllocateMemory( (PVOID *)&AName, sizeof(ADAPTER_NAME), 0, -1 );
		if ( AName == NULL ) 
		{
			return NDIS_STATUS_FAILURE;
		}

		NdisMoveMemory(AName->realname,NdisName,Klen);
		NdisMoveMemory(AName->devicename,DevName,Klen1);
		AName->realnamestr.Length=strlen(NdisName);
		AName->realnamestr.MaximumLength=Klen;
		AName->realnamestr.Buffer=AName->realname;

		InsertHeadList( &GlobalDeviceExtension->AdapterNames, &AName->ListElement);

		Klen=64;
		i++;
	}
	
	TRACE_LEAVE( "Bind_Names" );
	
	if(i==0) return NDIS_STATUS_FAILURE;
	else return NDIS_STATUS_SUCCESS;
	
}

/************************************************************
Callback function called by NDIS when the last insatnce of 
the packet driver is closed by the capture driver,
i.e. when the driver is unloaded
INPUT:
OUTPUT:
************************************************************/
VOID NDIS_API PacketUnload()
{
	TRACE_ENTER( "Unload" );

	TRACE_LEAVE( "Unload" );
	return;
}
/************************************************************
this function returns the descriptor of the adapter from 
the device ID and process tag 
INPUT: Name of the adapter to open
OUTPUT:	instance of the driver
************************************************************/
POPEN_INSTANCE GetRunningAdapter(DWORD hDevice,DWORD tagProcess)
{
	DWORD		dwBytes = 0; 
	DWORD		dwSec_Counter=1000; // Or something like that 
	BYTE		*lpzName; 
	POPEN_INSTANCE		pOpen; 
	PWRAPPER_MAC_BLOCK		pWMBlock; 
	PNDIS_MAC_CHARACTERISTICS		pNMChar; 
	PLIST_ENTRY                                   pEntry; 
	PLIST_ENTRY                                   pHead; 
	
	NdisAcquireSpinLock(&GlobalDeviceExtension->OpenSpinLock); 
	
	pHead = &(GlobalDeviceExtension->OpenList); 
	pOpen = 0; 
	
	pEntry=pHead->Flink; 
	
	do 
	{    
        pOpen = CONTAINING_RECORD( pEntry, OPEN_INSTANCE, ListElement ); 
        if((pOpen->hDevice==hDevice)&&(pOpen->tagProcess==tagProcess)){ 
			NdisReleaseSpinLock( &GlobalDeviceExtension->OpenSpinLock ); 
			return pOpen; 
		} 
		pEntry=pEntry->Flink; 
		dwSec_Counter--; 
		
	}while ((pEntry != pHead)&&(dwSec_Counter));
	
	NdisReleaseSpinLock( &GlobalDeviceExtension->OpenSpinLock ); 
	return NULL; 
}

/************************************************************
this function returns the NDIS name of an adapter given its
device name 
INPUT: Name of the adapter to open
OUTPUT:	instance of the driver
************************************************************/

PNDIS_STRING GetNDISAdapterName(BYTE* DeviceName)
{
    PADAPTER_NAME	pAdap;
	UINT			count=0;
	PLIST_ENTRY pHead = &(GlobalDeviceExtension->AdapterNames);
	PLIST_ENTRY pEntry;

	TRACE_ENTER( "GetNDISAdapterName" );	

	pEntry=pHead->Flink; 

	if(IsListEmpty(pHead)){
		if(Bind_Names()==NDIS_STATUS_FAILURE)
			return NULL;
	}
	
	do {    
		pAdap = CONTAINING_RECORD( pEntry, ADAPTER_NAME, ListElement );
		if(compare(pAdap->devicename,DeviceName)==1)return &(pAdap->realnamestr);
		pEntry=pEntry->Flink;
	}while (pEntry != pHead || count++>32); 

	TRACE_LEAVE( "GetNDISAdapterName" );
	  
	return NULL;
}

/************************************************************
This function evaluates the length of a string.
Useful to avoid the string library functions that are not 
defined at this level
************************************************************/
ULONG
strlen( BYTE *s )
{
	ULONG len = 0;
	while ( *s++ ) len++;
	return len;
}


/************************************************************
This function compares two strings
************************************************************/
BYTE compare(BYTE *s1,BYTE *s2)
{
	TRACE_ENTER( "compare" );	

	while (*s1 && *s2)
	{
		if (*s1!=*s2)  return (BYTE) 0;
					
		s1++;
		s2++;
			
	}

	TRACE_LEAVE( "compare" );

	if ((*s1==0) && (*s2==0)) return (BYTE) 1;
	else return (BYTE) 0;
} 

/************************************************************
Return the names of all the MAC drivers on which the driver 
is attached
INPUT:	dwDDB e hDevice - parameters coming from the 
		DeviceIOControl procedure, not used here.
OUTPUT:	pDiocParms - structure containing the returned buffer
************************************************************/

DWORD PacketGetMacNameList( DWORD  				dwDDB,
                      DWORD  				hDevice,
                      PDIOCPARAMETERS	pDiocParms ) 
{
	DWORD					          dwBytes = 0;
    BYTE				              *lpzName;
    PADAPTER_NAME	                  pAdap;
	PWRAPPER_MAC_BLOCK			      pWMBlock;
	PNDIS_MAC_CHARACTERISTICS		  pNMChar;
    ULONG                             uLength;
      
	PLIST_ENTRY pHead = &(GlobalDeviceExtension->AdapterNames);
	PLIST_ENTRY pEntry;

	TRACE_ENTER( "PacketGetMacNameList" );	

	pEntry=pHead->Flink; 
	do {    
	pAdap = CONTAINING_RECORD( pEntry, ADAPTER_NAME, ListElement );
	uLength  = strlen( pAdap->devicename );

	if ( uLength < pDiocParms->cbOutBuffer - dwBytes - 1 )
	{
		strcat( (BYTE*)(pDiocParms->lpvOutBuffer), pAdap->devicename );
		strcat( (BYTE*)(pDiocParms->lpvOutBuffer), " " );
		dwBytes += (uLength + 1);
	}
	else break;

	pEntry=pEntry->Flink;
	}while (pEntry != pHead); 
 	  
	*(ULONG*)(pDiocParms->lpcbBytesReturned) = dwBytes;
	IF_TRACE_MSG( "     Bytes Returned: %lu", *(ULONG*)(pDiocParms->lpcbBytesReturned) );
	
	TRACE_LEAVE( "PacketGetMacNameList" );	

	return NDIS_STATUS_SUCCESS;

}

/************************************************************
This is the dispatch routine for create/open and close requests.
These requests complete successfully.
INPUT:	dwDDB e hDevice - parameters sent by the DeviceIOControl procedure
		dwService - requested service
		pDiocParms - structure containing the parameters of the call
OUTPUT:	the status of the operation
************************************************************/

DWORD _stdcall PacketIOControl( DWORD  			dwService,
                                DWORD  			dwDDB,
                                DWORD  			hDevice,
                                PDIOCPARAMETERS pDiocParms ) 
{
	PUCHAR				tpointer;
	int					*StatsBuf;
	PUCHAR				prog;
	ULONG				dim,timeout;
	NDIS_STATUS			Status;
	PPACKET_OID_DATA	reqbuff;
	POPEN_INSTANCE		Open,tOpen;
	PNDIS_STRING		str;
	ULONG				mode;
	PLIST_ENTRY			pEntry;
	PLIST_ENTRY			pHead;
    PADAPTER_NAME		AName;
	UINT				i;
	SHORT				timezone;

	TRACE_ENTER( "DeviceIoControl" );

	if(!(dwService==IOCTL_PROTOCOL_MACNAME || 
		 dwService==IOCTL_OPEN || 
		 dwService==0)){
		Open=GetRunningAdapter(hDevice,pDiocParms->tagProcess);
		if(Open==NULL) return NDIS_STATUS_FAILURE;
	}

	switch ( dwService )
	{
	case IOCTL_OPEN:	//open message

		Instances++;

		//get the NDIS name of current adapter
		str=GetNDISAdapterName((BYTE*)pDiocParms->lpvInBuffer);

		if(str==NULL) return NDIS_STATUS_FAILURE;
		//try to open an instance of the adapter
		Status = PacketOpen( str, dwDDB, hDevice, pDiocParms);
		
		return Status;


	break;


	case BIOCGSTATS: //fuction to obtain the capture stats

		StatsBuf=(int*)pDiocParms->lpvOutBuffer;
		StatsBuf[0]=Open->Received;
		StatsBuf[1]=Open->Dropped;
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 8;
		return NDIS_STATUS_SUCCESS;

	break;


	case BIOCEVNAME: //fuction to set the shared Event

		Open->ReadEvent=((DWORD*)pDiocParms->lpvInBuffer)[0];
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;

		return NDIS_STATUS_SUCCESS;

	break;


	case BIOCSETF:  //fuction to set a new bpf filter

		/*free the previous buffer if it was present*/
		if(Open->bpfprogram!=NULL){
			NdisFreeMemory(Open->bpfprogram,Open->bpfprogramlen,0);
			Open->bpfprogram=NULL; //NULL means accept all 
			Open->bpfprogramlen=0;
		}

		/*get the pointer to the new program*/
		prog=(PUCHAR)pDiocParms->lpvInBuffer;

		/*before accepting the program we must check that it's valid
		Otherwise, a bogus program could easily crash the system*/
		
		Open->bpfprogramlen=pDiocParms->cbInBuffer;
		if(bpf_validate((struct bpf_insn*)prog,Open->bpfprogramlen/sizeof(struct bpf_insn))==0)
		{
			Open->bpfprogramlen=0;
			Open->bpfprogram=NULL; 
			return NDIS_STATUS_FAILURE; // filter not accepted
		}

		/*allocate the memory to contain the new filter program*/
		if(NdisAllocateMemory(&Open->bpfprogram,Open->bpfprogramlen, 0, -1 )==NDIS_STATUS_FAILURE)
		{
			// no memory
			Open->bpfprogramlen=0;
			Open->bpfprogram=NULL; 
			return NDIS_STATUS_FAILURE;
		}

		/*copy the program in the new buffer*/
		NdisMoveMemory(Open->bpfprogram,prog,Open->bpfprogramlen);

		/*reset the buffer that could contain packets that don't match the filter*/
		Open->Bhead=0;
		Open->Btail=0;
		Open->BLastByte=0;
		Open->Received=0;
		Open->Dropped=0;

		*(DWORD *)(pDiocParms->lpcbBytesReturned) = Open->bpfprogramlen;

	break;


	case BIOCSETBUFFERSIZE:	//function to set the dimension of the buffer for the packets

		/*get the size to allocate*/
		dim=((PULONG)pDiocParms->lpvInBuffer)[0];
		/*free the old buffer*/
		if(Open->Buffer!=NULL)
		NdisFreeMemory(Open->Buffer,Open->BufSize,0);

		Open->Buffer=NULL;
		/*allocate the new buffer*/
		
		if(dim>0){
			NdisAllocateMemory( (PVOID *)&tpointer,dim, 0, -1 );
			if (tpointer==NULL)
			{
				// no memory
				Open->BufSize=0;
				return NDIS_STATUS_FAILURE;
			}
			
			Open->Buffer=tpointer;
		}
			
		Open->Bhead=0;
		Open->Btail=0;
		Open->BLastByte=0;
		Open->BufSize=(UINT)dim;

		*(DWORD *)(pDiocParms->lpcbBytesReturned) = dim;
		
		break;

	case BIOCSMODE:

		mode=((PULONG)pDiocParms->lpvInBuffer)[0];
		if(mode==MODE_STAT){
			Open->mode=MODE_STAT;
			Open->Nbytes=0;
			Open->Npackets=0;

			if(Open->TimeOut==0)Open->TimeOut=1000;
		}
		else if(mode==MODE_CAPT){
			Open->mode=MODE_CAPT;
			return NDIS_STATUS_SUCCESS;
		}
		else{
			return NDIS_STATUS_FAILURE;
		}

		break;

	case BIOCSRTIMEOUT:

		timeout=((PULONG)pDiocParms->lpvInBuffer)[0];
		Open->TimeOut=timeout;

		*(DWORD *)(pDiocParms->lpcbBytesReturned) = timeout;

		break;

	case BIOCSTIMEZONE:

		timezone=((PSHORT)pDiocParms->lpvInBuffer)[0];

		Open->StartTime+=((__int64)timezone)*(__int64)1193182*60;

		*(DWORD *)(pDiocParms->lpcbBytesReturned) = timezone;

		break;

	case BIOCSWRITEREP: //set the writes repetition number

		Open->Nwrites=((PULONG)pDiocParms->lpvInBuffer)[0];

		*(DWORD *)(pDiocParms->lpcbBytesReturned) = Open->Nwrites;

		break;
	
	case DIOC_CLOSEHANDLE:
		Status=PacketClose( Open, dwDDB, hDevice, pDiocParms );

		Instances--;

		if(Instances<=0)
			if ( GlobalDeviceExtension )
			{
				//If any instance is still opened we must close it
				NdisAcquireSpinLock(&GlobalDeviceExtension->OpenSpinLock);
				
				nOpen=0;
				
				pHead = &(GlobalDeviceExtension->OpenList);
				if(pHead!=NULL && !IsListEmpty(pHead))
				{
					//count the number of open instances
					pEntry=pHead->Flink; 
					do {    
						tOpen = CONTAINING_RECORD( pEntry, OPEN_INSTANCE, ListElement );
						
						pEntry=pEntry->Flink;
						if(tOpen!=NULL)
							InstToClose[nOpen++]=tOpen;
						
					}while (pEntry != pHead); 
					
					for(i=0;i<nOpen;i++){
						PacketClose(InstToClose[i],0,InstToClose[i]->hDevice,NULL);				
					}
				}
				
				NdisReleaseSpinLock( &GlobalDeviceExtension->OpenSpinLock );
				
				//free the names' list
				pHead = &(GlobalDeviceExtension->AdapterNames);
				if(pHead!=NULL)
				{
					while((pEntry=PacketRemoveHeadList(pHead))!=NULL){
						AName= CONTAINING_RECORD( pEntry, ADAPTER_NAME, ListElement);
						NdisFreeMemory(AName,sizeof(ADAPTER_NAME),0);
					}
				}
				
				//unregister the protocol from NDIS
				NdisDeregisterProtocol( &Status, GlobalDeviceExtension->NdisProtocolHandle );
				
				//free the global device extension
				NdisFreeMemory(GlobalDeviceExtension,sizeof( DEVICE_EXTENSION ),0);
			}
		
		break;

	case IOCTL_PROTOCOL_RESET:

		PacketReset( &Status, Open );
	
		break;
	
	case BIOCQUERYOID:
	case BIOCSETOID:
	case IOCTL_PROTOCOL_STATISTICS:

		return PacketRequest( Open, dwService, dwDDB, hDevice, pDiocParms );

	case IOCTL_PROTOCOL_READ:

		return PacketRead( Open, dwDDB, hDevice, pDiocParms );

	case IOCTL_PROTOCOL_WRITE:

		return PacketWrite( Open, dwDDB, hDevice, pDiocParms );

	case IOCTL_PROTOCOL_MACNAME:

		PacketGetMacNameList( dwDDB, hDevice, pDiocParms );
		break;
      		
	default: 
		/*unknown function*/
		*(DWORD *)(pDiocParms->lpcbBytesReturned) = 0;
		break;
	}
   TRACE_LEAVE( "DeviceIoControl" );

   return NDIS_STATUS_SUCCESS;
}



/************************************************************
Function called by NDIS when there is something to communicate
to the upper level
************************************************************/
VOID
PacketStatus(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN NDIS_STATUS   Status,
    IN PVOID         StatusBuffer,
    IN UINT          StatusBufferSize
    )
{
   TRACE_ENTER( "Status Indication" );
   TRACE_LEAVE( "Status Indication" );
   return;
}

/************************************************************
Complete the previous call
************************************************************/
VOID NDIS_API
PacketStatusComplete(
    IN NDIS_HANDLE  ProtocolBindingContext
    )
{

   TRACE_ENTER( "StatusIndicationComplete" );
   TRACE_LEAVE( "StatusIndicationComplete" );
   return;
}

/************************************************************
Removes an element from a list.
Performs a check to see if the list is empty
************************************************************/
PLIST_ENTRY 
PacketRemoveHeadList(
    IN PLIST_ENTRY pListHead
    )
{
	if ( !IsListEmpty( pListHead ) )
	{
		PLIST_ENTRY pLE = RemoveHeadList( pListHead );
		return pLE;
	}

	return NULL;
}
