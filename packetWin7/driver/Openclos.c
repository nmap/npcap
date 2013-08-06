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
#include "..\..\Common\WpcapNames.h"


static
VOID
NPF_ReleaseOpenInstanceResources(POPEN_INSTANCE pOpen);

static NDIS_MEDIUM MediumArray[] = {
	NdisMedium802_3,
//	NdisMediumWan,
	NdisMediumFddi,
	NdisMediumArcnet878_2,
	NdisMediumAtm,
	NdisMedium802_5
};

#define NUM_NDIS_MEDIA  (sizeof MediumArray / sizeof MediumArray[0])

//Itoa. Replaces the buggy RtlIntegerToUnicodeString
void PacketItoa(UINT n,PUCHAR buf){
int i;

	for(i=0;i<20;i+=2){
		buf[18-i]=(n%10)+48;
		buf[19-i]=0;
		n/=10;
	}

}

/// Global start time. Used as an absolute reference for timestamp conversion.
struct time_conv G_Start_Time = {
	0,	
	{0, 0},	
};

ULONG g_NumOpenedInstances = 0;

BOOLEAN NPF_StartUsingBinding(
    IN POPEN_INSTANCE pOpen)
{
	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
	
	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);

	if (pOpen->AdapterBindingStatus != ADAPTER_BOUND)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		return FALSE;
	}
	
	pOpen->AdapterHandleUsageCounter++;

	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
	
	return TRUE;
}

VOID NPF_StopUsingBinding(
    IN POPEN_INSTANCE pOpen)
{
	ASSERT(pOpen != NULL);
//
//  There is no risk in calling this function from abobe passive level 
//  (i.e. DISPATCH, in this driver) as we acquire a spinlock and decrement a 
//  counter.
//
//	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);

	ASSERT(pOpen->AdapterHandleUsageCounter > 0);
	ASSERT(pOpen->AdapterBindingStatus == ADAPTER_BOUND);

	pOpen->AdapterHandleUsageCounter--;

	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
}

VOID
NPF_CloseBinding(
    IN POPEN_INSTANCE pOpen)
{
	NDIS_EVENT Event;
	NDIS_STATUS Status;

	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);

	while(pOpen->AdapterHandleUsageCounter > 0)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event,1);
		NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	}

	//
	// now the UsageCounter is 0
	//

	while(pOpen->AdapterBindingStatus == ADAPTER_UNBINDING)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event,1);
		NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	}

	//
	// now the binding status is either bound or unbound
	//

	if (pOpen->AdapterBindingStatus == ADAPTER_UNBOUND)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		return;
	}

	ASSERT(pOpen->AdapterBindingStatus == ADAPTER_BOUND);

	pOpen->AdapterBindingStatus = ADAPTER_UNBINDING;

	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);

	//
	// do the release procedure
	//
	NdisResetEvent(&pOpen->NdisOpenCloseCompleteEvent);

	// Close the adapter
	NdisCloseAdapter(
		&Status,
		pOpen->AdapterHandle
		);

	if (Status == NDIS_STATUS_PENDING)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Pending NdisCloseAdapter");
		NdisWaitEvent(&pOpen->NdisOpenCloseCompleteEvent, 0);
	}
	else
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Not Pending NdisCloseAdapter");
	}

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	pOpen->AdapterBindingStatus = ADAPTER_UNBOUND;
	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
}

//-------------------------------------------------------------------

NTSTATUS NPF_Open(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

	PDEVICE_EXTENSION	DeviceExtension;
	POPEN_INSTANCE		Open;
	PIO_STACK_LOCATION  IrpSp;
	NDIS_STATUS			Status;
	NDIS_STATUS			ErrorStatus;
	UINT				i;
	PUCHAR				tpointer;
	PLIST_ENTRY			PacketListEntry;
	NTSTATUS			returnStatus;

//  
//	Old registry based WinPcap names
//
//	WCHAR				EventPrefix[MAX_WINPCAP_KEY_CHARS];
//	UINT				RegStrLen;

	TRACE_ENTER();

	DeviceExtension = DeviceObject->DeviceExtension;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	//  allocate some memory for the open structure
	Open=ExAllocatePoolWithTag(NonPagedPool, sizeof(OPEN_INSTANCE), '0OWA');

	if (Open==NULL) {
		// no memory
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(
		Open,
		sizeof(OPEN_INSTANCE)
		);

//  
//	Old registry based WinPcap names
//
//	//
//	// Get the Event names base from the registry
//	//
//	RegStrLen = sizeof(EventPrefix)/sizeof(EventPrefix[0]);
//
//	NPF_QueryWinpcapRegistryString(NPF_EVENTS_NAMES_REG_KEY_WC,
//		EventPrefix,
//		RegStrLen,
//		NPF_EVENTS_NAMES_WIDECHAR);
//
		
	Open->DeviceExtension=DeviceExtension;

	//  Allocate a packet pool for our xmit and receive packets
	NdisAllocatePacketPool(
		&Status,
		&Open->PacketPool,
		TRANSMIT_PACKETS,
		sizeof(PACKET_RESERVED));

	if (Status != NDIS_STATUS_SUCCESS) {

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate packet pool");

		ExFreePool(Open);
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NdisInitializeEvent(&Open->WriteEvent);
	NdisInitializeEvent(&Open->NdisRequestEvent);
	NdisInitializeEvent(&Open->NdisWriteCompleteEvent);
	NdisInitializeEvent(&Open->DumpEvent);
	NdisAllocateSpinLock(&Open->MachineLock);
	NdisAllocateSpinLock(&Open->WriteLock);
	Open->WriteInProgress = FALSE;

	for (i = 0; i < g_NCpu; i++)
	{
		NdisAllocateSpinLock(&Open->CpuData[i].BufferLock);
	}

	NdisInitializeEvent(&Open->NdisOpenCloseCompleteEvent);

	//  list to hold irp's want to reset the adapter
	InitializeListHead(&Open->ResetIrpList);

	//  Initialize the request list
	KeInitializeSpinLock(&Open->RequestSpinLock);
	InitializeListHead(&Open->RequestList);

#ifdef HAVE_BUGGY_TME_SUPPORT
	// Initializes the extended memory of the NPF machine
	Open->mem_ex.buffer = ExAllocatePoolWithTag(NonPagedPool, DEFAULT_MEM_EX_SIZE, '2OWA');
	if((Open->mem_ex.buffer) == NULL)
	{
		//
		// no memory
		//
		ExFreePool(Open);
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Open->mem_ex.size = DEFAULT_MEM_EX_SIZE;
	RtlZeroMemory(Open->mem_ex.buffer, DEFAULT_MEM_EX_SIZE);
#endif //HAVE_BUGGY_TME_SUPPORT


	//
	// Initialize the open instance
	//
	Open->bpfprogram = NULL;	//reset the filter
	Open->mode = MODE_CAPT;
	Open->Nbytes.QuadPart = 0;
	Open->Npackets.QuadPart = 0;
	Open->Nwrites = 1;
	Open->Multiple_Write_Counter = 0;
	Open->MinToCopy = 0;
	Open->TimeOut.QuadPart = (LONGLONG)1;
	Open->DumpFileName.Buffer = NULL;
	Open->DumpFileHandle = NULL;
#ifdef HAVE_BUGGY_TME_SUPPORT
	Open->tme.active = TME_NONE_ACTIVE;
#endif // HAVE_BUGGY_TME_SUPPORT
	Open->DumpLimitReached = FALSE;
	Open->MaxFrameSize = 0;
	Open->WriterSN=0;
	Open->ReaderSN=0;
	Open->Size=0;
	Open->SkipSentPackets = FALSE;
	Open->ReadEvent = NULL;

	//
	// we need to keep a counter of the pending IRPs
	// so that when the IRP_MJ_CLEANUP dispatcher gets called,
	// we can wait for those IRPs to be completed
	//
	Open->NumPendingIrps = 0;
	Open->ClosePending = FALSE;
	NdisAllocateSpinLock(&Open->OpenInUseLock);

	//
	//allocate the spinlock for the statistic counters
	//
	NdisAllocateSpinLock(&Open->CountersLock);

	//
	//  link up the request stored in our open block
	//
	for (i = 0 ; i < MAX_REQUESTS ; i++ ) 
	{
		NdisInitializeEvent(&Open->Requests[i].InternalRequestCompletedEvent);

		ExInterlockedInsertTailList(
			&Open->RequestList,
			&Open->Requests[i].ListElement,
			&Open->RequestSpinLock);
	}

	NdisResetEvent(&Open->NdisOpenCloseCompleteEvent);

	// 
	// set the proper binding flags before trying to open the MAC
	//
	Open->AdapterBindingStatus = ADAPTER_BOUND;
	Open->AdapterHandleUsageCounter = 0;
	NdisAllocateSpinLock(&Open->AdapterHandleLock);

	//
	//  Try to open the MAC
	//
	TRACE_MESSAGE2(PACKET_DEBUG_LOUD,"Opening the device %ws, BindingContext=%p",DeviceExtension->AdapterName.Buffer, Open);

	returnStatus = STATUS_SUCCESS;

	NdisOpenAdapter(
		&Status,
		&ErrorStatus,
		&Open->AdapterHandle,
		&Open->Medium,
		MediumArray,
		NUM_NDIS_MEDIA,
		g_NdisProtocolHandle,
		Open,
		&DeviceExtension->AdapterName,
		0,
		NULL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD,"Opened the device, Status=%x",Status);

	if (Status == NDIS_STATUS_PENDING)
	{
		NdisWaitEvent(&Open->NdisOpenCloseCompleteEvent, 0);

		if (!NT_SUCCESS(Open->OpenCloseStatus))
		{
			returnStatus = Open->OpenCloseStatus;
		}
		else
		{
			returnStatus = STATUS_SUCCESS;
		}
	}
	else
	{
		//
		// request not pending, we know the result, and OpenComplete has not been called.
		//
		if (Status == NDIS_STATUS_SUCCESS)
		{
			returnStatus = STATUS_SUCCESS;
		}
		else
		{
			//
			// this is not completely correct, as we are converting an NDIS_STATUS to a NTSTATUS
			//
			returnStatus = Status;

		}
	}

	if (returnStatus == STATUS_SUCCESS)
	{
		ULONG localNumOpenedInstances;	
		//
		// complete the open
		//
		localNumOpenedInstances = InterlockedIncrement(&g_NumOpenedInstances);

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Opened Instances: %u", localNumOpenedInstances);

		// Get the absolute value of the system boot time.
		// This is used for timestamp conversion.
		TIME_SYNCHRONIZE(&G_Start_Time);

		returnStatus = NPF_GetDeviceMTU(Open, Irp, &Open->MaxFrameSize);

		if (!NT_SUCCESS(returnStatus))
		{
			//
			// Close the binding
			//
			NPF_CloseBinding(Open);
		}
	}

	if (!NT_SUCCESS(returnStatus))
	{
		NPF_ReleaseOpenInstanceResources(Open);
		//
		// Free the open instance itself
		//
		ExFreePool(Open);
		
	}
	else
	{
		//  Save or open here
		IrpSp->FileObject->FsContext=Open;
	}

	Irp->IoStatus.Status = returnStatus;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return returnStatus;
}

BOOLEAN 
NPF_StartUsingOpenInstance(
				   IN POPEN_INSTANCE pOpen
				   )
{
	BOOLEAN returnStatus;

	NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	if (pOpen->ClosePending)
	{
		returnStatus = FALSE;
	}
	else
	{
		returnStatus = TRUE;
		pOpen->NumPendingIrps ++;
	}
	NdisReleaseSpinLock(&pOpen->OpenInUseLock);

	return returnStatus;
}

VOID
NPF_StopUsingOpenInstance(
				  IN POPEN_INSTANCE pOpen
				  )
{
	NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	ASSERT(pOpen->NumPendingIrps > 0);
	pOpen->NumPendingIrps --;
	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}

VOID
NPF_CloseOpenInstance(
				IN POPEN_INSTANCE pOpen
				)
{
	ULONG i = 0;
	NDIS_EVENT Event;

	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->OpenInUseLock);

	pOpen->ClosePending = TRUE;

	while(pOpen->NumPendingIrps > 0)
	{
		NdisReleaseSpinLock(&pOpen->OpenInUseLock);
		NdisWaitEvent(&Event,1);
		NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	}

	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}


VOID
NPF_ReleaseOpenInstanceResources(POPEN_INSTANCE pOpen)
{
		PKEVENT pEvent;
		UINT i;

		TRACE_ENTER();

		ASSERT(pOpen != NULL);
		ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open= %p", pOpen);

		NdisFreePacketPool(pOpen->PacketPool);

#ifdef HAVE_BUGGY_TME_SUPPORT
		//
		// free mem_ex
		//
		pOpen->mem_ex.size = 0;
		if(pOpen->mem_ex.buffer != NULL)
			ExFreePool(pOpen->mem_ex.buffer);
#endif //HAVE_BUGGY_TME_SUPPORT

		//
		// Free the filter if it's present
		//
		if(pOpen->bpfprogram != NULL)
			ExFreePool(pOpen->bpfprogram);

//
// Jitted filters are supported on x86 (32bit) only
// 
#ifdef _X86_
		// Free the jitted filter if it's present
		if(pOpen->Filter != NULL)
			BPF_Destroy_JIT_Filter(pOpen->Filter);
#endif //_X86_

		//
		// Dereference the read event.
		//

		if (pOpen->ReadEvent != NULL)
            ObDereferenceObject(pOpen->ReadEvent);

		//
		// free the buffer
		// NOTE: the buffer is fragmented among the various CPUs, but the base pointer of the
		// allocated chunk of memory is stored in the first slot (pOpen->CpuData[0])
		//
		if (pOpen->Size > 0)
			ExFreePool(pOpen->CpuData[0].Buffer);

		//
		// free the per CPU spinlocks
		//
		for (i = 0; i < g_NCpu; i++)
		{
			NdisFreeSpinLock(&Open->CpuData[i].BufferLock);
		}

		//
		// Free the string with the name of the dump file
		//
		if(pOpen->DumpFileName.Buffer!=NULL)
			ExFreePool(pOpen->DumpFileName.Buffer);

		TRACE_EXIT();
}


//-------------------------------------------------------------------

VOID NPF_OpenAdapterComplete(
	IN NDIS_HANDLE  ProtocolBindingContext,
    IN NDIS_STATUS  Status,
    IN NDIS_STATUS  OpenErrorStatus)
{

	POPEN_INSTANCE		Open;
	PLIST_ENTRY			RequestListEntry;
	PINTERNAL_REQUEST	MaxSizeReq;
	NDIS_STATUS			ReqStatus;

	TRACE_ENTER();

	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	ASSERT(Open != NULL);

	if (Status != NDIS_STATUS_SUCCESS) 
	{
		//
		// this is not completely correct, as we are converting an NDIS_STATUS to a NTSTATUS
		//
		Open->OpenCloseStatus = Status;
	}
	else 
	{
		Open->OpenCloseStatus = STATUS_SUCCESS;
	}

	//
	// wake up the caller of NdisOpen, that is NPF_Open
	//
	NdisSetEvent(&Open->NdisOpenCloseCompleteEvent);
	
	TRACE_EXIT();
}
 
NTSTATUS
NPF_GetDeviceMTU(
			 IN POPEN_INSTANCE pOpen,
			 IN PIRP	pIrp,
			 OUT PUINT  pMtu)
{
    PLIST_ENTRY			RequestListEntry;
	PINTERNAL_REQUEST	MaxSizeReq;
	NDIS_STATUS			ReqStatus;

	TRACE_ENTER();

	ASSERT(pOpen != NULL);
	ASSERT(pIrp != NULL);
	ASSERT(pMtu != NULL);

	// Extract a request from the list of free ones
	RequestListEntry = ExInterlockedRemoveHeadList(&pOpen->RequestList, &pOpen->RequestSpinLock);

	if (RequestListEntry == NULL)
	{
		//
		// THIS IS WRONG
		//

		//
		// Assume Ethernet
		//
		*pMtu = 1514;	
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}

	MaxSizeReq = CONTAINING_RECORD(RequestListEntry, INTERNAL_REQUEST, ListElement);

	MaxSizeReq->Request.RequestType = NdisRequestQueryInformation;
	MaxSizeReq->Request.DATA.QUERY_INFORMATION.Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;

	MaxSizeReq->Request.DATA.QUERY_INFORMATION.InformationBuffer = pMtu;
	MaxSizeReq->Request.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof(*pMtu);

	NdisResetEvent(&MaxSizeReq->InternalRequestCompletedEvent);

	//  submit the request
	NdisRequest(
		&ReqStatus,
		pOpen->AdapterHandle,
		&MaxSizeReq->Request);

	if (ReqStatus == NDIS_STATUS_PENDING)
	{
		NdisWaitEvent(&MaxSizeReq->InternalRequestCompletedEvent, 0);
		ReqStatus = MaxSizeReq->RequestStatus;
	}

	//
	// Put the request in the list of the free ones
	//
	ExInterlockedInsertTailList(&pOpen->RequestList, &MaxSizeReq->ListElement, &pOpen->RequestSpinLock);

	if (ReqStatus == NDIS_STATUS_SUCCESS)
	{
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
	else
	{
		//
		// THIS IS WRONG
		//

		//
		// Assume Ethernet
		//
		*pMtu = 1514;	

		TRACE_EXIT();
		return STATUS_SUCCESS;
	
		// return ReqStatus;
	}
}


//-------------------------------------------------------------------
NTSTATUS
NPF_Close(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	POPEN_INSTANCE    pOpen;
	PIO_STACK_LOCATION  IrpSp;
	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	pOpen = IrpSp->FileObject->FsContext;

	ASSERT(pOpen != NULL);
	//
	// Free the open instance itself
	//
	ExFreePool(pOpen);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------
NTSTATUS
NPF_Cleanup(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{

	POPEN_INSTANCE    Open;
	NDIS_STATUS     Status;
	PIO_STACK_LOCATION  IrpSp;
	LARGE_INTEGER ThreadDelay;
	ULONG localNumOpenInstances;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	Open = IrpSp->FileObject->FsContext;
	
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open = %p\n", Open);

	ASSERT(Open != NULL);

	NPF_CloseOpenInstance(Open);

	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent,0,FALSE);

	NPF_CloseBinding(Open);
	
	// NOTE:
	// code commented out because the kernel dump feature is disabled
	//
	//if (AdapterAlreadyClosing == FALSE)
	//{

	//	
	//	 Unfreeze the consumer
	//	
	//	if(Open->mode & MODE_DUMP)
	//		NdisSetEvent(&Open->DumpEvent);
	//	else
	//		KeSetEvent(Open->ReadEvent,0,FALSE);

	//	//
	//	// If this instance is in dump mode, complete the dump and close the file
	//	//
	//	if((Open->mode & MODE_DUMP) && Open->DumpFileHandle != NULL)
	//	{
	//		NTSTATUS wres;

	//		ThreadDelay.QuadPart = -50000000;

	//		//
	//		// Wait the completion of the thread
	//		//
	//		wres = KeWaitForSingleObject(Open->DumpThreadObject,
	//			UserRequest,
	//			KernelMode,
	//			TRUE,
	//			&ThreadDelay);

	//		ObDereferenceObject(Open->DumpThreadObject);

	//		//
	//		// Flush and close the dump file
	//		//
	//		NPF_CloseDumpFile(Open);
	//	}
	//}


	//
	// release all the resources
	//
	NPF_ReleaseOpenInstanceResources(Open);

//	IrpSp->FileObject->FsContext = NULL;
	
	//
	// Decrease the counter of open instances
	//
	localNumOpenInstances = InterlockedDecrement(&g_NumOpenedInstances);
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Opened Instances: %u", localNumOpenInstances);

	if(localNumOpenInstances == 0)
	{
		//
		// Force a synchronization at the next NPF_Open().
		// This hopefully avoids the synchronization issues caused by hibernation or standby.
		//
		TIME_DESYNCHRONIZE(&G_Start_Time);
	}


	//
	// and complete the IRP with status success
	//
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

	return(STATUS_SUCCESS);
}

//-------------------------------------------------------------------

VOID
NPF_CloseAdapterComplete(IN NDIS_HANDLE  ProtocolBindingContext,IN NDIS_STATUS  Status)
{
    POPEN_INSTANCE    Open;
    PIRP              Irp;

	TRACE_ENTER();

	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	ASSERT(Open != NULL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open= %p", Open);

	NdisSetEvent(&Open->NdisOpenCloseCompleteEvent);

	TRACE_EXIT();
	return;

}
//-------------------------------------------------------------------

#ifdef NDIS50
NDIS_STATUS
NPF_PowerChange(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT pNetPnPEvent)
{
	TRACE_ENTER();
	
	TIME_DESYNCHRONIZE(&G_Start_Time);
	TIME_SYNCHRONIZE(&G_Start_Time);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}
#endif

//-------------------------------------------------------------------

VOID
NPF_BindAdapter(
    OUT PNDIS_STATUS            Status,
    IN  NDIS_HANDLE             BindContext,
    IN  PNDIS_STRING            DeviceName,
    IN  PVOID                   SystemSpecific1,
    IN  PVOID                   SystemSpecific2
    )
{
	TRACE_ENTER();
	TRACE_EXIT();
}

//-------------------------------------------------------------------

VOID
NPF_UnbindAdapter(
    OUT PNDIS_STATUS        Status,
    IN  NDIS_HANDLE         ProtocolBindingContext,
    IN  NDIS_HANDLE         UnbindContext
    )
{
    POPEN_INSTANCE   Open =(POPEN_INSTANCE)ProtocolBindingContext;

	TRACE_ENTER();

	ASSERT(Open != NULL);

	//
	// The following code has been disabled bcause the kernel dump feature has been disabled.
	//
	////
	//// Awake a possible pending read on this instance
	//// TODO should be ok.
	////
 //	if(Open->mode & MODE_DUMP)
 //		NdisSetEvent(&Open->DumpEvent);
 //	else
	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent,0,FALSE);

	//
	// The following code has been disabled bcause the kernel dump feature has been disabled.
	//
	////
	//// If this instance is in dump mode, complete the dump and close the file
	//// TODO needs to be checked again.
	////
 //	if((Open->mode & MODE_DUMP) && Open->DumpFileHandle != NULL)
 //		NPF_CloseDumpFile(Open);

	*Status = NDIS_STATUS_SUCCESS;

	NPF_CloseBinding(Open);

	TRACE_EXIT();
	return;
}

//-------------------------------------------------------------------

VOID
NPF_ResetComplete(IN NDIS_HANDLE  ProtocolBindingContext,IN NDIS_STATUS  Status)

{
    POPEN_INSTANCE      Open;
    PIRP                Irp;

    PLIST_ENTRY         ResetListEntry;

	TRACE_ENTER();

    Open = (POPEN_INSTANCE)ProtocolBindingContext;

    //
    //  remove the reset IRP from the list
    //
    ResetListEntry=ExInterlockedRemoveHeadList(
                       &Open->ResetIrpList,
                       &Open->RequestSpinLock
                       );

    Irp=CONTAINING_RECORD(ResetListEntry,IRP,Tail.Overlay.ListEntry);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

    return;

}
