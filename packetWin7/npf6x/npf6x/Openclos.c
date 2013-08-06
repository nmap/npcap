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

#include "stdafx.h"

#include <ntddk.h>
#include <ndis.h>

#include "debug.h"
#include "packet.h"
#include "..\..\..\Common\WpcapNames.h"


static
VOID NPF_ReleaseOpenInstanceResources(POPEN_INSTANCE pOpen);

static NDIS_MEDIUM MediumArray[] =
{
	NdisMedium802_3,
	//	NdisMediumWan,
	NdisMediumFddi, NdisMediumArcnet878_2, NdisMediumAtm, NdisMedium802_5
};

#define NUM_NDIS_MEDIA  (sizeof MediumArray / sizeof MediumArray[0])

//Itoa. Replaces the buggy RtlIntegerToUnicodeString
// void PacketItoa(UINT n, PUCHAR buf)
// {
// 	int i;
// 	for(i=0;i<20;i+=2){
// 		buf[18-i]=(n%10)+48;
// 		buf[19-i]=0;
// 		n/=10;
// 	}
// }

/// Global start time. Used as an absolute reference for timestamp conversion.
struct time_conv G_Start_Time =
{
	0, {0, 0},
};

ULONG g_NumOpenedInstances = 0;

extern POPEN_INSTANCE g_arrOpen;

BOOLEAN NPF_StartUsingBinding(IN POPEN_INSTANCE pOpen)
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

VOID NPF_StopUsingBinding(IN POPEN_INSTANCE pOpen)
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

VOID NPF_CloseBinding(IN POPEN_INSTANCE pOpen)
{
	NDIS_EVENT Event;
	NDIS_STATUS Status;

	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);

	while (pOpen->AdapterHandleUsageCounter > 0)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event, 1);
		NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	}

	//
	// now the UsageCounter is 0
	//

	while (pOpen->AdapterBindingStatus == ADAPTER_UNBINDING)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event, 1);
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
	// 	NdisResetEvent(&pOpen->NdisOpenCloseCompleteEvent);
	// 
	// 	// Close the adapter
	// 	Status = NdisCloseAdapterEx(pOpen->AdapterHandle);
	// 
	// 	if (Status == NDIS_STATUS_PENDING)
	// 	{
	// 		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Pending NdisCloseAdapter");
	// 		NdisWaitEvent(&pOpen->NdisOpenCloseCompleteEvent, 0);
	// 	}
	// 	else
	// 	{
	// 		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Not Pending NdisCloseAdapter");
	// 	}
	TRACE_MESSAGE(PACKET_DEBUG_LOUD, "No need to call NdisCloseAdapter here");

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	pOpen->AdapterBindingStatus = ADAPTER_UNBOUND;
	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
}

VOID NPF_CloseBindingAndAdapter(IN POPEN_INSTANCE pOpen)
{
	NDIS_EVENT Event;
	NDIS_STATUS Status;

	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);

	while (pOpen->AdapterHandleUsageCounter > 0)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event, 1);
		NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	}

	//
	// now the UsageCounter is 0
	//

	while (pOpen->AdapterBindingStatus == ADAPTER_UNBINDING)
	{
		NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
		NdisWaitEvent(&Event, 1);
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
	Status = NdisCloseAdapterEx(pOpen->AdapterHandle);

	if (Status == NDIS_STATUS_PENDING)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Pending NdisCloseAdapter");
		NdisWaitEvent(&pOpen->NdisOpenCloseCompleteEvent, 0);
	}
	else
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Not Pending NdisCloseAdapter");
	}
	TRACE_MESSAGE(PACKET_DEBUG_LOUD, "No need to call NdisCloseAdapter here");

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	pOpen->AdapterBindingStatus = ADAPTER_UNBOUND;
	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
}

//-------------------------------------------------------------------

NTSTATUS NPF_OpenAdapter(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PDEVICE_EXTENSION DeviceExtension;
	POPEN_INSTANCE Open;
	PIO_STACK_LOCATION IrpSp;
	NDIS_STATUS Status;
	NDIS_STATUS ErrorStatus;
	UINT i;
	PUCHAR tpointer;
	PLIST_ENTRY PacketListEntry;
	NTSTATUS returnStatus;
	ULONG localNumOpenedInstances;	

	NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
	NDIS_OPEN_PARAMETERS OpenParameters;
	NET_FRAME_TYPE FrameTypeArray[2] =
	{
		NDIS_ETH_TYPE_802_1X, NDIS_ETH_TYPE_802_1Q
	};

	//  
	//	Old registry based WinPcap names
	//
	//	WCHAR				EventPrefix[MAX_WINPCAP_KEY_CHARS];
	//	UINT				RegStrLen;

	TRACE_ENTER();

	DeviceExtension = DeviceObject->DeviceExtension;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	Open = NPF_GetCopyFromOpenArray(&DeviceExtension->AdapterName, DeviceExtension);

	if (Open == NULL)
	{
		//cannot find the adapter from the global open array.
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
	}

	Open->DeviceExtension = DeviceExtension;
	TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Opening the device %ws, BindingContext=%p", DeviceExtension->AdapterName.Buffer, Open);

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
		IrpSp->FileObject->FsContext = Open;
	}

	NPF_AddToOpenArray(Open);
	NPF_AddToGroupOpenArray(Open);

	Irp->IoStatus.Status = returnStatus;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return returnStatus;
}

BOOLEAN NPF_StartUsingOpenInstance(IN POPEN_INSTANCE pOpen)
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

VOID NPF_StopUsingOpenInstance(IN POPEN_INSTANCE pOpen)
{
	NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	ASSERT(pOpen->NumPendingIrps > 0);
	pOpen->NumPendingIrps --;
	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}

VOID NPF_CloseOpenInstance(IN POPEN_INSTANCE pOpen)
{
	ULONG i = 0;
	NDIS_EVENT Event;

	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->OpenInUseLock);

	pOpen->ClosePending = TRUE;

	while (pOpen->NumPendingIrps > 0)
	{
		NdisReleaseSpinLock(&pOpen->OpenInUseLock);
		NdisWaitEvent(&Event, 1);
		NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	}

	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}


VOID NPF_ReleaseOpenInstanceResources(POPEN_INSTANCE pOpen)
{
	PKEVENT pEvent;
	UINT i;

	TRACE_ENTER();

	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open= %p", pOpen);

	//Release the adapter name
	if (pOpen->AdapterName.MaximumLength != 0)
	{
		NdisFreeString(pOpen->AdapterName);
		pOpen->AdapterName.Buffer = NULL;
		pOpen->AdapterName.Length = 0;
		pOpen->AdapterName.MaximumLength = 0;
	}

	//NdisFreePacketPool(pOpen->PacketPool);
	if (pOpen->PacketPool)
	{
		NdisFreeNetBufferListPool(pOpen->PacketPool);
		pOpen->PacketPool = NULL;
	}

	//
	// Free the filter if it's present
	//
	if (pOpen->bpfprogram != NULL)
		ExFreePool(pOpen->bpfprogram);

	//
	// Jitted filters are supported on x86 (32bit) only
	// 
#ifdef _X86_
	// Free the jitted filter if it's present
	if (pOpen->Filter != NULL)
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
		NdisFreeSpinLock(&pOpen->CpuData[i].BufferLock);
	}

	//
	// Free the string with the name of the dump file
	//
	if (pOpen->DumpFileName.Buffer != NULL)
		ExFreePool(pOpen->DumpFileName.Buffer);

	TRACE_EXIT();
}


//-------------------------------------------------------------------

VOID NPF_OpenAdapterCompleteEx(IN NDIS_HANDLE  ProtocolBindingContext, IN NDIS_STATUS  Status)
{
	POPEN_INSTANCE Open;
	PLIST_ENTRY RequestListEntry;
	PINTERNAL_REQUEST MaxSizeReq;
	NDIS_STATUS ReqStatus;

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

NTSTATUS NPF_GetDeviceMTU(IN POPEN_INSTANCE pOpen, IN PIRP	pIrp, OUT PUINT  pMtu)
{
	PLIST_ENTRY RequestListEntry;
	PINTERNAL_REQUEST MaxSizeReq;
	NDIS_STATUS ReqStatus;

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
	ReqStatus = NdisOidRequest(pOpen->AdapterHandle, &MaxSizeReq->Request);

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
NTSTATUS NPF_CloseAdapter(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	POPEN_INSTANCE pOpen;
	PIO_STACK_LOCATION IrpSp;
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

NTSTATUS NPF_CloseAdapterForUnclosed(POPEN_INSTANCE pOpen)
{
	TRACE_ENTER();

	ASSERT(pOpen != NULL);
	//
	// Free the open instance itself
	//
	ExFreePool(pOpen);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------
NTSTATUS NPF_Cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	POPEN_INSTANCE Open;
	NDIS_STATUS Status;
	PIO_STACK_LOCATION IrpSp;
	LARGE_INTEGER ThreadDelay;
	ULONG localNumOpenInstances;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	Open = IrpSp->FileObject->FsContext;

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open = %p\n", Open);

	ASSERT(Open != NULL);

	NPF_RemoveFromOpenArray(Open);
	NPF_RemoveFromGroupOpenArray(Open);

	NPF_CloseOpenInstance(Open);

	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent, 0, FALSE);

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

	if (localNumOpenInstances == 0)
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
NTSTATUS NPF_CleanupForUnclosed(POPEN_INSTANCE Open)
{
	NDIS_STATUS Status;
	LARGE_INTEGER ThreadDelay;
	ULONG localNumOpenInstances;

	TRACE_ENTER();

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open = %p\n", Open);

	ASSERT(Open != NULL);

	NPF_RemoveFromOpenArray(Open);
	NPF_RemoveFromGroupOpenArray(Open);

	NPF_CloseOpenInstance(Open);

	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent, 0, FALSE);

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

	if (localNumOpenInstances == 0)
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

	TRACE_EXIT();

	return(STATUS_SUCCESS);
}

//-------------------------------------------------------------------

VOID NPF_CloseAdapterCompleteEx(IN NDIS_HANDLE  ProtocolBindingContext)
{
	POPEN_INSTANCE Open;
	PIRP Irp;

	TRACE_ENTER();

	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	ASSERT(Open != NULL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open= %p", Open);

	NdisSetEvent(&Open->NdisOpenCloseCompleteEvent);

	TRACE_EXIT();
	return;
}

//-------------------------------------------------------------------

NDIS_STATUS NPF_NetPowerChange(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT_NOTIFICATION pNetPnPEvent)
{
	TRACE_ENTER();

	TIME_DESYNCHRONIZE(&G_Start_Time);
	TIME_SYNCHRONIZE(&G_Start_Time);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

void NPF_AddToOpenArray(POPEN_INSTANCE Open)
{
	POPEN_INSTANCE CurOpen;
	TRACE_ENTER();

	if (g_arrOpen == NULL)
	{
		g_arrOpen = Open;
	}
	else
	{
		CurOpen = g_arrOpen;
		while (CurOpen->Next != NULL)
		{
			CurOpen = CurOpen->Next;
		}
		CurOpen->Next = Open;
	}

	TRACE_EXIT();
}

void NPF_AddToGroupOpenArray(POPEN_INSTANCE Open)
{
	POPEN_INSTANCE CurOpen;
	POPEN_INSTANCE GroupRear;
	TRACE_ENTER();

	if (Open->DirectBinded)
	{
		IF_LOUD(DbgPrint("NPF_AddToGroupOpenArray: never should be here.\n");)
		TRACE_EXIT();
		return;
	}

	for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
	{
		if (NPF_CompareAdapterName(&CurOpen->AdapterName, &Open->AdapterName) == 0 && CurOpen->DirectBinded)
		{
			GroupRear = CurOpen;
			while (GroupRear->GroupNext != NULL)
			{
				GroupRear = GroupRear->GroupNext;
			}
			GroupRear->GroupNext = Open;
			Open->GroupHead = CurOpen;

			TRACE_EXIT();
			return;
		}
	}

	IF_LOUD(DbgPrint("NPF_AddToGroupOpenArray: never should be here.\n");)
	TRACE_EXIT();
}

void NPF_RemoveFromOpenArray(POPEN_INSTANCE Open)
{
	POPEN_INSTANCE CurOpen = NULL;
	POPEN_INSTANCE PrevOpen = NULL;

	if (Open == NULL)
	{
		return;
	}

	for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
	{
		if (CurOpen == Open)
		{
			if (CurOpen == g_arrOpen)
			{
				g_arrOpen = CurOpen->Next;
			}
			else
			{
				PrevOpen->Next = CurOpen->Next;
			}
			//return;
		}
		PrevOpen = CurOpen;
	}
}

void NPF_RemoveFromGroupOpenArray(POPEN_INSTANCE Open)
{
	POPEN_INSTANCE CurOpen;
	POPEN_INSTANCE GroupOpen;
	POPEN_INSTANCE GroupPrev = NULL;
	TRACE_ENTER();

	if (Open->DirectBinded)
	{
		IF_LOUD(DbgPrint("NPF_RemoveFromGroupOpenArray: never should be here.\n");)
		TRACE_EXIT();
		return;
	}

	GroupOpen = Open->GroupHead;
	while (GroupOpen)
	{
		if (GroupOpen == Open)
		{
			if (GroupPrev == NULL)
			{
				ASSERT(GroupPrev != NULL);
				IF_LOUD(DbgPrint("NPF_RemoveFromGroupOpenArray: never should be here.\n");)
				TRACE_EXIT();
				return;
			}
			else
			{
				GroupPrev->GroupNext = GroupOpen->GroupNext;
				TRACE_EXIT();
				return;
			}
		}
		GroupPrev = GroupOpen;
		GroupOpen = GroupOpen->GroupNext;
	}

	IF_LOUD(DbgPrint("NPF_RemoveFromGroupOpenArray: never should be here.\n");)
	TRACE_EXIT();
}

//\Device\{C0EF51E2-3E9E-4FFA-92D3-53FE1969E6C2}
//\Device\NdisWanIp
//\DEVICE\{C0EF51E2-3E9E-4FFA-92D3-53FE1969E6C2}
//\DEVICE\NdisWanIp
int NPF_CompareAdapterName(PNDIS_STRING s1, PNDIS_STRING s2)
{
	int i;
	WCHAR buf1[255];
	WCHAR buf2[255];
	TRACE_ENTER();

	wcscpy(buf1, s1->Buffer);
	wcscpy(buf2, s2->Buffer);
	if (wcslen(buf1) < 7 || wcslen(buf2) < 7)
	{
		IF_LOUD(DbgPrint("NPF_CompareAdapterName: never should be here.\n");)
		TRACE_EXIT();
		return -1;
	}

	for (i = 1; i < 7; i ++)
	{
		if (buf1[i] >= L'A' && buf1[i] <= L'Z')
		{
			buf1[i] += ('a' - 'A');
		}
		if (buf2[i] >= L'A' && buf2[i] <= L'Z')
		{
			buf2[i] += ('a' - 'A');
		}
	}
	TRACE_EXIT();
	return wcscmp(buf1, buf2);
}

POPEN_INSTANCE NPF_GetCopyFromOpenArray(PNDIS_STRING pAdapterName, PDEVICE_EXTENSION DeviceExtension)
{
	POPEN_INSTANCE CurOpen;
	TRACE_ENTER();

	for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
	{
		if (NPF_CompareAdapterName(&CurOpen->AdapterName, pAdapterName) == 0)
		{
			return NPF_DuplicateOpenObject(CurOpen, DeviceExtension);
		}
	}

	TRACE_EXIT();
	return NULL;
}

void NPF_RemoveUnclosedAdapters()
{
	POPEN_INSTANCE CurOpen;
	POPEN_INSTANCE Open;
	BOOLEAN NoDirectedBindedRemaining = TRUE;
	TRACE_ENTER();

	for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
	{
		if (CurOpen->DirectBinded)
		{
			NoDirectedBindedRemaining = FALSE;
		}
	}

	if (NoDirectedBindedRemaining)
	{
		for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
		{
			NPF_CleanupForUnclosed(CurOpen);
			NPF_CloseAdapterForUnclosed(CurOpen);
		}
		
	}

	TRACE_EXIT();
}

POPEN_INSTANCE NPF_DuplicateOpenObject(POPEN_INSTANCE OriginalOpen, PDEVICE_EXTENSION DeviceExtension)
{
	POPEN_INSTANCE Open;
	TRACE_ENTER();

	Open = NPF_CreateOpenObject(&OriginalOpen->AdapterName, OriginalOpen->Medium, DeviceExtension);
	Open->AdapterHandle = OriginalOpen->AdapterHandle;
	Open->DirectBinded = FALSE;

	TRACE_EXIT();
	return Open;
}

POPEN_INSTANCE NPF_CreateOpenObject(PNDIS_STRING AdapterName, UINT SelectedIndex, PDEVICE_EXTENSION DeviceExtension)
{
	POPEN_INSTANCE Open;
	UINT i;
	NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
	TRACE_ENTER();

	//  allocate some memory for the open structure
	Open = ExAllocatePoolWithTag(NonPagedPool, sizeof(OPEN_INSTANCE), '0OWA');

	if (Open == NULL)
	{
		// no memory
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate memory pool");

		return NULL;
	}

	RtlZeroMemory(Open, sizeof(OPEN_INSTANCE));

	Open->DeviceExtension = DeviceExtension; //can be NULL before any actual bindings.
	Open->DirectBinded = TRUE;

	NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
	PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	PoolParameters.Header.Size = sizeof(PoolParameters);
	PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_TCP_IP;
	PoolParameters.ContextSize = 0;
	PoolParameters.fAllocateNetBuffer = TRUE;
	PoolParameters.PoolTag = NPF6X_ALLOC_TAG;

	Open->PacketPool = NdisAllocateNetBufferListPool(NULL, &PoolParameters);
	if (Open->PacketPool == NULL)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate packet pool");

		ExFreePool(Open);

		return NULL;
	}

	// 	//  Allocate a packet pool for our xmit and receive packets
	// 	NdisAllocatePacketPool(
	// 		&Status,
	// 		&Open->PacketPool,
	// 		TRANSMIT_PACKETS,
	// 		sizeof(PACKET_RESERVED));
	// 
	// 	if (Status != NDIS_STATUS_SUCCESS) {
	// 
	// 		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate packet pool");
	// 
	// 		ExFreePool(Open);
	// 		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
	// 		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	// 		return STATUS_INSUFFICIENT_RESOURCES;
	// 	}

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

	//
	// Initialize the open instance
	//
	//Open->BindContext = NULL;
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
	Open->WriterSN = 0;
	Open->ReaderSN = 0;
	Open->Size = 0;
	Open->SkipSentPackets = FALSE;
	Open->ReadEvent = NULL;

	Open->AdapterName.Buffer = ExAllocatePool(NonPagedPool, 255 * sizeof(WCHAR));
	Open->AdapterName.MaximumLength = 255 * sizeof(WCHAR);
	Open->AdapterName.Length = 0;
	RtlCopyUnicodeString(&Open->AdapterName, AdapterName);

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
	for (i = 0 ; i < MAX_REQUESTS ; i++)
	{
		NdisInitializeEvent(&Open->Requests[i].InternalRequestCompletedEvent);

		ExInterlockedInsertTailList(&Open->RequestList, &Open->Requests[i].ListElement, &Open->RequestSpinLock);
	}

	NdisResetEvent(&Open->NdisOpenCloseCompleteEvent);

	// 
	// set the proper binding flags before trying to open the MAC
	//
	Open->AdapterBindingStatus = ADAPTER_BOUND;
	Open->AdapterHandleUsageCounter = 0;
	NdisAllocateSpinLock(&Open->AdapterHandleLock);

	Open->Medium = SelectedIndex; //Can be 0 before the first bindding.

	TRACE_EXIT();
	return Open;
}

//------------------------------------------------------------------

NDIS_STATUS NPF_BindAdapterEx(IN NDIS_HANDLE ProtocolDriverContext, IN NDIS_HANDLE BindContext, IN PNDIS_BIND_PARAMETERS BindParameters)
{
	NTSTATUS Status;
	NTSTATUS returnStatus;
	UINT i;
	POPEN_INSTANCE Open;
	NDIS_OPEN_PARAMETERS OpenParameters;
	UINT tmpSelectedMediumIndex;
	NDIS_HANDLE tmpAdapterHandle;


	TRACE_ENTER();
	
	IF_LOUD (DbgPrint("NPF_BindAdapterEx: AdapterName=%ws, MacAddress=%c-%c-%c-%c-%c-%c\n",
		BindParameters->AdapterName->Buffer,
		BindParameters->CurrentMacAddress[0], 
		BindParameters->CurrentMacAddress[1], 
		BindParameters->CurrentMacAddress[2], 
		BindParameters->CurrentMacAddress[3], 
		BindParameters->CurrentMacAddress[4], 
		BindParameters->CurrentMacAddress[5]);)


	Open = NPF_CreateOpenObject(BindParameters->AdapterName, 0, NULL);
	if (Open == NULL)
	{
		returnStatus = STATUS_INSUFFICIENT_RESOURCES;
		TRACE_EXIT();
		return returnStatus;
	}

	//
	//  Try to open the MAC
	//
	//TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Opening the device %ws, BindingContext=%p", DeviceExtension->AdapterName.Buffer, Open);

	returnStatus = STATUS_SUCCESS;

	NdisZeroMemory(&OpenParameters, sizeof(NDIS_OPEN_PARAMETERS));
	OpenParameters.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
	OpenParameters.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
	OpenParameters.Header.Size = sizeof(NDIS_OPEN_PARAMETERS);
	OpenParameters.AdapterName = BindParameters->AdapterName;
	OpenParameters.MediumArray = MediumArray;
	OpenParameters.MediumArraySize = sizeof(MediumArray) / sizeof(NDIS_MEDIUM);
	OpenParameters.SelectedMediumIndex = &Open->Medium;
	OpenParameters.FrameTypeArray = NULL;
	OpenParameters.FrameTypeArraySize = 0;
	//OpenParameters.FrameTypeArray = &FrameTypeArray[0];
	//OpenParameters.FrameTypeArraySize = sizeof(FrameTypeArray) / sizeof(NET_FRAME_TYPE);


	NDIS_DECLARE_PROTOCOL_OPEN_CONTEXT(OPEN_INSTANCE);
	Status = NdisOpenAdapterEx(g_NdisProtocolHandle, Open, &OpenParameters, BindContext, &Open->AdapterHandle);

	// 	NdisOpenAdapter(
	// 		&Status,
	// 		&ErrorStatus,
	// 		&Open->AdapterHandle,
	// 		&Open->Medium,
	// 		MediumArray,
	// 		NUM_NDIS_MEDIA,
	// 		g_NdisProtocolHandle,
	// 		Open,
	// 		&DeviceExtension->AdapterName,
	// 		0,
	// 		NULL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Opened the device, Status=%x", Status);

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
		NPF_AddToOpenArray(Open); //aki
	}

	TRACE_EXIT();
	return returnStatus;
}

//-------------------------------------------------------------------


NDIS_STATUS NPF_UnbindAdapterEx(IN  NDIS_HANDLE UnbindContext, IN  NDIS_HANDLE ProtocolBindingContext)
{
	NTSTATUS Status;
	ULONG localNumOpenInstances;
	POPEN_INSTANCE Open = (POPEN_INSTANCE)ProtocolBindingContext;

	TRACE_ENTER();

	Status = NDIS_STATUS_SUCCESS;
	ASSERT(Open != NULL);

// 	if (Open->ReadEvent != NULL)
// 		KeSetEvent(Open->ReadEvent,0,FALSE);


	NPF_RemoveFromOpenArray(Open); //aki
	NPF_CloseBindingAndAdapter(Open);
	//NPF_ReleaseOpenInstanceResources(Open);
	//ExFreePool(Open);

	NPF_RemoveUnclosedAdapters(); //aki

	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

VOID NPF_ResetComplete(IN NDIS_HANDLE  ProtocolBindingContext, IN NDIS_STATUS  Status)
{
	POPEN_INSTANCE Open;
	PIRP Irp;

	PLIST_ENTRY ResetListEntry;

	TRACE_ENTER();

	Open = (POPEN_INSTANCE)ProtocolBindingContext;

	//
	//  remove the reset IRP from the list
	//
	ResetListEntry = ExInterlockedRemoveHeadList(&Open->ResetIrpList, &Open->RequestSpinLock);

	Irp = CONTAINING_RECORD(ResetListEntry, IRP, Tail.Overlay.ListEntry);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

	return;
}
