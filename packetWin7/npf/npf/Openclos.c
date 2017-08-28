/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and my not be redistributed or incorporated    *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
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

#include <ntddk.h>
#include <ndis.h>

#include "debug.h"
#include "packet.h"
#include "Loopback.h"
#include "Lo_send.h"
#include "..\..\..\Common\WpcapNames.h"

extern NDIS_STRING g_LoopbackAdapterName;
extern NDIS_STRING g_SendToRxAdapterName;
extern NDIS_STRING g_BlockRxAdapterName;
extern NDIS_STRING devicePrefix;
extern ULONG g_Dot11SupportMode;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	extern HANDLE g_WFPEngineHandle;
	extern PDEVICE_OBJECT g_LoopbackDevObj;
#endif

extern NDIS_HANDLE FilterDriverHandle_WiFi; // NDIS handle for WiFi filter driver

static
VOID
NPF_ReleaseOpenInstanceResources(POPEN_INSTANCE pOpen);

/// Global start time. Used as an absolute reference for timestamp conversion.
struct time_conv G_Start_Time =
{
	0, {0, 0},
};

ULONG g_NumOpenedInstances = 0;

extern POPEN_INSTANCE g_arrOpen; //Adapter OPEN_INSTANCE list head, each list item is a group head.
extern NDIS_SPIN_LOCK g_OpenArrayLock; //The lock for adapter OPEN_INSTANCE list.
extern POPEN_INSTANCE g_LoopbackOpenGroupHead; // Loopback adapter OPEN_INSTANCE group head, this pointer points to one item in g_arrOpen list.
//-------------------------------------------------------------------

BOOLEAN
NPF_StartUsingBinding(
	IN POPEN_INSTANCE pOpen
	)
{
	ASSERT(pOpen != NULL);
	// NPF_OpenAdapter() is not called on PASSIVE_LEVEL, so the assertion will fail.
	// ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

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

//-------------------------------------------------------------------

VOID
NPF_StopUsingBinding(
	IN POPEN_INSTANCE pOpen
	)
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

//-------------------------------------------------------------------

VOID
NPF_CloseBinding(
	IN POPEN_INSTANCE pOpen
	)
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

	NdisAcquireSpinLock(&pOpen->AdapterHandleLock);
	pOpen->AdapterBindingStatus = ADAPTER_UNBOUND;
	NdisReleaseSpinLock(&pOpen->AdapterHandleLock);
}

//-------------------------------------------------------------------

NTSTATUS
NPF_OpenAdapter(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PDEVICE_EXTENSION		DeviceExtension;
	POPEN_INSTANCE			GroupHead;
	POPEN_INSTANCE			Open;
	PIO_STACK_LOCATION		IrpSp;
	NDIS_STATUS				Status = STATUS_SUCCESS;
	ULONG					localNumOpenedInstances;

	TRACE_ENTER();

	DeviceExtension = DeviceObject->DeviceExtension;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	// Find the head adapter of the global open array.
	GroupHead = NPF_GetOpenByAdapterName(&DeviceExtension->AdapterName, DeviceExtension->Dot11);

	if (GroupHead == NULL)
	{
		// Can't find the adapter from the global open array.
		TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
			"NPF_GetOpenByAdapterName error, GroupHead=NULL, AdapterName=%ws, Dot11=%d",
			DeviceExtension->AdapterName.Buffer,
			DeviceExtension->Dot11);

		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (NPF_StartUsingBinding(GroupHead) == FALSE)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
			"NPF_StartUsingOpenInstance error, AdapterName=%ws",
			DeviceExtension->AdapterName.Buffer);

		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Create a group child adapter object from the head adapter.
	Open = NPF_DuplicateOpenObject(GroupHead, DeviceExtension);

	Open->DeviceExtension = DeviceExtension;
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	TRACE_MESSAGE3(PACKET_DEBUG_LOUD,
		"Opening the device %ws, BindingContext=%p, Loopback=%u",
		DeviceExtension->AdapterName.Buffer,
		Open,
		Open->Loopback);
#else
	TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
		"Opening the device %ws, BindingContext=%p, Loopback=<Not supported>",
		DeviceExtension->AdapterName.Buffer,
		Open);
#endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (Open->Loopback)
	{
		if ((g_LoopbackDevObj != NULL) && (g_WFPEngineHandle == INVALID_HANDLE_VALUE))
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "g_LoopbackDevObj=%p, init WSK injection handles and register callouts", g_LoopbackDevObj);
			// Use Windows Filtering Platform (WFP) to capture loopback packets, also help WSK take care of loopback packet sending.
			Status = NPF_InitInjectionHandles();
			if (!NT_SUCCESS(Status))
			{
				goto NPF_OpenAdapter_End;
			}

			Status = NPF_RegisterCallouts(g_LoopbackDevObj);
			if (!NT_SUCCESS(Status))
			{
				if (g_WFPEngineHandle != INVALID_HANDLE_VALUE)
				{
					NPF_UnregisterCallouts();
				}

				goto NPF_OpenAdapter_End;
			}
		}
		else
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "g_LoopbackDevObj=%p, NO need to init WSK code", g_LoopbackDevObj);
		}
	}
#endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (Open->Loopback)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "This is loopback adapter, set MTU to: %u", NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN);
		Open->MaxFrameSize = NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN;
		Status = STATUS_SUCCESS;
	}
	else
#endif
	{
		Open->MaxFrameSize = 1514;
		Status = STATUS_SUCCESS;
		// This call will cause SYSTEM_SERVICE_EXCEPTION BSoD sometimes.
		// I didn't figure out the reason, I threw an ask on Stackoverflow: http://stackoverflow.com/questions/31869373/get-system-service-exception-bluescreen-when-starting-wireshark-on-win10-vmware
		// But no replies, so I just workaround by hard-coding it as 1514 for now.
// 		if (NPF_GetDeviceMTU(Open, &Open->MaxFrameSize) != STATUS_SUCCESS)
// 		{
// 			Open->MaxFrameSize = 1514;
// 		}
	}

#ifdef HAVE_DOT11_SUPPORT
	// Fetch the device's data rate mapping table with the OID_DOT11_DATA_RATE_MAPPING_TABLE OID.
	if (Open->Dot11)
	{
		if (NPF_GetDataRateMappingTable(Open, &Open->DataRateMappingTable) != STATUS_SUCCESS)
		{
			Open->HasDataRateMappingTable = FALSE;
		}
		else
		{
			Open->HasDataRateMappingTable = TRUE;
		}
	}
#endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
NPF_OpenAdapter_End:;
#endif
	if (!NT_SUCCESS(Status))
	{
		// Free the open instance' resources
		NPF_ReleaseOpenInstanceResources(Open);

		// Free the open instance itself
		ExFreePool(Open);
		Open = NULL;

		NPF_StopUsingBinding(GroupHead);

		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return Status;
	}
	else
	{
		//  Save or open here
		IrpSp->FileObject->FsContext = Open;
	}

	//
	// complete the open
	//
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open = %p\n", Open);
	localNumOpenedInstances = InterlockedIncrement(&g_NumOpenedInstances);
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Opened Instances: %u", localNumOpenedInstances);

	// Get the absolute value of the system boot time.
	// This is used for timestamp conversion.
	TIME_SYNCHRONIZE(&G_Start_Time);

	NPF_AddToGroupOpenArray(Open, GroupHead);

	NPF_StopUsingBinding(GroupHead);

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

BOOLEAN
NPF_StartUsingOpenInstance(
	IN POPEN_INSTANCE pOpen)

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

//-------------------------------------------------------------------

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

//-------------------------------------------------------------------

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

	while (pOpen->NumPendingIrps > 0)
	{
		NdisReleaseSpinLock(&pOpen->OpenInUseLock);
		NdisWaitEvent(&Event, 1);
		NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	}

	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}

//-------------------------------------------------------------------

VOID
NPF_ReleaseOpenInstanceResources(
	POPEN_INSTANCE pOpen
	)
{
	PKEVENT pEvent;
	UINT i;

	TRACE_ENTER();

	ASSERT(pOpen != NULL);
	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open= %p", pOpen);

	if (pOpen->PacketPool) // Release the packet buffer pool
	{
		NdisFreeNetBufferListPool(pOpen->PacketPool);
		pOpen->PacketPool = NULL;
	}

	// Release the adapter name
	if (pOpen->AdapterName.Buffer)
	{
		ExFreePool(pOpen->AdapterName.Buffer);
		pOpen->AdapterName.Buffer = NULL;
		pOpen->AdapterName.Length = 0;
		pOpen->AdapterName.MaximumLength = 0;
	}

	//
	// Free the filter if it's present
	//
	if (pOpen->bpfprogram != NULL)
	{
		ExFreePool(pOpen->bpfprogram);
		pOpen->bpfprogram = NULL;
	}

	//
	// Jitted filters are supported on x86 (32bit) only
	//
#ifdef _X86_
	// Free the jitted filter if it's present
	if (pOpen->Filter != NULL)
	{
		BPF_Destroy_JIT_Filter(pOpen->Filter);
	}
#endif //_X86_

	//
	// Dereference the read event.
	//

	if (pOpen->ReadEvent != NULL)
	{
		ObDereferenceObject(pOpen->ReadEvent);
	}

	//
	// free the buffer
	// NOTE: the buffer is fragmented among the various CPUs, but the base pointer of the
	// allocated chunk of memory is stored in the first slot (pOpen->CpuData[0])
	//
	if (pOpen->Size > 0)
	{
		ExFreePool(pOpen->CpuData[0].Buffer);
		pOpen->CpuData[0].Buffer = NULL;
		pOpen->Size = 0;
	}

	//
	// free the per CPU spinlocks
	//
	for (i = 0; i < g_NCpu; i++)
	{
		NdisFreeSpinLock(&pOpen->CpuData[i].BufferLock);
	}

	NdisFreeSpinLock(&pOpen->OIDLock);
	NdisFreeSpinLock(&pOpen->CountersLock);
	NdisFreeSpinLock(&pOpen->WriteLock);
	NdisFreeSpinLock(&pOpen->GroupLock);
	NdisFreeSpinLock(&pOpen->MachineLock);
	NdisFreeSpinLock(&pOpen->AdapterHandleLock);
	NdisFreeSpinLock(&pOpen->OpenInUseLock);

	//
	// Free the string with the name of the dump file
	//
	if (pOpen->DumpFileName.Buffer != NULL)
	{
		ExFreePool(pOpen->DumpFileName.Buffer);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

NTSTATUS
NPF_GetDeviceMTU(
	IN POPEN_INSTANCE pOpen,
	OUT PUINT pMtu
	)
{
	TRACE_ENTER();
	ASSERT(pOpen != NULL);
	ASSERT(pMtu != NULL);

	UINT Mtu = 0;
	ULONG BytesProcessed = 0;

	NPF_DoInternalRequest(pOpen,
		NdisRequestQueryInformation,
		OID_GEN_MAXIMUM_TOTAL_SIZE,
		&Mtu,
		sizeof(Mtu),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(Mtu) || Mtu == 0)
	{
		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		*pMtu = Mtu;
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
}

//-------------------------------------------------------------------
#ifdef HAVE_DOT11_SUPPORT
NTSTATUS
NPF_GetDataRateMappingTable(
	IN POPEN_INSTANCE pOpen,
	OUT PDOT11_DATA_RATE_MAPPING_TABLE pDataRateMappingTable
)
{
	TRACE_ENTER();
	ASSERT(pOpen != NULL);
	ASSERT(pDataRateMappingTable != NULL);

	DOT11_DATA_RATE_MAPPING_TABLE DataRateMappingTable = { 0 };
	ULONG BytesProcessed = 0;

	NPF_DoInternalRequest(pOpen,
		NdisRequestQueryInformation,
		OID_DOT11_DATA_RATE_MAPPING_TABLE,
		&DataRateMappingTable,
		sizeof(DataRateMappingTable),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(DataRateMappingTable))
	{
		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		*pDataRateMappingTable = DataRateMappingTable;
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
}

//-------------------------------------------------------------------

USHORT
NPF_LookUpDataRateMappingTable(
	IN POPEN_INSTANCE pOpen,
	IN UCHAR ucDataRate
)
{
	UINT i;
	PDOT11_DATA_RATE_MAPPING_TABLE pTable = &pOpen->DataRateMappingTable;
	USHORT usRetDataRateValue = 0;
	TRACE_ENTER();

	if (!pOpen->HasDataRateMappingTable)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Data rate mapping table not found, Open = %p\n", pOpen);
		TRACE_EXIT();
		return usRetDataRateValue;
	}

	for (i = 0; i < pTable->uDataRateMappingLength; i ++)
	{
		if (pTable->DataRateMappingEntries[i].ucDataRateIndex == ucDataRate)
		{
			usRetDataRateValue = pTable->DataRateMappingEntries[i].usDataRateValue;
			break;
		}
	}

	TRACE_EXIT();
	return usRetDataRateValue;
}

//-------------------------------------------------------------------

NTSTATUS
NPF_GetCurrentOperationMode(
	IN POPEN_INSTANCE pOpen,
	OUT PDOT11_CURRENT_OPERATION_MODE pCurrentOperationMode
)
{
	TRACE_ENTER();
	ASSERT(pOpen != NULL);
	ASSERT(pCurrentOperationMode != NULL);

	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode = { 0 };
	ULONG BytesProcessed = 0;

	NPF_DoInternalRequest(pOpen,
		NdisRequestQueryInformation,
		OID_DOT11_CURRENT_OPERATION_MODE,
		&CurrentOperationMode,
		sizeof(CurrentOperationMode),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(CurrentOperationMode))
	{
		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		*pCurrentOperationMode = CurrentOperationMode;
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
}

//-------------------------------------------------------------------

ULONG
NPF_GetCurrentOperationMode_Wrapper(
	IN POPEN_INSTANCE pOpen
)
{
	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode;
	if (NPF_GetCurrentOperationMode(pOpen, &CurrentOperationMode) != STATUS_SUCCESS)
	{
		return DOT11_OPERATION_MODE_UNKNOWN;
	}
	else
	{
		// Possible return values are:
		// 1: DOT11_OPERATION_MODE_EXTENSIBLE_STATION
		// 2: DOT11_OPERATION_MODE_EXTENSIBLE_AP
		// 3: DOT11_OPERATION_MODE_NETWORK_MONITOR
		return CurrentOperationMode.uCurrentOpMode;
	}
}

//-------------------------------------------------------------------

NTSTATUS
NPF_GetCurrentChannel(
	IN POPEN_INSTANCE pOpen,
	OUT PULONG pCurrentChannel
)
{
	TRACE_ENTER();
	ASSERT(pOpen != NULL);
	ASSERT(pCurrentChannel != NULL);

	ULONG CurrentChannel = 0;
	ULONG BytesProcessed = 0;

	NPF_DoInternalRequest(pOpen,
		NdisRequestQueryInformation,
		OID_DOT11_CURRENT_CHANNEL,
		&CurrentChannel,
		sizeof(CurrentChannel),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(CurrentChannel))
	{
		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		*pCurrentChannel = CurrentChannel;
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
}

//-------------------------------------------------------------------

ULONG
NPF_GetCurrentChannel_Wrapper(
	IN POPEN_INSTANCE pOpen
)
{
	ULONG CurrentChannel;
	if (NPF_GetCurrentChannel(pOpen, &CurrentChannel) != STATUS_SUCCESS)
	{
		return 0;
	}
	else
	{
		// Possible return values are: 1 - 14
		return CurrentChannel;
	}
}

//-------------------------------------------------------------------

NTSTATUS
NPF_GetCurrentFrequency(
	IN POPEN_INSTANCE pOpen,
	OUT PULONG pCurrentFrequency
)
{
	TRACE_ENTER();
	ASSERT(pOpen != NULL);
	ASSERT(pCurrentFrequency != NULL);

	ULONG CurrentFrequency = 0;
	ULONG BytesProcessed = 0;

	NPF_DoInternalRequest(pOpen,
		NdisRequestQueryInformation,
		OID_DOT11_CURRENT_FREQUENCY,
		&CurrentFrequency,
		sizeof(CurrentFrequency),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(CurrentFrequency))
	{
		TRACE_EXIT();
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		*pCurrentFrequency = CurrentFrequency;
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}
}

//-------------------------------------------------------------------

ULONG
NPF_GetCurrentFrequency_Wrapper(
	IN POPEN_INSTANCE pOpen
)
{
	ULONG CurrentFrequency;
	if (NPF_GetCurrentFrequency(pOpen, &CurrentFrequency) != STATUS_SUCCESS)
	{
		return 0;
	}
	else
	{
		// Possible return values are: 0 - 200
		return CurrentFrequency;
	}
}
#endif
//-------------------------------------------------------------------

NTSTATUS
NPF_CloseAdapter(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
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
	if (pOpen)
	{
		ExFreePool(pOpen);
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

NTSTATUS
NPF_Cleanup(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
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

	NPF_RemoveFromGroupOpenArray(Open); //Remove the adapter from the group adapter list

	NPF_CloseOpenInstance(Open);

	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent, 0, FALSE);

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

	Status = STATUS_SUCCESS;

	//
	// and complete the IRP with status success
	//
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();

	return Status;
}

//-------------------------------------------------------------------

void
NPF_AddToOpenArray(
	POPEN_INSTANCE Open
	)
{
	POPEN_INSTANCE CurOpen;

	TRACE_ENTER();

	NdisAcquireSpinLock(&g_OpenArrayLock);
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
	NdisReleaseSpinLock(&g_OpenArrayLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

void
NPF_AddToGroupOpenArray(
	POPEN_INSTANCE Open,
	POPEN_INSTANCE GroupHead
	)
{
	POPEN_INSTANCE GroupRear;

	TRACE_ENTER();

	NdisAcquireSpinLock(&GroupHead->GroupLock);
	GroupRear = GroupHead;
	while (GroupRear->GroupNext != NULL)
	{
		GroupRear = GroupRear->GroupNext;
	}
	GroupRear->GroupNext = Open;
	Open->GroupHead = GroupHead;

	NdisReleaseSpinLock(&GroupHead->GroupLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

void
NPF_RemoveFromOpenArray(
	POPEN_INSTANCE Open
	)
{
	POPEN_INSTANCE CurOpen = NULL;
	POPEN_INSTANCE PrevOpen = NULL;
	POPEN_INSTANCE GroupOpen;

	if (!Open)
	{
		IF_LOUD(DbgPrint("NPF_RemoveFromOpenArray: Open is NULL.\n");)
		return;
	}

	TRACE_ENTER();

	NdisAcquireSpinLock(&g_OpenArrayLock);
	if (g_arrOpen == Open) {
		g_arrOpen = Open->Next;
		// CurOpen must be set or a later check will fail.
		CurOpen = g_arrOpen;
	}
	else {
		PrevOpen = g_arrOpen;
		CurOpen = PrevOpen->Next;
		while (CurOpen)
		{
			if (CurOpen == Open)
			{
				PrevOpen->Next = CurOpen->Next;
				break;
			}
			PrevOpen = CurOpen;
			CurOpen = CurOpen->Next;
		}
	}

	if (Open == g_LoopbackOpenGroupHead) {
	  g_LoopbackOpenGroupHead = NULL;
	}

	// Remove the links between group head and group members.
	NdisAcquireSpinLock(&Open->GroupLock);
	GroupOpen = Open->GroupNext;
	while (GroupOpen)
	{
		GroupOpen->GroupHead = NULL;
		GroupOpen = GroupOpen->GroupNext;
	}
	Open->GroupNext = NULL;
	NdisReleaseSpinLock(&Open->GroupLock);

	NdisReleaseSpinLock(&g_OpenArrayLock);

	if (!CurOpen)
		IF_LOUD(DbgPrint("NPF_RemoveFromOpenArray: error, the open isn't in the global open list.\n");)
	TRACE_EXIT();
}

//-------------------------------------------------------------------

void
NPF_RemoveFromGroupOpenArray(
	POPEN_INSTANCE Open
	)
{
	POPEN_INSTANCE GroupOpen;
	POPEN_INSTANCE GroupPrev = NULL;

	TRACE_ENTER();

	if (!Open->GroupHead || Open->GroupHead == Open)
	{
		IF_LOUD(DbgPrint("NPF_RemoveFromGroupOpenArray: error, the open doesn't have a group head.\n");)
		TRACE_EXIT();
		return;
	}

	NdisAcquireSpinLock(&Open->GroupHead->GroupLock);
	GroupPrev = Open->GroupHead;
	GroupOpen = GroupPrev->GroupNext;
	while (GroupOpen)
	{
		if (GroupOpen == Open)
		{
			GroupPrev->GroupNext = GroupOpen->GroupNext;
			NdisReleaseSpinLock(&Open->GroupHead->GroupLock);
			GroupOpen->GroupHead = NULL;

			TRACE_EXIT();
			return;

 		}
		GroupPrev = GroupOpen;
		GroupOpen = GroupOpen->GroupNext;
	}
	NdisReleaseSpinLock(&Open->GroupHead->GroupLock);

	IF_LOUD(DbgPrint("NPF_RemoveFromGroupOpenArray: error, the open isn't in the group open list.\n");)

	TRACE_EXIT();
}

//-------------------------------------------------------------------

BOOLEAN
NPF_EqualAdapterName(
	PNDIS_STRING s1,
	PNDIS_STRING s2
	)
{
	int i;
	BOOLEAN bResult = TRUE;
	// TRACE_ENTER();

	if (s1->Length != s2->Length)
	{
		IF_LOUD(DbgPrint("NPF_EqualAdapterName: length not the same\n");)
		// IF_LOUD(DbgPrint("NPF_EqualAdapterName: length not the same, s1->Length = %d, s2->Length = %d\n", s1->Length, s2->Length);)
		// TRACE_EXIT();
		return FALSE;
	}

	for (i = 0; i < s2->Length / 2; i ++)
	{
		if (L'A' <= s1->Buffer[i] && s1->Buffer[i] <= L'Z')
		{
			if (s2->Buffer[i] - s1->Buffer[i] != 0 && s2->Buffer[i] - s1->Buffer[i] != L'a' - L'A')
			{
				bResult = FALSE;
				break;
			}
		}
		else if (L'a' <= s1->Buffer[i] && s1->Buffer[i] <= L'z')
		{
			if (s2->Buffer[i] - s1->Buffer[i] != 0 && s2->Buffer[i] - s1->Buffer[i] != L'A' - L'a')
			{
				bResult = FALSE;
				break;
			}
		}
		else if (s2->Buffer[i] - s1->Buffer[i] != 0)
		{
			bResult = FALSE;
			break;
		}
	}

	// Print unicode strings using %ws will cause page fault blue screen with IRQL = DISPATCH_LEVEL, so we disable the string print for now.
	// IF_LOUD(DbgPrint("NPF_EqualAdapterName: bResult = %d, s1 = %ws, s2 = %ws\n", i, bResult, s1->Buffer, s2->Buffer);)
	if (bResult)
	{
		IF_LOUD(DbgPrint("NPF_EqualAdapterName: bResult == TRUE\n");)
	}
	// TRACE_EXIT();
	return bResult;
}

//-------------------------------------------------------------------

POPEN_INSTANCE
NPF_GetOpenByAdapterName(
	PNDIS_STRING pAdapterName,
	BOOLEAN Dot11
	)
{
	POPEN_INSTANCE CurOpen;
	TRACE_ENTER();

	NdisAcquireSpinLock(&g_OpenArrayLock);
	for (CurOpen = g_arrOpen; CurOpen != NULL; CurOpen = CurOpen->Next)
	{
		if (NPF_StartUsingBinding(CurOpen) == FALSE)
		{
			continue;
		}

		if (NPF_EqualAdapterName(&CurOpen->AdapterName, pAdapterName) && CurOpen->Dot11 == Dot11)
		{
			NPF_StopUsingBinding(CurOpen);
			NdisReleaseSpinLock(&g_OpenArrayLock);
			return CurOpen;
		}
		else
		{
			NPF_StopUsingBinding(CurOpen);
		}
	}
	NdisReleaseSpinLock(&g_OpenArrayLock);

	TRACE_EXIT();
	return NULL;
}

//-------------------------------------------------------------------

POPEN_INSTANCE
NPF_DuplicateOpenObject(
	POPEN_INSTANCE OriginalOpen,
	PDEVICE_EXTENSION DeviceExtension
	)
{
	POPEN_INSTANCE Open;
	TRACE_ENTER();

	Open = NPF_CreateOpenObject(&OriginalOpen->AdapterName, OriginalOpen->Medium, DeviceExtension);
	Open->AdapterHandle = OriginalOpen->AdapterHandle;
	Open->DirectBinded = FALSE;
	Open->MaxFrameSize = OriginalOpen->MaxFrameSize;
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	Open->Loopback = OriginalOpen->Loopback;
#endif
#ifdef HAVE_DOT11_SUPPORT
	Open->Dot11 = OriginalOpen->Dot11;
#endif

#ifdef HAVE_RX_SUPPORT
	Open->SendToRxPath = OriginalOpen->SendToRxPath;
	Open->BlockRxPath = OriginalOpen->BlockRxPath;
#endif

	TRACE_EXIT();
	return Open;
}

//-------------------------------------------------------------------

POPEN_INSTANCE
NPF_CreateOpenObject(
	PNDIS_STRING AdapterName,
	UINT SelectedIndex,
	PDEVICE_EXTENSION DeviceExtension)
{
	POPEN_INSTANCE Open;
	UINT i;
	NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
	TRACE_ENTER();

	// allocate some memory for the open structure
	Open = ExAllocatePoolWithTag(NonPagedPool, sizeof(OPEN_INSTANCE), '0OWA');

	if (Open == NULL)
	{
		// no memory
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate memory pool");
		TRACE_EXIT();
		return NULL;
	}

	RtlZeroMemory(Open, sizeof(OPEN_INSTANCE));

	Open->DeviceExtension = DeviceExtension; //can be NULL before any actual bindings.
	Open->DirectBinded = TRUE;
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	Open->Loopback = FALSE;
#endif

#ifdef HAVE_RX_SUPPORT
	Open->SendToRxPath = FALSE;
	Open->BlockRxPath = FALSE;
#endif

#ifdef HAVE_DOT11_SUPPORT
	Open->Dot11 = FALSE;
	Open->Dot11PacketFilter = 0x0;
	Open->HasDataRateMappingTable = FALSE;
#endif

	NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
	PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	PoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	PoolParameters.fAllocateNetBuffer = TRUE;
	PoolParameters.ContextSize = 0;
	PoolParameters.PoolTag = NPF_ALLOC_TAG;
	PoolParameters.DataSize = 0;

	Open->PacketPool = NdisAllocateNetBufferListPool(NULL, &PoolParameters);
	if (Open->PacketPool == NULL)
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate packet pool");
		ExFreePool(Open);
		TRACE_EXIT();
		return NULL;
	}

	NdisInitializeEvent(&Open->WriteEvent);
	NdisInitializeEvent(&Open->NdisRequestEvent);
	NdisInitializeEvent(&Open->NdisWriteCompleteEvent);
	NdisInitializeEvent(&Open->DumpEvent);
	NdisAllocateSpinLock(&Open->MachineLock);
	NdisAllocateSpinLock(&Open->WriteLock);
	NdisAllocateSpinLock(&Open->GroupLock);
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

	Open->AdapterName.Buffer = ExAllocatePoolWithTag(NonPagedPool, 255 * sizeof(WCHAR), 'NPCA');
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
	Open->PausePending = FALSE;
	NdisAllocateSpinLock(&Open->OpenInUseLock);

	//
	//allocate the spinlock for the statistic counters
	//
	NdisAllocateSpinLock(&Open->CountersLock);

	//
	//allocate the spinlock for the OID requests
	//
	NdisAllocateSpinLock(&Open->OIDLock);

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

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_RegisterOptions(
	NDIS_HANDLE  NdisFilterHandle,
	NDIS_HANDLE  FilterDriverContext
	)
/*++

Routine Description:

	Register optional handlers with NDIS.  This sample does not happen to
	have any optional handlers to register, so this routine does nothing
	and could simply have been omitted.  However, for illustrative purposes,
	it is presented here.

Arguments:

	NdisFilterHandle - pointer the driver handle received from
							 NdisFRegisterFilterDriver

	FilterDriverContext    - pointer to our context passed into
							 NdisFRegisterFilterDriver

Return Value:

	NDIS_STATUS_SUCCESS

--*/
{
	TRACE_ENTER();

	ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
	if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
	{
		IF_LOUD(DbgPrint("NPF_RegisterOptions: driver doesn't match error, FilterDriverContext = %p, FilterDriverObject = %p.\n", FilterDriverContext, FilterDriverObject);)
		return NDIS_STATUS_INVALID_PARAMETER;
	}

	TRACE_EXIT();

	return NDIS_STATUS_SUCCESS;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_AttachAdapter(
	NDIS_HANDLE                     NdisFilterHandle,
	NDIS_HANDLE                     FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
	)
{
	POPEN_INSTANCE			Open = NULL;
	NDIS_STATUS             Status;
	NDIS_STATUS				returnStatus;
	NDIS_FILTER_ATTRIBUTES	FilterAttributes;
	BOOLEAN					bFalse = FALSE;
	BOOLEAN					bDot11;

	TRACE_ENTER();

	do
	{
		ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
		if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
		{
			Status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		// Verify the media type is supported.  This is a last resort; the
		// the filter should never have been bound to an unsupported miniport
		// to begin with.  If this driver is marked as a Mandatory filter (which
		// is the default for this sample; see the INF file), failing to attach
		// here will leave the network adapter in an unusable state.
		//
		// Your setup/install code should not bind the filter to unsupported
		// media types.
		if ((AttachParameters->MiniportMediaType != NdisMedium802_3)
				&& (AttachParameters->MiniportMediaType != NdisMediumNative802_11)
				&& (AttachParameters->MiniportMediaType != NdisMediumWan) //we don't care this kind of miniports
				&& (AttachParameters->MiniportMediaType != NdisMediumWirelessWan) //we don't care this kind of miniports
				&& (AttachParameters->MiniportMediaType != NdisMediumFddi)
				&& (AttachParameters->MiniportMediaType != NdisMediumArcnet878_2)
				&& (AttachParameters->MiniportMediaType != NdisMediumAtm)
				&& (AttachParameters->MiniportMediaType != NdisMedium802_5))
		{
			IF_LOUD(DbgPrint("Unsupported media type: MiniportMediaType = %d.\n", AttachParameters->MiniportMediaType);)

			returnStatus = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		// An example:
		// AdapterName = "\DEVICE\{4F4B4BD7-340D-45D3-8F59-8A1E167BC75D}"
		// FilterModuleGuidName = "{4F4B4BD7-340D-45D3-8F59-8A1E167BC75D}-{7DAF2AC8-E9F6-4765-A842-F1F5D2501351}-0000"
		IF_LOUD(DbgPrint("NPF_AttachAdapter: AdapterName=%ws, MacAddress=%02X-%02X-%02X-%02X-%02X-%02X, MiniportMediaType=%d\n",
			AttachParameters->BaseMiniportName->Buffer,
			AttachParameters->CurrentMacAddress[0],
			AttachParameters->CurrentMacAddress[1],
			AttachParameters->CurrentMacAddress[2],
			AttachParameters->CurrentMacAddress[3],
			AttachParameters->CurrentMacAddress[4],
			AttachParameters->CurrentMacAddress[5],
			AttachParameters->MiniportMediaType);
		);

		IF_LOUD(DbgPrint("NPF_AttachAdapter: FilterModuleGuidName=%ws, FilterModuleGuidName[%d]=%d\n",
			AttachParameters->FilterModuleGuidName->Buffer,
			SECOND_LAST_HEX_INDEX_OF_FILTER_UNIQUE_NAME,
			AttachParameters->FilterModuleGuidName->Buffer[SECOND_LAST_HEX_INDEX_OF_FILTER_UNIQUE_NAME]);
		);

		if (AttachParameters->FilterModuleGuidName->Buffer[SECOND_LAST_HEX_INDEX_OF_FILTER_UNIQUE_NAME] == L'4')
		{
			IF_LOUD(DbgPrint("NPF_AttachAdapter: This is the standard filter binding!\n");)
			bDot11 = FALSE;
		}
		else if (AttachParameters->FilterModuleGuidName->Buffer[SECOND_LAST_HEX_INDEX_OF_FILTER_UNIQUE_NAME] == L'5')
		{
			IF_LOUD(DbgPrint("NPF_AttachAdapter: This is the WiFi filter binding!\n");)
			bDot11 = TRUE;
		}
		else
		{
			IF_LOUD(DbgPrint("NPF_AttachAdapter: error, unrecognized filter binding!\n");)

			returnStatus = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		// The WiFi filter will only bind to the 802.11 wirelress adapters.
		if (g_Dot11SupportMode && bDot11)
		{
			if (AttachParameters->MiniportMediaType != NdisMediumNative802_11)
			{
				IF_LOUD(DbgPrint("Unsupported media type for the WiFi filter: MiniportMediaType = %d, expected = 16 (NdisMediumNative802_11).\n", AttachParameters->MiniportMediaType);)

				returnStatus = NDIS_STATUS_INVALID_PARAMETER;
				break;
			}
		}

		// Disable this code for now, because it invalidates most adapters to be bound, reason needs to be clarified.
// 		if (AttachParameters->LowerIfIndex != AttachParameters->BaseMiniportIfIndex)
// 		{
// 			IF_LOUD(DbgPrint("Don't bind to other altitudes than exactly over the miniport: LowerIfIndex = %d, BaseMiniportIfIndex = %d.\n", AttachParameters->LowerIfIndex, AttachParameters->BaseMiniportIfIndex);)
// 
// 			returnStatus = NDIS_STATUS_NOT_SUPPORTED;
// 			break;
// 		}

		// create the adapter object
		Open = NPF_CreateOpenObject(AttachParameters->BaseMiniportName, AttachParameters->MiniportMediaType, NULL);
		if (Open == NULL)
		{
			returnStatus = NDIS_STATUS_RESOURCES;
			TRACE_EXIT();
			return returnStatus;
		}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		// Determine whether this is our loopback adapter for the open_instance.
		if (g_LoopbackAdapterName.Buffer != NULL)
		{
			if (RtlCompareMemory(g_LoopbackAdapterName.Buffer + devicePrefix.Length / 2, AttachParameters->BaseMiniportName->Buffer + devicePrefix.Length / 2,
				AttachParameters->BaseMiniportName->Length - devicePrefix.Length) == AttachParameters->BaseMiniportName->Length - devicePrefix.Length)
			{
				// Commented this check because when system recovers from sleep, all adapters will be reattached, but g_LoopbackOpenGroupHead != NULL, so no adapter will be tagged as loopback.
// 				if (g_LoopbackOpenGroupHead == NULL)
// 				{
					Open->Loopback = TRUE;
					g_LoopbackOpenGroupHead = Open;
//				}
			}
		}
		else
		{
			IF_LOUD(DbgPrint("NPF_AttachAdapter: g_LoopbackAdapterName.Buffer=NULL\n");)
		}
#endif

#ifdef HAVE_RX_SUPPORT
		// Determine whether this is our send-to-Rx adapter for the open_instance.
		if (g_SendToRxAdapterName.Buffer != NULL)
		{
			int iAdapterCnt = (g_SendToRxAdapterName.Length / 2 + 1) / ADAPTER_NAME_SIZE_WITH_SEPARATOR;
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
				"g_SendToRxAdapterName.Length=%d, iAdapterCnt=%d",
				g_SendToRxAdapterName.Length,
				iAdapterCnt);
			for (int i = 0; i < iAdapterCnt; i++)
			{
				if (RtlCompareMemory(g_SendToRxAdapterName.Buffer + devicePrefix.Length / 2 + ADAPTER_NAME_SIZE_WITH_SEPARATOR * i,
					AttachParameters->BaseMiniportName->Buffer + devicePrefix.Length / 2,
					AttachParameters->BaseMiniportName->Length - devicePrefix.Length)
					== AttachParameters->BaseMiniportName->Length - devicePrefix.Length)
				{
					Open->SendToRxPath = TRUE;
					break;
				}
			}
		}
		// Determine whether this is our block-Rx adapter for the open_instance.
		if (g_BlockRxAdapterName.Buffer != NULL)
		{
			int iAdapterCnt = (g_BlockRxAdapterName.Length / 2 + 1) / ADAPTER_NAME_SIZE_WITH_SEPARATOR;
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
				"g_BlockRxAdapterName.Length=%d, iAdapterCnt=%d",
				g_BlockRxAdapterName.Length,
				iAdapterCnt);
			for (int i = 0; i < iAdapterCnt; i++)
			{
				if (RtlCompareMemory(g_BlockRxAdapterName.Buffer + devicePrefix.Length / 2 + ADAPTER_NAME_SIZE_WITH_SEPARATOR * i,
					AttachParameters->BaseMiniportName->Buffer + devicePrefix.Length / 2,
					AttachParameters->BaseMiniportName->Length - devicePrefix.Length)
					== AttachParameters->BaseMiniportName->Length - devicePrefix.Length)
				{
					Open->BlockRxPath = TRUE;
					break;
				}
			}
		}
#endif

		returnStatus = STATUS_SUCCESS;

		NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
		FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
		FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
		FilterAttributes.Flags = 0;

		NDIS_DECLARE_FILTER_MODULE_CONTEXT(OPEN_INSTANCE);
		Status = NdisFSetAttributes(NdisFilterHandle,
			Open,
			&FilterAttributes);

		if (Status != NDIS_STATUS_SUCCESS)
		{
			returnStatus = Status;
			IF_LOUD(DbgPrint("NdisFSetAttributes: error, Status=%x.\n", Status);)
			NPF_ReleaseOpenInstanceResources(Open);
			//
			// Free the open instance itself
			//
			ExFreePool(Open);
		}
		else
		{
			Open->AdapterHandle = NdisFilterHandle;
			Open->HigherPacketFilter = NPF_GetPacketFilter(Open);
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"HigherPacketFilter=%x",
				Open->HigherPacketFilter);

			Open->PhysicalMedium = NPF_GetPhysicalMedium(Open);
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD,
				"PhysicalMedium=%x",
				Open->PhysicalMedium);

#ifdef HAVE_DOT11_SUPPORT
			if (g_Dot11SupportMode && bDot11)
			{
				// Handling raw 802.11 packets need to set NDIS_PACKET_TYPE_802_11_RAW_DATA and NDIS_PACKET_TYPE_802_11_RAW_MGMT in the packet filter.
				Open->Dot11 = bDot11;
				Open->Dot11PacketFilter = NDIS_PACKET_TYPE_802_11_RAW_DATA | NDIS_PACKET_TYPE_802_11_RAW_MGMT;
				ULONG combinedPacketFilter = Open->HigherPacketFilter | Open->MyPacketFilter | Open->Dot11PacketFilter;
				Status = NPF_SetPacketFilter(Open, combinedPacketFilter);

				TRACE_MESSAGE2(PACKET_DEBUG_LOUD,
					"NPF_SetPacketFilter, Status=%x, Dot11PacketFilter=%x",
					Status,
					Open->Dot11PacketFilter);
			}
#endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			TRACE_MESSAGE4(PACKET_DEBUG_LOUD,
				"Opened the device %ws, BindingContext=%p, Loopback=%d, dot11=%d",
				AttachParameters->BaseMiniportName->Buffer,
				Open,
				Open->Loopback,
				Open->Dot11);
#else
			TRACE_MESSAGE3(PACKET_DEBUG_LOUD,
				"Opened the device %ws, BindingContext=%p, Loopback=<Not supported>, dot11=%d",
				AttachParameters->BaseMiniportName->Buffer,
				Open,
				Open->Dot11);
#endif

			returnStatus = STATUS_SUCCESS;
			NPF_AddToOpenArray(Open);
		}
	}
	while (bFalse);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "returnStatus=%x", returnStatus);
	TRACE_EXIT();
	return returnStatus;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_Pause(
	NDIS_HANDLE                     FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
	)
{
	POPEN_INSTANCE          Open = (POPEN_INSTANCE)FilterModuleContext;
	NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(PauseParameters);
	TRACE_ENTER();

	NdisAcquireSpinLock(&Open->AdapterHandleLock);
	Open->PausePending = TRUE;
	NdisReleaseSpinLock(&Open->AdapterHandleLock);

	Status = NDIS_STATUS_SUCCESS;
	
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_Restart(
	NDIS_HANDLE                     FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
	)
{

	POPEN_INSTANCE	Open = (POPEN_INSTANCE) FilterModuleContext;
	NDIS_STATUS		Status;

	TRACE_ENTER();

	TIME_DESYNCHRONIZE(&G_Start_Time);
	TIME_SYNCHRONIZE(&G_Start_Time);


	NdisAcquireSpinLock(&Open->AdapterHandleLock);
	Open->PausePending = FALSE;
	NdisReleaseSpinLock(&Open->AdapterHandleLock);

	Status = NDIS_STATUS_SUCCESS;
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_DetachAdapter(
	NDIS_HANDLE     FilterModuleContext
	)
/*++

Routine Description:

	Filter detach routine.
	This is a required function that will deallocate all the resources allocated during
	FilterAttach. NDIS calls FilterAttach to remove a filter instance from a filter stack.

Arguments:

	FilterModuleContext - pointer to the filter context area.

Return Value:
	None.

NOTE: Called at PASSIVE_LEVEL and the filter is in paused state

--*/
{
	POPEN_INSTANCE		Open = (POPEN_INSTANCE) FilterModuleContext;
	POPEN_INSTANCE		GroupOpen;
	BOOLEAN				bFalse = FALSE;

	TRACE_ENTER();

  /* No need to lock the group since we are paused. Also, can't lock because
   * that raises IRQL and NPF_CloseOpenInstance requires PASSIVE_LEVEL */
	for (GroupOpen = Open->GroupNext; GroupOpen != NULL; GroupOpen = GroupOpen->GroupNext)
	{
		NPF_CloseOpenInstance(GroupOpen);

		if (GroupOpen->ReadEvent != NULL)
			KeSetEvent(GroupOpen->ReadEvent, 0, FALSE);
	}

	NPF_CloseBinding(Open);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// "Npcap Loopback Adapter" is going to be detached, invalidate its global pointer as well. 
	if (Open->Loopback && Open == g_LoopbackOpenGroupHead)
	{
		g_LoopbackOpenGroupHead = NULL;
	}
#endif

	NPF_RemoveFromOpenArray(Open); // Must add this, if not, SYSTEM_SERVICE_EXCEPTION BSoD will occur.
	NPF_ReleaseOpenInstanceResources(Open);
	ExFreePool(Open);

	TRACE_EXIT();
	return;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_OidRequest(
	NDIS_HANDLE         FilterModuleContext,
	PNDIS_OID_REQUEST   Request
	)
/*++

Routine Description:

	Request handler
	Handle requests from upper layers

Arguments:

	FilterModuleContext   - our filter
	Request               - the request passed down


Return Value:

	 NDIS_STATUS_SUCCESS
	 NDIS_STATUS_PENDING
	 NDIS_STATUS_XXX

NOTE: Called at <= DISPATCH_LEVEL  (unlike a miniport's MiniportOidRequest)

--*/
{
	POPEN_INSTANCE          Open = (POPEN_INSTANCE) FilterModuleContext;
	NDIS_STATUS             Status;
	PNDIS_OID_REQUEST       ClonedRequest=NULL;
	BOOLEAN                 bSubmitted = FALSE;
	PFILTER_REQUEST_CONTEXT Context;
	BOOLEAN                 bFalse = FALSE;
	ULONG					combinedPacketFilter = 0;

	TRACE_ENTER();

	do
	{
		Status = NdisAllocateCloneOidRequest(Open->AdapterHandle,
											Request,
											NPF_ALLOC_TAG,
											&ClonedRequest);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "FilterOidRequest: Cannot Clone Request\n");
			break;
		}

		if (Request->RequestType == NdisRequestSetInformation && Request->DATA.SET_INFORMATION.Oid == OID_GEN_CURRENT_PACKET_FILTER)
		{

			Open->HigherPacketFilter = *(ULONG *) Request->DATA.SET_INFORMATION.InformationBuffer;
#ifdef HAVE_DOT11_SUPPORT
			Open->LowerPacketFilter = Open->HigherPacketFilter | Open->MyPacketFilter | Open->Dot11PacketFilter;
#else
			Open->LowerPacketFilter = Open->HigherPacketFilter | Open->MyPacketFilter;
#endif
			ClonedRequest->DATA.SET_INFORMATION.InformationBuffer = &Open->LowerPacketFilter;
		}

		Context = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
		*Context = Request; //SourceReserved != NULL indicates that this is other module's request

		bSubmitted = TRUE;

		//
		// Use same request ID
		//
		ClonedRequest->RequestId = Request->RequestId;

		Open->PendingOidRequest = ClonedRequest;

		Status = NdisFOidRequest(Open->AdapterHandle, ClonedRequest);

		if (Status != NDIS_STATUS_PENDING)
		{
			NPF_OidRequestComplete(Open, ClonedRequest, Status);
			Status = NDIS_STATUS_PENDING;
		}


	}while (bFalse);

	if (bSubmitted == FALSE)
	{
		switch(Request->RequestType)
		{
			case NdisRequestMethod:
				Request->DATA.METHOD_INFORMATION.BytesRead = 0;
				Request->DATA.METHOD_INFORMATION.BytesNeeded = 0;
				Request->DATA.METHOD_INFORMATION.BytesWritten = 0;
				break;

			case NdisRequestSetInformation:
				Request->DATA.SET_INFORMATION.BytesRead = 0;
				Request->DATA.SET_INFORMATION.BytesNeeded = 0;
				break;

			case NdisRequestQueryInformation:
			case NdisRequestQueryStatistics:
			default:
				Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
				Request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
				break;
		}

	}

	TRACE_EXIT();
	return Status;

}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_CancelOidRequest(
	NDIS_HANDLE             FilterModuleContext,
	PVOID                   RequestId
	)
/*++

Routine Description:

	Cancels an OID request

	If your filter driver does not intercept and hold onto any OID requests,
	then you do not need to implement this routine.  You may simply omit it.
	Furthermore, if the filter only holds onto OID requests so it can pass
	down a clone (the most common case) the filter does not need to implement
	this routine; NDIS will then automatically request that the lower-level
	filter/miniport cancel your cloned OID.

	Most filters do not need to implement this routine.

Arguments:

	FilterModuleContext   - our filter
	RequestId             - identifies the request(s) to cancel

--*/
{
	POPEN_INSTANCE                      Open = (POPEN_INSTANCE) FilterModuleContext;
	PNDIS_OID_REQUEST                   Request = NULL;
	PFILTER_REQUEST_CONTEXT             Context;
	PNDIS_OID_REQUEST                   OriginalRequest = NULL;
	BOOLEAN                             bFalse = FALSE;

	FILTER_ACQUIRE_LOCK(&Open->OIDLock, bFalse);

	Request = Open->PendingOidRequest;

	if (Request != NULL)
	{
		Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);

		OriginalRequest = (*Context);
	}

	if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId))
	{
		FILTER_RELEASE_LOCK(&Open->OIDLock, bFalse);

		NdisFCancelOidRequest(Open->AdapterHandle, RequestId);
	}
	else
	{
		FILTER_RELEASE_LOCK(&Open->OIDLock, bFalse);
	}
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_OidRequestComplete(
	NDIS_HANDLE         FilterModuleContext,
	PNDIS_OID_REQUEST   Request,
	NDIS_STATUS         Status
	)
/*++

Routine Description:

	Notification that an OID request has been completed

	If this filter sends a request down to a lower layer, and the request is
	pended, the FilterOidRequestComplete routine is invoked when the request
	is complete.  Most requests we've sent are simply clones of requests
	received from a higher layer; all we need to do is complete the original
	higher request.

	However, if this filter driver sends original requests down, it must not
	attempt to complete a pending request to the higher layer.

Arguments:

	FilterModuleContext   - our filter context area
	NdisRequest           - the completed request
	Status                - completion status

--*/
{
	POPEN_INSTANCE                      Open = (POPEN_INSTANCE) FilterModuleContext;
	PNDIS_OID_REQUEST                   OriginalRequest;
	PFILTER_REQUEST_CONTEXT             Context;
	BOOLEAN                             bFalse = FALSE;

	TRACE_ENTER();

	Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
	OriginalRequest = (*Context);

	//
	// This is an internal request
	//
	if (OriginalRequest == NULL)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Status = %p", Status);
		NPF_InternalRequestComplete(Open, Request, Status);
		TRACE_EXIT();
		return;
	}


	FILTER_ACQUIRE_LOCK(&Open->OIDLock, bFalse);

	ASSERT(Open->PendingOidRequest == Request);
	Open->PendingOidRequest = NULL;

	FILTER_RELEASE_LOCK(&Open->OIDLock, bFalse);


	//
	// Copy the information from the returned request to the original request
	//
	switch(Request->RequestType)
	{
		case NdisRequestMethod:
			OriginalRequest->DATA.METHOD_INFORMATION.OutputBufferLength =  Request->DATA.METHOD_INFORMATION.OutputBufferLength;
			OriginalRequest->DATA.METHOD_INFORMATION.BytesRead = Request->DATA.METHOD_INFORMATION.BytesRead;
			OriginalRequest->DATA.METHOD_INFORMATION.BytesNeeded = Request->DATA.METHOD_INFORMATION.BytesNeeded;
			OriginalRequest->DATA.METHOD_INFORMATION.BytesWritten = Request->DATA.METHOD_INFORMATION.BytesWritten;
			break;

		case NdisRequestSetInformation:
			OriginalRequest->DATA.SET_INFORMATION.BytesRead = Request->DATA.SET_INFORMATION.BytesRead;
			OriginalRequest->DATA.SET_INFORMATION.BytesNeeded = Request->DATA.SET_INFORMATION.BytesNeeded;
			break;

		case NdisRequestQueryInformation:
		case NdisRequestQueryStatistics:
		default:
			OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
			OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
			break;
	}


	(*Context) = NULL;

	NdisFreeCloneOidRequest(Open->AdapterHandle, Request);

	NdisFOidRequestComplete(Open->AdapterHandle, OriginalRequest, Status);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_Status(
	NDIS_HANDLE             FilterModuleContext,
	PNDIS_STATUS_INDICATION StatusIndication
	)
/*++

Routine Description:

	Status indication handler

Arguments:

	FilterModuleContext     - our filter context
	StatusIndication        - the status being indicated

NOTE: called at <= DISPATCH_LEVEL

  FILTER driver may call NdisFIndicateStatus to generate a status indication to
  all higher layer modules.

--*/
{
	POPEN_INSTANCE      Open = (POPEN_INSTANCE) FilterModuleContext;

// 	TRACE_ENTER();
// 	IF_LOUD(DbgPrint("NPF: Status Indication\n");)

	IF_LOUD(DbgPrint("status %x\n", StatusIndication->StatusCode);)

	//
	// The filter may do processing on the status indication here, including
	// intercepting and dropping it entirely.  However, the sample does nothing
	// with status indications except pass them up to the higher layer.  It is
	// more efficient to omit the FilterStatus handler entirely if it does
	// nothing, but it is included in this sample for illustrative purposes.
	//
	NdisFIndicateStatus(Open->AdapterHandle, StatusIndication);

/*	TRACE_EXIT();*/
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_DevicePnPEventNotify(
	NDIS_HANDLE             FilterModuleContext,
	PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
	)
/*++

Routine Description:

	Device PNP event handler

Arguments:

	FilterModuleContext         - our filter context
	NetDevicePnPEvent           - a Device PnP event

NOTE: called at PASSIVE_LEVEL

--*/
{
	POPEN_INSTANCE		   Open = (POPEN_INSTANCE) FilterModuleContext;
	NDIS_DEVICE_PNP_EVENT  DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;

/*	TRACE_ENTER();*/

	//
	// The filter may do processing on the event here, including intercepting
	// and dropping it entirely.  However, the sample does nothing with Device
	// PNP events, except pass them down to the next lower* layer.  It is more
	// efficient to omit the FilterDevicePnPEventNotify handler entirely if it
	// does nothing, but it is included in this sample for illustrative purposes.
	//
	// * Trivia: Device PNP events percolate DOWN the stack, instead of upwards
	// like status indications and Net PNP events.  So the next layer is the
	// LOWER layer.
	//

	switch (DevicePnPEvent)
	{

		case NdisDevicePnPEventQueryRemoved:
		case NdisDevicePnPEventRemoved:
		case NdisDevicePnPEventSurpriseRemoved:
		case NdisDevicePnPEventQueryStopped:
		case NdisDevicePnPEventStopped:
		case NdisDevicePnPEventPowerProfileChanged:
		case NdisDevicePnPEventFilterListChanged:
			break;

		default:
			IF_LOUD(DbgPrint("FilterDevicePnPEventNotify: Invalid event.\n");)
			break;
	}

	NdisFDevicePnPEventNotify(Open->AdapterHandle, NetDevicePnPEvent);

/*	TRACE_EXIT();*/
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_NetPnPEvent(
	NDIS_HANDLE              FilterModuleContext,
	PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification
	)
/*++

Routine Description:

	Net PNP event handler

Arguments:

	FilterModuleContext         - our filter context
	NetPnPEventNotification     - a Net PnP event

NOTE: called at PASSIVE_LEVEL

--*/
{
	POPEN_INSTANCE			  Open = (POPEN_INSTANCE) FilterModuleContext;
	NDIS_STATUS               Status = NDIS_STATUS_SUCCESS;

	TRACE_ENTER();

	//
	// The filter may do processing on the event here, including intercepting
	// and dropping it entirely.  However, the sample does nothing with Net PNP
	// events, except pass them up to the next higher layer.  It is more
	// efficient to omit the FilterNetPnPEvent handler entirely if it does
	// nothing, but it is included in this sample for illustrative purposes.
	//

	Status = NdisFNetPnPEvent(Open->AdapterHandle, NetPnPEventNotification);

	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_ReturnEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	ULONG               ReturnFlags
	)
/*++

Routine Description:

	FilterReturnNetBufferLists handler.
	FilterReturnNetBufferLists is an optional function. If provided, NDIS calls
	FilterReturnNetBufferLists to return the ownership of one or more NetBufferLists
	and their embedded NetBuffers to the filter driver. If this handler is NULL, NDIS
	will skip calling this filter when returning NetBufferLists to the underlying
	miniport and will call the next lower driver in the stack. A filter that doesn't
	provide a FilterReturnNetBufferLists handler cannot originate a receive indication
	on its own.

Arguments:

	FilterInstanceContext       - our filter context area
	NetBufferLists              - a linked list of NetBufferLists that this
								  filter driver indicated in a previous call to
								  NdisFIndicateReceiveNetBufferLists
	ReturnFlags                 - flags specifying if the caller is at DISPATCH_LEVEL

--*/
{
	POPEN_INSTANCE		Open = (POPEN_INSTANCE) FilterModuleContext;
	PNET_BUFFER_LIST    CurrNbl = NetBufferLists;
	UINT                NumOfNetBufferLists = 0;
	BOOLEAN             DispatchLevel;
	ULONG               Ref;

/*	TRACE_ENTER();*/

	// Return the received NBLs.  If you removed any NBLs from the chain, make
	// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
	NdisFReturnNetBufferLists(Open->AdapterHandle, NetBufferLists, ReturnFlags);

/*	TRACE_EXIT();*/
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_CancelSendNetBufferLists(
	NDIS_HANDLE             FilterModuleContext,
	PVOID                   CancelId
	)
/*++

Routine Description:

	This function cancels any NET_BUFFER_LISTs pended in the filter and then
	calls the NdisFCancelSendNetBufferLists to propagate the cancel operation.

	If your driver does not queue any send NBLs, you may omit this routine.
	NDIS will propagate the cancelation on your behalf more efficiently.

Arguments:

	FilterModuleContext      - our filter context area.
	CancelId                 - an identifier for all NBLs that should be dequeued

Return Value:

	None

*/
{
	POPEN_INSTANCE  Open = (POPEN_INSTANCE) FilterModuleContext;

	NdisFCancelSendNetBufferLists(Open->AdapterHandle, CancelId);
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_SetModuleOptions(
	NDIS_HANDLE             FilterModuleContext
	)
/*++

Routine Description:

	This function set the optional handlers for the filter

Arguments:

	FilterModuleContext: The FilterModuleContext given to NdisFSetAttributes

Return Value:

	NDIS_STATUS_SUCCESS
	NDIS_STATUS_RESOURCES
	NDIS_STATUS_FAILURE

--*/
{
   NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
   UNREFERENCED_PARAMETER(FilterModuleContext);

   return Status;
}

//-------------------------------------------------------------------

ULONG
NPF_GetPhysicalMedium(
	NDIS_HANDLE FilterModuleContext
)
{
	TRACE_ENTER();

	ULONG PhysicalMedium = 0;
	ULONG BytesProcessed = 0;

	// get the PhysicalMedium when filter driver loads
	NPF_DoInternalRequest(FilterModuleContext,
		NdisRequestQueryInformation,
		OID_GEN_PHYSICAL_MEDIUM,
		&PhysicalMedium,
		sizeof(PhysicalMedium),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(PhysicalMedium))
	{
		IF_LOUD(DbgPrint("BytesProcessed != sizeof(PhysicalMedium), BytesProcessed = %x, sizeof(PhysicalMedium) = %x\n", BytesProcessed, sizeof(PhysicalMedium));)
			TRACE_EXIT();
		return 0;
	}
	else
	{
		TRACE_EXIT();
		return PhysicalMedium;
	}
}


//-------------------------------------------------------------------

ULONG
NPF_GetPacketFilter(
	NDIS_HANDLE FilterModuleContext
	)
{
	TRACE_ENTER();

	ULONG PacketFilter = 0;
	ULONG BytesProcessed = 0;

	// get the PacketFilter when filter driver loads
	NPF_DoInternalRequest(FilterModuleContext,
		NdisRequestQueryInformation,
		OID_GEN_CURRENT_PACKET_FILTER,
		&PacketFilter,
		sizeof(PacketFilter),
		0,
		0,
		&BytesProcessed
		);

	if (BytesProcessed != sizeof(PacketFilter))
	{
		IF_LOUD(DbgPrint("BytesProcessed != sizeof(PacketFilter), BytesProcessed = %x, sizeof(PacketFilter) = %x\n", BytesProcessed, sizeof(PacketFilter));)
		TRACE_EXIT();
		return 0;
	}
	else
	{
		TRACE_EXIT();
		return PacketFilter;
	}
}

//-------------------------------------------------------------------

NDIS_STATUS
NPF_SetPacketFilter(
	NDIS_HANDLE FilterModuleContext,
	ULONG PacketFilter
)
{
	TRACE_ENTER();

	NDIS_STATUS Status;
	ULONG BytesProcessed = 0;

	// get the PacketFilter when filter driver loads
	NPF_DoInternalRequest(FilterModuleContext,
		NdisRequestQueryInformation,
		OID_GEN_CURRENT_PACKET_FILTER,
		&PacketFilter,
		sizeof(PacketFilter),
		0,
		0,
		&BytesProcessed
	);

	if (BytesProcessed != sizeof(PacketFilter))
	{
		IF_LOUD(DbgPrint("BytesProcessed != sizeof(PacketFilter), BytesProcessed = %x, sizeof(PacketFilter) = %x\n", BytesProcessed, sizeof(PacketFilter));)
		TRACE_EXIT();
		Status = NDIS_STATUS_FAILURE;
		return Status;
	}
	else
	{
		TRACE_EXIT();
		Status = NDIS_STATUS_SUCCESS;
		return Status;
	}
}

//-------------------------------------------------------------------

NDIS_STATUS
NPF_DoInternalRequest(
	_In_ NDIS_HANDLE			      FilterModuleContext,
	_In_ NDIS_REQUEST_TYPE            RequestType,
	_In_ NDIS_OID                     Oid,
	_Inout_updates_bytes_to_(InformationBufferLength, *pBytesProcessed)
		 PVOID                        InformationBuffer,
	_In_ ULONG                        InformationBufferLength,
	_In_opt_ ULONG                    OutputBufferLength,
	_In_ ULONG                        MethodId,
	_Out_ PULONG                      pBytesProcessed
	)
{
	TRACE_ENTER();

	POPEN_INSTANCE				Open = (POPEN_INSTANCE) FilterModuleContext;
	INTERNAL_REQUEST            FilterRequest;
	PNDIS_OID_REQUEST           NdisRequest = &FilterRequest.Request;
	NDIS_STATUS                 Status = NDIS_STATUS_FAILURE;
	BOOLEAN                     bFalse;

	bFalse = FALSE;
	*pBytesProcessed = 0;
	NdisZeroMemory(NdisRequest, sizeof(NDIS_OID_REQUEST));

	NdisInitializeEvent(&FilterRequest.InternalRequestCompletedEvent);
	NdisResetEvent(&FilterRequest.InternalRequestCompletedEvent);

	if (*((PVOID *) FilterRequest.Request.SourceReserved) != NULL)
	{
		*((PVOID *) FilterRequest.Request.SourceReserved) = NULL; //indicates this is a self-sent request
	}

	NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	NdisRequest->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
	NdisRequest->RequestType = RequestType;

	switch (RequestType)
	{
		case NdisRequestQueryInformation:
			NdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
			NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength = InformationBufferLength;
			break;

		case NdisRequestSetInformation:
			NdisRequest->DATA.SET_INFORMATION.Oid = Oid;
			NdisRequest->DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
			break;

		case NdisRequestMethod:
			NdisRequest->DATA.METHOD_INFORMATION.Oid = Oid;
			NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
			NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength = InformationBufferLength;
			NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
			break;

		default:
			IF_LOUD(DbgPrint("Unsupported RequestType: %d\n", RequestType);)
			IF_LOUD(DbgPrint("Status = %x\n", Status);)
			TRACE_EXIT();
			return Status;
			// ASSERT(bFalse);
			// break;
	}

	NdisRequest->RequestId = (PVOID)NPF_REQUEST_ID;

	Status = NdisFOidRequest(Open->AdapterHandle, NdisRequest);

	if (Status == NDIS_STATUS_PENDING)
	{
		NdisWaitEvent(&FilterRequest.InternalRequestCompletedEvent, 0);
		Status = FilterRequest.RequestStatus;
	}

	if (Status == NDIS_STATUS_SUCCESS)
	{
		if (RequestType == NdisRequestSetInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.SET_INFORMATION.BytesRead;
		}

		if (RequestType == NdisRequestQueryInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
		}

		if (RequestType == NdisRequestMethod)
		{
			*pBytesProcessed = NdisRequest->DATA.METHOD_INFORMATION.BytesWritten;
		}

		//
		// The driver below should set the correct value to BytesWritten
		// or BytesRead. But now, we just truncate the value to InformationBufferLength
		//
		if (RequestType == NdisRequestMethod)
		{
			if (*pBytesProcessed > OutputBufferLength)
			{
				*pBytesProcessed = OutputBufferLength;
			}
		}
		else
		{
			if (*pBytesProcessed > InformationBufferLength)
			{
				*pBytesProcessed = InformationBufferLength;
			}
		}
	}

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Status = %p", Status);
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

VOID
NPF_InternalRequestComplete(
	_In_ NDIS_HANDLE                  FilterModuleContext,
	_In_ PNDIS_OID_REQUEST            NdisRequest,
	_In_ NDIS_STATUS                  Status
	)
/*++

Routine Description:

	NDIS entry point indicating completion of a pended NDIS_OID_REQUEST.

Arguments:

	FilterModuleContext - pointer to filter module context
	NdisRequest - pointer to NDIS request
	Status - status of request completion

Return Value:

	None

--*/
{
	PINTERNAL_REQUEST pRequest;

	UNREFERENCED_PARAMETER(FilterModuleContext);

	TRACE_ENTER();

	pRequest = CONTAINING_RECORD(NdisRequest, INTERNAL_REQUEST, Request);

	//
	// Set the request result
	//
	pRequest->RequestStatus = Status;
	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "pRequest->RequestStatus = Status = %x", Status);

	//
	// and awake the caller
	//
	NdisSetEvent(&pRequest->InternalRequestCompletedEvent);

	TRACE_EXIT();
}

