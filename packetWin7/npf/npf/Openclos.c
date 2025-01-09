/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2023 by Nmap Software LLC ("The Nmap Project").  All
 * rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it is not
 * open source software and may not be redistributed or used in other software
 * without special permission from the Nmap Project. The standard (free) version
 * is usually limited to installation on five systems. For more details, see the
 * LICENSE file included with Npcap and also available at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not a
 * substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap OEM
 * within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may choose
 * between a perpetual unlimited license or a quarterly term license, along with
 * options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to use
 * Npcap OEM internally, without redistribution outside their organization. This
 * allows them to bypass the 5-system usage cap of the Npcap free edition. It
 * includes commercial support and update options, and provides the extra Npcap
 * OEM features such as the silent installer for automated deployment. Prices
 * and details: https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a warranty.
 * Npcap OEM also includes a silent installer for unattended installation.
 * Further details about Npcap OEM are available from https://npcap.com/oem/,
 * and you are also welcome to contact us at sales@nmap.com to ask any questions
 * or set up a license for your organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will be
 * free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial licensing
 * customers) has granted you additional rights to Npcap or Npcap OEM, those
 * additional rights take precedence where they conflict with the terms of the
 * license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features. By sending
 * these changes to the Nmap Project (including through direct email or our
 * mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap. If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. Warranty rights and commercial support are
 * available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license header.
 * We have kept those for attribution purposes, but any license terms granted by
 * those notices apply only to their original work, and not to any changes made
 * by the Nmap Project or to this entire file.
 *
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

#include "Packet.h"
#include "Loopback.h"
#include "..\..\..\Common\WpcapNames.h"

extern PNPCAP_DRIVER_EXTENSION g_pDriverExtension;

/*!
  \brief Add the open context to the group open array of a filter module.
  \param pOpen Pointer to open context structure.
  \param pFiltMod Pointer to filter module context structure.

  This function is used by NPF_OpenAdapter to add a new open context to
  the group open array of a filter module, this array is designed to help find and clean the specific adapter context.
  A filter module context is generated by NPF_AttachAdapter(), it handles with NDIS.
  A open instance is generated by NPF_OpenAdapter(), it handles with the WinPcap
  up-level packet.dll and so on.
*/
_When_(bAtDispatchLevel != 0, _IRQL_requires_(DISPATCH_LEVEL))
void
NPF_AddToGroupOpenArray(
	_In_ POPEN_INSTANCE pOpen,
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ BOOLEAN bAtDispatchLevel
	);

/*!
  \brief Remove the filter module context from the global filter module array.
  \param pFiltMod Pointer to filter module context structure.

  This function is used by NPF_DetachAdapter(), NPF_Cleanup() and NPF_CleanupForUnclosed()
  to remove a filter module context from the global filter module array.
*/
void
NPF_RemoveFromFilterModuleArray(
	_Inout_ PNPCAP_FILTER_MODULE pFiltMod
	);

/*!
  \brief Get a pointer to filter module from the global array.
  \param pAdapterName The adapter name of the target filter module.
  \return Pointer to the filter module, or NULL if not found.

  This function is used to create a group member adapter for the group head one.
*/
_Ret_maybenull_
PNPCAP_FILTER_MODULE
NPF_GetFilterModuleByAdapterName(
	_In_ PNDIS_STRING pAdapterName
	);

/*!
  \brief Create a new Open instance
  \return Pointer to the new open instance.

*/

_Must_inspect_result_
_Success_(return != NULL)
__drv_allocatesMem(mem)
__declspec(restrict) POPEN_INSTANCE
NPF_CreateOpenObject(
	_In_ NDIS_HANDLE NdisHandle
	);

#ifdef HAVE_DOT11_SUPPORT
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NPF_GetDataRateMappingTable(
	_In_ PNPCAP_FILTER_MODULE pFiltMod
	);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NPF_GetCurrentOperationMode(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_Out_ PDOT11_CURRENT_OPERATION_MODE pCurrentOperationMode);

_IRQL_requires_(PASSIVE_LEVEL)
ULONG NPF_GetCurrentOperationMode_Wrapper(
	_In_ PNPCAP_FILTER_MODULE pFiltMod);

#endif
//-------------------------------------------------------------------

_Use_decl_annotations_
BOOLEAN
NPF_IsOpenInstance(
	POPEN_INSTANCE pOpen
	)
{
	if (pOpen == NULL)
	{
		return FALSE;
	}
	if (pOpen->OpenSignature != OPEN_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}

_Use_decl_annotations_
BOOLEAN
NPF_StartUsingBinding(
	PNPCAP_FILTER_MODULE pFiltMod, BOOLEAN AtDispatchLevel
	)
{
	if (!pFiltMod) {
		return FALSE;
	}
	// NPF_OpenAdapter() is not called on PASSIVE_LEVEL, so the assertion will fail.
	// ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	FILTER_ACQUIRE_LOCK(&pFiltMod->AdapterHandleLock, AtDispatchLevel);

	if (pFiltMod->AdapterBindingStatus != FilterRunning)
	{
		FILTER_RELEASE_LOCK(&pFiltMod->AdapterHandleLock, AtDispatchLevel);
		return FALSE;
	}

	pFiltMod->AdapterHandleUsageCounter++;

	FILTER_RELEASE_LOCK(&pFiltMod->AdapterHandleLock, AtDispatchLevel);

	return TRUE;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_StopUsingBinding(
	PNPCAP_FILTER_MODULE pFiltMod, BOOLEAN AtDispatchLevel
	)
{
	NT_ASSERT(pFiltMod != NULL);
	//
	//  There is no risk in calling this function from abobe passive level
	//  (i.e. DISPATCH, in this driver) as we acquire a spinlock and decrement a
	//  counter.
	//
	//	ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	FILTER_ACQUIRE_LOCK(&pFiltMod->AdapterHandleLock, AtDispatchLevel);

	NT_ASSERT(pFiltMod->AdapterHandleUsageCounter > 0);

	pFiltMod->AdapterHandleUsageCounter--;

	FILTER_RELEASE_LOCK(&pFiltMod->AdapterHandleLock, AtDispatchLevel);
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_ResetBufferContents(
	POPEN_INSTANCE Open,
	BOOLEAN AcquireLock
)
{
	LOCK_STATE_EX lockState;
	PLIST_ENTRY Curr;
	PNPF_CAP_DATA pCapData;

	if (AcquireLock)
		NdisAcquireRWLockWrite(Open->BufferLock, &lockState, 0);
	Open->Accepted = 0;
	Open->Dropped = 0;
	Open->Received = 0;

	// Clear packets from the buffer
	Curr = Open->PacketQueue.Flink;
	while (Curr != &Open->PacketQueue)
	{
		NT_ASSERT(Curr != NULL);
		pCapData = CONTAINING_RECORD(Curr, NPF_CAP_DATA, PacketQueueEntry);
		Curr = Curr->Flink;

		NPF_ReturnCapData(pCapData);
	}
	// Remove links
	InitializeListHead(&Open->PacketQueue);
	// Reset Free counter
	Open->Free = Open->Size;
	if (AcquireLock)
		NdisReleaseRWLock(Open->BufferLock, &lockState);
}

_Use_decl_annotations_
VOID NPF_ReturnNBCopies(PNPF_NB_COPIES pNBCopy)
{
	PVOID pDeleteMe = pNBCopy->Buffer;
	LONG refcount = NpfInterlockedDecrement(&pNBCopy->refcount);
	NT_ASSERT(refcount >= 0);
	if (refcount == 0)
	{
		if (pDeleteMe != NULL)
		{
			NT_ASSERT(pNBCopy->ulSize > 0);
			ExFreePoolWithTag(pDeleteMe, NPF_PACKET_DATA_TAG);
		}
		ExFreeToLookasideListEx(&g_pDriverExtension->NBCopiesPool, pNBCopy);
	}
}

_Use_decl_annotations_
VOID NPF_ReturnNBLCopy(PNPF_NBL_COPY pNBLCopy)
{
	PUCHAR pDot11RadiotapHeader = pNBLCopy->Dot11RadiotapHeader;
	LONG refcount = NpfInterlockedDecrement(&pNBLCopy->refcount);
	NT_ASSERT(refcount >= 0);
	if (refcount == 0)
	{
		ExFreeToLookasideListEx(&g_pDriverExtension->NBLCopyPool, pNBLCopy);
		if (pDot11RadiotapHeader != NULL)
		{
			ExFreeToLookasideListEx(&g_pDriverExtension->Dot11HeaderPool, pDot11RadiotapHeader);
		}
	}
}

_Use_decl_annotations_
VOID NPF_ReturnCapData(PNPF_CAP_DATA pCapData)
{
	PNPF_NB_COPIES pNBCopy = pCapData->pNBCopy;
	PNPF_NBL_COPY pNBLCopy = (pNBCopy ? pNBCopy->pNBLCopy : NULL);
	ExFreeToLookasideListEx(&g_pDriverExtension->CapturePool, pCapData);
	if (pNBLCopy)
	{
		NPF_ReturnNBLCopy(pNBLCopy);
	}
	if (pNBCopy)
	{
		NPF_ReturnNBCopies(pNBCopy);
	}
}

//-------------------------------------------------------------------

VOID
NPF_AddToAllOpensList(_In_ POPEN_INSTANCE pOpen)
{
	LOCK_STATE_EX lockState;

	NdisAcquireRWLockWrite(g_pDriverExtension->AllOpensLock, &lockState, 0);
	InsertTailList(&g_pDriverExtension->AllOpens, &pOpen->AllOpensEntry);
	NdisReleaseRWLock(g_pDriverExtension->AllOpensLock, &lockState);
}

VOID
NPF_RemoveFromAllOpensList(_In_ POPEN_INSTANCE pOpen)
{
	LOCK_STATE_EX lockState;

	NdisAcquireRWLockWrite(g_pDriverExtension->AllOpensLock, &lockState, 0);
	RemoveEntryList(&pOpen->AllOpensEntry);
	NdisReleaseRWLock(g_pDriverExtension->AllOpensLock, &lockState);
}

_Use_decl_annotations_
NTSTATUS
NPF_OpenAdapter(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	PNPCAP_FILTER_MODULE			pFiltMod = NULL;
	POPEN_INSTANCE			Open;
	PIO_STACK_LOCATION		IrpSp;
	ULONG idx;
	PUNICODE_STRING FileName;
	NDIS_HANDLE NdisFilterHandle = g_pDriverExtension->FilterDriverHandle;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	// I/O manager should not be handing us IRPs until DriverEntry returns,
	// but we can exercise healthy paranoia
	if (!NT_VERIFY(NdisFilterHandle) || !NT_VERIFY(g_pDriverExtension->AllOpensLock))
	{
		Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_DEVICE_NOT_READY;
	}

	FileName = &IrpSp->FileObject->FileName;
	// Skip leading slashes
	for (idx = 0; idx < FileName->Length && FileName->Buffer[idx] == L'\\'; idx++);
	// If the filename is empty or all slashes, this is a request for the "root" device.
	// Otherwise, look for a filter module for it.
	if (idx != FileName->Length)
	{
		// Find the head adapter of the global array.
		pFiltMod = NPF_GetFilterModuleByAdapterName(&IrpSp->FileObject->FileName);

		if (pFiltMod == NULL)
		{
			// Can't find the adapter from the global open array.
			INFO_DBG(
				"NPF_GetFilterModuleByAdapterName error, pFiltMod=NULL, AdapterName=%ws",
				IrpSp->FileObject->FileName.Buffer);

			Irp->IoStatus.Status = STATUS_NDIS_INTERFACE_NOT_FOUND;
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			TRACE_EXIT();
			return STATUS_NDIS_INTERFACE_NOT_FOUND;
		}

		if (NPF_StartUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN) == FALSE)
		{
			INFO_DBG(
				"NPF_StartUsingBinding error, AdapterName=%ws",
				IrpSp->FileObject->FileName.Buffer);

			Irp->IoStatus.Status = STATUS_NDIS_OPEN_FAILED;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			TRACE_EXIT();
			return STATUS_NDIS_OPEN_FAILED;
		}

		NdisFilterHandle = pFiltMod->AdapterHandle;
	}

	// Create a group child adapter object from the head adapter.
	Open = NPF_CreateOpenObject(NdisFilterHandle);
	if (Open == NULL)
	{
		if (pFiltMod)
			NPF_StopUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN);
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	Open->UserPID = IoGetRequestorProcessId(Irp);

	INFO_DBG(
		"Open(%p) name=%ws, Loopback=%d\n",
		Open,
		IrpSp->FileObject->FileName.Buffer,
		pFiltMod ? pFiltMod->Loopback : 0);

	IrpSp->FileObject->FsContext = Open;

	NPF_AddToAllOpensList(Open);

	//
	// complete the open
	//

	if (pFiltMod)
	{
		// Initializes pFiltMod, AdapterID, bDot11, bLoopback, OpenStatus
		NPF_AddToGroupOpenArray(Open, pFiltMod, FALSE);
		NPF_StopUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN);
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NPF_EnableOps(_In_ PNPCAP_FILTER_MODULE pFiltMod)
{
	NTSTATUS Status = STATUS_PENDING;
	NDIS_EVENT Event;

	if (pFiltMod == NULL)
	{
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
	switch(pFiltMod->OpsState)
	{
		case OpsEnabled:
			// Already good to go;
			Status = STATUS_SUCCESS;
			break;
		case OpsEnabling:
		case OpsDisabling:
			NdisInitializeEvent(&Event);
			NdisResetEvent(&Event);
			// Wait for other thread to finish enabling
			while (pFiltMod->OpsState == OpsEnabling || pFiltMod->OpsState == OpsDisabling)
			{
				NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);
				NdisWaitEvent(&Event, 1);
				NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
			}
			if (pFiltMod->OpsState == OpsEnabled)
			{
				Status = STATUS_SUCCESS;
				break;
			}
			else if (pFiltMod->OpsState != OpsDisabled)
			{
				Status = STATUS_DRIVER_INTERNAL_ERROR;
				break;
			}
			// else drop through to OpsDisabled:
		case OpsDisabled:
			// Time to get to work
			pFiltMod->OpsState = OpsEnabling;
			break;
		default:
			Status = STATUS_INVALID_DEVICE_STATE;
	}
	NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);

	if (Status != STATUS_PENDING)
	{
		return Status;
	}

	Status = STATUS_SUCCESS;
	do
	{

#ifdef HAVE_DOT11_SUPPORT
		// DataRateMappingTable
		if (pFiltMod->Dot11)
		{
			// Fetch the device's data rate mapping table with the OID_DOT11_DATA_RATE_MAPPING_TABLE OID.
			if (!NT_SUCCESS(NPF_GetDataRateMappingTable(pFiltMod)))
			{
				INFO_DBG("pFiltMod(%p) failed to fetch dot11 table.\n", pFiltMod);
			}
		}
#endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (pFiltMod->Loopback)
		{
			Status = NPF_InitWFP();
			if (!NT_SUCCESS(Status)) {
				break;
			}
		}
#endif
	} while (0);

	pFiltMod->OpsState = NT_SUCCESS(Status) ? OpsEnabled : OpsDisabled;
	return Status;
}

VOID
NPF_RegisterBpf(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ PNPCAP_BPF_PROGRAM pBpfProgram)
{
	// Assert/verify pBpfProgram fields are set
	LOCK_STATE_EX lockState;

	// Lock the BpfPrograms list
	NdisAcquireRWLockWrite(pFiltMod->BpfProgramsLock, &lockState, 0);
	// Insert/update the bpf for this open instance
	if (pBpfProgram->BpfProgramsEntry.Flink != NULL)
	{
		// This program is in the list already.
#if DBG
		// In debug mode, we can verify/assert this.
		BOOLEAN bFound = FALSE;
		NT_ASSERT(pBpfProgram->BpfProgramsEntry.Blink != NULL);
		for (PLIST_ENTRY Curr = pFiltMod->BpfPrograms.Flink;
				Curr != &pFiltMod->BpfPrograms;
				Curr = Curr->Flink)
		{
			if (Curr == &pBpfProgram->BpfProgramsEntry)
			{
				NT_ASSERT(Curr->Flink->Blink == Curr);
				bFound = TRUE;
				break;
			}
		}
		NT_ASSERT(bFound);
#endif
	}
	else
	{
		NT_ASSERT(pBpfProgram->BpfProgramsEntry.Blink == NULL);
		InsertTailList(&pFiltMod->BpfPrograms, &pBpfProgram->BpfProgramsEntry);
	}
	// Unlock the list
	NdisReleaseRWLock(pFiltMod->BpfProgramsLock, &lockState);
}
VOID
NPF_UnregisterBpf(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ PNPCAP_BPF_PROGRAM pBpfProgram)
{
	LOCK_STATE_EX lockState;
	if (pBpfProgram->BpfProgramsEntry.Flink == NULL &&
			NT_VERIFY(pBpfProgram->BpfProgramsEntry.Blink == NULL))
	{
		return;
	}
	NT_ASSERT(pBpfProgram->BpfProgramsEntry.Blink != NULL);
	// Lock the BpfPrograms list
	NdisAcquireRWLockWrite(pFiltMod->BpfProgramsLock, &lockState, 0);
	// remove the bpf for this open instance
	RemoveEntryList(&pBpfProgram->BpfProgramsEntry);
	// Unlock the list
	NdisReleaseRWLock(pFiltMod->BpfProgramsLock, &lockState);

	// Make sure we know this has been removed
	pBpfProgram->BpfProgramsEntry.Flink = NULL;
	pBpfProgram->BpfProgramsEntry.Blink = NULL;
}

/* State table. SUCCESS = PendingIrps[MaxState]++
 *               \  MaxState
 *                \ --------
 * OpenStatus      \  OpenRunning | OpenInitializing | OpenAttached | OpenDetached | OpenClosed
 * -----------------|-------------|------------------|--------------|--------------|-----------
 * OpenRunning      | SUCCESS     | BUG              | SUCCESS      | SUCCESS      | BUG
 * OpenInitializing | Wait        | BUG              | SUCCESS      | SUCCESS      | BUG
 * OpenAttached     | EnableOps   | BUG              | SUCCESS      | SUCCESS      | BUG
 * OpenDetached     | FAIL        | BUG              | FAIL         | SUCCESS      | BUG
 * OpenClosed       | FAIL        | BUG              | FAIL         | FAIL         | BUG
 */
_Use_decl_annotations_
BOOLEAN
NPF_StartUsingOpenInstance(
	POPEN_INSTANCE pOpen, OPEN_STATE MaxState, BOOLEAN AtDispatchLevel)
{
	BOOLEAN returnStatus = TRUE;
	BOOLEAN bAttached = FALSE;
	NDIS_EVENT Event;

	if (!NT_VERIFY(MaxState < OpenClosed && MaxState != OpenInitializing))
	{
		ERROR_DBG("Invalid MaxState: %d\n", MaxState);
		return FALSE;
	}

	// Check if it's closing; no need to lock for this, since aligned reads are atomic
	if (pOpen->OpenStatus >= OpenClosed)
	{
		WARNING_DBG("pOpen %p is closing (OpenStatus: %d)\n", pOpen, pOpen->OpenStatus);
		return FALSE;
	}

	// Have to hold this lock before checking/using pOpen->pFiltMod
	FILTER_ACQUIRE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);

	// Do we need an attached adapter?
	if (MaxState <= OpenAttached)
	{
		bAttached = (pOpen->pFiltMod != NULL && NPF_StartUsingBinding(pOpen->pFiltMod, TRUE));
		if (!bAttached)
		{
			// Not attached, but need to be.
			FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
			WARNING_DBG("Not attached: pFiltMod = %p\n", pOpen->pFiltMod);
			return FALSE;
		}
	}

	if (MaxState == OpenRunning)
	{
		// NPF_EnableOps must be called at PASSIVE_LEVEL. Release the lock first.
		NT_ASSERT(!AtDispatchLevel);
		if (AtDispatchLevel) {
			// This is really bad! We should never be able to get here.
			ERROR_DBG("CRITICAL ERROR: called at DISPATCH_LEVEL\n");
			returnStatus = FALSE;
		}
		else if (pOpen->OpenStatus == OpenAttached)
		{
			pOpen->OpenStatus = OpenInitializing;
			FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
			returnStatus = NT_SUCCESS(NPF_EnableOps(pOpen->pFiltMod));
			FILTER_ACQUIRE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);

			if (returnStatus)
			{
				// Get the absolute value of the system boot time.
				// This is used for timestamp conversion.
				TIME_SYNCHRONIZE(&pOpen->start);
				NPF_UpdateTimestampModeCounts(pOpen->pFiltMod, pOpen->TimestampMode, TIMESTAMPMODE_UNSET);

				// Insert a null filter (accept all)
				NPF_RegisterBpf(pOpen->pFiltMod, &pOpen->BpfProgram);
				pOpen->OpenStatus = OpenRunning;
			}
			else
			{
				pOpen->OpenStatus = OpenAttached;
			}
		}
		else if (pOpen->OpenStatus == OpenInitializing)
		{
			// Wait until it's ready...
			NdisInitializeEvent(&Event);
			NdisResetEvent(&Event);
			// Wait for other thread to finish enabling
			while (pOpen->OpenStatus == OpenInitializing)
			{
				FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
				INFO_DBG("Waiting, OpenStatus = %d\n", pOpen->OpenStatus);
				NdisWaitEvent(&Event, 1);
				FILTER_ACQUIRE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
			}
		}
	}

	INFO_DBG("OpenStatus = %d; MaxState = %d\n", pOpen->OpenStatus, MaxState);
	returnStatus = returnStatus && (pOpen->OpenStatus <= MaxState);
	if (returnStatus)
	{
		NT_ASSERT(MaxState < OpenClosed); // No IRPs can be pending for OpenClosed or higher state.
		pOpen->PendingIrps[MaxState]++;
	}
	else if (bAttached)
	{
		// Failed to change OpenStatus, so have to release/deref the adapter binding, too.
		NPF_StopUsingBinding(pOpen->pFiltMod, TRUE);
	}
	FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);

	return returnStatus;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_StopUsingOpenInstance(
	POPEN_INSTANCE pOpen,
	OPEN_STATE MaxState,
	BOOLEAN AtDispatchLevel
	)
{
	FILTER_ACQUIRE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
	NT_ASSERT(MaxState < OpenClosed);
	NT_ASSERT(pOpen->PendingIrps[MaxState] > 0);
	pOpen->PendingIrps[MaxState]--;

	if (MaxState <= OpenAttached)
	{
		NPF_StopUsingBinding(pOpen->pFiltMod, AtDispatchLevel);
	}
	FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, AtDispatchLevel);
}

//-------------------------------------------------------------------

_Use_decl_annotations_
OPEN_STATE
NPF_DemoteOpenStatus(
	POPEN_INSTANCE pOpen,
	OPEN_STATE NewState
	)
{
	if (pOpen->OpenStatus == OpenClosed) {
		// No change
		return OpenClosed;
	}
	OPEN_STATE OldState = InterlockedExchange((LONG *)&pOpen->OpenStatus, (LONG) NewState);

	NT_ASSERT(NewState > OldState);
	INFO_DBG("Open %p: %d -> %d\n", pOpen, OldState, NewState);
	if (OldState == OpenRunning)
	{
		NPF_UpdateTimestampModeCounts(pOpen->pFiltMod, TIMESTAMPMODE_UNSET, pOpen->TimestampMode);
		NPF_UnregisterBpf(pOpen->pFiltMod, &pOpen->BpfProgram);
	}

	return OldState;
}

//-------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
VOID NPF_OpenWaitPendingIrps(
		_At_(pOpen->OpenStatus, _In_range_(OpenDetached,OpenClosed))
	_In_ POPEN_INSTANCE pOpen
	)
{
	NDIS_EVENT Event;
	OPEN_STATE state;

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	NT_ASSERT(pOpen->OpenStatus <= OpenClosed);
	NT_ASSERT(pOpen->OpenStatus >= OpenDetached);

	// Wait for IRPs that require an attached adapter
	for (state = pOpen->OpenStatus - 1; state < pOpen->OpenStatus && state >= OpenRunning; state--)
	{
		while (pOpen->PendingIrps[state] > 0)
		{
			INFO_DBG("Open %p: %lu pending IRPS at %d\n", pOpen, pOpen->PendingIrps[state], state);
			NdisReleaseSpinLock(&pOpen->OpenInUseLock);
			NdisWaitEvent(&Event, 1);
			NdisAcquireSpinLock(&pOpen->OpenInUseLock);
		}
	}
	NdisReleaseSpinLock(&pOpen->OpenInUseLock);
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_ReleaseOpenInstanceResources(
	POPEN_INSTANCE pOpen
	)
{

	TRACE_ENTER();

	NT_ASSERT(pOpen != NULL);
	NT_ASSERT(pOpen->OpenStatus == OpenClosed);

	INFO_DBG("Open= %p\n", pOpen);


	//
	// Free the filter if it's present
	//
	if (pOpen->BpfProgram.bpf_program != NULL)
	{
		ExFreePool(pOpen->BpfProgram.bpf_program);
		pOpen->BpfProgram.bpf_program = NULL;
	}

	//
	// Dereference the read event.
	//

	if (pOpen->ReadEvent != NULL)
	{
		ObDereferenceObject(pOpen->ReadEvent);
		pOpen->ReadEvent = NULL;
	}

	//
	// free the buffer
	//
	if (pOpen->Size > 0)
	{
		// *should* be no need to acquire this lock, but better safe than sorry?
		NPF_ResetBufferContents(pOpen, TRUE);
	}

	NdisFreeRWLock(pOpen->BufferLock);
	NdisFreeSpinLock(&pOpen->CountersLock);
	NdisFreeSpinLock(&pOpen->OpenInUseLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_ReleaseFilterModuleResources(
	PNPCAP_FILTER_MODULE pFiltMod
	)
{
	TRACE_ENTER();

	NT_ASSERT(pFiltMod != NULL);

	if (pFiltMod->PacketPool) // Release the packet buffer pool
	{
		NdisFreeNetBufferListPool(pFiltMod->PacketPool);
		pFiltMod->PacketPool = NULL;
	}

	// Release the adapter name
	if (pFiltMod->AdapterName.Buffer)
	{
		ExFreePool(pFiltMod->AdapterName.Buffer);
		pFiltMod->AdapterName.Buffer = NULL;
		pFiltMod->AdapterName.Length = 0;
		pFiltMod->AdapterName.MaximumLength = 0;
	}

#ifdef HAVE_DOT11_SUPPORT
	if (pFiltMod->DataRateMappingTable)
	{
		ExFreePoolWithTag(pFiltMod->DataRateMappingTable, NPF_DOT11_POOL_TAG);
		pFiltMod->DataRateMappingTable = NULL;
	}
#endif

	NdisFreeSpinLock(&pFiltMod->OIDLock);
	NdisFreeRWLock(pFiltMod->OpenInstancesLock);
	NdisFreeRWLock(pFiltMod->BpfProgramsLock);
	NdisFreeSpinLock(&pFiltMod->AdapterHandleLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

/* Issue an OID query for a 4-byte value (ULONG). Address must be allocated
 * from nonpaged pool.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NPF_OidGetUlongNonpagedPtr(
		_At_(pFiltMod->AdapterBindingStatus, _In_range_(FilterPausing, FilterRestarting))
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ NDIS_OID Oid,
	_Out_ PULONG pNonpagedUlong
	)
{
	if (!NT_VERIFY(pNonpagedUlong != NULL))
	{
		return STATUS_INVALID_PARAMETER;
	}
	ULONG BytesProcessed = 0;

	NTSTATUS Status = NPF_DoInternalRequest(pFiltMod,
		NdisRequestQueryInformation,
		Oid,
		pNonpagedUlong,
		sizeof(ULONG),
		0,
		0,
		&BytesProcessed
	);

	INFO_DBG("pFiltMod(%p) Oid %#x, Status %#x, %lu bytes\n",
			pFiltMod, Oid, Status, BytesProcessed);
	if (Status == NDIS_STATUS_SUCCESS)
	{
		NT_ASSERT(BytesProcessed == sizeof(ULONG));
	}
	return Status;
}

//-------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
inline NTSTATUS
NPF_GetDeviceMTU(
	_In_ PNPCAP_FILTER_MODULE pFiltMod
	)
{
	NT_ASSERT(pFiltMod->AdapterBindingStatus == FilterRestarting);

	INFO_DBG("pFiltMod(%p) OID_GEN_MAXIMUM_TOTAL_SIZE (%#x)\n",
			pFiltMod, OID_GEN_MAXIMUM_TOTAL_SIZE);

	return NPF_OidGetUlongNonpagedPtr(pFiltMod,
		OID_GEN_MAXIMUM_TOTAL_SIZE,
		&pFiltMod->MaxFrameSize
	);
}

/*!
  \brief Get the packet filter of the adapter.
  \param FilterModuleContext Pointer to the filter context structure.
  \return the packet filter.

  This function is used to get the original adapter packet filter with
  a NPF_AttachAdapter(), it is stored in the HigherPacketFilter, the combination
  of HigherPacketFilter and MyPacketFilter will be the final packet filter
  the low-level adapter sees.
*/
_IRQL_requires_(PASSIVE_LEVEL)
inline NTSTATUS
NPF_GetPacketFilter(
	_In_ PNPCAP_FILTER_MODULE pFiltMod
	)
{
	// This can only be used before we start mucking with the packet filter.
	INFO_DBG("pFiltMod(%p) OID_GEN_CURRENT_PACKET_FILTER (%#x)\n",
			pFiltMod, OID_GEN_CURRENT_PACKET_FILTER);
	if (!pFiltMod->PacketFilterGetOK)
	{
		INFO_DBG("pFiltMod(%p) OID_GEN_CURRENT_PACKET_FILTER query not supported\n", pFiltMod);
		return STATUS_NOT_SUPPORTED;
	}
	NTSTATUS Status = NPF_OidGetUlongNonpagedPtr(pFiltMod,
		OID_GEN_CURRENT_PACKET_FILTER,
		&pFiltMod->HigherPacketFilter
	);

	if (Status == STATUS_SUCCESS)
	{
		pFiltMod->HigherPacketFilterSet = 1;
		pFiltMod->PacketFilterGetOK = 1;
	}
	else if (Status == NDIS_STATUS_INVALID_OID)
	{
		pFiltMod->PacketFilterGetOK = 0;
	}

	return Status;
}

//-------------------------------------------------------------------
#ifdef HAVE_DOT11_SUPPORT
_Use_decl_annotations_
NTSTATUS
NPF_GetDataRateMappingTable(
	PNPCAP_FILTER_MODULE pFiltMod
)
{
	TRACE_ENTER();
	NT_ASSERT(pFiltMod != NULL);

	// Check if it's already set
	if (pFiltMod->DataRateMappingTable != NULL)
	{
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}

	// Not set, allocate a new one
	PDOT11_DATA_RATE_MAPPING_TABLE pDRMT = NPF_AllocateZeroNonpaged(sizeof(DOT11_DATA_RATE_MAPPING_TABLE), NPF_DOT11_POOL_TAG);
	if (pDRMT == NULL)
	{
		WARNING_DBG("Failed to allocate DOT11_DATA_RATE_MAPPING_TABLE\n");
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Interlocked op to avoid race condition.
	PDOT11_DATA_RATE_MAPPING_TABLE pOld = InterlockedCompareExchangePointer(&pFiltMod->DataRateMappingTable, pDRMT, NULL);
	// If the old value was not null, we lost the race and will leave it to the other thread to complete.
	if (pOld != NULL)
	{
		ExFreePoolWithTag(pDRMT, NPF_DOT11_POOL_TAG);
		TRACE_EXIT();
		return STATUS_SUCCESS;
	}

	// Otherwise we won the race and pFiltMod now points to our DRMT.
	// Using NPF_AnalysisAssumeAliased since InterlockedCompareExchangePointer does not have SAL annotations to note that pFiltMod->DataRateMappingTable now points to pDRMT.
	if (!NT_VERIFY(pFiltMod->DataRateMappingTable == pDRMT))
	{
		ExFreePoolWithTag(pDRMT, NPF_DOT11_POOL_TAG);
		TRACE_EXIT();
		return STATUS_INTERNAL_ERROR;
	}
	NPF_AnalysisAssumeAliased(pDRMT);

	ULONG BytesProcessed = 0;

	NDIS_STATUS Status = NPF_DoInternalRequest(pFiltMod,
		NdisRequestQueryInformation,
		OID_DOT11_DATA_RATE_MAPPING_TABLE,
		pDRMT,
		sizeof(DOT11_DATA_RATE_MAPPING_TABLE),
		0,
		0,
		&BytesProcessed
	);

	if (Status == NDIS_STATUS_SUCCESS && (
		BytesProcessed != sizeof(DOT11_DATA_RATE_MAPPING_TABLE)
		|| pDRMT->Header.Type != NDIS_OBJECT_TYPE_DEFAULT
		|| pDRMT->Header.Revision != DOT11_DATA_RATE_MAPPING_TABLE_REVISION_1
		|| pDRMT->Header.Size != sizeof(DOT11_DATA_RATE_MAPPING_TABLE)
		))
	{
		WARNING_DBG("pFiltMod(%p) DOT11_DATA_RATE_MAPPING_TABLE Status %#x, read %lu, expected %zu\n",
				pFiltMod, Status, BytesProcessed, sizeof(DOT11_DATA_RATE_MAPPING_TABLE));
		Status = NDIS_STATUS_INVALID_DATA;
		pFiltMod->DataRateMappingTable = NULL;
		ExFreePoolWithTag(pDRMT, NPF_DOT11_POOL_TAG);
	}
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
USHORT
NPF_LookUpDataRateMappingTable(
	PNPCAP_FILTER_MODULE pFiltMod,
	UCHAR ucDataRate
)
{
	UINT i;
	PDOT11_DATA_RATE_MAPPING_TABLE pTable = pFiltMod->DataRateMappingTable;
	USHORT usRetDataRateValue = 0;
	TRACE_ENTER();

	if (!pTable)
	{
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

_Use_decl_annotations_
NTSTATUS
NPF_GetCurrentOperationMode(
	PNPCAP_FILTER_MODULE pFiltMod,
	PDOT11_CURRENT_OPERATION_MODE pCurrentOperationMode
)
{
	TRACE_ENTER();
	NT_ASSERT(pFiltMod != NULL);
	NT_ASSERT(pCurrentOperationMode != NULL);

	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode = { 0 };
	ULONG BytesProcessed = 0;
    PVOID pBuffer = NULL;

    pBuffer = NPF_AllocateZeroNonpaged(sizeof(CurrentOperationMode), NPF_INTERNAL_OID_TAG);
    if (pBuffer == NULL)
    {
        INFO_DBG("Allocate pBuffer failed\n");
            TRACE_EXIT();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

	NPF_DoInternalRequest(pFiltMod,
		NdisRequestQueryInformation,
		OID_DOT11_CURRENT_OPERATION_MODE,
		pBuffer,
		sizeof(CurrentOperationMode),
		0,
		0,
		&BytesProcessed
	);

    CurrentOperationMode = *(DOT11_CURRENT_OPERATION_MODE *) pBuffer;
    ExFreePoolWithTag(pBuffer, NPF_INTERNAL_OID_TAG);

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

_Use_decl_annotations_
ULONG
NPF_GetCurrentOperationMode_Wrapper(
	PNPCAP_FILTER_MODULE pFiltMod
)
{
	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode;
	if (NPF_GetCurrentOperationMode(pFiltMod, &CurrentOperationMode) != STATUS_SUCCESS)
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

// pCurrentChannel must point to nonpaged memory
_IRQL_requires_(PASSIVE_LEVEL)
inline NTSTATUS
NPF_GetCurrentChannel(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_Out_ PULONG pCurrentChannel
)
{
	return NPF_OidGetUlongNonpagedPtr(pFiltMod,
		OID_DOT11_CURRENT_CHANNEL,
		pCurrentChannel
	);
}

//-------------------------------------------------------------------

// pCurrentFrequency must point to nonpaged memory
_IRQL_requires_(PASSIVE_LEVEL)
inline NTSTATUS
NPF_GetCurrentFrequency(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_Out_ PULONG pCurrentFrequency
)
{
	return NPF_OidGetUlongNonpagedPtr(pFiltMod,
		OID_DOT11_CURRENT_FREQUENCY,
		pCurrentFrequency
	);
}

#endif
//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_CloseAdapter(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE pOpen;
	PIO_STACK_LOCATION IrpSp;
	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	pOpen = IrpSp->FileObject->FsContext;
	if (!NPF_IsOpenInstance(pOpen))
	{
		Irp->IoStatus.Status = STATUS_INVALID_HANDLE;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INVALID_HANDLE;
	}

	//
	// Free the open instance itself
	//
	NT_ASSERT(pOpen->OpenStatus == OpenClosed);
	ExFreePool(pOpen);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_Cleanup(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE Open;
	NDIS_STATUS Status;
	PIO_STACK_LOCATION IrpSp;
	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	Open = IrpSp->FileObject->FsContext;
	if (!NPF_IsOpenInstance(Open))
	{
		Irp->IoStatus.Status = STATUS_INVALID_HANDLE;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INVALID_HANDLE;
	}

	INFO_DBG("Open = %p\n", Open);

	NT_ASSERT(Open != NULL);

	OPEN_STATE OldState = NPF_DemoteOpenStatus(Open, OpenClosed);
	if (Open->ReadEvent != NULL)
		KeSetEvent(Open->ReadEvent, 0, FALSE);
	NPF_OpenWaitPendingIrps(Open);

	// If it was already marked as detached, don't try to detach it twice.
	if (OldState < OpenDetached) {
		NPF_RemoveFromGroupOpenArray(Open); //Remove the Open from the filter module's list
	}

	//
	// release all the resources
	//
	NPF_ReleaseOpenInstanceResources(Open);
	NPF_RemoveFromAllOpensList(Open);

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

_Use_decl_annotations_
void
NPF_AddToFilterModuleArray(
	PNPCAP_FILTER_MODULE pFiltMod
	)
{
	TRACE_ENTER();

	NdisAcquireSpinLock(&g_pDriverExtension->FilterArrayLock);
	PushEntryList(&g_pDriverExtension->arrFiltMod, &pFiltMod->FilterModulesEntry);
	NdisReleaseSpinLock(&g_pDriverExtension->FilterArrayLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
void
NPF_AddToGroupOpenArray(
	POPEN_INSTANCE pOpen,
	PNPCAP_FILTER_MODULE pFiltMod,
	BOOLEAN bAtDispatchLevel
	)
{
	TRACE_ENTER();

	LOCK_STATE_EX lockState;

	FILTER_ACQUIRE_LOCK(&pOpen->OpenInUseLock, bAtDispatchLevel);

	NT_ASSERT(pOpen->OpenStatus >= OpenDetached);
	NT_ASSERT(pOpen->pFiltMod == NULL);
	NT_ASSERT(pOpen->OpenInstancesEntry.Next == NULL);

	// Acquire lock for writing (modify list)
	NdisAcquireRWLockWrite(pFiltMod->OpenInstancesLock, &lockState, NDIS_RWL_AT_DISPATCH_LEVEL);

	PushEntryList(&pFiltMod->OpenInstances, &pOpen->OpenInstancesEntry);

	// 'OR' in the open's filter
#ifdef HAVE_DOT11_SUPPORT
	if (pFiltMod->Dot11)
	{
		pOpen->MyPacketFilter |= NPCAP_DOT11_RAW_PACKET_FILTER;
	}
#endif
	pFiltMod->MyPacketFilter |= pOpen->MyPacketFilter;
	pFiltMod->MyLookaheadSize = max(pFiltMod->MyLookaheadSize, pOpen->MyLookaheadSize);

	NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);

	pOpen->pFiltMod = pFiltMod;
	pOpen->AdapterID = pFiltMod->AdapterID;
	pOpen->bDot11 = pFiltMod->Dot11;
	pOpen->bLoopback = pFiltMod->Loopback;
	pOpen->OpenStatus = OpenAttached;
	FILTER_RELEASE_LOCK(&pOpen->OpenInUseLock, bAtDispatchLevel);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
void
NPF_RemoveFromFilterModuleArray(
	PNPCAP_FILTER_MODULE pFiltMod
	)
{
	PSINGLE_LIST_ENTRY Prev = NULL;
	PSINGLE_LIST_ENTRY Curr = NULL;

	TRACE_ENTER();
	NT_ASSERT(pFiltMod != NULL);

	NdisAcquireSpinLock(&g_pDriverExtension->FilterArrayLock);

	Prev = &g_pDriverExtension->arrFiltMod;
	Curr = Prev->Next;
	while (Curr != NULL)
	{
		if (Curr == &(pFiltMod->FilterModulesEntry)) {
			Prev->Next = Curr->Next;
			break;
		}
		Prev = Curr;
		Curr = Prev->Next;
	}

	NdisReleaseSpinLock(&g_pDriverExtension->FilterArrayLock);

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
void
NPF_RemoveFromGroupOpenArray(
	POPEN_INSTANCE pOpen
	)
{
	PNPCAP_FILTER_MODULE pFiltMod;
	PSINGLE_LIST_ENTRY Prev = NULL;
	PSINGLE_LIST_ENTRY Curr = NULL;
	POPEN_INSTANCE pCurrOpen = NULL;

	ULONG NewPacketFilter;
	ULONG NewLookaheadSize;
	BOOLEAN found = FALSE;
	BOOLEAN last = FALSE;
	LOCK_STATE_EX lockState;

	TRACE_ENTER();

	NdisAcquireSpinLock(&pOpen->OpenInUseLock);
	pFiltMod = pOpen->pFiltMod;
	if (!NT_VERIFY(pFiltMod)) {
		/* This adapter was already removed, so no filter module exists.
		 * Nothing left to do!
		 */
		if (!NT_VERIFY(pOpen->OpenStatus >= OpenDetached)) {
			pOpen->OpenStatus = OpenDetached;
		}
		NT_ASSERT(pOpen->OpenInstancesEntry.Next == NULL);
		NdisReleaseSpinLock(&pOpen->OpenInUseLock);
		return;
	}
	pOpen->OpenStatus = max(pOpen->OpenStatus, OpenDetached);
	NPF_UnregisterBpf(pOpen->pFiltMod, &pOpen->BpfProgram);
	pOpen->pFiltMod = NULL;
	NdisReleaseSpinLock(&pOpen->OpenInUseLock);

	// Acquire lock for writing (modify list)
	NdisAcquireRWLockWrite(pFiltMod->OpenInstancesLock, &lockState, 0);

	/* Recalculate the combined tracked interface parameters */
	NewPacketFilter = 0;
	NewLookaheadSize = 0;

	Prev = &(pFiltMod->OpenInstances);
	Curr = Prev->Next;
	while (Curr != NULL)
	{
		if (Curr == &(pOpen->OpenInstancesEntry)) {
			/* This is the one to remove. Ignore its parameters. */
			Prev->Next = Curr->Next;
			found = TRUE;
		}
		else if (!pFiltMod->Loopback)
		{
			/* OR the filter in */
			pCurrOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
			NewPacketFilter |= pCurrOpen->MyPacketFilter;
			NewLookaheadSize = max(NewLookaheadSize, pCurrOpen->MyLookaheadSize);
		}
		/* Regardless, keep traversing. */
		Prev = Curr;
		Curr = Prev->Next;
	}

	// Avoid multiple entry points to the list
	pOpen->OpenInstancesEntry.Next = NULL;

	if (!NT_VERIFY(found))
	{
		ERROR_DBG("the open isn't in the group open list.\n");
		NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);
		TRACE_EXIT();
		return;
	}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// If this was the last loopback instance, get ready to release WFP resources.
	// Have to release all locks first so IRQL is PASSIVE_LEVEL
	if (pFiltMod->Loopback && pFiltMod->OpenInstances.Next == NULL)
	{
		FILTER_ACQUIRE_LOCK(&pFiltMod->AdapterHandleLock, TRUE);
		if(pFiltMod->OpsState == OpsEnabled)
		{
			// Ops enabled. Signal intent to disable.
			pFiltMod->OpsState = OpsDisabling;
			last = TRUE;
		}
		else {
			// Either someone else is disabling or it's already disabled
			NT_ASSERT(pFiltMod->OpsState == OpsDisabling || pFiltMod->OpsState == OpsDisabled);
		}
		FILTER_RELEASE_LOCK(&pFiltMod->AdapterHandleLock, TRUE);
	}
#endif

	NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// No more loopback handles open, and it's our responsibility to clean up. Release WFP resources.
	if (last && !g_pDriverExtension->bTestMode) {
		NPF_ReleaseWFP(FALSE);

		FILTER_ACQUIRE_LOCK(&pFiltMod->AdapterHandleLock, FALSE);
		NT_ASSERT(pFiltMod->OpsState == OpsDisabling);
		pFiltMod->OpsState = OpsDisabled;
		FILTER_RELEASE_LOCK(&pFiltMod->AdapterHandleLock, FALSE);
	}
#endif

	/* If the packet filter has changed, originate an OID Request to set it to the new value */
	if (STATUS_SUCCESS != NPF_SetPacketFilter(pFiltMod, NewPacketFilter))
	{
		INFO_DBG("Failed to set resulting packet filter.\n");
	}
	// If the new lookahead value is different than the old one, originate an OID request to set to the new value
	if (STATUS_SUCCESS != NPF_SetLookaheadSize(pFiltMod, NewLookaheadSize))
	{
		INFO_DBG("Failed to set resulting lookahead.\n");
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

/*!
  \brief Compare two NDIS strings.
  \param s1 The first string.
  \param s2 The second string.
  \param cchOffset *Character* offset into s2 where comparison should begin. NOT BYTE OFFSET.
  \return  TRUE if s1 contains s2 at Offset, FALSE otherwise

  This function is used to help decide whether two adapter names are the same.
  Tolerates differences in null-termination of either string.
*/
BOOLEAN
NPF_EqualAdapterName(
	_In_ PCNDIS_STRING s1,
	_In_ PCNDIS_STRING s2,
	_In_ USHORT cchOffset
	)
{
	USHORT i;
	USHORT compare_len;
	WCHAR wc1, wc2;
	BOOLEAN bResult = TRUE;
	// TRACE_ENTER();

	if (s1->Buffer == NULL || s2->Buffer == NULL) {
		INFO_DBG("null buffer\n");
		return FALSE;
	}

	compare_len = BYTES2CCH(s1->Length);
	// If it's null-terminated, don't compare null terminator since s2 might not be null-terminated.
	if (s1->Buffer[compare_len - 1] == UNICODE_NULL)
	{
		compare_len -= 1;
	}

	if (BYTES2CCH(s2->Length) - compare_len < cchOffset)
	{
		INFO_DBG("length too short\n");
		return FALSE;
	}

	for (i = 0; bResult && i < compare_len; i++)
	{
		wc1 = s1->Buffer[i];
		wc2 = s2->Buffer[cchOffset + i];
		switch(wc1 - wc2)
		{
			case 0:
				// Equal, same case
				break;
			case L'a' - L'A':
				// same iff wc1 is lower
				bResult = wc1 >= L'a' && wc1 <= L'z';
				break;
			case L'A' - L'a':
				// same iff wc1 is caps
				bResult = wc1 >= L'A' && wc1 <= L'Z';
				break;
			default:
				bResult = FALSE;
				break;
		}
	}

	// Now check that we didn't only find a prefix of s2
	bResult = bResult && ( // Matches up to compare_len AND
		BYTES2CCH(s2->Length) - compare_len == cchOffset // that's all there is
		|| s2->Buffer[cchOffset + compare_len] == UNICODE_NULL // OR s2 is null-terminated
		|| s2->Buffer[cchOffset + compare_len] == L';' // OR s2 is a list and the next one starts here
		);

	// Print unicode strings using %ws will cause page fault blue screen with IRQL = DISPATCH_LEVEL, so we disable the string print for now.
	// INFO_DBG("bResult = %d, s1 = %ws, s2 = %ws\n", i, bResult, s1->Buffer, s2->Buffer);
	INFO_DBG("bResult == %u\n", bResult);
	// TRACE_EXIT();
	return bResult;
}

/* Returns true if AdName is in the semicolon-separated list AdSet */
BOOLEAN
NPF_ContainsAdapterName(
	_In_ PCNDIS_STRING AdSet,
	_In_ PCNDIS_STRING AdName
	)
{
	USHORT i = 0;

	if (AdSet->Buffer == NULL || AdName->Buffer == NULL) {
		INFO_DBG("null buffer\n");
		return FALSE;
	}
	while (i < BYTES2CCH(AdSet->Length))
	{
		if (NPF_EqualAdapterName(AdName, AdSet, i))
		{
			return TRUE;
		}
		while (i < BYTES2CCH(AdSet->Length) && AdSet->Buffer[i] != L';')
		{
			i++;
		}
		i++;
	}
	return FALSE;
}

//-------------------------------------------------------------------
/* Ensure string "a" is long enough to contain "b" after the offset.
 * Length does not include the null terminator, so account for that with sizeof(WCHAR).
 * Then compare memory. Length is length in bytes, but buffer is a PWCHAR.
 */
#define PUNICODE_CONTAINS(a, b, byteoffset) ((a->Length >= byteoffset + CONST_WCHAR_BYTES(b)) && CONST_WCHAR_BYTES(b) == RtlCompareMemory(a->Buffer + BYTES2CCH(byteoffset), b, CONST_WCHAR_BYTES(b)))
_Use_decl_annotations_
PNPCAP_FILTER_MODULE
NPF_GetFilterModuleByAdapterName(
	PNDIS_STRING pAdapterName
	)
{
	PSINGLE_LIST_ENTRY Curr = NULL;
	PNPCAP_FILTER_MODULE pFiltMod = NULL;
	size_t i = 0;
	USHORT cchShrink = 0;
	BOOLEAN Dot11 = FALSE;
	BOOLEAN Found = FALSE;
	NDIS_STRING BaseName = {0};
	TRACE_ENTER();

	if (pAdapterName->Buffer == NULL || pAdapterName->Length == 0) {
		return NULL;
	}

	// strip off leading backslashes
	while (CCH2BYTES(cchShrink) < pAdapterName->Length && pAdapterName->Buffer[cchShrink] == L'\\') {
		cchShrink++;
	}


	// Make sure we can hold at least as long a name as requested.
	BaseName.MaximumLength = max(sizeof(L"Loopback"), pAdapterName->MaximumLength);
	BaseName.Buffer = NPF_AllocateZeroNonpaged(BaseName.MaximumLength, NPF_UNICODE_BUFFER_TAG);
	if (BaseName.Buffer == NULL) {
		INFO_DBG("failed to allocate BaseName.Buffer\n");
		TRACE_EXIT();
		return NULL;
	}

#ifdef HAVE_DOT11_SUPPORT
	// Check for WIFI_ prefix and strip it
	if (PUNICODE_CONTAINS(pAdapterName, NPF_DEVICE_NAMES_TAG_WIDECHAR_WIFI, CCH2BYTES(cchShrink))) {
		cchShrink += CONST_WCHAR_CCH(NPF_DEVICE_NAMES_TAG_WIDECHAR_WIFI);
		Dot11 = TRUE;
	}
#endif

	// Do the strip
	for (i=cchShrink; i < BYTES2CCH(pAdapterName->Length) && (i - cchShrink) < BYTES2CCH(BaseName.MaximumLength); i++) {
		BaseName.Buffer[i - cchShrink] = pAdapterName->Buffer[i];
	}
	BaseName.Length = pAdapterName->Length - CCH2BYTES(cchShrink);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (!Dot11 // WIFI and Loopback are not compatible
		&& NPF_EqualAdapterName(&g_pDriverExtension->LoopbackAdapterName, &BaseName, 0)) // This is a request for legacy loopback
	{
		// Replace the name with the fake loopback adapter name
		RtlCopyMemory(BaseName.Buffer, L"Loopback", sizeof(L"Loopback"));
		BaseName.Length = CONST_WCHAR_BYTES(L"Loopback");
	}
#endif

	// Now go looking for the appropriate module
	NdisAcquireSpinLock(&g_pDriverExtension->FilterArrayLock);
	for (Curr = g_pDriverExtension->arrFiltMod.Next; Curr != NULL; Curr = Curr->Next)
	{
		pFiltMod = CONTAINING_RECORD(Curr, NPCAP_FILTER_MODULE, FilterModulesEntry);
		if (NPF_StartUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN) == FALSE)
		{
			continue;
		}

		Found = (pFiltMod->Dot11 == Dot11 && NPF_EqualAdapterName(&pFiltMod->AdapterName, &BaseName, 0));

		NPF_StopUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN);
		if (Found)
		{
			break;
		}
	}
	NdisReleaseSpinLock(&g_pDriverExtension->FilterArrayLock);
	ExFreePoolWithTag(BaseName.Buffer, NPF_UNICODE_BUFFER_TAG);
	if (!Found)
	{
		pFiltMod = NULL;
	}

	TRACE_EXIT();
	return pFiltMod;
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
_Use_decl_annotations_
PNPCAP_FILTER_MODULE
NPF_GetLoopbackFilterModule()
{
	PSINGLE_LIST_ENTRY Curr = NULL;
	PNPCAP_FILTER_MODULE pFiltMod = NULL;
	TRACE_ENTER();

	NdisAcquireSpinLock(&g_pDriverExtension->FilterArrayLock);
	for (Curr = g_pDriverExtension->arrFiltMod.Next; Curr != NULL; Curr = Curr->Next)
	{
		pFiltMod = CONTAINING_RECORD(Curr, NPCAP_FILTER_MODULE, FilterModulesEntry);
		if (NPF_StartUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN) == FALSE)
		{
			continue;
		}

		if (pFiltMod->Loopback)
		{
			NPF_StopUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN);
			NdisReleaseSpinLock(&g_pDriverExtension->FilterArrayLock);
			return pFiltMod;
		}
		else
		{
			NPF_StopUsingBinding(pFiltMod, NPF_IRQL_UNKNOWN);
		}
	}
	NdisReleaseSpinLock(&g_pDriverExtension->FilterArrayLock);

	TRACE_EXIT();
	return NULL;
}
#endif
//-------------------------------------------------------------------

_Use_decl_annotations_
POPEN_INSTANCE
NPF_CreateOpenObject(NDIS_HANDLE NdisHandle)
{
	POPEN_INSTANCE Open;
	TRACE_ENTER();

	// allocate some memory for the open structure
	Open = NPF_AllocateZeroNonpaged(sizeof(OPEN_INSTANCE), NPF_OPEN_TAG);

	if (Open == NULL)
	{
		// no memory
		INFO_DBG("Failed to allocate memory pool\n");
		TRACE_EXIT();
		return NULL;
	}

	/* Buffer */
	Open->BufferLock = NdisAllocateRWLock(NdisHandle);
	if (Open->BufferLock == NULL)
	{
		INFO_DBG("Failed to allocate BufferLock\n");
		ExFreePool(Open);
		TRACE_EXIT();
		return NULL;
	}

	InitializeListHead(&Open->PacketQueue);
	KeInitializeSpinLock(&Open->PacketQueueLock);
	Open->Accepted = 0;
	Open->Received = 0;
	Open->Dropped = 0;

	Open->OpenSignature = OPEN_SIGNATURE;
	Open->OpenStatus = OpenClosed;
	Open->ReattachStatus = OpenClosed;

	//
	// Initialize the open instance
	//
	//Open->BindContext = NULL;
	Open->TimestampMode = g_pDriverExtension->TimestampMode;
	Open->bModeCapt = 1;
	Open->Nbytes.QuadPart = 0;
	Open->Npackets.QuadPart = 0;
	Open->Nwrites = 1;
	Open->MinToCopy = 0;
	Open->Size = 0;
	Open->SkipSentPackets = FALSE;
	Open->MyPacketFilter = 0;
	Open->MyLookaheadSize = 0;
	Open->ReadEvent = NULL;

	//
	// we need to keep a counter of the pending IRPs
	// so that when the IRP_MJ_CLEANUP dispatcher gets called,
	// we can wait for those IRPs to be completed
	// NB: no IRPs can be pending for the OpenClosed state.
	for (OPEN_STATE state = 0; state < OpenClosed; state++)
	{
		Open->PendingIrps[state] = 0;
	}
	NdisAllocateSpinLock(&Open->OpenInUseLock);
	Open->OpenInstancesEntry.Next = NULL;

	//
	//allocate the spinlock for the statistic counters
	//
	NdisAllocateSpinLock(&Open->CountersLock);

	Open->OpenStatus = OpenDetached;

	TRACE_EXIT();
	return Open;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
PNPCAP_FILTER_MODULE
NPF_CreateFilterModule(
	NDIS_HANDLE NdisFilterHandle,
	PNDIS_STRING AdapterName)
{
	PNPCAP_FILTER_MODULE pFiltMod;
	NET_BUFFER_LIST_POOL_PARAMETERS PoolParameters;
	BOOLEAN bAllocFailed = FALSE;

	// allocate some memory for the filter module structure
	pFiltMod = NPF_AllocateZeroNonpaged(sizeof(NPCAP_FILTER_MODULE), NPF_FILTMOD_TAG);

	if (pFiltMod == NULL)
	{
		// no memory
		INFO_DBG("Failed to allocate memory pool\n");
		return NULL;
	}

	pFiltMod->AdapterHandle = NdisFilterHandle;
	pFiltMod->AdapterBindingStatus = FilterDetached;
	pFiltMod->Loopback = FALSE;

	pFiltMod->SendToRxPath = FALSE;
	pFiltMod->BlockRxPath = FALSE;

	pFiltMod->Dot11 = FALSE;

	pFiltMod->FilterModulesEntry.Next = NULL;
	pFiltMod->OpenInstances.Next = NULL;
	InitializeListHead(&pFiltMod->BpfPrograms);

	// Pool sizes based on observations on a single-core Hyper-V VM while
	// running our test suite.

	//  Initialize the pools
	do {
		pFiltMod->OpenInstancesLock = NdisAllocateRWLock(NdisFilterHandle);
		if (pFiltMod->OpenInstancesLock == NULL)
		{
			INFO_DBG("Failed to allocate OpenInstancesLock\n");
			bAllocFailed = TRUE;
			break;
		}

		pFiltMod->BpfProgramsLock = NdisAllocateRWLock(NdisFilterHandle);
		if (pFiltMod->BpfProgramsLock == NULL)
		{
			INFO_DBG("Failed to allocate BpfProgramsLock\n");
			bAllocFailed = TRUE;
			break;
		}

		NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
		PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		PoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
		PoolParameters.fAllocateNetBuffer = TRUE;
		PoolParameters.ContextSize = sizeof(PACKET_RESERVED);
		PoolParameters.PoolTag = NPF_PACKET_POOL_TAG;
		PoolParameters.DataSize = 0;

		pFiltMod->PacketPool = NdisAllocateNetBufferListPool(NdisFilterHandle, &PoolParameters);
		if (pFiltMod->PacketPool == NULL)
		{
			INFO_DBG("Failed to allocate packet pool\n");
			bAllocFailed = TRUE;
			break;
		}

		pFiltMod->AdapterName.MaximumLength = AdapterName->MaximumLength - DEVICE_PATH_BYTES;
		pFiltMod->AdapterName.Buffer = NPF_AllocateZeroNonpaged(pFiltMod->AdapterName.MaximumLength, NPF_UNICODE_BUFFER_TAG);
		if (pFiltMod->AdapterName.Buffer == NULL)
		{
			INFO_DBG("Failed to allocate AdapterName buffer\n");
			bAllocFailed = TRUE;
			break;
		}
		pFiltMod->AdapterName.Length = 0;
		RtlAppendUnicodeToString(&pFiltMod->AdapterName, AdapterName->Buffer + DEVICE_PATH_CCH);
	} while (0);

	if (bAllocFailed) {
		if (pFiltMod->PacketPool)
			NdisFreeNetBufferListPool(pFiltMod->PacketPool);
		if (pFiltMod->OpenInstancesLock)
			NdisFreeRWLock(pFiltMod->OpenInstancesLock);
		if (pFiltMod->BpfProgramsLock)
			NdisFreeRWLock(pFiltMod->BpfProgramsLock);
		ExFreePool(pFiltMod);
		return NULL;
	}
	
	// Default; expect this will be overwritten in NPF_Restart,
	// or for Loopback when creating the fake module.
	pFiltMod->MaxFrameSize = 1514;

	//
	//allocate the spinlock for the OID requests
	//
	NdisAllocateSpinLock(&pFiltMod->OIDLock);

	//
	// set the proper binding flags before trying to open the MAC
	//
	pFiltMod->AdapterHandleUsageCounter = 0;
	NdisAllocateSpinLock(&pFiltMod->AdapterHandleLock);

	pFiltMod->OpsState = OpsDisabled;

	INFO_DBG("pFiltMod(%p) created for %ws\n", pFiltMod, pFiltMod->AdapterName.Buffer);
	return pFiltMod;
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
	UNREFERENCED_PARAMETER(NdisFilterHandle);
	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!((PNPCAP_FILTER_MODULE) NdisFilterHandle)->Loopback);
#endif

	TRACE_EXIT();

	return NDIS_STATUS_SUCCESS;
}

//-------------------------------------------------------------------

struct MediaParams {
	BOOLEAN RawIP:1;
	BOOLEAN EtherHeader:1;
	BOOLEAN Dot11:1;
	BOOLEAN PacketFilterGetOK:1;
	BOOLEAN Fragile:1;
	BOOLEAN SplitMdls:1;
};

static NDIS_STATUS NPF_ValidateParameters(
	_Out_ struct MediaParams *pParams,
	_In_ NDIS_MEDIUM MiniportMediaType,
	_In_ NDIS_PHYSICAL_MEDIUM MiniportPhysicalMediaType,
	_In_opt_ NDIS_HANDLE MiniportMediaSpecificAttributes
        )
{
	NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
	// Defaults
	pParams->Fragile = 1;
	pParams->RawIP = 0;
	pParams->EtherHeader = 0;
	pParams->PacketFilterGetOK = 1;
    // Verify the media type is supported.  This is a last resort; the
    // the filter should never have been bound to an unsupported miniport
    // to begin with.  If this driver is marked as a Mandatory filter (which
    // is the default for this sample; see the INF file), failing to attach
    // here will leave the network adapter in an unusable state.
    //
	switch (MiniportMediaType)
	{
		case NdisMediumNative802_11:
			// The WiFi filter will only bind to the 802.11
			// wireless adapters that support NetworkMonitor mode.
			pParams->Dot11 = g_pDriverExtension->bDot11SupportMode;
			// NDIS always answers OID_GEN_CURRENT_PACKET_FILTER queries for
			// Wifi adapters with NDIS_STATUS_INVALID_OID
			pParams->PacketFilterGetOK = 0;
			pParams->Fragile = 0;
#ifdef HAVE_DOT11_SUPPORT
			if (pParams->Dot11 && MiniportMediaSpecificAttributes)
			{
				PNDIS_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES pDot11Attrs = MiniportMediaSpecificAttributes;
				if (pDot11Attrs->Header.Type == NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES
						&& !(pDot11Attrs->OpModeCapability & DOT11_OPERATION_MODE_NETWORK_MONITOR))
				{
					INFO_DBG("Adapter does not support NetMon\n");
					Status = NDIS_STATUS_INVALID_PARAMETER;
				}
			}
#endif
			break;
		case NdisMedium802_3:
			pParams->Fragile = 0;
			pParams->EtherHeader = 1;
			break;
		case NdisMediumWan:
			pParams->EtherHeader = 1;
			pParams->Fragile = 1;
			break;
		case NdisMediumWirelessWan:
		case NdisMediumIP:
			pParams->RawIP = 1;
		default:
			pParams->Fragile = 1;
			break;
	}
	if (MiniportPhysicalMediaType == NdisPhysicalMediumBluetooth)
	{
		pParams->SplitMdls = 1;
	}
	return Status;
}

_Use_decl_annotations_
NDIS_STATUS
NPF_AttachAdapter(
	NDIS_HANDLE                     NdisFilterHandle,
	NDIS_HANDLE                     FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
	)
{
	PNPCAP_FILTER_MODULE pFiltMod = NULL;
	struct MediaParams params = {0};
	LOCK_STATE_EX lockState;
	NDIS_STATUS             Status;
	NDIS_STATUS				returnStatus;
	NDIS_FILTER_ATTRIBUTES	FilterAttributes;
	SINGLE_LIST_ENTRY ReattachOpens = {NULL};
	BOOLEAN					bFalse = FALSE;

	TRACE_ENTER();

	do
	{
		// FilterModuleGuidName = "{ADAPTER_GUID}-{FILTER_GUID}-0000"

		returnStatus = NPF_ValidateParameters(&params, AttachParameters->MiniportMediaType, AttachParameters->MiniportPhysicalMediaType, AttachParameters->MiniportMediaSpecificAttributes);
		INFO_DBG("FilterModuleGuidName=%ws, bDot11=%u, MediaType=%d\n",
			AttachParameters->FilterModuleGuidName->Buffer,
			params.Dot11, AttachParameters->MiniportMediaType);

		if (returnStatus != STATUS_SUCCESS)
			break;

#if NDIS_SUPPORT_NDIS630
		// If it's a SR-IOV virtual function driver, we're bound at the iovvf layer, so don't go mucking with packet filters!
		if (AttachParameters->Header.Revision >= NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4
			&& AttachParameters->SriovCapabilities
			&& (AttachParameters->SriovCapabilities->SriovCapabilities & NDIS_SRIOV_CAPS_VF_MINIPORT) > 0
			) {
			params.Fragile = 1;
		}
#endif

		// Disable this code for now, because it invalidates most adapters to be bound, reason needs to be clarified.
// 		if (AttachParameters->LowerIfIndex != AttachParameters->BaseMiniportIfIndex)
// 		{
// 			INFO_DBG("Don't bind to other altitudes than exactly over the miniport: LowerIfIndex = %d, BaseMiniportIfIndex = %d.\n", AttachParameters->LowerIfIndex, AttachParameters->BaseMiniportIfIndex);
// 
// 			returnStatus = NDIS_STATUS_NOT_SUPPORTED;
// 			break;
// 		}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		// Determine whether this is the legacy loopback adapter
		if (NPF_EqualAdapterName(&g_pDriverExtension->LoopbackAdapterName, AttachParameters->BaseMiniportName, DEVICE_PATH_CCH))
		{
			// This request is for the legacy loopback adapter listed in the Registry.
			// Since we now have a fake filter module for this, deny the binding.
			// We'll intercept open requests for this name elsewhere and redirect to the fake one.
			returnStatus = NDIS_STATUS_NOT_SUPPORTED;
			break;
		}
#endif

		// create the adapter object
		pFiltMod = NPF_CreateFilterModule(NdisFilterHandle, AttachParameters->BaseMiniportName);
		if (pFiltMod == NULL)
		{
			returnStatus = NDIS_STATUS_RESOURCES;
			TRACE_EXIT();
			return returnStatus;
		}
		pFiltMod->AdapterID = AttachParameters->BaseMiniportNetLuid;
		pFiltMod->AdapterBindingStatus = FilterAttaching;
		pFiltMod->RawIP = params.RawIP;
		pFiltMod->EtherHeader = params.EtherHeader;
		pFiltMod->Dot11 = params.Dot11;
		pFiltMod->PacketFilterGetOK = params.PacketFilterGetOK;
		pFiltMod->Fragile = params.Fragile;
		pFiltMod->SplitMdls = params.SplitMdls;

#ifdef HAVE_RX_SUPPORT
		// Determine whether this is our send-to-Rx adapter for the open_instance.
		if (NPF_ContainsAdapterName(&g_pDriverExtension->SendToRxAdapterName, &pFiltMod->AdapterName))
		{
			pFiltMod->SendToRxPath = TRUE;
		}
		// Determine whether this is our block-Rx adapter for the open_instance.
		if (NPF_ContainsAdapterName(&g_pDriverExtension->BlockRxAdapterName, &pFiltMod->AdapterName))
		{
			pFiltMod->BlockRxPath = TRUE;
		}
#endif

		NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
		FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
		FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		FilterAttributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
		FilterAttributes.Flags = 0;

		NDIS_DECLARE_FILTER_MODULE_CONTEXT(NPCAP_FILTER_MODULE);
		Status = NdisFSetAttributes(NdisFilterHandle,
			pFiltMod,
			&FilterAttributes);

		if (Status != NDIS_STATUS_SUCCESS)
		{
			returnStatus = Status;
			INFO_DBG("NdisFSetAttributes: error, Status=%x.\n", Status);
			break;
		}

		INFO_DBG(
			"Opened the device %ws, BindingContext=%p, dot11=%u",
			pFiltMod->AdapterName.Buffer,
			pFiltMod,
			pFiltMod->Dot11);


		// Initial attach may be done before driver has finished loading and device is created, so be safe.
		// When this runs during DriverEntry, this lock may not be set up yet.
		if ( NULL != g_pDriverExtension->AllOpensLock
				// Pretty sure this can't happen, but it'd be bad to proceed here if it did.
				&& pFiltMod->AdapterID.Value != 0) {
			// Traverse the AllOpens list looking for detached instances.
			NdisAcquireRWLockRead(g_pDriverExtension->AllOpensLock, &lockState, 0);
			for (PLIST_ENTRY Curr = g_pDriverExtension->AllOpens.Flink; Curr != &(g_pDriverExtension->AllOpens); Curr = Curr->Flink)
			{
				POPEN_INSTANCE pOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, AllOpensEntry);
				// If it doesn't already have a filter module and it's not Loopback (since this is for NDIS only)
				if (pOpen->OpenStatus == OpenDetached && pOpen->pFiltMod == NULL && !pOpen->bLoopback
						// and its Dot11 status matches
						&& pOpen->bDot11 == pFiltMod->Dot11
						// and the AdapterID matches
					       	&& pOpen->AdapterID.Value == pFiltMod->AdapterID.Value)
				{
					// add it to this filter module's list.
					PushEntryList(&ReattachOpens, &pOpen->OpenInstancesEntry);
				}
			}
			NdisReleaseRWLock(g_pDriverExtension->AllOpensLock, &lockState);
			// For each of the discovered instances, start it up again
			PSINGLE_LIST_ENTRY Curr = PopEntryList(&ReattachOpens);
			while (Curr != NULL)
			{
				POPEN_INSTANCE pOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
				// NPF_AddToGroupOpenArray handles updating MyPacketFilter and MyLookaheadSize
				NPF_AddToGroupOpenArray(pOpen, pFiltMod, 0);
				if (pOpen->ReattachStatus < OpenAttached)
				{
					NPF_UpdateTimestampModeCounts(pFiltMod, pOpen->TimestampMode, TIMESTAMPMODE_UNSET);
					NPF_RegisterBpf(pOpen->pFiltMod, &pOpen->BpfProgram);
				}
				pOpen->OpenStatus = pOpen->ReattachStatus;
				Curr = PopEntryList(&ReattachOpens);
			}
		}

		returnStatus = STATUS_SUCCESS;
		pFiltMod->AdapterBindingStatus = FilterPaused;
		NPF_AddToFilterModuleArray(pFiltMod);
		// If any handles are running, enable ops again.
		if (pFiltMod->nTimestampQPC > 0 || pFiltMod->nTimestampQST > 0 || pFiltMod->nTimestampQST_Precise > 0)
		{
			NPF_EnableOps(pFiltMod);
		}
	}
	while (bFalse);

	if (!NT_SUCCESS(returnStatus) && pFiltMod != NULL) {
		NPF_ReleaseFilterModuleResources(pFiltMod);
		//
		// Free the object itself
		//
		ExFreePool(pFiltMod);
		pFiltMod = NULL;
	}
	INFO_DBG("returnStatus=%x\n", returnStatus);
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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE)FilterModuleContext;
	NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
	NDIS_EVENT Event;

	UNREFERENCED_PARAMETER(PauseParameters);
	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

	NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
	NT_ASSERT(pFiltMod->AdapterBindingStatus == FilterRunning);
	pFiltMod->AdapterBindingStatus = FilterPausing;
	
	while (pFiltMod->AdapterHandleUsageCounter > 0)
	{
		NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);
		NdisWaitEvent(&Event, 1);
		NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
	}

	pFiltMod->AdapterBindingStatus = FilterPaused;
	NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);

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

	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE)FilterModuleContext;
	NDIS_STATUS		Status;
	NTSTATUS ntStatus;
	ULONG ulTmp = 0;
	PNDIS_RESTART_ATTRIBUTES Curr = RestartParameters->RestartAttributes;
	PNDIS_RESTART_GENERAL_ATTRIBUTES GenAttr = NULL;
	struct MediaParams params = {0};

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	if (RestartParameters == NULL)
	{
		// Can't validate, but probably fine. Also, I don't think this is possible.
		return NDIS_STATUS_SUCCESS;
	}

	NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
	NT_ASSERT(pFiltMod->AdapterBindingStatus == FilterPaused);
	pFiltMod->AdapterBindingStatus = FilterRestarting;
	NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);

	Status = NPF_ValidateParameters(&params, RestartParameters->MiniportMediaType, RestartParameters->MiniportPhysicalMediaType, NULL);
	if (Status != NDIS_STATUS_SUCCESS) {
		goto NPF_Restart_End;
	}
	pFiltMod->RawIP = params.RawIP;
	pFiltMod->EtherHeader = params.EtherHeader;
	pFiltMod->Dot11 = params.Dot11;
	pFiltMod->PacketFilterGetOK = params.PacketFilterGetOK;
	pFiltMod->Fragile = params.Fragile;

	while (Curr) {
		INFO_DBG("pFiltMod(%p) NDIS_RESTART_ATTRIBUTES Oid = %#x\n", pFiltMod, Curr->Oid);
		switch (Curr->Oid) {
			case OID_GEN_MINIPORT_RESTART_ATTRIBUTES:
				GenAttr = (PNDIS_RESTART_GENERAL_ATTRIBUTES) Curr->Data;
				// MtuSize is actually OID_GEN_MAXIMUM_FRAME_SIZE and does not include link header
				// We'll grab it because it's available, but we'll try to get something better
				pFiltMod->MaxFrameSize = GenAttr->MtuSize;
				INFO_DBG("pFiltMod(%p) NDIS_RESTART_ATTRIBUTES MtuSize = %lu\n", pFiltMod, GenAttr->MtuSize);
				pFiltMod->SupportedPacketFilters = GenAttr->SupportedPacketFilters;
#ifdef HAVE_DOT11_SUPPORT
				if (pFiltMod->Dot11)
				{
					// This is not reported in SupportedPacketFilters. Have to override it here.
					pFiltMod->SupportedPacketFilters |= NPCAP_DOT11_RAW_PACKET_FILTER;
				}
#endif
				INFO_DBG("pFiltMod(%p) NDIS_RESTART_ATTRIBUTES SupportedPacketFilters = %#x\n", pFiltMod, GenAttr->SupportedPacketFilters);
				pFiltMod->HigherLookaheadSize = GenAttr->LookaheadSize;
				INFO_DBG("pFiltMod(%p) NDIS_RESTART_ATTRIBUTES LookaheadSize = %lu\n", pFiltMod, GenAttr->LookaheadSize);
				break;
			// These have not been seen before, but worth a shot to save an OID request later:
			case OID_GEN_CURRENT_PACKET_FILTER:
				pFiltMod->HigherPacketFilter = *(PULONG) Curr->Data;
				pFiltMod->HigherPacketFilterSet = 1;
				break;
		}
		Curr = Curr->Next;
	}
	if (!NT_VERIFY(GenAttr != NULL))
	{
		ERROR_DBG("Did not find OID_GEN_MINIPORT_RESTART_ATTRIBUTES in RestartAttributes!");
	}

	// Now try OID_GEN_MAXIMUM_TOTAL_SIZE, including link header
	// If it fails, no big deal; we have the MTU at least.
	ulTmp = pFiltMod->MaxFrameSize;
	ntStatus = NPF_GetDeviceMTU(pFiltMod);
	if (!NT_SUCCESS(ntStatus))
	{
		pFiltMod->MaxFrameSize = ulTmp;
	}

	// Now that we have SupportedPacketFilters, we can set our own PacketFilter if necessary
	ulTmp = pFiltMod->MyPacketFilter;
	// Force NPF_SetPacketFilter to send the OID in case the filter was reset while we were detached.
	pFiltMod->MyPacketFilter = 0;
	ntStatus = NPF_SetPacketFilter(pFiltMod, ulTmp);
	if (!NT_SUCCESS(ntStatus))
	{
		WARNING_DBG("NPF_SetPacketFilter: error, Status=%x.\n", ntStatus);
	}

	// And we may have to set the lookahead size if this is a reattach
	ulTmp = pFiltMod->MyLookaheadSize;
	pFiltMod->MyLookaheadSize = 0;
	ntStatus = NPF_SetLookaheadSize(pFiltMod, ulTmp);
	if (!NT_SUCCESS(ntStatus))
	{
		WARNING_DBG("NPF_SetLookaheadSize: error, Status=%x.\n", ntStatus);
	}


NPF_Restart_End:
	NdisAcquireSpinLock(&pFiltMod->AdapterHandleLock);
	pFiltMod->AdapterBindingStatus = NDIS_STATUS_SUCCESS == Status ? FilterRunning : FilterPaused;
	NdisReleaseSpinLock(&pFiltMod->AdapterHandleLock);

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
	FilterAttach. NDIS calls FilterDetach to remove a filter instance from a filter stack.

Arguments:

	FilterModuleContext - pointer to the filter context area.

Return Value:
	None.

NOTE: Called at PASSIVE_LEVEL and the filter is in paused state

--*/
{
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE)FilterModuleContext;
	PSINGLE_LIST_ENTRY Curr = NULL;
	SINGLE_LIST_ENTRY DetachedOpens = {NULL};
	POPEN_INSTANCE pOpen = NULL;
	LOCK_STATE_EX lockState;

	TRACE_ENTER();

	/* This callback is called for loopback module by NPF_Unload. */
	NT_ASSERT(pFiltMod->AdapterBindingStatus == FilterPaused || pFiltMod->Loopback);

	NdisAcquireRWLockWrite(pFiltMod->OpenInstancesLock, &lockState, 0);
	Curr = PopEntryList(&pFiltMod->OpenInstances);
	while (Curr != NULL)
	{
		pOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
		pOpen->ReattachStatus = NPF_DemoteOpenStatus(pOpen, OpenDetached);
		// If it's closed, ignore it. Someone else will take it from here.
		if (pOpen->ReattachStatus != OpenClosed) {
			PushEntryList(&DetachedOpens, Curr);

			if (pOpen->ReadEvent != NULL)
				KeSetEvent(pOpen->ReadEvent, 0, FALSE);
		}

		Curr = PopEntryList(&pFiltMod->OpenInstances);
	}
	NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);
	NT_ASSERT(pFiltMod->nTimestampQPC == 0 && pFiltMod->nTimestampQST == 0 && pFiltMod->nTimestampQST_Precise == 0);

	// Restore original filter and lookahead value
	NPF_SetPacketFilter(pFiltMod, 0);
	NPF_SetLookaheadSize(pFiltMod, 0);
	// Ensure demotions complete before we wait for pending irps
	KeMemoryBarrier();

	// for each of the instances, wait for pending irps
	Curr = PopEntryList(&DetachedOpens);
	while (Curr != NULL)
	{
		pOpen = CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry);
		NPF_OpenWaitPendingIrps(pOpen);
		NdisAcquireSpinLock(&pOpen->OpenInUseLock);
		pOpen->pFiltMod = NULL;
		pOpen->OpenInstancesEntry.Next = NULL;
		NdisReleaseSpinLock(&pOpen->OpenInUseLock);
		Curr = PopEntryList(&DetachedOpens);
	}

	INFO_DBG("pFiltMod(%p)->AdapterHandleUsageCounter == %lu\n", pFiltMod, pFiltMod->AdapterHandleUsageCounter);
	while (pFiltMod->AdapterHandleUsageCounter > 0)
	{
		NdisMSleep(100);
	}
	pFiltMod->AdapterBindingStatus = FilterDetached;

	NPF_RemoveFromFilterModuleArray(pFiltMod); // Must add this, if not, SYSTEM_SERVICE_EXCEPTION BSoD will occur.
	NPF_ReleaseFilterModuleResources(pFiltMod);
	ExFreePool(pFiltMod);

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	NDIS_STATUS             Status;
	PNDIS_OID_REQUEST       ClonedRequest=NULL;
	BOOLEAN                 bSubmitted = FALSE;
	PFILTER_REQUEST_CONTEXT Context;
	BOOLEAN                 bFalse = FALSE;
    PVOID pBuffer = NULL;

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	do
	{
		Status = NdisAllocateCloneOidRequest(pFiltMod->AdapterHandle,
											Request,
											NPF_CLONE_OID_TAG,
											&ClonedRequest);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			INFO_DBG("FilterOidRequest: Cannot Clone Request\n");
			break;
		}

		if (!pFiltMod->Fragile && Request->RequestType == NdisRequestSetInformation &&
				(Request->DATA.SET_INFORMATION.Oid == OID_GEN_CURRENT_PACKET_FILTER
				 || Request->DATA.SET_INFORMATION.Oid == OID_GEN_CURRENT_LOOKAHEAD))
		{
			// ExAllocatePoolWithTag is permitted to be used at DISPATCH_LEVEL iff allocating from NPF_NONPAGED
#pragma warning(suppress: 28118)
			pBuffer = NPF_AllocateZeroNonpaged(sizeof(ULONG), NPF_CLONE_OID_TAG);
			if (pBuffer == NULL)
			{
				INFO_DBG("Allocate pBuffer failed, cannot modify OID value.\n");
			}
			else
			{

				switch (Request->DATA.SET_INFORMATION.Oid)
				{
					case OID_GEN_CURRENT_PACKET_FILTER:
						pFiltMod->HigherPacketFilter = *(ULONG *) Request->DATA.SET_INFORMATION.InformationBuffer;
						pFiltMod->HigherPacketFilterSet = 1;
#if DBG
						if (pFiltMod->AdapterBindingStatus == FilterRunning
								&& *(PULONG) pBuffer & ~pFiltMod->SupportedPacketFilters)
							WARNING_DBG("Upper driver setting unsupported packet filter: %#x\n", *(PULONG) pBuffer);
#endif
						*(PULONG) pBuffer = pFiltMod->HigherPacketFilter | pFiltMod->MyPacketFilter;
						break;
					case OID_GEN_CURRENT_LOOKAHEAD:
						pFiltMod->HigherLookaheadSize = *(ULONG *) Request->DATA.SET_INFORMATION.InformationBuffer;
						// We already checked for <= earlier, but better to be clear:
						*(PULONG) pBuffer = max(pFiltMod->HigherLookaheadSize, pFiltMod->MyLookaheadSize);
						break;
					default:
						NT_ASSERT(FALSE && "UNREACHABLE");
						break;
				}
				ClonedRequest->DATA.SET_INFORMATION.InformationBuffer = pBuffer;
			}
		}

		Context = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
		*Context = Request; //SourceReserved != NULL indicates that this is other module's request

		bSubmitted = TRUE;

		//
		// Use same request ID
		//
		ClonedRequest->RequestId = Request->RequestId;

		pFiltMod->PendingOidRequest = ClonedRequest;

		Status = NdisFOidRequest(pFiltMod->AdapterHandle, ClonedRequest);

		if (Status != NDIS_STATUS_PENDING)
		{
			NPF_OidRequestComplete(pFiltMod, ClonedRequest, Status);
			// We return PENDING here because NPF_OidRequestComplete called
			// NdisFOidRequestComplete, which is only allowed if this function returns PENDING.
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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	PNDIS_OID_REQUEST                   Request = NULL;
	PFILTER_REQUEST_CONTEXT             Context;
	PNDIS_OID_REQUEST                   OriginalRequest = NULL;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	FILTER_ACQUIRE_LOCK(&pFiltMod->OIDLock, NPF_IRQL_UNKNOWN);

	Request = pFiltMod->PendingOidRequest;

	if (Request != NULL)
	{
		Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);

		OriginalRequest = (*Context);
	}

	if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId))
	{
		FILTER_RELEASE_LOCK(&pFiltMod->OIDLock, NPF_IRQL_UNKNOWN);

		NdisFCancelOidRequest(pFiltMod->AdapterHandle, RequestId);
	}
	else
	{
		FILTER_RELEASE_LOCK(&pFiltMod->OIDLock, NPF_IRQL_UNKNOWN);
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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	PNDIS_OID_REQUEST                   OriginalRequest;
	PFILTER_REQUEST_CONTEXT             Context;

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
	OriginalRequest = (*Context);

	//
	// This is an internal request
	//
	if (OriginalRequest == NULL)
	{
		INFO_DBG("pFiltMod(%p) INTERNAL_REQUEST Oid %#x, Status %x\n", pFiltMod, Request->DATA.Oid, Status);
		PINTERNAL_REQUEST pRequest = CONTAINING_RECORD(Request, INTERNAL_REQUEST, Request);
		NT_ASSERT(pRequest->pFiltMod == pFiltMod);
		// Set the request result
		pRequest->RequestStatus = Status;
		// and awake the caller
		NdisSetEvent(&pRequest->InternalRequestCompletedEvent);
		TRACE_EXIT();
		return;
	}


	FILTER_ACQUIRE_LOCK(&pFiltMod->OIDLock, NPF_IRQL_UNKNOWN);

	NT_ASSERT(pFiltMod->PendingOidRequest == Request);
	pFiltMod->PendingOidRequest = NULL;

	FILTER_RELEASE_LOCK(&pFiltMod->OIDLock, NPF_IRQL_UNKNOWN);


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
            if (OriginalRequest->DATA.SET_INFORMATION.InformationBuffer != Request->DATA.SET_INFORMATION.InformationBuffer)
            {
                /* We modified the data on clone, e.g. OID_GEN_CURRENT_PACKET_FILTER */
                ExFreePoolWithTag(Request->DATA.SET_INFORMATION.InformationBuffer, NPF_CLONE_OID_TAG);
            }
			break;

		case NdisRequestQueryInformation:
		case NdisRequestQueryStatistics:
		default:
			OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
			OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
			break;
	}



	(*Context) = NULL;

	NdisFreeCloneOidRequest(pFiltMod->AdapterHandle, Request);

	NdisFOidRequestComplete(pFiltMod->AdapterHandle, OriginalRequest, Status);

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

// 	TRACE_ENTER();
// 	INFO_DBG("NPF: Status Indication\n");

	INFO_DBG("status %x\n", StatusIndication->StatusCode);

	// We can use this if we haven't mucked with it yet.
	if (StatusIndication->StatusCode == NDIS_STATUS_PACKET_FILTER
			&& pFiltMod->MyPacketFilter != 0
			&& !pFiltMod->HigherPacketFilterSet)
	{
		NT_ASSERT(StatusIndication->StatusBufferSize >= sizeof(ULONG));
		pFiltMod->HigherPacketFilter = *(PULONG)StatusIndication->StatusBuffer;
		pFiltMod->HigherPacketFilterSet = 1;
	}

	// If it's ours, drop it here. Otherwise, pass it on.
	if (StatusIndication->SourceHandle != pFiltMod->AdapterHandle)
	{
		NdisFIndicateStatus(pFiltMod->AdapterHandle, StatusIndication);
	}

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	NDIS_DEVICE_PNP_EVENT  DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

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
			INFO_DBG("FilterDevicePnPEventNotify: Invalid event.\n");
			break;
	}

	NdisFDevicePnPEventNotify(pFiltMod->AdapterHandle, NetDevicePnPEvent);

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	NDIS_STATUS               Status = NDIS_STATUS_SUCCESS;

	TRACE_ENTER();

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	//
	// The filter may do processing on the event here, including intercepting
	// and dropping it entirely.  However, the sample does nothing with Net PNP
	// events, except pass them up to the next higher layer.  It is more
	// efficient to omit the FilterNetPnPEvent handler entirely if it does
	// nothing, but it is included in this sample for illustrative purposes.
	//

	Status = NdisFNetPnPEvent(pFiltMod->AdapterHandle, NetPnPEventNotification);

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	if (NetBufferLists->SourceHandle == pFiltMod->AdapterHandle)
	{
		// This is one of ours; free it.
		NPF_FreePackets(pFiltMod, NetBufferLists);
	}
	else
	{
		// Return the received NBLs.  If you removed any NBLs from the chain, make
		// sure the chain isn't empty (i.e., NetBufferLists!=NULL).
		NdisFReturnNetBufferLists(pFiltMod->AdapterHandle, NetBufferLists, ReturnFlags);
	}

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
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!pFiltMod->Loopback);
#endif

	NdisFCancelSendNetBufferLists(pFiltMod->AdapterHandle, CancelId);
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

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	/* This callback is only for the NDIS LWF, not WFP/loopback */
	NT_ASSERT(!((PNPCAP_FILTER_MODULE)FilterModuleContext)->Loopback);
#endif

   return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS
NPF_SetPacketFilter(
	PNPCAP_FILTER_MODULE pFiltMod,
	ULONG PacketFilter
)
{
	PVOID pBuffer = NULL;
	NDIS_STATUS Status = STATUS_SUCCESS;
	ULONG BytesProcessed = 0;
	LOCK_STATE_EX lockState;
	ULONG NewPF = 0, OldPF = 0;
	BOOLEAN bail_early = FALSE;

	TRACE_DBG("pFiltMod=%p, PacketFilter=%#lx\n", pFiltMod, PacketFilter);

	if (pFiltMod->Fragile || pFiltMod->Loopback)
	{
		// Fake it
		bail_early = TRUE;
	}

	if (!pFiltMod->HigherPacketFilterSet)
	{
		Status = NPF_GetPacketFilter(pFiltMod);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			INFO_DBG("pFiltMod(%p) can't set PacketFilter; no valid HigherPacketFilter present.\n", pFiltMod);
			// Have to fake success; many miniport types don't like queries to OID_GEN_CURRENT_PACKET_FILTER.
			Status = STATUS_SUCCESS;
			bail_early = TRUE;
		}
	}

	if (bail_early)
	{
		pFiltMod->MyPacketFilter = PacketFilter;
		return Status;
	}

	// Only set packet filter if we know what it was previously and can revert to that.
	NT_ASSERT(pFiltMod->HigherPacketFilterSet);

	NdisAcquireRWLockWrite(pFiltMod->OpenInstancesLock, &lockState, 0);

	// Calculate old and new effective filters
	OldPF = pFiltMod->SupportedPacketFilters & (pFiltMod->HigherPacketFilter | pFiltMod->MyPacketFilter);
	NewPF = pFiltMod->SupportedPacketFilters & (pFiltMod->HigherPacketFilter | PacketFilter);

	// If the new effective filter is the same as the old one, nothing left to do.
	bail_early = (OldPF == NewPF);

	// Regardless, track our current preferred packet filter.
	pFiltMod->MyPacketFilter = PacketFilter;

	NdisReleaseRWLock(pFiltMod->OpenInstancesLock, &lockState);

	if (bail_early)
	{
		return NDIS_STATUS_SUCCESS;
	}

	pBuffer = NPF_AllocateZeroNonpaged(sizeof(PacketFilter), NPF_INTERNAL_OID_TAG);
	if (pBuffer == NULL)
	{
		INFO_DBG("Allocate pBuffer failed\n");
			TRACE_EXIT();
		return NDIS_STATUS_RESOURCES;
	}
	// Init the buffer
	*(PULONG) pBuffer = NewPF;
	INFO_DBG("New packet filter: %#lx\n", NewPF);

	// set the PacketFilter
	Status = NPF_DoInternalRequest(pFiltMod,
		NdisRequestSetInformation,
		OID_GEN_CURRENT_PACKET_FILTER,
		pBuffer,
		sizeof(PacketFilter),
		0,
		0,
		&BytesProcessed
	);
	// Some drivers do not set BytesRead for Set requests
	UNREFERENCED_PARAMETER(BytesProcessed);

	ExFreePoolWithTag(pBuffer, NPF_INTERNAL_OID_TAG);

	TRACE_EXIT();
	return Status;
}

_Use_decl_annotations_
NDIS_STATUS
NPF_SetLookaheadSize(
	PNPCAP_FILTER_MODULE pFiltMod,
	ULONG LookaheadSize
)
{
	PVOID pBuffer = NULL;
	NDIS_STATUS Status = STATUS_SUCCESS;
	ULONG BytesProcessed = 0;
	ULONG OldValue = pFiltMod->MyLookaheadSize;

	TRACE_ENTER();
	pFiltMod->MyLookaheadSize = LookaheadSize;

	if (pFiltMod->Fragile || pFiltMod->Loopback)
	{
		// Fake it
		return NDIS_STATUS_SUCCESS;
	}

	// If neither the new or the old value is greater than the upper value,
	if (LookaheadSize <= pFiltMod->HigherLookaheadSize
			&& OldValue <= pFiltMod->HigherLookaheadSize)
	{
		// Nothing left to do!
		return NDIS_STATUS_SUCCESS;
	}
	// If the new value is the same as the old one,
	if (LookaheadSize == OldValue)
	{
		// Nothing left to do!
		return NDIS_STATUS_SUCCESS;
	}
	// Otherwise, we have to update the stack with our new max value.

	pBuffer = NPF_AllocateZeroNonpaged(sizeof(ULONG), NPF_INTERNAL_OID_TAG);
	if (pBuffer == NULL)
	{
		INFO_DBG("Allocate pBuffer failed\n");
			TRACE_EXIT();
		return NDIS_STATUS_RESOURCES;
	}
	*(PULONG) pBuffer = max(pFiltMod->HigherLookaheadSize, LookaheadSize);

	// set the LookaheadSize
	Status = NPF_DoInternalRequest(pFiltMod,
		NdisRequestSetInformation,
		OID_GEN_CURRENT_LOOKAHEAD,
		pBuffer,
		sizeof(ULONG),
		0,
		0,
		&BytesProcessed
	);

	ExFreePoolWithTag(pBuffer, NPF_INTERNAL_OID_TAG);

	// Some drivers do not set BytesRead for Set requests
	UNREFERENCED_PARAMETER(BytesProcessed);
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NDIS_STATUS NPF_DoInternalRequest(
	PNPCAP_FILTER_MODULE pFiltMod,
	NDIS_REQUEST_TYPE RequestType,
	NDIS_OID Oid,
	PVOID InformationBuffer,
	ULONG InformationBufferLength,
	ULONG OutputBufferLength,
	ULONG MethodId,
	PULONG pBytesProcessed)
{
	TRACE_ENTER();
	// NdisFOidRequest requires Restarting, Running, Pausing, or Paused state.
	NT_ASSERT(pFiltMod->AdapterBindingStatus >= FilterPausing && pFiltMod->AdapterBindingStatus <= FilterRestarting);

	NDIS_STATUS                 Status = NDIS_STATUS_FAILURE;

	*pBytesProcessed = 0;

	PINTERNAL_REQUEST pInternalRequest = ExAllocateFromLookasideListEx(&g_pDriverExtension->InternalRequestPool);
	if (pInternalRequest == NULL)
	{
		ERROR_DBG("Failed to allocate pInternalRequest\n");
		Status = NDIS_STATUS_RESOURCES;
		goto InternalRequestExit;
	}
	RtlZeroMemory(pInternalRequest, sizeof(INTERNAL_REQUEST));

	PNDIS_OID_REQUEST NdisRequest = &pInternalRequest->Request;

	pInternalRequest->pFiltMod = pFiltMod;
	pInternalRequest->RequestStatus = NDIS_STATUS_PENDING;

	NdisInitializeEvent(&pInternalRequest->InternalRequestCompletedEvent);
	NdisResetEvent(&pInternalRequest->InternalRequestCompletedEvent);

	NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
#if NDIS_SUPPORT_NDIS650
	if (g_pDriverExtension->NdisVersion >= NDIS_RUNTIME_VERSION_650) {
		NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_2;
		NdisRequest->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_2;
	} else
#else
	{
		NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
		NdisRequest->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
	}
#endif
	NdisRequest->RequestType = RequestType;
	NdisRequest->RequestHandle = pFiltMod->AdapterHandle;
	*(PVOID *)NdisRequest->SourceReserved = NULL; //indicates this is a self-sent request
	NdisRequest->DATA.Oid = Oid;

	switch (RequestType)
	{
		case NdisRequestQueryInformation:
			NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength = InformationBufferLength;
			break;

		case NdisRequestSetInformation:
			NdisRequest->DATA.SET_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.SET_INFORMATION.InformationBufferLength = InformationBufferLength;
			break;

		case NdisRequestMethod:
			NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
			NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer = InformationBuffer;
			NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength = InformationBufferLength;
			NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
			break;

		default:
			INFO_DBG("Unsupported RequestType: %d\n", RequestType);
			TRACE_EXIT();
			Status = NDIS_STATUS_INVALID_PARAMETER;
			goto InternalRequestExit;
			break;
	}

	NdisRequest->RequestId = (PVOID)NPF_REQUEST_ID;

	Status = NdisFOidRequest(pFiltMod->AdapterHandle, NdisRequest);

	if (Status == NDIS_STATUS_PENDING)
	{
		// Wait for this event which is signaled by NPF_OidRequestComplete,
		// which also sets RequestStatus appropriately
		NdisWaitEvent(&pInternalRequest->InternalRequestCompletedEvent, 0);
		Status = pInternalRequest->RequestStatus;
	}

	if (Status == NDIS_STATUS_SUCCESS)
	{
		// The driver below should set the correct value to BytesWritten
		// or BytesRead. But now, we just truncate the value to InformationBufferLength
		// due to bug in Nortel driver ipsecw2k.sys v. 4.10.0.0 that doesn't set the BytesWritten correctly
		// The driver is the one shipped with Nortel client Contivity VPN Client V04_65.18, and the MD5 for the buggy (unsigned) driver
		// is 3c2ff8886976214959db7d7ffaefe724 *ipsecw2k.sys (there are multiple copies of this binary with the same exact version info!)
		// The (certified) driver shipped with Nortel client Contivity VPN Client V04_65.320 doesn't seem affected by the bug.
		switch (RequestType)
		{
			case NdisRequestSetInformation:
				*pBytesProcessed = min(NdisRequest->DATA.SET_INFORMATION.BytesRead, InformationBufferLength);
				break;
			case NdisRequestQueryInformation:
				*pBytesProcessed = min(NdisRequest->DATA.QUERY_INFORMATION.BytesWritten, InformationBufferLength);
				break;
			case NdisRequestMethod:
				*pBytesProcessed = min(NdisRequest->DATA.METHOD_INFORMATION.BytesWritten, OutputBufferLength);
				break;
			default:
				NT_ASSERT(RequestType && FALSE);
				Status = NDIS_STATUS_INVALID_PARAMETER;
				goto InternalRequestExit;
				break;
		}
	}
	else if (Status == NDIS_STATUS_INDICATION_REQUIRED)
	{
		// We don't handle this currently
		WARNING_DBG("pFiltMod(%p) OID %#x NDIS_STATUS_INDICATION_REQUIRED\n", pFiltMod, Oid);
	}

InternalRequestExit:

	if (pInternalRequest)
	{
		ExFreeToLookasideListEx(&g_pDriverExtension->InternalRequestPool, pInternalRequest);
	}
	INFO_DBG("pFiltMod(%p) OID %s %#x: Status = %#x; Bytes = %lu\n", pFiltMod, RequestType == NdisRequestQueryInformation ? "GET" : "SET", Oid, Status, *pBytesProcessed);
	TRACE_EXIT();
	return Status;
}

_Use_decl_annotations_
VOID NPF_UpdateTimestampModeCounts(
		PNPCAP_FILTER_MODULE pFiltMod,
		ULONG newmode,
		ULONG oldmode)
{
	LONG result = 0;
	if (pFiltMod == NULL || newmode == oldmode)
		return;

	switch (newmode)
	{
		case TIMESTAMPMODE_UNSET:
			result = 1;
			break;
		case TIMESTAMPMODE_SINGLE_SYNCHRONIZATION:
			result = InterlockedIncrement(&pFiltMod->nTimestampQPC);
			break;
		case TIMESTAMPMODE_QUERYSYSTEMTIME:
			result = InterlockedIncrement(&pFiltMod->nTimestampQST);
			break;
		case TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE:
			result = InterlockedIncrement(&pFiltMod->nTimestampQST_Precise);
			break;
		default:
			NT_ASSERT(FALSE);
			break;
	}
	NT_ASSERT(result > 0);
	switch (oldmode)
	{
		case TIMESTAMPMODE_UNSET:
			result = 0;
			break;
		case TIMESTAMPMODE_SINGLE_SYNCHRONIZATION:
			result = InterlockedDecrement(&pFiltMod->nTimestampQPC);
			break;
		case TIMESTAMPMODE_QUERYSYSTEMTIME:
			result = InterlockedDecrement(&pFiltMod->nTimestampQST);
			break;
		case TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE:
			result = InterlockedDecrement(&pFiltMod->nTimestampQST_Precise);
			break;
		default:
			NT_ASSERT(FALSE);
			break;
	}
	NT_ASSERT(result >= 0);
}
