/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and may not be redistributed or incorporated   *
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

#include "Loopback.h"
#include "Lo_send.h"
#include "debug.h"
#include "packet.h"
#include "win_bpf.h"
#include "ioctls.h"

#include "..\..\..\Common\WpcapNames.h"

#ifdef ALLOC_PRAGMA
#pragma NDIS_INIT_FUNCTION(DriverEntry)
#endif // ALLOC_PRAGMA

#if DBG
// Declare the global debug flag for this driver.
ULONG PacketDebugFlag = PACKET_DEBUG_LOUD;

#endif

SINGLE_LIST_ENTRY g_arrFiltMod = {0}; //Adapter filter module list head
NDIS_SPIN_LOCK g_FilterArrayLock; //The lock for adapter filter module list.

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
//
// Global variables used by WFP
//
NDIS_STRING g_LoopbackAdapterName;
NDIS_STRING g_LoopbackRegValueName = NDIS_STRING_CONST("LoopbackAdapter");
#endif

#ifdef HAVE_RX_SUPPORT

NDIS_STRING g_SendToRxAdapterName;
NDIS_STRING g_SendToRxRegValueName = NDIS_STRING_CONST("SendToRxAdapters");
NDIS_STRING g_BlockRxAdapterName;
NDIS_STRING g_BlockRxRegValueName = NDIS_STRING_CONST("BlockRxAdapters");

#endif

NDIS_STRING g_NPF_Prefix;
NDIS_STRING g_NPF_Prefix_WIFI;
NDIS_STRING devicePrefix = NDIS_STRING_CONST("\\Device\\");
NDIS_STRING symbolicLinkPrefix = NDIS_STRING_CONST("\\DosDevices\\");

NDIS_STRING g_AdminOnlyRegValueName = NDIS_STRING_CONST("AdminOnly");
NDIS_STRING g_DltNullRegValueName = NDIS_STRING_CONST("DltNull");
NDIS_STRING g_Dot11SupportRegValueName = NDIS_STRING_CONST("Dot11Support");
NDIS_STRING g_VlanSupportRegValueName = NDIS_STRING_CONST("VlanSupport");
NDIS_STRING g_TimestampRegValueName = NDIS_STRING_CONST("TimestampMode");

ULONG g_AdminOnlyMode = 0;
ULONG g_DltNullMode = 0;
ULONG g_Dot11SupportMode = 0;
ULONG g_VlanSupportMode = 0;
ULONG g_TimestampMode = 0;

ULONG g_NCpu;

//
// Global variables
//
NDIS_HANDLE         FilterDriverHandle = NULL;			// NDIS handle for filter driver
NDIS_HANDLE         FilterDriverHandle_WiFi = NULL;		// NDIS handle for WiFi filter driver
NDIS_HANDLE         FilterDriverObject;					// Driver object for filter driver

typedef ULONG (*NDISGROUPMAXPROCESSORCOUNT)(
	USHORT Group
	);
//KeGetCurrentProcessorNumberEx
typedef ULONG (*KEGETCURRENTPROCESSORNUMBEREX)(
	PPROCESSOR_NUMBER ProcNumber
	);

NDISGROUPMAXPROCESSORCOUNT g_My_NdisGroupMaxProcessorCount = NULL;
KEGETCURRENTPROCESSORNUMBEREX g_My_KeGetCurrentProcessorNumberEx = NULL;

//-------------------------------------------------------------------
ULONG
My_NdisGroupMaxProcessorCount(
	)
{
	ULONG Cpu;
	if (g_My_NdisGroupMaxProcessorCount) // for NDIS620 and later (Win7 and later).
	{
		Cpu = g_My_NdisGroupMaxProcessorCount(ALL_PROCESSOR_GROUPS);
		if (Cpu > NPF_MAX_CPU_NUMBER - 1)
		{
			Cpu = NPF_MAX_CPU_NUMBER - 1;
		}
	}
	else // for NDIS6 (Vista)
	{
		Cpu = NdisSystemProcessorCount();
	}
	return Cpu;
}

//-------------------------------------------------------------------
ULONG
My_KeGetCurrentProcessorNumber(
)
{
	ULONG Cpu;
	if (g_My_KeGetCurrentProcessorNumberEx) // for NDIS620 and later (Win7 and later).
	{
		Cpu = g_My_KeGetCurrentProcessorNumberEx(NULL);
		if (Cpu > NPF_MAX_CPU_NUMBER - 1)
		{
			Cpu = NPF_MAX_CPU_NUMBER - 1;
		}
	}
	else // for NDIS6 (Vista)
	{
		Cpu = KeGetCurrentProcessorNumber();
	}
	return Cpu;
}


#ifdef NPCAP_READ_ONLY
// For read-only Npcap, we want an explicit denial function for the Write call.
// The IOCTLs will be rejected as "invalid request"
_Dispatch_type_(IRP_MJ_WRITE)
DRIVER_DISPATCH NPF_Deny;

NTSTATUS NPF_Deny(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp
		)
{
	TRACE_ENTER();
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_EXIT();
	return STATUS_UNSUCCESSFUL;
}
#endif

//-------------------------------------------------------------------
//
//  Packet Driver's entry routine.
//
_Use_decl_annotations_
NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	)
{
	NDIS_FILTER_DRIVER_CHARACTERISTICS FChars; // The specification for the filter.
	NDIS_FILTER_DRIVER_CHARACTERISTICS FChars_WiFi; // The specification for the WiFi filter.
	UNICODE_STRING parametersPath;
	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT devObjP;
#ifndef NPCAP_READ_ONLY
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)"); // this SDDL means only permits System and Administrator to modify the device.
#else
	// For convenience and clarity, deny write access here. In reality, we
	// remove any code that injects packets in this configuration
	UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)"); // this SDDL means only permits System and Administrator to modify the device.
#endif
	const GUID guidClassNPF = { 0x26e0d1e0L, 0x8189, 0x12e0, { 0x99, 0x14, 0x08, 0x00, 0x22, 0x30, 0x19, 0x04 } };
	UNICODE_STRING deviceSymLink;

	// Use NonPaged Pool instead of No-Execute (NX) Nonpaged Pool for Win8 and later, this is for security purpose.
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	
	UNICODE_STRING AdapterName;
	ULONG OsMajorVersion, OsMinorVersion;

	NDIS_STRING strNdisGroupMaxProcessorCount;
	NDIS_STRING strKeGetCurrentProcessorNumberEx;
	NDIS_STRING strKeGetProcessorIndexFromNumber;

	UNREFERENCED_PARAMETER(RegistryPath);

	TRACE_ENTER();
	FilterDriverObject = DriverObject;

	PsGetVersion(&OsMajorVersion, &OsMinorVersion, NULL, NULL);
	TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "OS Version: %d.%d\n", OsMajorVersion, OsMinorVersion);

	RtlInitUnicodeString(&parametersPath, NULL);
	parametersPath.MaximumLength=RegistryPath->Length+wcslen(L"\\Parameters")*sizeof(WCHAR)+sizeof(UNICODE_NULL);
	parametersPath.Buffer=ExAllocatePoolWithTag(PagedPool, parametersPath.MaximumLength, '4PWA');
	if (!parametersPath.Buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(parametersPath.Buffer, parametersPath.MaximumLength);
	RtlCopyUnicodeString(&parametersPath, RegistryPath);
	RtlAppendUnicodeToString(&parametersPath, L"\\Parameters");

	Status = RtlCheckRegistryKey(RTL_REGISTRY_ABSOLUTE,
			parametersPath.Buffer);
	if (NT_SUCCESS(Status)) {
		// Get the AdminOnly option, if AdminOnly=1, devices will be created with the safe SDDL, to make sure only Administrators can use Npcap driver.
		// If the registry key doesn't exist, we view it as AdminOnly=0, so no protect to the driver access.
		g_AdminOnlyMode = NPF_GetRegistryOption_Integer(&parametersPath, &g_AdminOnlyRegValueName);
		// Get the DltNull option, if DltNull=1, loopback traffic will be DLT_NULL/DLT_LOOP style, including captured and sent packets.
		// If the registry key doesn't exist, we view it as DltNull=0, so loopback traffic are Ethernet packets.
		g_DltNullMode = NPF_GetRegistryOption_Integer(&parametersPath, &g_DltNullRegValueName);
		// Get the Dot11Support option, if Dot11Support=1, Npcap driver will enable the raw 802.11 functions.
		// If the registry key doesn't exist, we view it as Dot11Support=1, so has raw 802.11 support.
		g_Dot11SupportMode = NPF_GetRegistryOption_Integer(&parametersPath, &g_Dot11SupportRegValueName);
		// Get the VlanSupport option, if VlanSupport=1, Npcap driver will try to recognize 802.1Q VLAN tag when capturing and sending data.
		// If the registry key doesn't exist, we view it as VlanSupport=0, so no VLAN support.
		g_VlanSupportMode = NPF_GetRegistryOption_Integer(&parametersPath, &g_VlanSupportRegValueName);
		// Get the TimestampMode option. The meanings of its values is described in time_calls.h.
		// If the registry key doesn't exist, we view it as TimestampMode=0, so the default "QueryPerformanceCounter" timestamp gathering method.
		g_TimestampMode = NPF_GetRegistryOption_Integer(&parametersPath, &g_TimestampRegValueName);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		NPF_GetRegistryOption_String(&parametersPath, &g_LoopbackRegValueName, &g_LoopbackAdapterName);
		if (g_LoopbackAdapterName.Buffer != NULL && g_LoopbackAdapterName.Length != ADAPTER_NAME_SIZE * 2)
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "g_LoopbackAdapterName is invalid, g_LoopbackAdapterName.Length = %d, ADAPTER_NAME_SIZE * 2 = %d\n",
					g_LoopbackAdapterName.Length, ADAPTER_NAME_SIZE * 2);
			ExFreePool(g_LoopbackAdapterName.Buffer);
			g_LoopbackAdapterName.Buffer = NULL;
			g_LoopbackAdapterName.Length = 0;
			g_LoopbackAdapterName.MaximumLength = 0;
		}
#endif
#ifdef HAVE_RX_SUPPORT
		NPF_GetRegistryOption_String(&parametersPath, &g_SendToRxRegValueName, &g_SendToRxAdapterName);
		NPF_GetRegistryOption_String(&parametersPath, &g_BlockRxRegValueName, &g_BlockRxAdapterName);
#endif
	}
	if (parametersPath.Buffer) ExFreePool(parametersPath.Buffer);
	if (g_AdminOnlyMode) {
		NdisInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
	}

	// RegistryPath = "\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\npcap" for standard driver
	// RegistryPath = "\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\npcap_wifi" for WiFi driver

	//
	// The Dot11 support is determined by whether the service is "npcap" or "npcap_wifi"
	//
// 	g_Dot11SupportMode = 0;
// 	for (USHORT i = 0; i < RegistryPath->Length / 2; i ++)
// 	{
// 		if (RegistryPath->Buffer[i] == L'_')
// 		{
// 			g_Dot11SupportMode = 1;
// 			break;
// 		}
// 	}
// 	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "g_Dot11SupportMode (based on RegistryPath) = %d\n", g_Dot11SupportMode);

	NdisInitUnicodeString(&g_NPF_Prefix, NPF_DEVICE_NAMES_PREFIX_WIDECHAR);

	if (g_Dot11SupportMode)
		NdisInitUnicodeString(&g_NPF_Prefix_WIFI, NPF_DEVICE_NAMES_PREFIX_WIDECHAR_WIFI);

	//
	// Initialize several CPU-related functions.
	//
	RtlInitUnicodeString(&strNdisGroupMaxProcessorCount, L"NdisGroupMaxProcessorCount");
	g_My_NdisGroupMaxProcessorCount = (NDISGROUPMAXPROCESSORCOUNT) NdisGetRoutineAddress(&strNdisGroupMaxProcessorCount);

	RtlInitUnicodeString(&strKeGetCurrentProcessorNumberEx, L"KeGetCurrentProcessorNumberEx");
	g_My_KeGetCurrentProcessorNumberEx = (KEGETCURRENTPROCESSORNUMBEREX) NdisGetRoutineAddress(&strKeGetCurrentProcessorNumberEx);

	//
	// Get number of CPUs and save it
	//
	g_NCpu = My_NdisGroupMaxProcessorCount();
	TRACE_MESSAGE3(PACKET_DEBUG_LOUD, "g_NCpu: %d, NPF_MAX_CPU_NUMBER: %d, g_My_NdisGroupMaxProcessorCount: %x\n", g_NCpu, NPF_MAX_CPU_NUMBER, g_My_NdisGroupMaxProcessorCount);

	//
	// Register as a service with NDIS
	//
	NPF_registerLWF(&FChars, FALSE);
	if (g_Dot11SupportMode)
		NPF_registerLWF(&FChars_WiFi, TRUE);

	DriverObject->DriverUnload = NPF_Unload;

	//
	// Standard device driver entry points stuff.
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = NPF_OpenAdapter;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = NPF_CloseAdapter;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = NPF_Cleanup;
	DriverObject->MajorFunction[IRP_MJ_READ] = NPF_Read;
#ifndef NPCAP_READ_ONLY
	DriverObject->MajorFunction[IRP_MJ_WRITE] = NPF_Write;
#else
	// Explicitly reject write calls
	DriverObject->MajorFunction[IRP_MJ_WRITE] = NPF_Deny;
#endif
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NPF_IoControl;

	// Create the "NPCAP" device itself:
	// TODO: handle wifi. suffix to file name?
	RtlInitUnicodeString(&AdapterName, L"\\Device\\" NPF_DRIVER_NAME_WIDECHAR);
	deviceSymLink.Length = 0;
	deviceSymLink.MaximumLength = (USHORT)(AdapterName.Length - devicePrefix.Length + symbolicLinkPrefix.Length + sizeof(UNICODE_NULL));

	deviceSymLink.Buffer = ExAllocatePoolWithTag(NonPagedPool, deviceSymLink.MaximumLength, '3PWA');
	if (deviceSymLink.Buffer == NULL)
	{
		TRACE_EXIT();
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlAppendUnicodeStringToString(&deviceSymLink, &symbolicLinkPrefix);
	RtlAppendUnicodeToString(&deviceSymLink, AdapterName.Buffer + devicePrefix.Length / sizeof(WCHAR));

	Status = IoCreateDeviceSecure(DriverObject, sizeof(DEVICE_EXTENSION), &AdapterName, FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, (LPCGUID)&guidClassNPF, &devObjP);
	if (!NT_SUCCESS(Status))
	{
		IF_LOUD(DbgPrint("\n\nIoCreateDevice status = %x\n", Status););

		ExFreePool(deviceSymLink.Buffer);

		TRACE_EXIT();
		return Status;
	}

	PDEVICE_EXTENSION devExtP = (PDEVICE_EXTENSION)devObjP->DeviceExtension;

	devObjP->Flags |= DO_DIRECT_IO;

	IF_LOUD(DbgPrint("Trying to create SymLink %ws\n", deviceSymLink.Buffer););

	Status = IoCreateSymbolicLink(&deviceSymLink, &AdapterName) != STATUS_SUCCESS;
	if (!NT_SUCCESS(Status))
	{
		IF_LOUD(DbgPrint("\n\nError creating SymLink %ws\nn", deviceSymLink.Buffer););

		IoDeleteDevice(devObjP);
		ExFreePool(deviceSymLink.Buffer);
		devExtP->ExportString = NULL;

		TRACE_EXIT();
		return Status;
	}

	devExtP->ExportString = deviceSymLink.Buffer;


#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// Use Winsock Kernel (WSK) to send loopback packets.
	// TODO: Allow this to continue but disable loopback if there's an error
	Status = NPF_WSKStartup();
	if (!NT_SUCCESS(Status))
	{
		TRACE_EXIT();
		return Status;
	}

	Status = NPF_WSKInitSockets();
	if (!NT_SUCCESS(Status))
	{
		NPF_WSKCleanup();
		TRACE_EXIT();
		return Status;
	}

	// Create the fake "filter module" for loopback capture
	// This is a hack to let NPF_CreateFilterModule create "\Device\NPCAP\Loopback" just like it usually does with a GUID
	NDIS_STRING LoopbackDeviceName = NDIS_STRING_CONST("\\Device\\Loopback");
	PNPCAP_FILTER_MODULE pFiltMod = NPF_CreateFilterModule(&LoopbackDeviceName, NdisMediumLoopback);
	if (pFiltMod == NULL)
	{
		NPF_WSKFreeSockets();
		NPF_WSKCleanup();
		TRACE_EXIT();
		return NDIS_STATUS_RESOURCES;
	}
	pFiltMod->Loopback = TRUE;
	// No need to mess with SendToRx/BlockRx, packet filters, NDIS filter characteristics, Dot11, etc.
	NPF_AddToFilterModuleArray(pFiltMod);
#endif

	/* Have to set this up before NdisFRegisterFilterDriver, since we can get Attach calls immediately after that! */
	NdisAllocateSpinLock(&g_FilterArrayLock);

	// Register the filter to NDIS.
	Status = NdisFRegisterFilterDriver(DriverObject,
		(NDIS_HANDLE) FilterDriverObject,
		&FChars,
		&FilterDriverHandle);
	if (Status != NDIS_STATUS_SUCCESS)
	{
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		NPF_WSKFreeSockets();
		NPF_WSKCleanup();
#endif
		NdisFreeSpinLock(&g_FilterArrayLock);
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NdisFRegisterFilterDriver: failed to register filter with NDIS, Status = %x", Status);
		TRACE_EXIT();
		return Status;
	}
	else
	{
		TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "NdisFRegisterFilterDriver: succeed to register filter with NDIS, Status = %x, FilterDriverHandle = %p", Status, FilterDriverHandle);
	}

	if (g_Dot11SupportMode)
	{
		// Register the WiFi filter to NDIS.
		Status = NdisFRegisterFilterDriver(DriverObject,
			(NDIS_HANDLE)FilterDriverObject,
			&FChars_WiFi,
			&FilterDriverHandle_WiFi);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NdisFRegisterFilterDriver: failed to register filter (WiFi) with NDIS, Status = %x", Status);

			// We still run the driver even with the 2nd filter doesn't work.
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "We only use the 1st Filter Handle now, FilterDriverHandle_WiFi = %p.", FilterDriverHandle_WiFi);
			// NdisFDeregisterFilterDriver(FilterDriverHandle);
			// TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Deleting the 1st Filter Handle = %p", FilterDriverHandle);

			// TRACE_EXIT();
			// return Status;
		}
		else
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "NdisFRegisterFilterDriver: succeed to register filter (WiFi) with NDIS, Status = %x, FilterDriverHandle_WiFi = %p", Status, FilterDriverHandle_WiFi);
		}
	}

	TRACE_EXIT();
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------
VOID
NPF_registerLWF(
	PNDIS_FILTER_DRIVER_CHARACTERISTICS pFChars,
	BOOLEAN bWiFiOrNot
	)
{
	NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(NPF_SERVICE_DESC_WIDECHAR); // display name
	NDIS_STRING UniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME); // unique name, quid name
	NDIS_STRING ServiceName = RTL_CONSTANT_STRING(NPF_DRIVER_NAME_SMALL_WIDECHAR); // this to match the service name in the INF
	NDIS_STRING FriendlyName_WiFi = RTL_CONSTANT_STRING(NPF_SERVICE_DESC_WIDECHAR_WIFI); // display name
	NDIS_STRING UniqueName_WiFi = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME_WIFI); // unique name, quid name
	NDIS_STRING ServiceName_WiFi = RTL_CONSTANT_STRING(NPF_DRIVER_NAME_SMALL_WIDECHAR_WIFI); // this to match the service name in the INF

	NdisZeroMemory(pFChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
	pFChars->Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
	pFChars->Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
	pFChars->Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
	pFChars->Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif

	pFChars->MajorNdisVersion = NDIS_FILTER_MAJOR_VERSION; // NDIS version is 6.2 (Windows 7)
	pFChars->MinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
	pFChars->MajorDriverVersion = 1; // Driver version is 1.0
	pFChars->MinorDriverVersion = 0;
	pFChars->Flags = 0;

	// Use different names for the WiFi driver.
	if (bWiFiOrNot)
	{
		pFChars->FriendlyName = FriendlyName_WiFi;
		pFChars->UniqueName = UniqueName_WiFi;
		pFChars->ServiceName = ServiceName_WiFi;
	}
	else
	{
		pFChars->FriendlyName = FriendlyName;
		pFChars->UniqueName = UniqueName;
		pFChars->ServiceName = ServiceName;
	}

	pFChars->SetOptionsHandler = NPF_RegisterOptions;
	pFChars->AttachHandler = NPF_AttachAdapter;
	pFChars->DetachHandler = NPF_DetachAdapter;
	pFChars->RestartHandler = NPF_Restart;
	pFChars->PauseHandler = NPF_Pause;
	pFChars->SetFilterModuleOptionsHandler = NPF_SetModuleOptions;
	pFChars->OidRequestHandler = NPF_OidRequest;
	pFChars->OidRequestCompleteHandler = NPF_OidRequestComplete;
	pFChars->CancelOidRequestHandler = NPF_CancelOidRequest;

	pFChars->SendNetBufferListsHandler = NPF_SendEx;
	pFChars->ReturnNetBufferListsHandler = NPF_ReturnEx;
	pFChars->SendNetBufferListsCompleteHandler = NPF_SendCompleteEx;
	pFChars->ReceiveNetBufferListsHandler = NPF_TapEx;
	pFChars->DevicePnPEventNotifyHandler = NPF_DevicePnPEventNotify;
	pFChars->NetPnPEventHandler = NPF_NetPnPEvent;
	pFChars->StatusHandler = NPF_Status;
	pFChars->CancelSendNetBufferListsHandler = NPF_CancelSendNetBufferLists;
}

//-------------------------------------------------------------------

#define ABSOLUTE(wait)				(wait)
#define RELATIVE(wait)				(-(wait))
#define NANOSECONDS(nanos)			(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)		(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)			(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)			(((signed __int64)(seconds)) * MILLISECONDS(1000L))


//-------------------------------------------------------------------
ULONG
NPF_GetRegistryOption_Integer(
	PUNICODE_STRING RegistryPath,
	PUNICODE_STRING RegValueName
	)
{
	ULONG returnValue = 0;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	TRACE_ENTER();
	IF_LOUD(DbgPrint("\nRegistryPath: %ws, RegValueName: %ws\n", RegistryPath->Buffer, RegValueName->Buffer);)

	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
	}
	else //OK
	{
		BOOLEAN bTried = FALSE;
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		IF_LOUD(DbgPrint("\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
REGISTRY_QUERY_VALUE_KEY:
		status = ZwQueryValueKey(keyHandle,
			RegValueName,
			KeyValuePartialInformation,
			&valueInfo,
			sizeof(valueInfo),
			&resultLength);

		if (status == STATUS_OBJECT_NAME_NOT_FOUND && bTried == FALSE)
		{
			LARGE_INTEGER delayTime;
			delayTime.QuadPart = RELATIVE(MILLISECONDS(500));
			IF_LOUD(DbgPrint("\nCalled KeDelayExecutionThread() to delay 500ms\n"););
			KeDelayExecutionThread(KernelMode, FALSE, &delayTime);
			bTried = TRUE;
			goto REGISTRY_QUERY_VALUE_KEY;
		}

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					RegValueName,
					KeyValuePartialInformation,
					valueInfoP,
					valueInfoLength,
					&resultLength);
				if (!NT_SUCCESS(status))
				{
					IF_LOUD(DbgPrint("Status of %x querying key value\n", status);)
				}
				else
				{
					IF_LOUD(DbgPrint("\"%ws\" Key = %08X\n", RegValueName->Buffer, *((DWORD *)valueInfoP->Data));)

					if (valueInfoP->DataLength == 4)
					{
						returnValue = *((DWORD *) valueInfoP->Data);
					}
				}

				ExFreePool(valueInfoP);
			}
			else
			{
				IF_LOUD(DbgPrint("Error Allocating the buffer for the NPF_GetRegistryOption_Integer function\n");)
			}
		}

		ZwClose(keyHandle);
	}

	TRACE_EXIT();
	return returnValue;
}

//-------------------------------------------------------------------
VOID
NPF_GetRegistryOption_String(
	PUNICODE_STRING RegistryPath,
	PUNICODE_STRING RegValueName,
	PNDIS_STRING g_OutputString
	)
{
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	TRACE_ENTER();
	IF_LOUD(DbgPrint("\nRegistryPath: %ws, RegValueName: %ws\n", RegistryPath->Buffer, RegValueName->Buffer);)

	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
	}
	else //OK
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		status = ZwQueryValueKey(keyHandle,
			RegValueName,
			KeyValuePartialInformation,
			&valueInfo,
			sizeof(valueInfo),
			&resultLength);

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					RegValueName,
					KeyValuePartialInformation,
					valueInfoP,
					valueInfoLength,
					&resultLength);
				if (!NT_SUCCESS(status))
				{
					IF_LOUD(DbgPrint("Status of %x querying key value\n", status);)
				}
				else
				{
					IF_LOUD(DbgPrint("\"%ws\" Key = %ws\n", RegValueName->Buffer, valueInfoP->Data);)

					g_OutputString->Length = (USHORT)(valueInfoP->DataLength - sizeof(UNICODE_NULL));
					g_OutputString->MaximumLength = (USHORT)(valueInfoP->DataLength);
					g_OutputString->Buffer = ExAllocatePoolWithTag(NonPagedPool, g_OutputString->MaximumLength, '3PWA');

					if (g_OutputString->Buffer)
						RtlCopyMemory(g_OutputString->Buffer, valueInfoP->Data, valueInfoP->DataLength);
				}

				ExFreePool(valueInfoP);
			}
			else
			{
				IF_LOUD(DbgPrint("Error Allocating the buffer for the NPF_GetRegistryOption_String function\n");)
			}
		}

		ZwClose(keyHandle);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_Unload(
	IN PDRIVER_OBJECT      DriverObject
)
/*++

Routine Description:

Filter driver's unload routine.
	Deregister the driver from NDIS.

Arguments:

	DriverObject - pointer to the system's driver object structure
				   for this driver

Return Value:

	NONE

--*/
{
	PDEVICE_OBJECT DeviceObject;
	PDEVICE_OBJECT OldDeviceObject;
	PDEVICE_EXTENSION DeviceExtension;
	NDIS_STATUS Status;
	NDIS_STRING SymLink;
	NDIS_EVENT Event;

	TRACE_ENTER();

	NdisInitializeEvent(&Event);
	NdisResetEvent(&Event);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// Free the loopback adapter name
	if (g_LoopbackAdapterName.Buffer != NULL)
	{
		ExFreePool(g_LoopbackAdapterName.Buffer);
		g_LoopbackAdapterName.Buffer = NULL;
	}

	// Release WSK resources.
	NPF_WSKFreeSockets();
	NPF_WSKCleanup();

	// Release WFP resources
	NPF_UnregisterCallouts();
	NPF_FreeInjectionHandles();
#endif

#ifdef HAVE_RX_SUPPORT
	// Free the send-to-Rx adapter name
	if (g_SendToRxAdapterName.Buffer != NULL)
	{
		ExFreePool(g_SendToRxAdapterName.Buffer);
		g_SendToRxAdapterName.Buffer = NULL;
	}
	if (g_BlockRxAdapterName.Buffer != NULL)
	{
		ExFreePool(g_BlockRxAdapterName.Buffer);
		g_BlockRxAdapterName.Buffer = NULL;
	}
#endif

	DeviceObject = DriverObject->DeviceObject;

	while (DeviceObject != NULL)
	{
		OldDeviceObject = DeviceObject;

		DeviceObject = DeviceObject->NextDevice;

		DeviceExtension = OldDeviceObject->DeviceExtension;

		TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Deleting Adapter, Device Obj=%p (%p)",
				DeviceObject, OldDeviceObject);

		if (DeviceExtension->ExportString)
		{
			RtlInitUnicodeString(&SymLink, DeviceExtension->ExportString);

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Deleting SymLink at %p", SymLink.Buffer);

			IoDeleteSymbolicLink(&SymLink);
			ExFreePool(DeviceExtension->ExportString);
			DeviceExtension->ExportString = NULL;
		}

		IoDeleteDevice(OldDeviceObject);
	}

	if (FilterDriverHandle)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NdisFDeregisterFilterDriver: Deleting Filter Handle = %p", FilterDriverHandle);
		NdisFDeregisterFilterDriver(FilterDriverHandle);
		FilterDriverHandle = NULL;
	}
	else
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NdisFDeregisterFilterDriver: Filter Handle = NULL, no need to delete.");
	}

	if (FilterDriverHandle_WiFi)
	{
		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "NdisFDeregisterFilterDriver: Deleting Filter Handle (WiFi) = %p", FilterDriverHandle_WiFi);
		NdisFDeregisterFilterDriver(FilterDriverHandle_WiFi);
		FilterDriverHandle_WiFi = NULL;
	}
	else
	{
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "NdisFDeregisterFilterDriver: Filter Handle (WiFi) = NULL, no need to delete.");
	}
	// NdisFDeregisterFilterDriver ought to have called FilterDetach, but something is leaking. Let's force a wait:
	NdisAcquireSpinLock(&g_FilterArrayLock);
	while (g_arrFiltMod.Next != NULL) {
		PNPCAP_FILTER_MODULE pFiltMod = CONTAINING_RECORD(g_arrFiltMod.Next, NPCAP_FILTER_MODULE, FilterModulesEntry);
		if (pFiltMod->Loopback) {
			// NDIS doesn't manage this, so we "detach" it ourselves.
			NdisReleaseSpinLock(&g_FilterArrayLock);
			NPF_DetachAdapter(pFiltMod);
		}
		else {
			// Wait for NDIS to release it
			NdisReleaseSpinLock(&g_FilterArrayLock);
			NdisWaitEvent(&Event, 1);
		}
		NdisAcquireSpinLock(&g_FilterArrayLock);
		NdisResetEvent(&Event);
	}
	NdisReleaseSpinLock(&g_FilterArrayLock);

	NdisFreeSpinLock(&g_FilterArrayLock);

	TRACE_EXIT();

	// Free the device names string that was allocated in the DriverEntry
	// NdisFreeString(g_NPF_Prefix);
}

#define SET_FAILURE_BUFFER_SMALL() do{\
	Information = 0; \
	Status = STATUS_BUFFER_TOO_SMALL; \
} while(FALSE)

#define SET_RESULT_SUCCESS(__a__) do{\
	Information = __a__;	\
	Status = STATUS_SUCCESS;	\
} while(FALSE)

#define SET_FAILURE_INVALID_REQUEST() do{\
	Information = 0; \
	Status = STATUS_INVALID_DEVICE_REQUEST; \
} while(FALSE)

#define SET_FAILURE_UNSUCCESSFUL()  do{\
	Information = 0; \
	Status = STATUS_UNSUCCESSFUL; \
} while(FALSE)

#define SET_FAILURE_NOMEM()  do{\
	Information = 0; \
	Status = STATUS_INSUFFICIENT_RESOURCES; \
} while(FALSE)

#define SET_FAILURE_CUSTOM(__b__) do{\
	Information = 0; \
	Status = __b__; \
	Status |= 1 << 29; \
} while(FALSE)

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS
NPF_IoControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	POPEN_INSTANCE			Open;
	PSINGLE_LIST_ENTRY Curr;
	PIO_STACK_LOCATION		IrpSp;
	PLIST_ENTRY				RequestListEntry;
	PINTERNAL_REQUEST		pRequest;
	ULONG					FunctionCode;
	NDIS_STATUS				Status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG					Information = 0;
	PLIST_ENTRY				PacketListEntry;
	UINT					i;
	PUCHAR					tpointer = NULL; //assign NULL to suppress error C4703: potentially uninitialized local pointer variable
	ULONG					dim, timeout;
	struct bpf_insn*		NewBpfProgram;
	PPACKET_OID_DATA		OidData;
	PVOID OidBuffer = NULL;
	int*					StatsBuf;
	ULONG					mode;
#ifdef NPCAP_KDUMP
	PWSTR					DumpNameBuff;
#endif
	PUCHAR					TmpBPFProgram;
	INT						WriteRes;
	BOOLEAN					SyncWrite = FALSE;
	struct bpf_insn*		initprogram;
	ULONG					insns;
	ULONG					cnt;
	BOOLEAN					IsExtendedFilter = FALSE;
	ULONG					StringLength;
	ULONG					NeededBytes;
	BOOLEAN					bAttached;
	PUINT					pStats;
	ULONG					StatsLength;
	PULONG					pCombinedPacketFilter;

	HANDLE					hUserEvent;
	PKEVENT					pKernelEvent;
#ifdef _AMD64_
	VOID* POINTER_32		hUserEvent32Bit;
#endif //_AMD64_

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	Open = IrpSp->FileObject->FsContext;
	if (!NPF_IsOpenInstance(Open))
	{
		Irp->IoStatus.Status = STATUS_INVALID_HANDLE;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_INVALID_HANDLE;
	}

	/* If this instance is not attached to the NDIS filter module, we can't do some operations. */
	bAttached = NPF_StartUsingOpenInstance(Open);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	TRACE_MESSAGE3(PACKET_DEBUG_LOUD,
		"Function code is %08lx Input size=%08lx Output size %08lx",
		FunctionCode,
		IrpSp->Parameters.DeviceIoControl.InputBufferLength,
		IrpSp->Parameters.DeviceIoControl.OutputBufferLength);

	switch (FunctionCode)
	{
	case BIOCGSTATS:
		//function to get the capture stats

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCGSTATS");

		StatsLength = 4 * sizeof(UINT);
		if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < StatsLength)
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		if (Irp->AssociatedIrp.SystemBuffer == NULL)
		{
			SET_FAILURE_UNSUCCESSFUL();
			break;
		}

		//
		// temp fix to a GIANT bug from LD. The CTL code has been defined as METHOD_NEITHER, so it
		// might well be a dangling pointer. We need to probe and lock the address.
		//

		pStats = (PUINT)(Irp->AssociatedIrp.SystemBuffer);
		
		pStats[3] = 0;
		pStats[0] = 0;
		pStats[1] = 0;
		pStats[2] = 0;		// Not yet supported

		for (i = 0 ; i < g_NCpu ; i++)
		{
			pStats[3] += Open->CpuData[i].Accepted;
			pStats[0] += Open->CpuData[i].Received;
			pStats[1] += Open->CpuData[i].Dropped;
			pStats[2] += 0;		// Not yet supported
		}

		SET_RESULT_SUCCESS(StatsLength);

		break;

	case BIOCGEVNAME:
		//function to get the name of the event associated with the current instance

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCGEVNAME");

		//
		// Since 20060405, the event handling has been changed:
		// we no longer use named events, instead the user level app creates an event,
		// and passes it back to the kernel, that references it (ObReferenceObjectByHandle), and
		// signals it.
		// For the time being, we still leave this ioctl code here, and we simply fail.
		//
		SET_FAILURE_INVALID_REQUEST();
		break;

#ifndef NPCAP_READ_ONLY
	case BIOCSENDPACKETSSYNC:
		SyncWrite = TRUE;

	case BIOCSENDPACKETSNOSYNC:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSENDPACKETSNOSYNC");

		if (!bAttached)
		{
			SET_FAILURE_UNSUCCESSFUL();
			break;
		}

		NdisAcquireSpinLock(&Open->WriteLock);
		if (Open->WriteInProgress)
		{
			NdisReleaseSpinLock(&Open->WriteLock);
			//
			// Another write operation is currently in progress
			//
			SET_FAILURE_UNSUCCESSFUL();
			break;
		}
		else
		{
			Open->WriteInProgress = TRUE;
		}
		NdisReleaseSpinLock(&Open->WriteLock);

		WriteRes = NPF_BufferedWrite(Irp,
			(PUCHAR) Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.InputBufferLength,
			SyncWrite);

		NdisAcquireSpinLock(&Open->WriteLock);
		Open->WriteInProgress = FALSE;
		NdisReleaseSpinLock(&Open->WriteLock);

		if (WriteRes >= 0)
		{
			SET_RESULT_SUCCESS(WriteRes);
		}
		else
		{
			SET_FAILURE_CUSTOM(-WriteRes);
		}
		break;
#endif // NPCAP_READ_ONLY

	case BIOCSETF:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETF");

		//
		// Get the pointer to the new program
		//
		NewBpfProgram = (struct bpf_insn *)Irp->AssociatedIrp.SystemBuffer;

		if (NewBpfProgram == NULL)
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		//
		// Lock the machine. After this call we are at DISPATCH level
		//
		NdisAcquireSpinLock(&Open->MachineLock);

		do
		{
			// Free the previous buffer if it was present
			if (Open->bpfprogram != NULL)
			{
				TmpBPFProgram = Open->bpfprogram;
				Open->bpfprogram = NULL;
				ExFreePool(TmpBPFProgram);
			}

			//
			// Jitted filters are supported on x86 (32bit) only
			//
#ifdef _X86_
			if (Open->Filter != NULL)
			{
				BPF_Destroy_JIT_Filter(Open->Filter);
				Open->Filter = NULL;
			}
#endif // _X86_

			insns = (IrpSp->Parameters.DeviceIoControl.InputBufferLength) / sizeof(struct bpf_insn);

			//count the number of operative instructions
			for (cnt = 0 ; (cnt < insns) && (NewBpfProgram[cnt].code != BPF_SEPARATION); cnt++)
				;

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Operative instructions=%u", cnt);

			if (cnt != insns)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error installing the BPF filter. The filter contains TME extensions,"
					" not supported on 64bit platforms.");

				SET_FAILURE_INVALID_REQUEST();
				break;
			}

			//the NPF processor has been initialized, we have to validate the operative instructions
			insns = cnt;

			//NOTE: the validation code checks for TME instructions, and fails if a TME instruction is
			//encountered on 64 bit machines
				if (bpf_validate(NewBpfProgram, cnt) == 0)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error validating program");
					//FIXME: the machine has been initialized(?), but the operative code is wrong.
					//we have to reset the machine!
					//something like: reallocate the mem_ex, and reset the tme_core
					SET_FAILURE_INVALID_REQUEST();
					break;
				}

			// Allocate the memory to contain the new filter program
			TmpBPFProgram = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cnt * sizeof(struct bpf_insn), '4PWA');
			if (TmpBPFProgram == NULL)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error - No memory for filter");
				// no memory

				SET_FAILURE_NOMEM();
				break;
			}

			//
			// At the moment the JIT compiler works on x86 (32 bit) only
			//
#ifdef _X86_
			// Create the new JIT filter function
			if (!IsExtendedFilter)
			{
				if ((Open->Filter = BPF_jitter(NewBpfProgram, cnt)) == NULL)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error jittering filter");

					ExFreePool(TmpBPFProgram);

					SET_FAILURE_UNSUCCESSFUL();
					break;
				}
			}
#endif //_X86_

			//copy the program in the new buffer
			RtlCopyMemory(TmpBPFProgram, NewBpfProgram, cnt * sizeof(struct bpf_insn));
			Open->bpfprogram = TmpBPFProgram;

			SET_RESULT_SUCCESS(0);
		}
		while (FALSE);

		//
		// release the machine lock and then reset the buffer
		//
		NdisReleaseSpinLock(&Open->MachineLock);

		NPF_ResetBufferContents(Open);

		break;

	case BIOCSMODE:
		//set the capture mode

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSMODE");

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		mode = *((PULONG)Irp->AssociatedIrp.SystemBuffer);

		///////kernel dump does not work at the moment//////////////////////////////////////////
		if (mode & MODE_DUMP)
		{
			SET_FAILURE_INVALID_REQUEST();
			break;
		}
		///////kernel dump does not work at the moment//////////////////////////////////////////

		if (mode == MODE_CAPT)
		{
			Open->mode = MODE_CAPT;

			SET_RESULT_SUCCESS(0);
			break;
		}
		else if (mode == MODE_MON)
		{
			//
			// The MONITOR_MODE (aka TME extensions) is not supported on
			// 64 bit architectures
			//

			SET_FAILURE_INVALID_REQUEST();

			break;
		}
		else
		{
			if (mode & MODE_STAT)
			{
				Open->mode = MODE_STAT;
				NdisAcquireSpinLock(&Open->CountersLock);
				Open->Nbytes.QuadPart = 0;
				Open->Npackets.QuadPart = 0;
				NdisReleaseSpinLock(&Open->CountersLock);

				if (Open->TimeOut.QuadPart == 0)
					Open->TimeOut.QuadPart = -10000000;
			}

			if (mode & MODE_DUMP)
			{
				Open->mode |= MODE_DUMP;
				// Open->MinToCopy=(Open->BufSize<2000000)?Open->BufSize/2:1000000;
			}

			SET_RESULT_SUCCESS(0);
			break;
		}

		SET_FAILURE_INVALID_REQUEST();

		break;

	case BIOCSETDUMPFILENAME:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETDUMPFILENAME");

		///////kernel dump does not work at the moment//////////////////////////////////////////
#ifdef NPCAP_KDUMP

		if(Open->mode & MODE_DUMP)
		{
		
			// Close current dump file
			if(Open->DumpFileHandle != NULL)
			{
				NPF_CloseDumpFile(Open);
				Open->DumpFileHandle = NULL;
			}
		
			if(IrpSp->Parameters.DeviceIoControl.InputBufferLength == 0){
				EXIT_FAILURE(0);
			}
		
			// Allocate the buffer that will contain the string
			DumpNameBuff=ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.InputBufferLength, '5PWA');
			if(DumpNameBuff==NULL || Open->DumpFileName.Buffer!=NULL){
				IF_LOUD(DbgPrint("NPF: unable to allocate the dump filename: not enough memory or name already set\n");)
					EXIT_FAILURE(0);
			}
		
			// Copy the buffer
			RtlCopyBytes((PVOID)DumpNameBuff,
				Irp->AssociatedIrp.SystemBuffer,
				IrpSp->Parameters.DeviceIoControl.InputBufferLength);
		
			// Force a \0 at the end of the filename to avoid that malformed strings cause RtlInitUnicodeString to crash the system
			((PSHORT)DumpNameBuff)[IrpSp->Parameters.DeviceIoControl.InputBufferLength/2-1]=0;
		
			// Create the unicode string
			RtlInitUnicodeString(&Open->DumpFileName, DumpNameBuff);
		
			IF_LOUD(DbgPrint("NPF: dump file name set to %ws, len=%d\n",
				Open->DumpFileName.Buffer,
				IrpSp->Parameters.DeviceIoControl.InputBufferLength);)
		
			// Try to create the file
			if ( NT_SUCCESS( NPF_OpenDumpFile(Open,&Open->DumpFileName,FALSE)) &&
				NT_SUCCESS( NPF_StartDump(Open)))
			{
				EXIT_SUCCESS(0);
			}
		}
		
		EXIT_FAILURE(0);
#else
		SET_FAILURE_INVALID_REQUEST();
#endif
		
		break;

	case BIOCSETDUMPLIMITS:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETDUMPLIMITS");

		///////kernel dump does not work at the moment//////////////////////////////////////////
#ifdef NPCAP_KDUMP

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < 2*sizeof(ULONG))
		{
			EXIT_FAILURE(0);
		}
		
		Open->MaxDumpBytes = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
		Open->MaxDumpPacks = *((PULONG)Irp->AssociatedIrp.SystemBuffer + 1);
		
		IF_LOUD(DbgPrint("NPF: Set dump limits to %u bytes, %u packs\n", Open->MaxDumpBytes, Open->MaxDumpPacks);)
		
		EXIT_SUCCESS(0);
#else
		SET_FAILURE_INVALID_REQUEST();
#endif
		
		break;

	case BIOCISDUMPENDED:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCISDUMPENDED");

		///////kernel dump does not work at the moment//////////////////////////////////////////
#ifdef NPCAP_KDUMP

		if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT))
		{
			EXIT_FAILURE(0);
		}

		*((UINT*)Irp->UserBuffer) = (Open->DumpLimitReached)?1:0;

		EXIT_SUCCESS(4);
#else
		SET_FAILURE_INVALID_REQUEST();
#endif

		break;

	case BIOCISETLOBBEH:
		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(INT))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		if (*(PINT) Irp->AssociatedIrp.SystemBuffer == NPF_DISABLE_LOOPBACK)
		{
			Open->SkipSentPackets = TRUE;

			//
			// Reset the capture buffers, since they could contain loopbacked packets
			//

			NPF_ResetBufferContents(Open);

			SET_RESULT_SUCCESS(0);
			break;
		}
		else if (*(PINT) Irp->AssociatedIrp.SystemBuffer == NPF_ENABLE_LOOPBACK)
		{
			Open->SkipSentPackets = FALSE;

			SET_RESULT_SUCCESS(0);
			break;
		}
		else
		{
			// Unknown operation
			SET_FAILURE_INVALID_REQUEST();
			break;
		}

		break;

	case BIOCSETEVENTHANDLE:

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETEVENTHANDLE");

#ifdef _AMD64_
		if (IoIs32bitProcess(Irp))
		{
			//
			// validate the input
			//
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(hUserEvent32Bit))
			{
				SET_FAILURE_INVALID_REQUEST();
				break;
			}

			hUserEvent32Bit = *(VOID * POINTER_32 *)Irp->AssociatedIrp.SystemBuffer;
			hUserEvent = hUserEvent32Bit;
		}
		else
#endif //_AMD64_
		{
			//
			// validate the input
			//
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(hUserEvent))
			{
				SET_FAILURE_INVALID_REQUEST();
				break;
			}

			hUserEvent = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
		}

		Status = ObReferenceObjectByHandle(hUserEvent,
			EVENT_MODIFY_STATE,
			*ExEventObjectType,
			Irp->RequestorMode,
			(PVOID *) &pKernelEvent,
			NULL);

		if (!NT_SUCCESS(Status))
		{
			// Status = ??? already set
			Information = 0;
			break;
		}


		if (InterlockedCompareExchangePointer(&Open->ReadEvent, pKernelEvent, NULL) != NULL)
		{
			//
			// dereference the new pointer
			//

			ObDereferenceObject(pKernelEvent);
			SET_FAILURE_INVALID_REQUEST();
			break;
		}

		KeResetEvent(Open->ReadEvent);

		SET_RESULT_SUCCESS(0);
		break;

	case BIOCSETBUFFERSIZE:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETBUFFERSIZE");

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		// Get the number of bytes to allocate
		dim = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
		
		// verify that the provided size value is sensible
		if (dim > NPF_MAX_BUFFER_SIZE)
		{
			SET_FAILURE_NOMEM();
			break;
		} 

		if (dim / g_NCpu < sizeof(struct PacketHeader))
		{
			dim = 0;
		}
		else
		{
			tpointer = ExAllocatePoolWithTag(NonPagedPool, dim, '6PWA');
			if (tpointer == NULL)
			{
				// no memory
				SET_FAILURE_NOMEM();
				break;
			}
		}

		//
		// acquire the locks for all the buffers
		//
		for (i = 0; i < g_NCpu ; i++)
		{
			NdisAcquireSpinLock(&Open->CpuData[i].BufferLock);
		}

		//
		// free the old buffer, if any
		//
		if (Open->CpuData[0].Buffer != NULL)
		{
			ExFreePool(Open->CpuData[0].Buffer);
			Open->CpuData[0].Buffer = NULL;
		}

		for (i = 0 ; i < g_NCpu ; i++)
		{
			if (dim > 0)
				Open->CpuData[i].Buffer = (PUCHAR)tpointer + (dim / g_NCpu) * i;
			else
				Open->CpuData[i].Buffer = NULL;
			Open->CpuData[i].Free = dim / g_NCpu;
			Open->CpuData[i].P = 0;
			Open->CpuData[i].C = 0;
			Open->CpuData[i].Accepted = 0;
			Open->CpuData[i].Dropped = 0;
			Open->CpuData[i].Received = 0;
		}

		Open->ReaderSN = 0;
		Open->WriterSN = 0;

		Open->Size = dim / g_NCpu;

		//
		// acquire the locks for all the buffers
		//
		i = g_NCpu;

		while (i > 0)
		{
			i --;
#pragma warning (disable: 28122)
			NdisReleaseSpinLock(&Open->CpuData[i].BufferLock);
		}

		SET_RESULT_SUCCESS(0);
		break;

	case BIOCSRTIMEOUT:
		//set the timeout on the read calls

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSRTIMEOUT");

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		timeout = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
		if (timeout == (ULONG) - 1)
			Open->TimeOut.QuadPart = (LONGLONG)IMMEDIATE;
		else
		{
			Open->TimeOut.QuadPart = (LONGLONG)timeout;
			Open->TimeOut.QuadPart *= 10000;
			Open->TimeOut.QuadPart = -Open->TimeOut.QuadPart;
		}

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Read timeout set to %I64d", Open->TimeOut.QuadPart);

		SET_RESULT_SUCCESS(0);
		break;

#ifndef NPCAP_READ_ONLY
	case BIOCSWRITEREP:
		//set the writes repetition number

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSWRITEREP");

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		Open->Nwrites = *((PULONG)Irp->AssociatedIrp.SystemBuffer);

		SET_RESULT_SUCCESS(0);
		break;

#endif // NPCAP_READ_ONLY

	case BIOCSMINTOCOPY:
		//set the minimum buffer's size to copy to the application

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSMINTOCOPY");

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		Open->MinToCopy = (*((PULONG)Irp->AssociatedIrp.SystemBuffer)) / g_NCpu;  //An hack to make the NCPU-buffers behave like a larger one

		SET_RESULT_SUCCESS(0);
		break;

	case BIOCSETOID:
	case BIOCQUERYOID:

		if (!bAttached)
		{
			SET_FAILURE_UNSUCCESSFUL();
			break;
		}

		OidData = Irp->AssociatedIrp.SystemBuffer;
		if (FunctionCode == BIOCQUERYOID)
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "BIOCQUERYOID Request: Oid=%08lx, Length=%08lx", OidData->Oid, OidData->Length);
		}
		else if (FunctionCode == BIOCSETOID)
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "BIOCSETOID Request: Oid=%08lx, Length=%08lx", OidData->Oid, OidData->Length);
		}
		else
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Unknown FunctionCode: %x, Oid=%08lx", FunctionCode, OidData->Oid);
			SET_FAILURE_INVALID_REQUEST();
			break;
		}

		//
		// gain ownership of the Ndis Handle
		//
		if (!Open->pFiltMod || NPF_StartUsingBinding(Open->pFiltMod) == FALSE)
		{
			//
			// MAC unbindind or unbound
			//
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Open->pFiltMod is unavailable or cannot bind, Open->pFiltMod=%p", Open->pFiltMod);
			SET_FAILURE_INVALID_REQUEST();
			break;
		}


		// Extract a request from the list of free ones
		RequestListEntry = ExInterlockedRemoveHeadList(&Open->pFiltMod->RequestList, &Open->pFiltMod->RequestSpinLock);
		if (RequestListEntry == NULL)
		{
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open->pFiltMod);

			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "RequestListEntry=NULL");
			SET_FAILURE_NOMEM();
			break;
		}

		pRequest = CONTAINING_RECORD(RequestListEntry, INTERNAL_REQUEST, ListElement);

		//
		//  See if it is an Ndis request
		//
		if ((IrpSp->Parameters.DeviceIoControl.InputBufferLength == IrpSp->Parameters.DeviceIoControl.OutputBufferLength) &&
			(IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA)) &&
			(IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA) - 1 + OidData->Length))
		{
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			if (Open->pFiltMod->Loopback)
			{ 
				// We don't really support OID requests on our fake loopback
				// adapter, but we can pretend.
				if (FunctionCode == BIOCSETOID) {
					switch (OidData->Oid) {
						// Using a switch instead of if/else in case there are
						// other OIDs we should accept
						case OID_GEN_CURRENT_PACKET_FILTER:
							SET_RESULT_SUCCESS(0);
							break;
						default:
							TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETOID not supported for Loopback");
							SET_FAILURE_INVALID_REQUEST();
							break;
					}
				}
				else {
					switch (OidData->Oid)
					{
						case OID_GEN_MAXIMUM_TOTAL_SIZE:
						case OID_GEN_TRANSMIT_BUFFER_SPACE:
						case OID_GEN_RECEIVE_BUFFER_SPACE:
							TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Loopback: AdapterName=%ws, OID_GEN_MAXIMUM_TOTAL_SIZE & BIOCGETOID, OidData->Data = %d", Open->pFiltMod->AdapterName.Buffer, NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN);
							*((PUINT)OidData->Data) = NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN;
							SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
							break;

						case OID_GEN_TRANSMIT_BLOCK_SIZE:
						case OID_GEN_RECEIVE_BLOCK_SIZE:
							TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Loopback: AdapterName=%ws, OID_GEN_TRANSMIT_BLOCK_SIZE & BIOCGETOID, OidData->Data = %d", Open->pFiltMod->AdapterName.Buffer, 1);
							*((PUINT)OidData->Data) = 1;
							SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
							break;
						case OID_GEN_MEDIA_IN_USE:
						case OID_GEN_MEDIA_SUPPORTED:
							TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Loopback: AdapterName=%ws, OID_GEN_MEDIA_IN_USE & BIOCGETOID, OidData->Data = %d", Open->pFiltMod->AdapterName.Buffer, NdisMediumNull);
							*((PUINT)OidData->Data) = g_DltNullMode ? NdisMediumNull : NdisMedium802_3;
							OidData->Length = sizeof(UINT);
							SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
							break;
						default:
							TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Unsupported BIOCQUERYOID for Loopback");
							SET_FAILURE_INVALID_REQUEST();
							break;
					}
				}

				//
				// Release ownership of the Ndis Handle
				//
				NPF_StopUsingBinding(Open->pFiltMod);

				ExInterlockedInsertTailList(&Open->pFiltMod->RequestList,
					&pRequest->ListElement,
					&Open->pFiltMod->RequestSpinLock);

				break;
			}
#endif

#ifdef HAVE_DOT11_SUPPORT
			if (Open->pFiltMod->Dot11 && (OidData->Oid == OID_GEN_MEDIA_IN_USE || OidData->Oid == OID_GEN_MEDIA_SUPPORTED))
			{
				if (FunctionCode == BIOCSETOID)
				{
					TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Dot11: AdapterName=%ws, OID_GEN_MEDIA_IN_USE & BIOCSETOID, fail it", Open->pFiltMod->AdapterName.Buffer);
					SET_FAILURE_UNSUCCESSFUL();
				}
				else
				{
					TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Dot11: AdapterName=%ws, OID_GEN_MEDIA_IN_USE & BIOCGETOID, OidData->Data = %d", Open->pFiltMod->AdapterName.Buffer, NdisMediumRadio80211);
					*((PUINT)OidData->Data) = NdisMediumRadio80211;
					OidData->Length = sizeof(UINT);
					SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
				}

				//
				// Release ownership of the Ndis Handle
				//
				NPF_StopUsingBinding(Open->pFiltMod);

				ExInterlockedInsertTailList(&Open->pFiltMod->RequestList,
					&pRequest->ListElement,
					&Open->pFiltMod->RequestSpinLock);

				break;
			}
#endif

			//
			//  The buffer is valid
			//
			NdisZeroMemory(&pRequest->Request, sizeof(NDIS_OID_REQUEST));
			pRequest->Request.Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
			pRequest->Request.Header.Revision = NDIS_OID_REQUEST_REVISION_1;
			pRequest->Request.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

			/* NDIS_OID_REQUEST.InformationBuffer must be non-paged */
			OidBuffer = ExAllocatePoolWithTag(NonPagedPool, OidData->Length, '0PWA');
			if (OidBuffer == NULL)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Failed to allocate OidBuffer");
				SET_FAILURE_NOMEM();
				break;
			}
			RtlCopyMemory(OidBuffer, OidData->Data, OidData->Length);

			if (FunctionCode == BIOCSETOID)
			{
				pRequest->Request.RequestType = NdisRequestSetInformation;
				pRequest->Request.DATA.SET_INFORMATION.Oid = OidData->Oid;

				pRequest->Request.DATA.SET_INFORMATION.InformationBuffer = OidBuffer;
				pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength = OidData->Length;
			}
			else
			{
				pRequest->Request.RequestType = NdisRequestQueryInformation;
				pRequest->Request.DATA.QUERY_INFORMATION.Oid = OidData->Oid;

				pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer = OidBuffer;
				pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength = OidData->Length;
			}

			NdisInitializeEvent(&pRequest->InternalRequestCompletedEvent);
			NdisResetEvent(&pRequest->InternalRequestCompletedEvent);

			if (*((PVOID *) pRequest->Request.SourceReserved) != NULL)
			{
				*((PVOID *) pRequest->Request.SourceReserved) = NULL;
			}

			//
			//  submit the request
			//
			pRequest->Request.RequestId = (PVOID) NPF_REQUEST_ID;
			pRequest->Request.RequestHandle = Open->pFiltMod->AdapterHandle;
			// ASSERT(Open->pFiltMod->AdapterHandle != NULL);

			if (OidData->Oid == OID_GEN_CURRENT_PACKET_FILTER && FunctionCode == BIOCSETOID)
			{
				ASSERT(Open->pFiltMod != NULL);

				// Disable setting Packet Filter for wireless adapters, because this will cause limited connectivity.
				if (Open->pFiltMod->PhysicalMedium == NdisPhysicalMediumNative802_11)
				{
					TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Wireless adapter can't set packet filter, will bypass this request, *(ULONG*)OidData->Data = %#lx, MyPacketFilter = %p",
						*(ULONG*)OidData->Data, Open->pFiltMod->MyPacketFilter);
					SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);

					//
					// Release ownership of the Ndis Handle
					//
					NPF_StopUsingBinding(Open->pFiltMod);

					ExInterlockedInsertTailList(&Open->pFiltMod->RequestList,
						&pRequest->ListElement,
						&Open->pFiltMod->RequestSpinLock);

					break;
				}

				// Store the requested packet filter for *this* Open instance
				Open->MyPacketFilter = *(ULONG*)OidData->Data;
				// Set the filter module's packet filter to the union of all instances' filters
				NdisAcquireSpinLock(&Open->pFiltMod->OpenInstancesLock);
				Open->pFiltMod->MyPacketFilter = 0;
				for (Curr = Open->pFiltMod->OpenInstances.Next; Curr != NULL; Curr = Curr->Next)
				{
					Open->pFiltMod->MyPacketFilter = Open->pFiltMod->MyPacketFilter | CONTAINING_RECORD(Curr, OPEN_INSTANCE, OpenInstancesEntry)->MyPacketFilter;
				}
				NdisReleaseSpinLock(&Open->pFiltMod->OpenInstancesLock);

                pCombinedPacketFilter = (PULONG) OidBuffer;
#ifdef HAVE_DOT11_SUPPORT
				*pCombinedPacketFilter = Open->pFiltMod->HigherPacketFilter | Open->pFiltMod->MyPacketFilter | Open->pFiltMod->Dot11PacketFilter;
#else
				*pCombinedPacketFilter = Open->pFiltMod->HigherPacketFilter | Open->pFiltMod->MyPacketFilter;
#endif
			}

			Status = NdisFOidRequest(Open->pFiltMod->AdapterHandle, &pRequest->Request);
		}
		else
		{
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open->pFiltMod);

			ExInterlockedInsertTailList(&Open->pFiltMod->RequestList,
				&pRequest->ListElement,
				&Open->pFiltMod->RequestSpinLock);

			//
			//  buffer too small
			//
			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "buffer is too small");
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		if (Status == NDIS_STATUS_PENDING)
		{
			NdisWaitEvent(&pRequest->InternalRequestCompletedEvent, 0);
			Status = pRequest->RequestStatus;
		}

		//
		// Release ownership of the Ndis Handle
		//
		NPF_StopUsingBinding(Open->pFiltMod);

		//
		// Complete the request
		//
		if (FunctionCode == BIOCSETOID)
		{
			OidData->Length = pRequest->Request.DATA.SET_INFORMATION.BytesRead;
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "BIOCSETOID completed, BytesRead = %u", OidData->Length);
		}
		else
		{
			if (FunctionCode == BIOCQUERYOID)
			{
				OidData->Length = pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten;

				if (Status == NDIS_STATUS_SUCCESS)
				{
					//
					// check for the stupid bug of the Nortel driver ipsecw2k.sys v. 4.10.0.0 that doesn't set the BytesWritten correctly
					// The driver is the one shipped with Nortel client Contivity VPN Client V04_65.18, and the MD5 for the buggy (unsigned) driver
					// is 3c2ff8886976214959db7d7ffaefe724 *ipsecw2k.sys (there are multiple copies of this binary with the same exact version info!)
					//
					// The (certified) driver shipped with Nortel client Contivity VPN Client V04_65.320 doesn't seem affected by the bug.
					//
					if (pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten > pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength)
					{
						TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Bogus return from NdisRequest (query): Bytes Written (%u) > InfoBufferLength (%u)!!", pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten, pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength);

						Status = NDIS_STATUS_INVALID_DATA;
					}
				}
				RtlCopyMemory(OidData->Data, OidBuffer, OidData->Length);

				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "BIOCQUERYOID completed, BytesWritten = %u", OidData->Length);
			}
		}


		ExInterlockedInsertTailList(&Open->pFiltMod->RequestList,
			&pRequest->ListElement,
			&Open->pFiltMod->RequestSpinLock);

		if (Status == NDIS_STATUS_SUCCESS)
		{
			SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
		}
		else
		{
			// Return the error code of NdisFOidRequest() to the application.
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Original NdisFOidRequest() Status = %#x", Status);
			SET_FAILURE_CUSTOM(Status);
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Custom NdisFOidRequest() Status = %#x", Status);
		}

		break;


	default:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Unknown IOCTL code");
		SET_FAILURE_INVALID_REQUEST();
		break;
	}

    if (OidBuffer != NULL)
    {
        ExFreePoolWithTag(OidBuffer, '0PWA');
    }


	//
	// release the Open structure
	//
	if (bAttached)
		NPF_StopUsingOpenInstance(Open);

	//
	// complete the IRP
	//
	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Status = %#x", Status);
	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

VOID
NPF_ResetBufferContents(
	IN POPEN_INSTANCE Open
	)
{
	UINT i;

	//
	// lock all the buffers
	//
	for (i = 0 ; i < g_NCpu ; i++)
	{
		NdisAcquireSpinLock(&Open->CpuData[i].BufferLock);
	}

	Open->ReaderSN = 0;
	Open->WriterSN = 0;

	//
	// reset their pointers
	//
	for (i = 0 ; i < g_NCpu ; i++)
	{
		Open->CpuData[i].C = 0;
		Open->CpuData[i].P = 0;
		Open->CpuData[i].Free = Open->Size;
		Open->CpuData[i].Accepted = 0;
		Open->CpuData[i].Dropped = 0;
		Open->CpuData[i].Received = 0;
	}

	//
	// release the locks in reverse order
	//
	i = g_NCpu;

	while (i > 0)
	{
		i--;
		NdisReleaseSpinLock(&Open->CpuData[i].BufferLock);
	}
}
