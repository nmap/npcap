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

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "win_bpf_filter_init.h"
#endif //HAVE_BUGGY_TME_SUPPORT

#include "..\..\..\Common\WpcapNames.h"

#ifdef ALLOC_PRAGMA
#pragma NDIS_INIT_FUNCTION(DriverEntry)
#endif // ALLOC_PRAGMA

#define				FILTER_UNIQUE_NAME		L"{7daf2ac8-e9f6-4765-a842-f1f5d2501340}"

#if DBG
// Declare the global debug flag for this driver.
ULONG PacketDebugFlag = PACKET_DEBUG_LOUD;

#endif

PDEVICE_EXTENSION GlobalDeviceExtension;

//
// Global strings
//
WCHAR g_NPF_PrefixBuffer[MAX_WINPCAP_KEY_CHARS] = NPF_DEVICE_NAMES_PREFIX_WIDECHAR;

POPEN_INSTANCE g_arrOpen = NULL; //Adapter open_instance list head, each list item is a group head.

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
//
// Global variables used by WFP
//
POPEN_INSTANCE g_LoopbackOpenGroupHead = NULL; // Loopback adapter open_instance group head, this pointer points to one item in g_arrOpen list.
PDEVICE_OBJECT g_LoopbackDevObj = NULL;

NDIS_STRING g_LoopbackAdapterName;
NDIS_STRING g_LoopbackRegValueName = NDIS_STRING_CONST("Loopback");

extern HANDLE g_WFPEngineHandle;
#endif

ULONG g_AdminOnlyMode = 0;

ULONG g_DltNullMode = 0;

NDIS_STRING g_NPF_Prefix;
NDIS_STRING devicePrefix = NDIS_STRING_CONST("\\Device\\");
NDIS_STRING symbolicLinkPrefix = NDIS_STRING_CONST("\\DosDevices\\");
NDIS_STRING tcpLinkageKeyName = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Services\\Tcpip\\Linkage");
NDIS_STRING AdapterListKey = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
NDIS_STRING bindValueName = NDIS_STRING_CONST("Bind");

NDIS_STRING g_AdminOnlyRegValueName = NDIS_STRING_CONST("AdminOnly");

NDIS_STRING g_DltNullRegValueName = NDIS_STRING_CONST("DltNull");

/// Global variable that points to the names of the bound adapters
WCHAR* bindP = NULL;

ULONG g_NCpu;

ULONG TimestampMode;

//
// Global variables
//
NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
NDIS_HANDLE         FilterDriverObject; // Driver object for filter driver

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
	NDIS_FILTER_DRIVER_CHARACTERISTICS FChars;
	NTSTATUS Status = STATUS_SUCCESS;

	NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(NPF_SERVICE_DESC_WIDECHAR); //display name
	NDIS_STRING UniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME); //unique name, quid name
	NDIS_STRING ServiceName = RTL_CONSTANT_STRING(NPF_DRIVER_NAME_SMALL_WIDECHAR); //this to match the service name in the INF
	WCHAR* bindT;
	PKEY_VALUE_PARTIAL_INFORMATION tcpBindingsP;
	UNICODE_STRING macName;
	ULONG OsMajorVersion, OsMinorVersion;
	UNREFERENCED_PARAMETER(RegistryPath);

	TRACE_ENTER();
	FilterDriverObject = DriverObject;

	PsGetVersion(&OsMajorVersion, &OsMinorVersion, NULL, NULL);
	TRACE_MESSAGE2(PACKET_DEBUG_INIT, "OS Version: %d.%d\n", OsMajorVersion, OsMinorVersion);

	//
	// Set timestamp gathering method getting it from the registry
	//
	ReadTimeStampModeFromRegistry(RegistryPath);
	TRACE_MESSAGE1(PACKET_DEBUG_INIT, "%ws", RegistryPath->Buffer);

	NdisInitUnicodeString(&g_NPF_Prefix, g_NPF_PrefixBuffer);

	//
	// Get number of CPUs and save it
	//
// #ifdef NDIS620
// 	g_NCpu = NdisGroupMaxProcessorCount(ALL_PROCESSOR_GROUPS);
// #else
	g_NCpu = NdisSystemProcessorCount();
/*#endif*/


	//
	// Register as a service with NDIS
	//
	NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
	FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
	FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
	FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
	FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif

	FChars.MajorNdisVersion = NDIS_FILTER_MAJOR_VERSION; //NDIS version is 6.2 (Windows 7)
	FChars.MinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
	FChars.MajorDriverVersion = 1; //Driver version is 1.0
	FChars.MinorDriverVersion = 0;
	FChars.Flags = 0;

	FChars.FriendlyName = FriendlyName;
	FChars.UniqueName = UniqueName;
	FChars.ServiceName = ServiceName;
	
	FChars.SetOptionsHandler = NPF_RegisterOptions;
	FChars.AttachHandler = NPF_AttachAdapter;
	FChars.DetachHandler = NPF_DetachAdapter;
	FChars.RestartHandler = NPF_Restart;
	FChars.PauseHandler = NPF_Pause;
	FChars.SetFilterModuleOptionsHandler = NPF_SetModuleOptions;
	FChars.OidRequestHandler = NPF_OidRequest;
	FChars.OidRequestCompleteHandler = NPF_OidRequestComplete;
	FChars.CancelOidRequestHandler = NPF_CancelOidRequest;

	FChars.SendNetBufferListsHandler = NPF_SendEx;
	FChars.ReturnNetBufferListsHandler = NPF_ReturnEx;
	FChars.SendNetBufferListsCompleteHandler = NPF_SendCompleteEx;
	FChars.ReceiveNetBufferListsHandler = NPF_TapEx;
	FChars.DevicePnPEventNotifyHandler = NPF_DevicePnPEventNotify;
	FChars.NetPnPEventHandler = NPF_NetPnPEvent;
	FChars.StatusHandler = NPF_Status;
	FChars.CancelSendNetBufferListsHandler = NPF_CancelSendNetBufferLists;

	DriverObject->DriverUnload = NPF_Unload;

	// 
	// Standard device driver entry points stuff.
	//
	DriverObject->MajorFunction[IRP_MJ_CREATE] = NPF_OpenAdapter;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = NPF_CloseAdapter;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = NPF_Cleanup; 
	DriverObject->MajorFunction[IRP_MJ_READ] = NPF_Read;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = NPF_Write;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NPF_IoControl;

	NPF_GetAdminOnlyOption(RegistryPath);

	NPF_GetDltNullOption(RegistryPath);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	NPF_GetLoopbackAdapterName(RegistryPath);
#endif

	bindP = getAdaptersList();

	if (bindP == NULL)
	{
		TRACE_MESSAGE(PACKET_DEBUG_INIT, "Adapters not found in the registry, try to copy the bindings of TCP-IP.");

		tcpBindingsP = getTcpBindings();

		if (tcpBindingsP == NULL)
		{
			TRACE_MESSAGE(PACKET_DEBUG_INIT, "TCP-IP not found, quitting.");
			goto RegistryError;
		}

		bindP = (WCHAR *)tcpBindingsP;
		bindT = (WCHAR *)(tcpBindingsP->Data);
	}
	else
	{
		bindT = bindP;
	}

	for (; *bindT != UNICODE_NULL; bindT += (macName.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR))
	{
		RtlInitUnicodeString(&macName, bindT);
		NPF_CreateDevice(DriverObject, &macName);
	}
	
	Status = NdisFRegisterFilterDriver(DriverObject,
		(NDIS_HANDLE) FilterDriverObject,
		&FChars,
		&FilterDriverHandle);
	if (Status != NDIS_STATUS_SUCCESS)
	{
		TRACE_MESSAGE(PACKET_DEBUG_INIT, "Failed to register filter with NDIS.");
		TRACE_EXIT();
		return Status;
	}

// #ifdef HAVE_WFP_LOOPBACK_SUPPORT
// 	if (DriverObject->DeviceObject)
// 	{
// 		Status = NPF_RegisterCallouts(DriverObject->DeviceObject);
// 		if (!NT_SUCCESS(Status))
// 		{
// 			if (gWFPEngineHandle != NULL)
// 			{
// 				NPF_UnregisterCallouts();
// 
// 				NdisFDeregisterFilterDriver(FilterDriverHandle);
// 			}
// 			TRACE_EXIT();
// 			return Status;
// 		}
// 	}
// #endif

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	// Use Winsock Kernel (WSK) to send loopback packets.
	Status = NPF_WSKStartup();
	if (!NT_SUCCESS(Status))
	{
		TRACE_EXIT();
		return Status;
	}

	Status = NPF_WSKInitSockets();
	if (!NT_SUCCESS(Status))
	{
		TRACE_EXIT();
		return Status;
	}
#endif

	TRACE_EXIT();
	return STATUS_SUCCESS;

RegistryError:

	Status = STATUS_UNSUCCESSFUL;
	TRACE_EXIT();
	return(Status);
}

//-------------------------------------------------------------------

PWCHAR
getAdaptersList(
	)
{
	PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;
	UINT BufPos = 0;
	UINT BufLen = 4096;

	PWCHAR DeviceNames = (PWCHAR)ExAllocatePoolWithTag(PagedPool, BufLen, '0PWA');

	TRACE_ENTER();

	if (DeviceNames == NULL)
	{
		IF_LOUD(DbgPrint("Unable the allocate the buffer for the list of the network adapters\n");)
		TRACE_EXIT();
		return NULL;
	}

	InitializeObjectAttributes(&objAttrs, &AdapterListKey, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, tcpLinkageKeyName.Buffer);)
	}
	else //OK
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		CHAR AdapInfo[1024];
		UINT i = 0;

		IF_LOUD (DbgPrint("getAdaptersList: scanning the list of the adapters in the registry, DeviceNames=%p\n", DeviceNames);)

		// Scan the list of the devices
		while((status = ZwEnumerateKey(keyHandle, i, KeyBasicInformation, AdapInfo, sizeof(AdapInfo), &resultLength)) == STATUS_SUCCESS)
		{
			WCHAR ExportKeyName[512];
			PWCHAR ExportKeyPrefix = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
			UINT ExportKeyPrefixSize = sizeof(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
			PWCHAR LinkageKeyPrefix = L"\\Linkage";
			UINT LinkageKeyPrefixSize = sizeof(L"\\Linkage");
			NDIS_STRING FinalExportKey = NDIS_STRING_CONST("Export");
			PKEY_BASIC_INFORMATION tInfo = (PKEY_BASIC_INFORMATION)AdapInfo;
			UNICODE_STRING AdapterKeyName;
			HANDLE ExportKeyHandle;

			RtlCopyMemory(ExportKeyName, ExportKeyPrefix, ExportKeyPrefixSize);

			RtlCopyMemory((PCHAR)ExportKeyName + ExportKeyPrefixSize, tInfo->Name, tInfo->NameLength + 2);

			RtlCopyMemory((PCHAR)ExportKeyName + ExportKeyPrefixSize + tInfo->NameLength, LinkageKeyPrefix, LinkageKeyPrefixSize);

			IF_LOUD(DbgPrint("Key name=%ws\n", ExportKeyName);)

			RtlInitUnicodeString(&AdapterKeyName, ExportKeyName);

			InitializeObjectAttributes(&objAttrs, &AdapterKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

			status = ZwOpenKey(&ExportKeyHandle, KEY_READ, &objAttrs);

			if (!NT_SUCCESS(status))
			{
				IF_LOUD(DbgPrint("OpenKey Failed, %d!\n", status);)
				i++;
				continue;
			}

			status = ZwQueryValueKey(ExportKeyHandle,
				&FinalExportKey,
				KeyValuePartialInformation,
				&valueInfo,
				sizeof(valueInfo),
				&resultLength);

			if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
			{
				IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
			}
			else
			{
				// We know how big it needs to be.
				ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
				PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
				if (valueInfoP != NULL)
				{
					status = ZwQueryValueKey(ExportKeyHandle,
						&FinalExportKey,
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
						IF_LOUD(DbgPrint("Device %d = %ws\n", i, valueInfoP->Data);)
						if(BufPos + valueInfoP->DataLength > BufLen)
						{
							// double the buffer size
							PWCHAR DeviceNames2 = (PWCHAR)ExAllocatePoolWithTag(PagedPool, BufLen << 1, '0PWA');
							if (DeviceNames2)
							{
								RtlCopyMemory((PCHAR)DeviceNames2, (PCHAR)DeviceNames, BufLen);
								BufLen <<= 1;
								ExFreePool(DeviceNames);
								DeviceNames = DeviceNames2;
							}
						} 
						if (BufPos + valueInfoP->DataLength < BufLen)
						{
							RtlCopyMemory((PCHAR)DeviceNames + BufPos,
								valueInfoP->Data,
								valueInfoP->DataLength);
							BufPos += valueInfoP->DataLength - 2;
						}
					}

					ExFreePool(valueInfoP);
				}
				else
				{
					IF_LOUD(DbgPrint("Error Allocating the buffer for the device name\n");)
				}
			}

			// terminate the buffer
			DeviceNames[BufPos / 2] = 0;
			DeviceNames[BufPos / 2 + 1] = 0;

			ZwClose(ExportKeyHandle);
			i++;
		}

		ZwClose(keyHandle);
	}
	if (BufPos == 0)
	{
		if (DeviceNames)
		{
			ExFreePool(DeviceNames);
		}
		TRACE_EXIT();
		return NULL;
	}
	TRACE_EXIT();
	return DeviceNames;
}

//-------------------------------------------------------------------

PKEY_VALUE_PARTIAL_INFORMATION
getTcpBindings(
	)
{
	PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	InitializeObjectAttributes(&objAttrs, &tcpLinkageKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, tcpLinkageKeyName.Buffer);)
	}
	else
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;

		IF_LOUD(DbgPrint("\n\nOpened %ws\n", tcpLinkageKeyName.Buffer);)

		status = ZwQueryValueKey(keyHandle,
		&bindValueName,
		KeyValuePartialInformation,
		&valueInfo,
		sizeof(valueInfo),
		&resultLength);

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '2PWA');

			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					&bindValueName,
					KeyValuePartialInformation,
					valueInfoP,
					valueInfoLength,
					&resultLength);

				if (!NT_SUCCESS(status))
				{
					IF_LOUD(DbgPrint("\n\nStatus of %x querying key value\n", status);)
					ExFreePool(valueInfoP);
				}
				else
				{
					if (valueInfoLength != resultLength)
					{
						IF_LOUD(DbgPrint("\n\nQuerying key value result len = %u "
						  "but previous len = %u\n", resultLength, valueInfoLength);)
						ExFreePool(valueInfoP);
					}
					else
					{
						if (valueInfoP->Type != REG_MULTI_SZ)
						{
							IF_LOUD(DbgPrint("\n\nTcpip bind value not REG_MULTI_SZ but %u\n", valueInfoP->Type);)
							ExFreePool(valueInfoP);
						}
						else
						{
							// It's OK
#if DBG
							ULONG i;
							WCHAR* dataP = (WCHAR*)(&valueInfoP->Data[0]);
							IF_LOUD (DbgPrint("\n\nBind value:\n");)for(i = 0; *dataP != UNICODE_NULL; i++)
							{
								UNICODE_STRING macName;
								RtlInitUnicodeString(&macName, dataP);
								IF_LOUD(DbgPrint("\n\nMac %u = %ws\n", i, macName.Buffer);)
								dataP += (macName.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR);
							}
#endif // DBG
							result = valueInfoP;
						}
					}
				}
			}
		}
		ZwClose(keyHandle);
	}
	return result;
}

//-------------------------------------------------------------------
VOID
NPF_GetAdminOnlyOption(
	PUNICODE_STRING RegistryPath
	)
{
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	TRACE_ENTER();

	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
	}
	else //OK
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		NDIS_STRING AdminOnlyValueName = g_AdminOnlyRegValueName;
		status = ZwQueryValueKey(keyHandle,
			&AdminOnlyValueName,
			KeyValuePartialInformation,
			&valueInfo,
			sizeof(valueInfo),
			&resultLength);

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					&AdminOnlyValueName,
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
					IF_LOUD(DbgPrint("Admin Only Key = %ws\n", valueInfoP->Data);)

					if (valueInfoP->DataLength == 4)
					{
						g_AdminOnlyMode = *((DWORD *) valueInfoP->Data);
					}
				}

				ExFreePool(valueInfoP);
			}
			else
			{
				IF_LOUD(DbgPrint("Error Allocating the buffer for the admin only option\n");)
			}
		}

		ZwClose(keyHandle);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------
VOID
NPF_GetDltNullOption(
	PUNICODE_STRING RegistryPath
	)
{
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	TRACE_ENTER();

	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
	}
	else //OK
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		NDIS_STRING DltNullValueName = g_DltNullRegValueName;
		status = ZwQueryValueKey(keyHandle,
			&DltNullValueName,
			KeyValuePartialInformation,
			&valueInfo,
			sizeof(valueInfo),
			&resultLength);

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					&DltNullValueName,
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
					IF_LOUD(DbgPrint("Dlt Null Key = %ws\n", valueInfoP->Data);)

						if (valueInfoP->DataLength == 4)
						{
							g_DltNullMode = *((DWORD *)valueInfoP->Data);
						}
				}

				ExFreePool(valueInfoP);
			}
			else
			{
				IF_LOUD(DbgPrint("Error Allocating the buffer for the admin only option\n");)
			}
		}

		ZwClose(keyHandle);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
VOID
NPF_GetLoopbackAdapterName(
	PUNICODE_STRING RegistryPath
	)
{
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;

	TRACE_ENTER();

	InitializeObjectAttributes(&objAttrs, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, RegistryPath->Buffer);)
	}
	else //OK
	{
		ULONG resultLength;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		NDIS_STRING LoopbackValueName = g_LoopbackRegValueName;
		status = ZwQueryValueKey(keyHandle,
			&LoopbackValueName,
			KeyValuePartialInformation,
			&valueInfo,
			sizeof(valueInfo),
			&resultLength);

		if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW))
		{
			IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
		}
		else
		{
			// We know how big it needs to be.
			ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
			PKEY_VALUE_PARTIAL_INFORMATION valueInfoP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
			if (valueInfoP != NULL)
			{
				status = ZwQueryValueKey(keyHandle,
					&LoopbackValueName,
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
					IF_LOUD(DbgPrint("Loopback Device Key = %ws\n", valueInfoP->Data);)

					g_LoopbackAdapterName.Length = 0;
					g_LoopbackAdapterName.MaximumLength = (USHORT)(valueInfoP->DataLength + sizeof(UNICODE_NULL));
					g_LoopbackAdapterName.Buffer = ExAllocatePoolWithTag(PagedPool, g_LoopbackAdapterName.MaximumLength, '3PWA');

					RtlCopyMemory(g_LoopbackAdapterName.Buffer, valueInfoP->Data, valueInfoP->DataLength);
				}

				ExFreePool(valueInfoP);
			}
			else
			{
				IF_LOUD(DbgPrint("Error Allocating the buffer for the device name\n");)
			}
		}

		ZwClose(keyHandle);
	}

	TRACE_EXIT();
}
#endif

//-------------------------------------------------------------------

BOOLEAN
	NPF_CreateDevice(
	IN OUT PDRIVER_OBJECT adriverObjectP,
	IN PUNICODE_STRING amacNameP
	)
{
	NTSTATUS status;
	PDEVICE_OBJECT devObjP;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceSymLink;

	TRACE_ENTER();

	IF_LOUD(DbgPrint("\n\ncreateDevice for MAC %ws\n", amacNameP->Buffer););
	if (RtlCompareMemory(amacNameP->Buffer, devicePrefix.Buffer, devicePrefix.Length) < devicePrefix.Length)
	{
		TRACE_EXIT();
		return FALSE;
	}

	deviceName.Length = 0;
	deviceName.MaximumLength = (USHORT)(amacNameP->Length + g_NPF_Prefix.Length + sizeof(UNICODE_NULL));
	deviceName.Buffer = ExAllocatePoolWithTag(PagedPool, deviceName.MaximumLength, '3PWA');

	if (deviceName.Buffer == NULL)
	{
		TRACE_EXIT();
		return FALSE;
	}

	deviceSymLink.Length = 0;
	deviceSymLink.MaximumLength = (USHORT)(amacNameP->Length - devicePrefix.Length + symbolicLinkPrefix.Length + g_NPF_Prefix.Length + sizeof(UNICODE_NULL));

	deviceSymLink.Buffer = ExAllocatePoolWithTag(NonPagedPool, deviceSymLink.MaximumLength, '3PWA');

	if (deviceSymLink.Buffer == NULL)
	{
		ExFreePool(deviceName.Buffer);
		TRACE_EXIT();
		return FALSE;
	}

	RtlAppendUnicodeStringToString(&deviceName, &devicePrefix);
	RtlAppendUnicodeStringToString(&deviceName, &g_NPF_Prefix);
	RtlAppendUnicodeToString(&deviceName, amacNameP->Buffer + devicePrefix.Length / sizeof(WCHAR));

	RtlAppendUnicodeStringToString(&deviceSymLink, &symbolicLinkPrefix);
	RtlAppendUnicodeStringToString(&deviceSymLink, &g_NPF_Prefix);
	RtlAppendUnicodeToString(&deviceSymLink, amacNameP->Buffer + devicePrefix.Length / sizeof(WCHAR));

	IF_LOUD(DbgPrint("Creating device name: %ws\n", deviceName.Buffer);)

	if (g_AdminOnlyMode != 0)
	{
		UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"); // this SDDL means only permits System and Administrator to access the device.
		const GUID guidClassNPF = { 0x26e0d1e0L, 0x8189, 0x12e0, { 0x99, 0x14, 0x08, 0x00, 0x22, 0x30, 0x19, 0x04 } };
		status = IoCreateDeviceSecure(adriverObjectP, sizeof(DEVICE_EXTENSION), &deviceName, FILE_DEVICE_TRANSPORT,
			FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, (LPCGUID)&guidClassNPF, &devObjP);
	}
	else
	{
		status = IoCreateDevice(adriverObjectP, sizeof(DEVICE_EXTENSION), &deviceName, FILE_DEVICE_TRANSPORT,
			FILE_DEVICE_SECURE_OPEN, FALSE, &devObjP);
	}

	if (NT_SUCCESS(status))
	{
		PDEVICE_EXTENSION devExtP = (PDEVICE_EXTENSION)devObjP->DeviceExtension;

		IF_LOUD(DbgPrint("Device created successfully\n"););

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		// Determine whether this is our loopback adapter for the device.
		devExtP->Loopback = FALSE;
		if (g_LoopbackAdapterName.Buffer != NULL)
		{
			if (RtlCompareMemory(g_LoopbackAdapterName.Buffer, amacNameP->Buffer, amacNameP->Length) == amacNameP->Length)
			{
				devExtP->Loopback = TRUE;
				g_LoopbackDevObj = devObjP;
			}
		}
#endif

		devObjP->Flags |= DO_DIRECT_IO;
		RtlInitUnicodeString(&devExtP->AdapterName, amacNameP->Buffer);   

		IF_LOUD(DbgPrint("Trying to create SymLink %ws\n", deviceSymLink.Buffer););

		if (IoCreateSymbolicLink(&deviceSymLink, &deviceName) != STATUS_SUCCESS)
		{
			IF_LOUD(DbgPrint("\n\nError creating SymLink %ws\nn", deviceSymLink.Buffer););

			ExFreePool(deviceName.Buffer);
			ExFreePool(deviceSymLink.Buffer);

			devExtP->ExportString = NULL;

			TRACE_EXIT();
			return FALSE;
		}

		IF_LOUD(DbgPrint("SymLink %ws successfully created.\n\n", deviceSymLink.Buffer););

		devExtP->ExportString = deviceSymLink.Buffer;

		ExFreePool(deviceName.Buffer);

		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		IF_LOUD(DbgPrint("\n\nIoCreateDevice status = %x\n", status););

		ExFreePool(deviceName.Buffer);
		ExFreePool(deviceSymLink.Buffer);

		TRACE_EXIT();
		return FALSE;
	}
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

	TRACE_ENTER();

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

	// Release WFP resources.
	NPF_FreeInjectionHandles();
	NPF_UnregisterCallouts();
#endif

	DeviceObject = DriverObject->DeviceObject;

	while (DeviceObject != NULL)
	{
		OldDeviceObject = DeviceObject;

		DeviceObject = DeviceObject->NextDevice;

		DeviceExtension = OldDeviceObject->DeviceExtension;

		TRACE_MESSAGE4(PACKET_DEBUG_LOUD, "Deleting Adapter %ws, Protocol Handle=%p, Device Obj=%p (%p)", DeviceExtension->AdapterName.Buffer, FilterDriverHandle, DeviceObject, OldDeviceObject);

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

	NdisFDeregisterFilterDriver(FilterDriverHandle);

	NPF_RemoveUnclosedAdapters();

	// Free the adapters names
	if (bindP != NULL)
	{
		ExFreePool(bindP);
		bindP = NULL;
	}

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

//-------------------------------------------------------------------

NTSTATUS
NPF_IoControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	POPEN_INSTANCE			Open;
	PIO_STACK_LOCATION		IrpSp;
	PLIST_ENTRY				RequestListEntry;
	PINTERNAL_REQUEST		pRequest;
	ULONG					FunctionCode;
	NDIS_STATUS				Status;
	ULONG					Information = 0;
	PLIST_ENTRY				PacketListEntry;
	UINT					i;
	PUCHAR					tpointer = NULL; //assign NULL to suppress error C4703: potentially uninitialized local pointer variable
	ULONG					dim, timeout;
	struct bpf_insn*		NewBpfProgram;
	PPACKET_OID_DATA		OidData;
	int*					StatsBuf;
	ULONG					mode;
	PWSTR					DumpNameBuff;
	PUCHAR					TmpBPFProgram;
	INT						WriteRes;
	BOOLEAN					SyncWrite = FALSE;
	struct bpf_insn*		initprogram;
	ULONG					insns;
	ULONG					cnt;
	BOOLEAN					IsExtendedFilter = FALSE;
	ULONG					StringLength;
	ULONG					NeededBytes;
	BOOLEAN					Flag;
	PUINT					pStats;
	ULONG					StatsLength;
	ULONG					combinedPacketFilter;

	HANDLE					hUserEvent;
	PKEVENT					pKernelEvent;
#ifdef _AMD64_
	VOID* POINTER_32		hUserEvent32Bit;
#endif //_AMD64_
	PMDL					mdl;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
	Open = IrpSp->FileObject->FsContext;

	if (NPF_StartUsingOpenInstance(Open) == FALSE)
	{
		// 
		// an IRP_MJ_CLEANUP was received, just fail the request
		//
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_CANCELLED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		TRACE_EXIT();
		return STATUS_CANCELLED;
	}

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

		if (Irp->UserBuffer == NULL)
		{
			SET_FAILURE_UNSUCCESSFUL();
			break;
		}

		//
		// temp fix to a GIANT bug from LD. The CTL code has been defined as METHOD_NEITHER, so it
		// might well be a dangling pointer. We need to probe and lock the address.
		//

		mdl = NULL;
		pStats = NULL;

		__try
		{
			mdl = IoAllocateMdl(Irp->UserBuffer, StatsLength, FALSE, TRUE, NULL);

			if (mdl == NULL)
			{
				SET_FAILURE_UNSUCCESSFUL();
				break;
			}

			MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);

			pStats = (PUINT)(Irp->UserBuffer);
		}
		__except(GetExceptionCode() == STATUS_ACCESS_VIOLATION)
		{
			pStats = NULL;
		}

		if (pStats == NULL)
		{
			if (mdl != NULL)
			{
				IoFreeMdl(mdl);
			}

			SET_FAILURE_UNSUCCESSFUL();
			break;
		}

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

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

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

	case BIOCSENDPACKETSSYNC:
		SyncWrite = TRUE;

	case BIOCSENDPACKETSNOSYNC:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSENDPACKETSNOSYNC");

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

		if (WriteRes != -1)
		{
			SET_RESULT_SUCCESS(WriteRes);
		}
		else
		{
			SET_FAILURE_UNSUCCESSFUL();
		}
		break;

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

#ifdef HAVE_BUGGY_TME_SUPPORT
			if ((cnt != insns) && (insns != cnt + 1) && (NewBpfProgram[cnt].code == BPF_SEPARATION))
			{
				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Initialization instructions = %u", insns - cnt - 1);

				IsExtendedFilter = TRUE;

				initprogram = &NewBpfProgram[cnt + 1];

				if (bpf_filter_init(initprogram, &(Open->mem_ex), &(Open->tme), &G_Start_Time) != INIT_OK)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error initializing NPF machine (bpf_filter_init)");

					SET_FAILURE_INVALID_REQUEST();
					break;
				}
			}
#else  // HAVE_BUGGY_TME_SUPPORT
			if (cnt != insns)
			{
				TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error installing the BPF filter. The filter contains TME extensions,"
					" not supported on 64bit platforms.");

				SET_FAILURE_INVALID_REQUEST();
				break;
			}
#endif // HAVE_BUGGY_TME_SUPPORT

			//the NPF processor has been initialized, we have to validate the operative instructions
			insns = cnt;

			//NOTE: the validation code checks for TME instructions, and fails if a TME instruction is
			//encountered on 64 bit machines
#ifdef HAVE_BUGGY_TME_SUPPORT
			if (bpf_validate(NewBpfProgram, cnt, Open->mem_ex.size) == 0)
#else //HAVE_BUGGY_TME_SUPPORT
				if (bpf_validate(NewBpfProgram, cnt) == 0)
#endif //HAVE_BUGGY_TME_SUPPORT
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error validating program");
					//FIXME: the machine has been initialized(?), but the operative code is wrong. 
					//we have to reset the machine!
					//something like: reallocate the mem_ex, and reset the tme_core
					SET_FAILURE_INVALID_REQUEST();
					break;
				}

			// Allocate the memory to contain the new filter program
			// We could need the original BPF binary if we are forced to use bpf_filter_with_2_buffers()
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

#ifdef HAVE_BUGGY_TME_SUPPORT
			Open->mode = MODE_MON;
			SET_RESULT_SUCCESS(0);
#else // HAVE_BUGGY_TME_SUPPORT
			SET_FAILURE_INVALID_REQUEST();
#endif // HAVE_BUGGY_TME_SUPPORT

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
		SET_FAILURE_INVALID_REQUEST();
		break;
		///////kernel dump does not work at the moment//////////////////////////////////////////

		//if(Open->mode & MODE_DUMP)
		//{
		//	
		//	// Close current dump file
		//	if(Open->DumpFileHandle != NULL)
		//	{
		//		NPF_CloseDumpFile(Open);
		//		Open->DumpFileHandle = NULL;
		//	}
		//	
		//	if(IrpSp->Parameters.DeviceIoControl.InputBufferLength == 0){
		//		EXIT_FAILURE(0);
		//	}
		//	
		//	// Allocate the buffer that will contain the string
		//	DumpNameBuff=ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.InputBufferLength, '5PWA');
		//	if(DumpNameBuff==NULL || Open->DumpFileName.Buffer!=NULL){
		//		IF_LOUD(DbgPrint("NPF: unable to allocate the dump filename: not enough memory or name already set\n");)
		//			EXIT_FAILURE(0);
		//	}
		//	
		//	// Copy the buffer
		//	RtlCopyBytes((PVOID)DumpNameBuff, 
		//		Irp->AssociatedIrp.SystemBuffer, 
		//		IrpSp->Parameters.DeviceIoControl.InputBufferLength);
		//	
		//	// Force a \0 at the end of the filename to avoid that malformed strings cause RtlInitUnicodeString to crash the system 
		//	((PSHORT)DumpNameBuff)[IrpSp->Parameters.DeviceIoControl.InputBufferLength/2-1]=0;
		//	
		//	// Create the unicode string
		//	RtlInitUnicodeString(&Open->DumpFileName, DumpNameBuff);
		//	
		//	IF_LOUD(DbgPrint("NPF: dump file name set to %ws, len=%d\n",
		//		Open->DumpFileName.Buffer,
		//		IrpSp->Parameters.DeviceIoControl.InputBufferLength);)
		//		
		//	// Try to create the file
		//	if ( NT_SUCCESS( NPF_OpenDumpFile(Open,&Open->DumpFileName,FALSE)) &&
		//		NT_SUCCESS( NPF_StartDump(Open)))
		//	{
		//		EXIT_SUCCESS(0);
		//	}
		//}
		//
		//EXIT_FAILURE(0);
		//
		//break;

	case BIOCSETDUMPLIMITS:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETDUMPLIMITS");

		///////kernel dump does not work at the moment//////////////////////////////////////////
		SET_FAILURE_INVALID_REQUEST();
		break;
		///////kernel dump does not work at the moment//////////////////////////////////////////

		//if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < 2*sizeof(ULONG))
		//{
		//	EXIT_FAILURE(0);
		//}
		//
		//Open->MaxDumpBytes = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
		//Open->MaxDumpPacks = *((PULONG)Irp->AssociatedIrp.SystemBuffer + 1);
		//
		//IF_LOUD(DbgPrint("NPF: Set dump limits to %u bytes, %u packs\n", Open->MaxDumpBytes, Open->MaxDumpPacks);)
		//
		//EXIT_SUCCESS(0);
		//
		//break;

	case BIOCISDUMPENDED:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCISDUMPENDED");

		///////kernel dump does not work at the moment//////////////////////////////////////////
		SET_FAILURE_INVALID_REQUEST();
		break;
		///////kernel dump does not work at the moment//////////////////////////////////////////

		//if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT))
		//{			
		//	EXIT_FAILURE(0);
		//}

		//*((UINT*)Irp->UserBuffer) = (Open->DumpLimitReached)?1:0;

		//EXIT_SUCCESS(4);

		//break;

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
#pragma prefast(suppress:8103, "There's no Spinlock leak here, as it's released some lines below.")
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

		do
		{
			i --;

#pragma prefast(suppress:8107, "There's no Spinlock leak here, as it's acquired some lines above.")
			NdisReleaseSpinLock(&Open->CpuData[i].BufferLock);
		}
		while (i != 0);

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

	case BIOCQUERYOID:
	case BIOCSETOID:
		
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETOID - BIOCQUERYOID");

		//
		// gain ownership of the Ndis Handle
		//
		if (NPF_StartUsingBinding(Open) == FALSE)
		{
			//
			// MAC unbindind or unbound
			//
			SET_FAILURE_INVALID_REQUEST();
			break;
		}


		// Extract a request from the list of free ones
		RequestListEntry = ExInterlockedRemoveHeadList(&Open->RequestList, &Open->RequestSpinLock);
		if (RequestListEntry == NULL)
		{
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open);

			SET_FAILURE_NOMEM();
			break;
		}

		pRequest = CONTAINING_RECORD(RequestListEntry, INTERNAL_REQUEST, ListElement);

		//
		//  See if it is an Ndis request
		//
		OidData = Irp->AssociatedIrp.SystemBuffer;

		if ((IrpSp->Parameters.DeviceIoControl.InputBufferLength == IrpSp->Parameters.DeviceIoControl.OutputBufferLength) &&
			(IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA)) &&
			(IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA) - 1 + OidData->Length))
		{
			TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "BIOCSETOID|BIOCQUERYOID Request: Oid=%08lx, Length=%08lx", OidData->Oid, OidData->Length);

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
			if (Open->Loopback && (OidData->Oid == OID_GEN_MAXIMUM_TOTAL_SIZE || OidData->Oid == OID_GEN_TRANSMIT_BUFFER_SPACE || OidData->Oid == OID_GEN_RECEIVE_BUFFER_SPACE))
			{
				if (FunctionCode == BIOCSETOID)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_MAXIMUM_TOTAL_SIZE & BIOCSETOID, fail it");
					SET_FAILURE_UNSUCCESSFUL();
				}
				else
				{
					TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_MAXIMUM_TOTAL_SIZE & BIOCGETOID, OidData->Data = %d", NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN);
					*((PUINT)OidData->Data) = NPF_LOOPBACK_INTERFACR_MTU + ETHER_HDR_LEN;
					SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
				}

				//
				// Release ownership of the Ndis Handle
				//
				NPF_StopUsingBinding(Open);

				ExInterlockedInsertTailList(&Open->RequestList,
					&pRequest->ListElement,
					&Open->RequestSpinLock);

				break;
			}
			else if (Open->Loopback && (OidData->Oid == OID_GEN_TRANSMIT_BLOCK_SIZE || OidData->Oid == OID_GEN_RECEIVE_BLOCK_SIZE))
			{
				if (FunctionCode == BIOCSETOID)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_TRANSMIT_BLOCK_SIZE & BIOCSETOID, fail it");
					SET_FAILURE_UNSUCCESSFUL();
				}
				else
				{
					TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_TRANSMIT_BLOCK_SIZE & BIOCGETOID, OidData->Data = %d", 1);
					*((PUINT)OidData->Data) = 1;
					SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
				}

				//
				// Release ownership of the Ndis Handle
				//
				NPF_StopUsingBinding(Open);

				ExInterlockedInsertTailList(&Open->RequestList,
					&pRequest->ListElement,
					&Open->RequestSpinLock);

				break;
			}
			else if (Open->Loopback && (OidData->Oid == OID_GEN_MEDIA_IN_USE || OidData->Oid == OID_GEN_MEDIA_SUPPORTED))
			{
				if (FunctionCode == BIOCSETOID)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_MEDIA_IN_USE & BIOCSETOID, fail it");
					SET_FAILURE_UNSUCCESSFUL();
				}
				else
				{
					TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Loopback: OID_GEN_MEDIA_IN_USE & BIOCGETOID, OidData->Data = %d", NdisMediumNull);
					*((PUINT)OidData->Data) = NdisMediumNull;
					OidData->Length = sizeof(UINT);
					SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
				}

				//
				// Release ownership of the Ndis Handle
				//
				NPF_StopUsingBinding(Open);

				ExInterlockedInsertTailList(&Open->RequestList,
					&pRequest->ListElement,
					&Open->RequestSpinLock);

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

			if (FunctionCode == BIOCSETOID)
			{
				pRequest->Request.RequestType = NdisRequestSetInformation;
				pRequest->Request.DATA.SET_INFORMATION.Oid = OidData->Oid;

				pRequest->Request.DATA.SET_INFORMATION.InformationBuffer = OidData->Data;
				pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength = OidData->Length;
			}
			else
			{
				pRequest->Request.RequestType = NdisRequestQueryInformation;
				pRequest->Request.DATA.QUERY_INFORMATION.Oid = OidData->Oid;

				pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer = OidData->Data;
				pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength = OidData->Length;
			}

			NdisResetEvent(&pRequest->InternalRequestCompletedEvent);

			if (*((PVOID *) pRequest->Request.SourceReserved) != NULL)
			{
				*((PVOID *) pRequest->Request.SourceReserved) = NULL;
			}

			//
			//  submit the request
			//
			pRequest->Request.RequestId = (PVOID) NPF_REQUEST_ID;
			// ASSERT(Open->AdapterHandle != NULL);

			if (OidData->Oid == OID_GEN_CURRENT_PACKET_FILTER && FunctionCode == BIOCSETOID)
			{
				// ASSERT(Open->GroupHead != NULL);
				if (Open->GroupHead)
				{
					Open->GroupHead->MyPacketFilter = *(ULONG*)OidData->Data;
					if (Open->GroupHead->MyPacketFilter == NDIS_PACKET_TYPE_ALL_LOCAL)
					{
						Open->GroupHead->MyPacketFilter = 0;
					}
					combinedPacketFilter = Open->GroupHead->HigherPacketFilter | Open->GroupHead->MyPacketFilter;
					pRequest->Request.DATA.SET_INFORMATION.InformationBuffer = &combinedPacketFilter;
				}
				else
				{
					//
					// Release ownership of the Ndis Handle
					//
					NPF_StopUsingBinding(Open);

					ExInterlockedInsertTailList(&Open->RequestList,
						&pRequest->ListElement,
						&Open->RequestSpinLock);

					SET_FAILURE_NOMEM();
					break;
				}
			}

			Status = NdisFOidRequest(Open->AdapterHandle, &pRequest->Request);
		}
		else
		{
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open);

			ExInterlockedInsertTailList(&Open->RequestList,
				&pRequest->ListElement,
				&Open->RequestSpinLock);

			//
			//  buffer too small
			//
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		if (Status == NDIS_STATUS_PENDING)
		{
			NdisWaitEvent(&pRequest->InternalRequestCompletedEvent, 1000);
			Status = pRequest->RequestStatus;
		}

		//
		// Release ownership of the Ndis Handle
		//
		NPF_StopUsingBinding(Open);

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

				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "BIOCQUERYOID completed, BytesWritten = %u", OidData->Length);
			}
		}


		ExInterlockedInsertTailList(&Open->RequestList,
			&pRequest->ListElement,
			&Open->RequestSpinLock);

		if (Status == NDIS_STATUS_SUCCESS)
		{
			SET_RESULT_SUCCESS(sizeof(PACKET_OID_DATA) - 1 + OidData->Length);
		}
		else
		{
			SET_FAILURE_INVALID_REQUEST();
		}

		break;


	default:
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Unknown IOCTL code");
		SET_FAILURE_INVALID_REQUEST();
		break;
	}


	//
	// release the Open structure
	//
	NPF_StopUsingOpenInstance(Open);

	//
	// complete the IRP
	//
	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);


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
		//#pragma prefast(suppress:8103, "There's no Spinlock leak here, as it's released some lines below.")
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

	do
	{
		i--;
#pragma prefast(suppress:8107, "There's no Spinlock leak here, as it's allocated some lines above.")
		NdisReleaseSpinLock(&Open->CpuData[i].BufferLock);
	}
	while (i != 0);
}