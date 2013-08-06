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
#include "win_bpf.h"
#include "ioctls.h"

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "win_bpf_filter_init.h"
#endif //HAVE_BUGGY_TME_SUPPORT

#include "..\..\Common\WpcapNames.h"


#if DBG
// Declare the global debug flag for this driver.
ULONG PacketDebugFlag = PACKET_DEBUG_LOUD;

#endif

PDEVICE_EXTENSION GlobalDeviceExtension;

//
// Global strings
//
WCHAR g_NPF_PrefixBuffer[MAX_WINPCAP_KEY_CHARS] = NPF_DEVICE_NAMES_PREFIX_WIDECHAR;
//  
//	Old registry based WinPcap names
//
//WCHAR g_NPF_PrefixBuffer[MAX_WINPCAP_KEY_CHARS];
NDIS_STRING g_NPF_Prefix;
NDIS_STRING devicePrefix = NDIS_STRING_CONST("\\Device\\");
NDIS_STRING symbolicLinkPrefix = NDIS_STRING_CONST("\\DosDevices\\");
NDIS_STRING tcpLinkageKeyName = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Services\\Tcpip\\Linkage");
NDIS_STRING AdapterListKey = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
NDIS_STRING bindValueName = NDIS_STRING_CONST("Bind");
NDIS_STRING g_WinpcapGlobalKey = NDIS_STRING_CONST("\\Registry\\Machine\\" WINPCAP_INSTANCE_KEY_WIDECHAR);
//NDIS_STRING g_WinpcapGlobalKey = NDIS_STRING_CONST("\\Registry\\Machine\\" WINPCAP_GLOBAL_KEY_WIDECHAR);

/// Global variable that points to the names of the bound adapters
WCHAR* bindP = NULL;

NDIS_HANDLE	g_NdisProtocolHandle = NULL;

ULONG g_NCpu;

ULONG TimestampMode;
UINT g_SendPacketFlags = 0;

static VOID NPF_ResetBufferContents(POPEN_INSTANCE Open);

//
//  Packet Driver's entry routine.
//
NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    NDIS_PROTOCOL_CHARACTERISTICS  ProtocolChar;
    UNICODE_STRING MacDriverName;
    UNICODE_STRING UnicodeDeviceName;
    PDEVICE_OBJECT DeviceObject = NULL;
    PDEVICE_EXTENSION DeviceExtension = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS ErrorCode = STATUS_SUCCESS;
    NDIS_STRING ProtoName = NDIS_STRING_CONST("PacketDriver");
    ULONG          DevicesCreated=0;
    PWSTR          BindString;
    PWSTR          ExportString;
    PWSTR          BindStringSave;
    PWSTR          ExportStringSave;
	WCHAR* bindT;
	PKEY_VALUE_PARTIAL_INFORMATION tcpBindingsP;
	UNICODE_STRING macName;
//  
//	Old registry based WinPcap names
//
//	UINT RegStrLen;
	ULONG			OsMajorVersion, OsMinorVersion;
	
	TRACE_ENTER();

#ifndef __NPF_NT4__

   TRACE_MESSAGE(PACKET_DEBUG_INIT, "DriverEntry -- NT4");

	//
	// Get OS version and store it in a global variable. 
	// For the moment we use the deprecated PsGetVersion() because the suggested
	// RtlGetVersion() doesn't seem to exist in Windows 2000, and we don't want
	// to have two separated drivers just for this call.
	// Morever, the NT4 version of the driver just excludes this, since those flags 
	// are not available.
	//
	// Note: both RtlGetVersion() and PsGetVersion() are documented to always return success.
	//
	//	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	//	RtlGetVersion(&OsVersion);
	PsGetVersion(&OsMajorVersion, &OsMinorVersion, NULL, NULL);
	TRACE_MESSAGE2(PACKET_DEBUG_INIT, "OS Version: %d.%d\n", OsMajorVersion, OsMinorVersion);

	//
	// Define the correct flag to skip the loopback packets, according to the OS
	//
	if((OsMajorVersion == 5) && (OsMinorVersion == 0))
	{
		// Windows 2000 wants both NDIS_FLAGS_DONT_LOOPBACK and NDIS_FLAGS_SKIP_LOOPBACK
		g_SendPacketFlags = NDIS_FLAGS_DONT_LOOPBACK | NDIS_FLAGS_SKIP_LOOPBACK_W2K;
	}
	else
	{
		// Windows XP, 2003 and follwing want only  NDIS_FLAGS_DONT_LOOPBACK
		g_SendPacketFlags =  NDIS_FLAGS_DONT_LOOPBACK;
	}
#endif //__NPF_NT4__

	//
	// Set timestamp gathering method getting it from the registry
	//
	ReadTimeStampModeFromRegistry(RegistryPath);

	TRACE_MESSAGE1(PACKET_DEBUG_INIT,"%ws",RegistryPath->Buffer);

//  
//	Old registry based WinPcap names
//
//	//
//	// Get the device names prefix from the registry
//	//
//	RegStrLen = sizeof(g_NPF_PrefixBuffer) / sizeof(g_NPF_PrefixBuffer[0]);
//
//	NPF_QueryWinpcapRegistryString(NPF_DEVICES_PREFIX_REG_KEY_WC,
//		g_NPF_PrefixBuffer,
//		RegStrLen,
//		NPF_DEVICE_NAMES_PREFIX_WIDECHAR);
//
	NdisInitUnicodeString(&g_NPF_Prefix, g_NPF_PrefixBuffer);


	//
	// Get number of CPUs and save it
	//
	g_NCpu = NdisSystemProcessorCount();

	RtlZeroMemory(&ProtocolChar,sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

	//
	// Register as a protocol with NDIS
	//
#ifdef NDIS50
    ProtocolChar.MajorNdisVersion            = 5;
#else
    ProtocolChar.MajorNdisVersion            = 3;
#endif
    ProtocolChar.MinorNdisVersion            = 0;
    ProtocolChar.Reserved                    = 0;
    ProtocolChar.OpenAdapterCompleteHandler  = NPF_OpenAdapterComplete;
    ProtocolChar.CloseAdapterCompleteHandler = NPF_CloseAdapterComplete;
    ProtocolChar.SendCompleteHandler         = NPF_SendComplete;
    ProtocolChar.TransferDataCompleteHandler = NPF_TransferDataComplete;
    ProtocolChar.ResetCompleteHandler        = NPF_ResetComplete;
    ProtocolChar.RequestCompleteHandler      = NPF_RequestComplete;
    ProtocolChar.ReceiveHandler              = NPF_tap;
    ProtocolChar.ReceiveCompleteHandler      = NPF_ReceiveComplete;
    ProtocolChar.StatusHandler               = NPF_Status;
    ProtocolChar.StatusCompleteHandler       = NPF_StatusComplete;
#ifdef NDIS50
    ProtocolChar.BindAdapterHandler          = NPF_BindAdapter;
    ProtocolChar.UnbindAdapterHandler        = NPF_UnbindAdapter;
    ProtocolChar.PnPEventHandler             = NPF_PowerChange;
    ProtocolChar.ReceivePacketHandler        = NULL;
#endif
    ProtocolChar.Name                        = ProtoName;

    NdisRegisterProtocol(
        &Status,
        &g_NdisProtocolHandle,
        &ProtocolChar,
        sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

	if (Status != NDIS_STATUS_SUCCESS) {

		TRACE_MESSAGE(PACKET_DEBUG_INIT,"Failed to register protocol with NDIS");

		TRACE_EXIT();
		return Status;

	}
	
    // 
	// Standard device driver entry points stuff.
	//
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NPF_Open;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = NPF_Close;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP]= NPF_Cleanup; 
    DriverObject->MajorFunction[IRP_MJ_READ]   = NPF_Read;
    DriverObject->MajorFunction[IRP_MJ_WRITE]  = NPF_Write;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = NPF_IoControl;
    DriverObject->DriverUnload = NPF_Unload;

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
			
		bindP = (WCHAR*)tcpBindingsP;
		bindT = (WCHAR*)(tcpBindingsP->Data);
			
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

	TRACE_EXIT();
	return STATUS_SUCCESS;

RegistryError:

    NdisDeregisterProtocol(
        &Status,
        g_NdisProtocolHandle
        );

    Status=STATUS_UNSUCCESSFUL;

	TRACE_EXIT();
    return(Status);
}

//-------------------------------------------------------------------

PWCHAR getAdaptersList(void)
{
	PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;
	UINT BufPos=0;
	UINT BufLen=4096;

	
	PWCHAR DeviceNames = (PWCHAR) ExAllocatePoolWithTag(PagedPool, BufLen, '0PWA');
	
	if (DeviceNames == NULL) {
		IF_LOUD(DbgPrint("Unable the allocate the buffer for the list of the network adapters\n");)
			return NULL;
	}
	
	InitializeObjectAttributes(&objAttrs, &AdapterListKey,
		OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status)) {
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, tcpLinkageKeyName.Buffer);)
	}
	else { //OK
		
		ULONG resultLength;
	    KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		CHAR AdapInfo[1024];
		UINT i=0;
		
		IF_LOUD(DbgPrint("getAdaptersList: scanning the list of the adapters in the registry, DeviceNames=%p\n",DeviceNames);)
			
			// Scan the list of the devices
			while((status=ZwEnumerateKey(keyHandle,i,KeyBasicInformation,AdapInfo,sizeof(AdapInfo),&resultLength))==STATUS_SUCCESS)
			{
				WCHAR ExportKeyName [512];
				PWCHAR ExportKeyPrefix = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
				UINT ExportKeyPrefixSize = sizeof(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
				PWCHAR LinkageKeyPrefix = L"\\Linkage";
				UINT LinkageKeyPrefixSize = sizeof(L"\\Linkage");
				NDIS_STRING FinalExportKey = NDIS_STRING_CONST("Export");
				PKEY_BASIC_INFORMATION tInfo= (PKEY_BASIC_INFORMATION)AdapInfo;
				UNICODE_STRING AdapterKeyName;
				HANDLE ExportKeyHandle;
				
				RtlCopyMemory(ExportKeyName,
					ExportKeyPrefix,
					ExportKeyPrefixSize);
				
				RtlCopyMemory((PCHAR)ExportKeyName+ExportKeyPrefixSize,
					tInfo->Name,
					tInfo->NameLength+2);
				
				RtlCopyMemory((PCHAR)ExportKeyName+ExportKeyPrefixSize+tInfo->NameLength,
					LinkageKeyPrefix,
					LinkageKeyPrefixSize);
				
				IF_LOUD(DbgPrint("Key name=%ws\n", ExportKeyName);)
										
				RtlInitUnicodeString(&AdapterKeyName, ExportKeyName);
				
				InitializeObjectAttributes(&objAttrs, &AdapterKeyName,
					OBJ_CASE_INSENSITIVE, NULL, NULL);
				
				status=ZwOpenKey(&ExportKeyHandle,KEY_READ,&objAttrs);
				
				if (!NT_SUCCESS(status)) {
					IF_LOUD(DbgPrint("OpenKey Failed, %d!\n",status);)
					i++;
					continue;
				}
				
				status = ZwQueryValueKey(ExportKeyHandle, &FinalExportKey,
					KeyValuePartialInformation, &valueInfo,
					sizeof(valueInfo), &resultLength);
				
				if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW)) {
					IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
				}
				else {                      // We know how big it needs to be.
					ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
					PKEY_VALUE_PARTIAL_INFORMATION valueInfoP =	(PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
					if (valueInfoP != NULL) {
						status = ZwQueryValueKey(ExportKeyHandle, &FinalExportKey,
							KeyValuePartialInformation,
							valueInfoP,
							valueInfoLength, &resultLength);
						if (!NT_SUCCESS(status)) {
							IF_LOUD(DbgPrint("Status of %x querying key value\n", status);)
						}
						else{
							IF_LOUD(DbgPrint("Device %d = %ws\n", i, valueInfoP->Data);)
								if( BufPos + valueInfoP->DataLength > BufLen ) {
									// double the buffer size
									PWCHAR DeviceNames2 = (PWCHAR) ExAllocatePoolWithTag(PagedPool, BufLen
										<< 1, '0PWA');
									if( DeviceNames2 ) {
										RtlCopyMemory((PCHAR)DeviceNames2, (PCHAR)DeviceNames, BufLen);
										BufLen <<= 1;
										ExFreePool(DeviceNames);
										DeviceNames = DeviceNames2;
									}
								} 
								if( BufPos + valueInfoP->DataLength < BufLen ) {
									RtlCopyMemory((PCHAR)DeviceNames+BufPos,
										valueInfoP->Data,
										valueInfoP->DataLength);
									BufPos+=valueInfoP->DataLength-2;
								}
						}
						
						ExFreePool(valueInfoP);
					}
					else {
						IF_LOUD(DbgPrint("Error Allocating the buffer for the device name\n");)
					}
					
				}
				
				// terminate the buffer
				DeviceNames[BufPos/2]=0;
				DeviceNames[BufPos/2+1]=0;
				
				ZwClose (ExportKeyHandle);
				i++;
				
			}
			
			ZwClose (keyHandle);
			
	}
	if(BufPos==0){
		ExFreePool(DeviceNames);
		return NULL;
	}
	return DeviceNames;
}

//-------------------------------------------------------------------

PKEY_VALUE_PARTIAL_INFORMATION getTcpBindings(void)
{
  PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
  OBJECT_ATTRIBUTES objAttrs;
  NTSTATUS status;
  HANDLE keyHandle;

  InitializeObjectAttributes(&objAttrs, &tcpLinkageKeyName,
	  OBJ_CASE_INSENSITIVE, NULL, NULL);
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

		  status = ZwQueryValueKey(keyHandle, &bindValueName,
		  KeyValuePartialInformation, &valueInfo,
		  sizeof(valueInfo), &resultLength);
	  if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW)) 
	  {
		  IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
	  }
	  else 
	  {                      // We know how big it needs to be.
		  ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
		  PKEY_VALUE_PARTIAL_INFORMATION valueInfoP =
			  (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '2PWA');

		  if (valueInfoP != NULL) 
		  {
			  status = ZwQueryValueKey(keyHandle, &bindValueName,
				  KeyValuePartialInformation,
				  valueInfoP,
				  valueInfoLength, &resultLength);

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
						  "but previous len = %u\n",
						  resultLength, valueInfoLength);)
					  ExFreePool(valueInfoP);
				  }
				  else 
				  {
					  if (valueInfoP->Type != REG_MULTI_SZ) 
					  {
						  IF_LOUD(DbgPrint("\n\nTcpip bind value not REG_MULTI_SZ but %u\n",
							  valueInfoP->Type);)
							  ExFreePool(valueInfoP);
					  }
					  else 
					  {                  // It's OK
#if DBG
						  ULONG i;
						  WCHAR* dataP = (WCHAR*)(&valueInfoP->Data[0]);
						  IF_LOUD(DbgPrint("\n\nBind value:\n");)
							  for (i = 0; *dataP != UNICODE_NULL; i++) {
								  UNICODE_STRING macName;
								  RtlInitUnicodeString(&macName, dataP);
								  IF_LOUD(DbgPrint("\n\nMac %u = %ws\n", i, macName.Buffer);)
									  dataP +=
									  (macName.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR);
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

BOOLEAN NPF_CreateDevice(IN OUT PDRIVER_OBJECT adriverObjectP,
					 IN PUNICODE_STRING amacNameP)
{
	NTSTATUS status;
	PDEVICE_OBJECT devObjP;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceSymLink;

	IF_LOUD(DbgPrint("\n\ncreateDevice for MAC %ws\n", amacNameP->Buffer););
	if (RtlCompareMemory(amacNameP->Buffer, devicePrefix.Buffer,
		devicePrefix.Length) < devicePrefix.Length) 
	{
		return FALSE;
	}

	deviceName.Length = 0;
	deviceName.MaximumLength = (USHORT)(amacNameP->Length + g_NPF_Prefix.Length + sizeof(UNICODE_NULL));
	deviceName.Buffer = ExAllocatePoolWithTag(PagedPool, deviceName.MaximumLength, '3PWA');

	if (deviceName.Buffer == NULL)
		return FALSE;

	deviceSymLink.Length = 0;
	deviceSymLink.MaximumLength =(USHORT)(amacNameP->Length-devicePrefix.Length 
		+ symbolicLinkPrefix.Length 
		+ g_NPF_Prefix.Length 
		+ sizeof(UNICODE_NULL));

	deviceSymLink.Buffer = ExAllocatePoolWithTag(NonPagedPool, deviceSymLink.MaximumLength, '3PWA');

	if (deviceSymLink.Buffer  == NULL)
	{
		ExFreePool(deviceName.Buffer);
		return FALSE;
	}

	RtlAppendUnicodeStringToString(&deviceName, &devicePrefix);
	RtlAppendUnicodeStringToString(&deviceName, &g_NPF_Prefix);
	RtlAppendUnicodeToString(&deviceName, amacNameP->Buffer +
		devicePrefix.Length / sizeof(WCHAR));

	RtlAppendUnicodeStringToString(&deviceSymLink, &symbolicLinkPrefix);
	RtlAppendUnicodeStringToString(&deviceSymLink, &g_NPF_Prefix);
	RtlAppendUnicodeToString(&deviceSymLink, amacNameP->Buffer +
		devicePrefix.Length / sizeof(WCHAR));

	IF_LOUD(DbgPrint("Creating device name: %ws\n", deviceName.Buffer);)

		status = IoCreateDevice(adriverObjectP, 
		sizeof(DEVICE_EXTENSION),
		&deviceName, 
		FILE_DEVICE_TRANSPORT, 
#ifdef __NPF_NT4__
		0, 
#else //__NPF_NT4__
		FILE_DEVICE_SECURE_OPEN,	
#endif //__NPF_NT4__
		FALSE,
		&devObjP);

	if (NT_SUCCESS(status)) 
	{
		PDEVICE_EXTENSION devExtP = (PDEVICE_EXTENSION)devObjP->DeviceExtension;
		
		IF_LOUD(DbgPrint("Device created successfully\n"););

		devObjP->Flags |= DO_DIRECT_IO;
		RtlInitUnicodeString(&devExtP->AdapterName,amacNameP->Buffer);   

		IF_LOUD(DbgPrint("Trying to create SymLink %ws\n",deviceSymLink.Buffer););

		if (IoCreateSymbolicLink(&deviceSymLink,&deviceName) != STATUS_SUCCESS)
		{
			IF_LOUD(DbgPrint("\n\nError creating SymLink %ws\nn", deviceSymLink.Buffer););

			ExFreePool(deviceName.Buffer);
			ExFreePool(deviceSymLink.Buffer);

			devExtP->ExportString = NULL;

			return FALSE;
		}

		IF_LOUD(DbgPrint("SymLink %ws successfully created.\n\n", deviceSymLink.Buffer););

		devExtP->ExportString = deviceSymLink.Buffer;

		ExFreePool(deviceName.Buffer);

		return TRUE;
	}

	else 
	{
		IF_LOUD(DbgPrint("\n\nIoCreateDevice status = %x\n", status););

		ExFreePool(deviceName.Buffer);
		ExFreePool(deviceSymLink.Buffer);
		
		return FALSE;
	}
}
//-------------------------------------------------------------------

VOID NPF_Unload(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT     DeviceObject;
	PDEVICE_OBJECT     OldDeviceObject;
	PDEVICE_EXTENSION  DeviceExtension;
	NDIS_STATUS        Status;
	NDIS_STRING		   SymLink;

	TRACE_ENTER();
	
	DeviceObject    = DriverObject->DeviceObject;

	while (DeviceObject != NULL) {
		OldDeviceObject = DeviceObject;

		DeviceObject = DeviceObject->NextDevice;

		DeviceExtension = OldDeviceObject->DeviceExtension;

		TRACE_MESSAGE4(PACKET_DEBUG_LOUD,"Deleting Adapter %ws, Protocol Handle=%p, Device Obj=%p (%p)",
			DeviceExtension->AdapterName.Buffer,
			g_NdisProtocolHandle,
			DeviceObject,
			OldDeviceObject);

		if (DeviceExtension->ExportString)
		{
			RtlInitUnicodeString(&SymLink , DeviceExtension->ExportString);

			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Deleting SymLink at %p", SymLink.Buffer);

			IoDeleteSymbolicLink(&SymLink);
			ExFreePool(DeviceExtension->ExportString);
		}

		IoDeleteDevice(OldDeviceObject);
	}

	NdisDeregisterProtocol(
		&Status,
		g_NdisProtocolHandle
		);

	// Free the adapters names
	ExFreePool( bindP );

	TRACE_EXIT();

	// Free the device names string that was allocated in the DriverEntry 
//	NdisFreeString(g_NPF_Prefix);
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

NTSTATUS NPF_IoControl(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
    POPEN_INSTANCE      Open;
    PIO_STACK_LOCATION  IrpSp;
    PLIST_ENTRY         RequestListEntry;
    PINTERNAL_REQUEST   pRequest;
    ULONG               FunctionCode;
    NDIS_STATUS	        Status;
	ULONG				Information = 0;
	PLIST_ENTRY         PacketListEntry;
	UINT				i;
	PUCHAR				tpointer;
	ULONG				dim,timeout;
	struct bpf_insn*	NewBpfProgram;
	PPACKET_OID_DATA    OidData;
	int					*StatsBuf;
    PNDIS_PACKET        pPacket;
	ULONG				mode;
	PWSTR				DumpNameBuff;
	PUCHAR				TmpBPFProgram;
	INT					WriteRes;
	BOOLEAN				SyncWrite = FALSE;
	struct bpf_insn		*initprogram;
	ULONG				insns;
	ULONG				cnt;
	BOOLEAN				IsExtendedFilter=FALSE;
	ULONG				StringLength;
	ULONG				NeededBytes;
	BOOLEAN				Flag;
	PUINT				pStats;
	ULONG				StatsLength;

	HANDLE				hUserEvent;
	PKEVENT				pKernelEvent;
#ifdef _AMD64_
    VOID*POINTER_32		hUserEvent32Bit;
#endif //_AMD64_
	PMDL				mdl;

	TRACE_ENTER();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
    FunctionCode=IrpSp->Parameters.DeviceIoControl.IoControlCode;
    Open=IrpSp->FileObject->FsContext;

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

	switch (FunctionCode){
		
	case BIOCGSTATS: //function to get the capture stats

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCGSTATS");

		StatsLength = 4*sizeof(UINT);
		if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < StatsLength)
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
			mdl = IoAllocateMdl(
				Irp->UserBuffer,  
				StatsLength,
				FALSE,
				TRUE,
				NULL);

			if (mdl == NULL)
			{
				SET_FAILURE_UNSUCCESSFUL();
				break;
			}

			MmProbeAndLockPages(
				mdl,
				UserMode,
				IoWriteAccess);

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

		for(i = 0 ; i < g_NCpu ; i++)
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
		
	case BIOCGEVNAME: //function to get the name of the event associated with the current instance
		
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
		if(Open->WriteInProgress)
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
			(PUCHAR)Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.InputBufferLength,
			SyncWrite);

		NdisAcquireSpinLock(&Open->WriteLock);
		Open->WriteInProgress = FALSE;
		NdisReleaseSpinLock(&Open->WriteLock);

		if( WriteRes != -1)
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
		NewBpfProgram = (struct bpf_insn*)Irp->AssociatedIrp.SystemBuffer;
		
		if(NewBpfProgram == NULL)
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
			if(Open->bpfprogram != NULL)
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

			insns = (IrpSp->Parameters.DeviceIoControl.InputBufferLength)/sizeof(struct bpf_insn);
		
			//count the number of operative instructions
			for (cnt = 0 ; (cnt < insns) &&(NewBpfProgram[cnt].code != BPF_SEPARATION); cnt++);
		
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Operative instructions=%u", cnt);

#ifdef HAVE_BUGGY_TME_SUPPORT
			if ( (cnt != insns) && (insns != cnt+1) && (NewBpfProgram[cnt].code == BPF_SEPARATION)) 
			{
				TRACE_MESSAGE1(PACKET_DEBUG_LOUD,"Initialization instructions = %u",insns-cnt-1);
		
				IsExtendedFilter = TRUE;

				initprogram = &NewBpfProgram[cnt+1];
				
				if(bpf_filter_init(initprogram,&(Open->mem_ex),&(Open->tme), &G_Start_Time)!=INIT_OK)
				{
				
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error initializing NPF machine (bpf_filter_init)");
					
					SET_FAILURE_INVALID_REQUEST();
					break;
				}
			}
#else  // HAVE_BUGGY_TME_SUPPORT
			if ( cnt != insns)
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
			if(bpf_validate(NewBpfProgram, cnt, Open->mem_ex.size) == 0)
#else //HAVE_BUGGY_TME_SUPPORT
			if(bpf_validate(NewBpfProgram, cnt) == 0)
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
			TmpBPFProgram = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cnt*sizeof(struct bpf_insn), '4PWA');
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
			if(!IsExtendedFilter)
			{
				if((Open->Filter = BPF_jitter(NewBpfProgram, cnt)) == NULL)
				{
					TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Error jittering filter");
					
					ExFreePool(TmpBPFProgram);

					SET_FAILURE_UNSUCCESSFUL();
					break;
				}
			}
#endif //_X86_

			//copy the program in the new buffer
			RtlCopyMemory(TmpBPFProgram,NewBpfProgram,cnt*sizeof(struct bpf_insn));
			Open->bpfprogram = TmpBPFProgram;

			SET_RESULT_SUCCESS(0);
		}
		while(FALSE);

		//
		// release the machine lock and then reset the buffer
		//
		NdisReleaseSpinLock(&Open->MachineLock);

		NPF_ResetBufferContents(Open);

		break;		
		
	case BIOCSMODE:  //set the capture mode

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSMODE");

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		mode=*((PULONG)Irp->AssociatedIrp.SystemBuffer);
		
///////kernel dump does not work at the moment//////////////////////////////////////////
		if (mode & MODE_DUMP)
		{			
			SET_FAILURE_INVALID_REQUEST();
			break;
		}
///////kernel dump does not work at the moment//////////////////////////////////////////

		if(mode == MODE_CAPT)
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
		else{
			if(mode & MODE_STAT){
				Open->mode = MODE_STAT;
				NdisAcquireSpinLock(&Open->CountersLock);
				Open->Nbytes.QuadPart = 0;
				Open->Npackets.QuadPart = 0;
				NdisReleaseSpinLock(&Open->CountersLock);
				
				if(Open->TimeOut.QuadPart==0)Open->TimeOut.QuadPart = -10000000;
				
			}
			
			if(mode & MODE_DUMP){
				
				Open->mode |= MODE_DUMP;
//				Open->MinToCopy=(Open->BufSize<2000000)?Open->BufSize/2:1000000;
				
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

#ifdef __NPF_NT4__

		// NT4 doesn't support loopback inhibition / activation
		SET_FAILURE_INVALID_REQUEST();
		break;

#else //not __NPF_NT4__
		//
		// win2000/xp/2003/vista
		//
		if(*(PINT)Irp->AssociatedIrp.SystemBuffer == NPF_DISABLE_LOOPBACK)
		{
			Open->SkipSentPackets = TRUE;
				
			//
			// Reset the capture buffers, since they could contain loopbacked packets
			//

			NPF_ResetBufferContents(Open);

			SET_RESULT_SUCCESS(0);
			break;

		}
		else
		if(*(PINT)Irp->AssociatedIrp.SystemBuffer == NPF_ENABLE_LOOPBACK)
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

#endif // !__NPF_NT4__
		break;

	case BIOCSETEVENTHANDLE:
		
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSETEVENTHANDLE");
		
#ifdef _AMD64_
		if (IoIs32bitProcess(Irp))
		{
            //
			// validate the input
			//
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof (hUserEvent32Bit))
			{
				SET_FAILURE_INVALID_REQUEST();
				break;
			}

			hUserEvent32Bit = *(VOID*POINTER_32*)Irp->AssociatedIrp.SystemBuffer;
			hUserEvent = hUserEvent32Bit;
		}
		else
#endif //_AMD64_
		{
            //
			// validate the input
			//
			if (IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof (hUserEvent))
			{
				SET_FAILURE_INVALID_REQUEST();
				break;
			}
	
			hUserEvent = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
		}

		//
		// NT4 doesn't seem to have EVENT_MODIFY_STATE, so on NT4 we request a wider set
		// of privileges for the event handle
		//
#ifdef __NPF_NT4__
		Status = ObReferenceObjectByHandle(hUserEvent,
			OBJECT_TYPE_ALL_ACCESS, *ExEventObjectType, Irp->RequestorMode,
			(PVOID*) &pKernelEvent, NULL);
#else   //__NPF_NT4__
		Status = ObReferenceObjectByHandle(hUserEvent,
			EVENT_MODIFY_STATE, *ExEventObjectType, Irp->RequestorMode,
			(PVOID*) &pKernelEvent, NULL);
#endif  //__NPF_NT4__		

		if (!NT_SUCCESS(Status))
		{
			// Status = ??? already set
			Information = 0;
			break;
		}


		//
		// NT4 does not have InterlockedCompareExchangePointer
		// InterlockedCompareExchange on NT4 has the same prototype of InterlockedCompareExchange
		// on NT5x, so we use this one.
		//
#ifdef __NPF_NT4__
		if (InterlockedCompareExchange(&Open->ReadEvent, pKernelEvent, NULL) != NULL)
#else
		if (InterlockedCompareExchangePointer(&Open->ReadEvent, pKernelEvent, NULL) != NULL)
#endif
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


		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
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
		}

		for (i = 0 ; i < g_NCpu ; i++)
		{
			if (dim > 0) 
				Open->CpuData[i].Buffer=(PUCHAR)tpointer + (dim/g_NCpu)*i;
			else
				Open->CpuData[i].Buffer = NULL;
			Open->CpuData[i].Free = dim/g_NCpu;
			Open->CpuData[i].P = 0;
			Open->CpuData[i].C = 0;
			Open->CpuData[i].Accepted = 0;
			Open->CpuData[i].Dropped = 0;
			Open->CpuData[i].Received = 0;
		}

		Open->ReaderSN=0;
		Open->WriterSN=0;

		Open->Size = dim/g_NCpu;

		//
		// acquire the locks for all the buffers
		//
		i = g_NCpu;

		do
		{
			i--;

#pragma prefast(suppress:8107, "There's no Spinlock leak here, as it's acquired some lines above.")
			NdisReleaseSpinLock(&Open->CpuData[i].BufferLock);
		}while(i != 0);

		SET_RESULT_SUCCESS(0);
		break;
		
	case BIOCSRTIMEOUT: //set the timeout on the read calls
		
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSRTIMEOUT");

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		timeout = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
		if(timeout == (ULONG)-1)
			Open->TimeOut.QuadPart=(LONGLONG)IMMEDIATE;
		else
		{
			Open->TimeOut.QuadPart = (LONGLONG)timeout;
			Open->TimeOut.QuadPart *= 10000;
			Open->TimeOut.QuadPart = -Open->TimeOut.QuadPart;
		}

		TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "Read timeout set to %I64d",Open->TimeOut.QuadPart);
		
		SET_RESULT_SUCCESS(0);		
		break;
		
	case BIOCSWRITEREP: //set the writes repetition number
		
		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSWRITEREP");

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		Open->Nwrites = *((PULONG)Irp->AssociatedIrp.SystemBuffer);

		SET_RESULT_SUCCESS(0);
		break;

	case BIOCSMINTOCOPY: //set the minimum buffer's size to copy to the application

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "BIOCSMINTOCOPY");

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

		Open->MinToCopy = (*((PULONG)Irp->AssociatedIrp.SystemBuffer))/g_NCpu;  //An hack to make the NCPU-buffers behave like a larger one
		
		SET_RESULT_SUCCESS(0);
		break;
		
//	case IOCTL_PROTOCOL_RESET:
//
//		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "IOCTL_PROTOCOL_RESET");
//
//		IoMarkIrpPending(Irp);
//		Irp->IoStatus.Status = STATUS_SUCCESS;
//
//		ExInterlockedInsertTailList(&Open->ResetIrpList,&Irp->Tail.Overlay.ListEntry,&Open->RequestSpinLock);
//      NdisReset(&Status,Open->AdapterHandle);
//      if (Status != NDIS_STATUS_PENDING)
//        {
//            IF_LOUD(DbgPrint("NPF: IoControl - ResetComplete being called\n");)
//				NPF_ResetComplete(Open,Status);
//        }
//		
//		break;
		
	case BIOCSETOID:
	case BIOCQUERYOID:
		
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
		RequestListEntry=ExInterlockedRemoveHeadList(&Open->RequestList,&Open->RequestSpinLock);
		if (RequestListEntry == NULL)
		{
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open);

			SET_FAILURE_NOMEM();
			break;
		}

		pRequest=CONTAINING_RECORD(RequestListEntry,INTERNAL_REQUEST,ListElement);

		//
        //  See if it is an Ndis request
        //
        OidData=Irp->AssociatedIrp.SystemBuffer;
		
        if ((IrpSp->Parameters.DeviceIoControl.InputBufferLength == IrpSp->Parameters.DeviceIoControl.OutputBufferLength)
            &&
            (IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA))
            &&
            (IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA)-1+OidData->Length)) {
			
            TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "BIOCSETOID|BIOCQUERYOID Request: Oid=%08lx, Length=%08lx",OidData->Oid,OidData->Length);
				
				//
				//  The buffer is valid
				//
				if (FunctionCode == BIOCSETOID){
					
					pRequest->Request.RequestType=NdisRequestSetInformation;
					pRequest->Request.DATA.SET_INFORMATION.Oid=OidData->Oid;
					
					pRequest->Request.DATA.SET_INFORMATION.InformationBuffer=OidData->Data;
					pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength=OidData->Length;
					
					
				} 
				else{
								
					pRequest->Request.RequestType=NdisRequestQueryInformation;
					pRequest->Request.DATA.QUERY_INFORMATION.Oid=OidData->Oid;
					
					pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer=OidData->Data;
					pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength=OidData->Length;
					
				}

				NdisResetEvent(&pRequest->InternalRequestCompletedEvent);
				
				//
				//  submit the request
				//
				NdisRequest(
					&Status,
					Open->AdapterHandle,
					&pRequest->Request
					);
				
        } else {
			//
			// Release ownership of the Ndis Handle
			//
			NPF_StopUsingBinding(Open);

            //
            //  buffer too small
            //
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
		NPF_StopUsingBinding(Open);

		//
		// Complete the request
		//
		if (FunctionCode == BIOCSETOID) 
		{
			OidData->Length = pRequest->Request.DATA.SET_INFORMATION.BytesRead;
			TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "BIOCSETOID completed, BytesRead = %u",OidData->Length);
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
						TRACE_MESSAGE2(PACKET_DEBUG_LOUD, "Bogus return from NdisRequest (query): Bytes Written (%u) > InfoBufferLength (%u)!!",
							pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten,
							pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength);

						Status = NDIS_STATUS_INVALID_DATA;
					}
				}

				TRACE_MESSAGE1(PACKET_DEBUG_LOUD, "BIOCQUERYOID completed, BytesWritten = %u",OidData->Length);
			}
		}


		ExInterlockedInsertTailList(
			&Open->RequestList,
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
NPF_RequestComplete(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN PNDIS_REQUEST NdisRequest,
    IN NDIS_STATUS   Status
    )

{
    PINTERNAL_REQUEST   pRequest;

	TRACE_ENTER();

    pRequest = CONTAINING_RECORD(NdisRequest,INTERNAL_REQUEST,Request);

	//
	// Set the request result
	//
	pRequest->RequestStatus = Status;

	//
	// and awake the caller
	//
	NdisSetEvent(&pRequest->InternalRequestCompletedEvent);

	TRACE_EXIT();
	return;

}

//-------------------------------------------------------------------

VOID
NPF_Status(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN NDIS_STATUS   Status,
    IN PVOID         StatusBuffer,
    IN UINT          StatusBufferSize
    )

{

    IF_LOUD(DbgPrint("NPF: Status Indication\n");)

    return;

}

//-------------------------------------------------------------------

VOID
NPF_StatusComplete(
    IN NDIS_HANDLE  ProtocolBindingContext
    )

{

    IF_LOUD(DbgPrint("NPF: StatusIndicationComplete\n");)

    return;

}

//-------------------------------------------------------------------

NTSTATUS
NPF_ReadRegistry(
    IN  PWSTR              *MacDriverName,
    IN  PWSTR              *PacketDriverName,
    IN  PUNICODE_STRING     RegistryPath
    )

{
    NTSTATUS   Status;

    RTL_QUERY_REGISTRY_TABLE ParamTable[4];

    PWSTR      Bind       = L"Bind";
    PWSTR      Export     = L"Export";
    PWSTR      Parameters = L"Parameters";
    PWSTR      Linkage    = L"Linkage";

    PWCHAR     Path;



    Path=ExAllocatePoolWithTag(PagedPool, RegistryPath->Length+sizeof(WCHAR), '7PWA');

    if (Path == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        Path,
        RegistryPath->Length+sizeof(WCHAR)
        );

    RtlCopyMemory(
        Path,
        RegistryPath->Buffer,
        RegistryPath->Length
        );

    IF_LOUD(DbgPrint("NPF: Reg path is %ws\n",RegistryPath->Buffer);)

    RtlZeroMemory(
        ParamTable,
        sizeof(ParamTable)
        );



    //
    //  change to the linkage key
    //

    ParamTable[0].QueryRoutine = NULL;
    ParamTable[0].Flags = RTL_QUERY_REGISTRY_SUBKEY;
    ParamTable[0].Name = Linkage;


    //
    //  Get the name of the mac driver we should bind to
    //

    ParamTable[1].QueryRoutine = NPF_QueryRegistryRoutine;
    ParamTable[1].Flags = RTL_QUERY_REGISTRY_REQUIRED |
                          RTL_QUERY_REGISTRY_NOEXPAND;

    ParamTable[1].Name = Bind;
    ParamTable[1].EntryContext = (PVOID)MacDriverName;
    ParamTable[1].DefaultType = REG_MULTI_SZ;

    //
    //  Get the name that we should use for the driver object
    //

    ParamTable[2].QueryRoutine = NPF_QueryRegistryRoutine;
    ParamTable[2].Flags = RTL_QUERY_REGISTRY_REQUIRED |
                          RTL_QUERY_REGISTRY_NOEXPAND;

    ParamTable[2].Name = Export;
    ParamTable[2].EntryContext = (PVOID)PacketDriverName;
    ParamTable[2].DefaultType = REG_MULTI_SZ;


    Status=RtlQueryRegistryValues(
               RTL_REGISTRY_ABSOLUTE,
               Path,
               ParamTable,
               NULL,
               NULL
               );


    ExFreePool(Path);

    return Status;
}

//-------------------------------------------------------------------

NTSTATUS
NPF_QueryRegistryRoutine(
    IN PWSTR     ValueName,
    IN ULONG     ValueType,
    IN PVOID     ValueData,
    IN ULONG     ValueLength,
    IN PVOID     Context,
    IN PVOID     EntryContext
    )

{

    PUCHAR       Buffer;

    IF_LOUD(DbgPrint("Perf: QueryRegistryRoutine\n");)

    if (ValueType != REG_MULTI_SZ) {

        return STATUS_OBJECT_NAME_NOT_FOUND;

    }

    Buffer=ExAllocatePoolWithTag(NonPagedPool, ValueLength, '8PWA');

    if (Buffer==NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;

    }

    RtlCopyMemory(
        Buffer,
        ValueData,
        ValueLength
        );

    *((PUCHAR *)EntryContext)=Buffer;

    return STATUS_SUCCESS;

}

VOID NPF_ResetBufferContents(POPEN_INSTANCE Open)
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
		Open->CpuData[i].C=0;
		Open->CpuData[i].P=0;
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

#if 0
//  
//	Old registry based WinPcap names
//

//-------------------------------------------------------------------

//NOTE: ValueLen is the length of Value in characters

VOID NPF_QueryWinpcapRegistryString(PWSTR SubKeyName,
								 WCHAR *Value,
                                 UINT ValueLen, 
								 WCHAR *DefaultValue)
{
	UINT CharsToCopy;

#ifdef WPCAP_OEM
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;
	UNICODE_STRING SubKeyToQueryU;
	CHAR kvpiBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(WCHAR) * MAX_WINPCAP_KEY_CHARS];
	ULONG QvkResultLength;
	PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInformation = (PKEY_VALUE_PARTIAL_INFORMATION)kvpiBuffer;	
	PWCHAR pResultingKeyValue;

	//
	// Create subkey string
	//
	RtlInitUnicodeString(&SubKeyToQueryU, SubKeyName);

	//
	// Init Attributes
	//
	InitializeObjectAttributes(&objAttrs,
		&g_WinpcapGlobalKey,
		OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	//
	// Open the key
	//
	status = ZwOpenKey(&keyHandle, 
		KEY_QUERY_VALUE, 
		&objAttrs);
	
	if(!NT_SUCCESS(status)) 
	{
		IF_LOUD(DbgPrint("NPF_QueryWinpcapRegistryKey: ZwOpenKey error %x\n", status);)
		
		//copy the default value and return
		CharsToCopy = wcslen(DefaultValue) + 1;
		if (CharsToCopy > ValueLen)
		{
			RtlCopyMemory(Value, DefaultValue, ValueLen * 2);
			Value[ValueLen - 1] = 0;
		}
		else
		{
			RtlCopyMemory(Value, DefaultValue, CharsToCopy * 2);
		}
		return;
	}

	//
	// Query the requested value
	//
	status = ZwQueryValueKey(keyHandle, 
		&SubKeyToQueryU,
		KeyValuePartialInformation, 
		pKeyValuePartialInformation,
		sizeof(kvpiBuffer),
		&QvkResultLength);

	if(!NT_SUCCESS(status))
	{
		IF_LOUD(DbgPrint("NPF_QueryWinpcapRegistryKey: Status of %x querying key value %ws\n", 
			status,
			SubKeyToQueryU.Buffer);)
		
		ZwClose(keyHandle);
		
		//copy the default value and return
		CharsToCopy = wcslen(DefaultValue) + 1;
		if (CharsToCopy > ValueLen)
		{
			RtlCopyMemory(Value, DefaultValue, ValueLen * 2);
			Value[ValueLen - 1] = 0;
		}
		else
		{
			RtlCopyMemory(Value, DefaultValue, CharsToCopy * 2);
		}
		return;
	}
	
	//
	// Check that the resulting value is of the correct type
	//
	if (pKeyValuePartialInformation->Type != REG_SZ)
	{
		IF_LOUD(DbgPrint("NPF_QueryWinpcapRegistryKey: the reg key has the wrong type (%u)\n", pKeyValuePartialInformation->Type);)
		
		ZwClose(keyHandle);
		
		//copy the default value and return
		CharsToCopy = wcslen(DefaultValue) + 1;
		if (CharsToCopy > ValueLen)
		{
			RtlCopyMemory(Value, DefaultValue, ValueLen * 2);
			Value[ValueLen - 1] = 0;
		}
		else
		{
			RtlCopyMemory(Value, DefaultValue, CharsToCopy * 2);
		}
		return;
	}

	pResultingKeyValue = (PWCHAR)pKeyValuePartialInformation->Data;

	//
	// Check we have enough space for the result. We include 1 to account for the UNICODE NULL terminator
	//
	if(wcslen(pResultingKeyValue) + 1 > ValueLen)
	{
		IF_LOUD(DbgPrint("NPF_QueryWinpcapRegistryKey: storage buffer too small\n");)		

		ZwClose(keyHandle);
		
		//copy the default value and return
		CharsToCopy = wcslen(DefaultValue) + 1;
		if (CharsToCopy > ValueLen)
		{
			RtlCopyMemory(Value, DefaultValue, ValueLen * 2);
			Value[ValueLen - 1] = 0;
		}
		else
		{
			RtlCopyMemory(Value, DefaultValue, CharsToCopy * 2);
		}
		return;
	}
	
	//
	// Copy the value to the user-provided values
	//
	wcscpy(Value, pResultingKeyValue);

	//
	// Free the key
	//
	ZwClose(keyHandle);

	return;

#else // WPCAP_OEM

	//copy the default value and return
	CharsToCopy = wcslen(DefaultValue) + 1;
	if (CharsToCopy > ValueLen)
	{
		RtlCopyMemory(Value, DefaultValue, ValueLen * 2);
		Value[ValueLen - 1] = 0;
	}
	else
	{
		RtlCopyMemory(Value, DefaultValue, CharsToCopy * 2);
	}
	return;

#endif // WPCAP_OEM
}

#endif