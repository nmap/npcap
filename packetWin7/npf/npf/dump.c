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
* Copyright (c) 2005 - 2007 CACE Technologies, Davis (California)
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
#include "win_bpf.h"

#ifdef __NPF_NT4__
extern POBJECT_TYPE* PsThreadType;
#endif

//-------------------------------------------------------------------

NTSTATUS NPF_OpenDumpFile(POPEN_INSTANCE Open, PUNICODE_STRING fileName, BOOLEAN Append)
{
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK IoStatus;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PDEVICE_OBJECT fsdDevice;
	FILE_STANDARD_INFORMATION StandardInfo;

	ASSERT(Open);
	ASSERT(fileName);

	IF_LOUD(DbgPrint("NPF: OpenDumpFile.\n");)

	// Check the instance parameter is non-null
	if (Open == NULL)
	{
		IF_LOUD(DbgPrint("NPF: OpenDumpFile, NULL Open parameter.\n");)
		return STATUS_INVALID_PARAMETER_1;
	}

	// Check the filename is non-null
	if (fileName == NULL)
	{
		IF_LOUD(DbgPrint("NPF: OpenDumpFile, NULL fileName parameter.\n");)
		return STATUS_INVALID_PARAMETER_2;
	}

	// Check the filename is valid
	ntStatus = RtlUnicodeStringValidate(fileName);
	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: OpenDumpFile, fileName parameter invalid, status=%x\n", ntStatus);)
		return ntStatus;
	}

	// Make sure the FullFileName has enough space for the filename and a prefix if required
	UNICODE_STRING FullFileName;
	DECLARE_CONST_UNICODE_STRING(filePrefix, L"\\\\?\\");
	FullFileName.Length = 0;
	FullFileName.MaximumLength = fileName->Length + filePrefix.Length;
	FullFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, FullFileName.MaximumLength * sizeof(WCHAR), '0DWA');
	if (FullFileName.Buffer == NULL)
	{
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		IF_LOUD(DbgPrint("NPF: Error allocating dump file name.\n");)
		return ntStatus;
	}

	// Add the extended path prefix if required
	if (RtlPrefixUnicodeString(&filePrefix, fileName, FALSE))
	{
		// No string extension required, set FullfileName to be the same as fileName
		ntStatus = RtlUnicodeStringCopy(&FullFileName, fileName);
		if (!NT_SUCCESS(ntStatus))
		{
			IF_LOUD(DbgPrint("NPF: Error copying dump file name, status=%x\n", ntStatus);)
			return ntStatus;
		}
	}
	else
	{
		// Concat the extended path prefix and the filename
		ntStatus = RtlUnicodeStringCopy(&FullFileName, &filePrefix);
		if (!NT_SUCCESS(ntStatus))
		{
			IF_LOUD(DbgPrint("NPF: Error copying dump file prefix, status=%x\n", ntStatus);)
			return ntStatus;
		}
		ntStatus = RtlUnicodeStringCat(&FullFileName, fileName);
		if (!NT_SUCCESS(ntStatus))
		{
			IF_LOUD(DbgPrint("NPF: Error appending dump file name, status=%x\n", ntStatus);)
			return ntStatus;
		}
	}

	IF_LOUD(DbgPrint("Packet: Attempting to open %wZ\n", &FullFileName);)

	InitializeObjectAttributes(&ObjectAttributes, &FullFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Create the dump file
	ntStatus = ZwCreateFile(&Open->DumpFileHandle, SYNCHRONIZE | FILE_WRITE_DATA, &ObjectAttributes,
		                    &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		                    (Append) ? FILE_OPEN_IF : FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: Error opening file %x\n", ntStatus);)

		ExFreePool(FullFileName.Buffer);
		Open->DumpFileHandle = NULL;
		ntStatus = STATUS_NO_SUCH_FILE;
		return ntStatus;
	}

	ExFreePool(FullFileName.Buffer);

	ntStatus = ObReferenceObjectByHandle(Open->DumpFileHandle, FILE_WRITE_ACCESS, *IoFileObjectType, KernelMode, &Open->DumpFileObject, 0);

	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: Error creating file, status=%x\n", ntStatus);)

		ZwClose(Open->DumpFileHandle);
		Open->DumpFileHandle = NULL;

		ntStatus = STATUS_NO_SUCH_FILE;
		return ntStatus;
	}

	fsdDevice = IoGetRelatedDeviceObject(Open->DumpFileObject);

	IF_LOUD(DbgPrint("NPF: Dump: write file created succesfully, status=%d \n", ntStatus);)

	return ntStatus;
}

//-------------------------------------------------------------------

NTSTATUS NPF_StartDump(POPEN_INSTANCE Open)
{
	NTSTATUS ntStatus;
	struct packet_file_header hdr;
	IO_STATUS_BLOCK IoStatus;
	//NDIS_REQUEST pRequest;
	ULONG MediaType;
	OBJECT_ATTRIBUTES ObjectAttributes;

	IF_LOUD(DbgPrint("NPF: StartDump.\n");)

	// Init the file header
	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;
	hdr.thiszone = 0; /*Currently not set*/
	hdr.snaplen = 1514;
	hdr.sigfigs = 0;

	// Detect the medium type
	switch (Open->Medium)
	{
	case NdisMediumWan:
		hdr.linktype = DLT_EN10MB;
		break;

	case NdisMedium802_3:
		hdr.linktype = DLT_EN10MB;
		break;

	case NdisMediumFddi:
		hdr.linktype = DLT_FDDI;
		break;

	case NdisMedium802_5:
		hdr.linktype = DLT_IEEE802;
		break;

	case NdisMediumArcnet878_2:
		hdr.linktype = DLT_ARCNET;
		break;

	case NdisMediumAtm:
		hdr.linktype = DLT_ATM_RFC1483;
		break;

	default:
		hdr.linktype = DLT_EN10MB;
	}

	// Write the header.
	// We can use ZwWriteFile because we are in the context of the application
	ntStatus = ZwWriteFile(Open->DumpFileHandle, NULL, NULL, NULL, &IoStatus, &hdr, sizeof(hdr), NULL, NULL);


	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: Error dumping file %x\n", ntStatus);)

		ZwClose(Open->DumpFileHandle);
		Open->DumpFileHandle = NULL;

		ntStatus = STATUS_NO_SUCH_FILE;
		return ntStatus;
	}

	Open->DumpOffset.QuadPart = 24;

	ntStatus = PsCreateSystemThread(&Open->DumpThreadHandle, THREAD_ALL_ACCESS, (ACCESS_MASK)0L, 0, 0, NPF_DumpThread, Open);

	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: Error creating dump thread, status=%x\n", ntStatus);)

		ZwClose(Open->DumpFileHandle);
		Open->DumpFileHandle = NULL;

		return ntStatus;
	}

	ntStatus = ObReferenceObjectByHandle(Open->DumpThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &Open->DumpThreadObject, 0);

	if (!NT_SUCCESS(ntStatus))
	{
		IF_LOUD(DbgPrint("NPF: Error creating dump thread, status=%x\n", ntStatus);)

		ObDereferenceObject(Open->DumpFileObject);
		ZwClose(Open->DumpFileHandle);
		Open->DumpFileHandle = NULL;

		return ntStatus;
	}


	return ntStatus;
}

//-------------------------------------------------------------------
// Dump Thread
//-------------------------------------------------------------------

VOID NPF_DumpThread(POPEN_INSTANCE Open)
{
	ULONG FrozenNic;

	IF_LOUD (DbgPrint("NPF: In the work routine.  Parameter = 0x%p\n", Open);)while(TRUE)
	{
		// Wait until some packets arrive or the timeout expires
		NdisWaitEvent(&Open->DumpEvent, 5000);

		IF_LOUD (DbgPrint("NPF: Worker Thread - event signalled\n");)if(Open->DumpLimitReached || Open->Size == 0)
		{
			// BufSize=0 means that this instance was closed, or that the buffer is too
			// small for any capture. In both cases it is better to end the dump

			IF_LOUD(DbgPrint("NPF: Worker Thread - Exiting happily\n");)
			IF_LOUD(DbgPrint("Thread: Dumpoffset=%I64d\n", Open->DumpOffset.QuadPart);)

			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}

		NdisResetEvent(&Open->DumpEvent);

		// Write the content of the buffer to the file
		if (NPF_SaveCurrentBuffer(Open) != STATUS_SUCCESS)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
	}
}

//-------------------------------------------------------------------

NTSTATUS NPF_SaveCurrentBuffer(POPEN_INSTANCE Open)
{
	UINT Thead;
	UINT Ttail;
	UINT TLastByte;
	PUCHAR CurrBuff;
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK IoStatus;
	PMDL lMdl;
	UINT SizeToDump;

#if 0

	Thead=Open->Bhead;
	Ttail=Open->Btail;
	TLastByte=Open->BLastByte;

	IF_LOUD(DbgPrint("NPF: NPF_SaveCurrentBuffer.\n");)

		// Get the address of the buffer
		CurrBuff=Open->Buffer;
	//
	// Fill the application buffer
	//
	if( Ttail < Thead )
	{
		if(Open->MaxDumpBytes &&
			(UINT)Open->DumpOffset.QuadPart /*+ GetBuffOccupation(Open)*/ > Open->MaxDumpBytes)
		{
			// Size limit reached
			UINT PktLen;

			SizeToDump = 0;

			// Scan the buffer to detect the exact amount of data to save
			while(TRUE){
				PktLen = ((struct sf_pkthdr*)(CurrBuff + Thead + SizeToDump))->caplen + sizeof(struct sf_pkthdr);

				if((UINT)Open->DumpOffset.QuadPart + SizeToDump + PktLen > Open->MaxDumpBytes)
					break;

				SizeToDump += PktLen;
			}

		}
		else
			SizeToDump = TLastByte-Thead;

		lMdl=IoAllocateMdl(CurrBuff+Thead, SizeToDump, FALSE, FALSE, NULL);
		if (lMdl == NULL)
		{
			// No memory: stop dump
			IF_LOUD(DbgPrint("NPF: dump thread: Failed to allocate Mdl\n");)
				return STATUS_UNSUCCESSFUL;
		}

		MmBuildMdlForNonPagedPool(lMdl);

		// Write to disk
		NPF_WriteDumpFile(Open->DumpFileObject,
			&Open->DumpOffset,
			SizeToDump,
			lMdl,
			&IoStatus);

		IoFreeMdl(lMdl);

		if(!NT_SUCCESS(IoStatus.Status)){
			// Error
			return STATUS_UNSUCCESSFUL;
		}

		if(SizeToDump != TLastByte-Thead){
			// Size limit reached.
			Open->DumpLimitReached = TRUE;

			// Awake the application
			KeSetEvent(Open->ReadEvent,0,FALSE);

			return STATUS_UNSUCCESSFUL;
		}

		// Update the packet buffer
		Open->DumpOffset.QuadPart+=(TLastByte-Thead);
		Open->BLastByte=Ttail;
		Open->Bhead=0;
	}

	if( Ttail > Thead ){

		if(Open->MaxDumpBytes &&
			(UINT)Open->DumpOffset.QuadPart /* +GetBuffOccupation(Open)*/ > Open->MaxDumpBytes)
		{
			// Size limit reached
			UINT PktLen;

			SizeToDump = 0;

			// Scan the buffer to detect the exact amount of data to save
			while(Thead + SizeToDump < Ttail){

				PktLen = ((struct sf_pkthdr*)(CurrBuff + Thead + SizeToDump))->caplen + sizeof(struct sf_pkthdr);

				if((UINT)Open->DumpOffset.QuadPart + SizeToDump + PktLen > Open->MaxDumpBytes)
					break;

				SizeToDump += PktLen;
			}

		}
		else
			SizeToDump = Ttail-Thead;

		lMdl=IoAllocateMdl(CurrBuff+Thead, SizeToDump, FALSE, FALSE, NULL);
		if (lMdl == NULL)
		{
			// No memory: stop dump
			IF_LOUD(DbgPrint("NPF: dump thread: Failed to allocate Mdl\n");)
				return STATUS_UNSUCCESSFUL;
		}

		MmBuildMdlForNonPagedPool(lMdl);

		// Write to disk
		NPF_WriteDumpFile(Open->DumpFileObject,
			&Open->DumpOffset,
			SizeToDump,
			lMdl,
			&IoStatus);

		IoFreeMdl(lMdl);

		if(!NT_SUCCESS(IoStatus.Status)){
			// Error
			return STATUS_UNSUCCESSFUL;
		}

		if(SizeToDump != Ttail-Thead){
			// Size limit reached.
			Open->DumpLimitReached = TRUE;

			// Awake the application
			KeSetEvent(Open->ReadEvent,0,FALSE);

			return STATUS_UNSUCCESSFUL;
		}

		// Update the packet buffer
		Open->DumpOffset.QuadPart+=(Ttail-Thead);
		Open->Bhead=Ttail;

	}
#endif
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

NTSTATUS NPF_CloseDumpFile(POPEN_INSTANCE Open)
{
	NTSTATUS ntStatus;
	IO_STATUS_BLOCK IoStatus;
	PMDL WriteMdl;
	PUCHAR VMBuff;
	UINT VMBufLen;

#if 0
	IF_LOUD(DbgPrint("NPF: NPF_CloseDumpFile.\n");)
		IF_LOUD(DbgPrint("Dumpoffset=%d\n",Open->DumpOffset.QuadPart);)

		DbgPrint("1\n");
	// Consistency check
	if(Open->DumpFileHandle == NULL)
		return STATUS_UNSUCCESSFUL;

	DbgPrint("2\n");
	ZwClose( Open->DumpFileHandle );

	ObDereferenceObject(Open->DumpFileObject);
	/*
	if(Open->DumpLimitReached == TRUE)
	// Limit already reached: don't save the rest of the buffer.
	return STATUS_SUCCESS;
	*/
	DbgPrint("3\n");

	NPF_OpenDumpFile(Open,&Open->DumpFileName, TRUE);

	// Flush the buffer to file
	NPF_SaveCurrentBuffer(Open);

	// Close The file
	ObDereferenceObject(Open->DumpFileObject);
	ZwClose( Open->DumpFileHandle );

	Open->DumpFileHandle = NULL;

	ObDereferenceObject(Open->DumpFileObject);
#endif
	return STATUS_SUCCESS;
}

//-------------------------------------------------------------------

static NTSTATUS PacketDumpCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	//
	// From Sebastian Gottschalk,
	// Wednesday, May 07, 2008 4:55 PM
	//
	// The issue is within dump.c!PacketDumpCompletion. As an I/O completion
	// routine it is bound to the contract that every pending IRP passed to this
	// routine has to be marked as pending in case that is wasn't yet. Since the
	// device returning this IRP is a filesystem device (PacketDumpCompletion is
	// setup by WriteDumpFile), such cases might happen and would then hang the
	// filesystem, soon hanging up then entire system.
	//
	// Solution: (TO BE TESTED)
	//
	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);

	// Copy the status information back into the "user" IOSB
	*Irp->UserIosb = Irp->IoStatus;

	// Wake up the mainline code
	KeSetEvent(Irp->UserEvent, 0, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

//-------------------------------------------------------------------

VOID NPF_WriteDumpFile(PFILE_OBJECT FileObject, PLARGE_INTEGER Offset, ULONG Length, PMDL Mdl, PIO_STATUS_BLOCK IoStatusBlock)
{
	PIRP irp;
	KEVENT event;
	PIO_STACK_LOCATION ioStackLocation;
	PDEVICE_OBJECT fsdDevice = IoGetRelatedDeviceObject(FileObject);
	NTSTATUS Status;

	// Set up the event we'll use
	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	// Allocate and build the IRP we'll be sending to the FSD
	irp = IoAllocateIrp(fsdDevice->StackSize, FALSE);

	if (!irp)
	{
		// Allocation failed, presumably due to memory allocation failure
		IoStatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
		IoStatusBlock->Information = 0;

		return;
	}

	irp->MdlAddress = Mdl;
	irp->UserEvent = &event;
	irp->UserIosb = IoStatusBlock;
	irp->Tail.Overlay.Thread = PsGetCurrentThread();
	irp->Tail.Overlay.OriginalFileObject = FileObject;
	irp->RequestorMode = KernelMode;

	// Indicate that this is a WRITE operation
	irp->Flags = IRP_WRITE_OPERATION;

	// Set up the next I/O stack location
	ioStackLocation = IoGetNextIrpStackLocation(irp);
	ioStackLocation->MajorFunction = IRP_MJ_WRITE;
	ioStackLocation->MinorFunction = 0;
	ioStackLocation->DeviceObject = fsdDevice;
	ioStackLocation->FileObject = FileObject;
	IoSetCompletionRoutine(irp, PacketDumpCompletion, 0, TRUE, TRUE, TRUE);
	ioStackLocation->Parameters.Write.Length = Length;
	ioStackLocation->Parameters.Write.ByteOffset = *Offset;


	// Send it on.  Ignore the return code
	(void)IoCallDriver(fsdDevice, irp);

	// Wait for the I/O to complete.
	KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);

	// Free the IRP now that we are done with it
	IoFreeIrp(irp);

	return;
}
