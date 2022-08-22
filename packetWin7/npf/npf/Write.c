/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library
 * and is copyright (c) 2013-2022 by Nmap Software LLC ("The Nmap Project").
 * All rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it
 * is not open source software and may not be redistributed or used in
 * other software without special permission from the Nmap
 * Project. The standard (free) version is usually limited to
 * installation on five systems. For more details, see the LICENSE
 * file included with Npcap and also avaialble at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not
 * a substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap
 * OEM within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may
 * choose between a perpetual unlimited license or a quarterly term license,
 * along with options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to
 * use Npcap OEM internally, without redistribution outside their
 * organization. This allows them to bypass the 5-system usage cap of the
 * Npcap free edition. It includes commercial support and update options, and
 * provides the extra Npcap OEM features such as the silent installer for
 * automated deployment. Prices and details:
 * https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a
 * warranty. Npcap OEM also includes a silent installer for unattended
 * installation. Further details about Npcap OEM are available from
 * https://npcap.com/oem/, and you are also welcome to contact us at
 * sales@nmap.com to ask any questions or set up a license for your
 * organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will
 * be free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial
 * licensing customers) has granted you additional rights to Npcap or
 * Npcap OEM, those additional rights take precedence where they
 * conflict with the terms of the license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features.  By
 * sending these changes to the Nmap Project (including through direct email
 * or our mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap.  If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights and commercial
 * support are available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license
 * header. We have kept those for attribution purposes, but any license terms
 * granted by those notices apply only to their original work, and not to any
 * changes made by the Nmap Project or to this entire file.
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
#include <fwpsk.h>

extern PNPCAP_DRIVER_EXTENSION g_pDriverExtension;

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
/*!
  \brief Send a loopback NBL.
  \param NetBufferList Pointer to NBL.

  Alternative to NdisFSendNetBufferLists, use the same NBL parameter, but it calls Winsock Kernel to send packet instead
  of NDIS functions.
*/
NTSTATUS
NPF_LoopbackSendNetBufferLists(
	_In_ POPEN_INSTANCE pOpen,
	_In_ __drv_aliasesMem PNET_BUFFER_LIST NetBufferList
	);

#endif

inline
__drv_allocatesMem(mem)
PVOID
#pragma warning(suppress: 28195) // We aren't really allocating it here, but we know that it was allocated in some other un-annotated function.
NPF_AnalysisAssumeAllocated(_In_ PVOID *p)
{
	return *p;
}

_Must_inspect_result_
_Success_(return != NULL)
__drv_allocatesMem(mem)
PMDL
NPF_CloneBufferToMdl(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ PVOID pBuf,
	_In_ ULONG uDataLen
       )
{
	PVOID npBuff = ExAllocatePoolWithTag(NPF_NONPAGED, uDataLen, NPF_BUFFERED_WRITE_TAG);
	if (npBuff == NULL)
	{
		INFO_DBG("NPF_BufferedWrite: unable to allocate non-paged buffer.\n");
		return NULL;
	}

	RtlCopyMemory(npBuff, pBuf, uDataLen);

	// Allocate an MDL to map the packet data
	PMDL TmpMdl = NdisAllocateMdl(pFiltMod->AdapterHandle, npBuff, uDataLen);

	if (TmpMdl == NULL)
	{
		// Unable to map the memory: packet lost
		INFO_DBG("NPF_BufferedWrite: unable to allocate the MDL.\n");

		ExFreePoolWithTag(npBuff, NPF_BUFFERED_WRITE_TAG);
		return NULL;
	}

	// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the buffer address
	// is stored in the MDL and we retrieve it (via NdisQueryMdl) in NPF_FreePackets called from NPF_ReturnEx.
	// Therefore, it is not leaking after this point.
	NPF_AnalysisAssumeAliased(npBuff);
	return TmpMdl;
}

VOID
NPF_FreeMdlAndBuffer(_In_ __drv_freesMem(mem) PMDL pMdl)
{
	PVOID npBuff = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority|MdlMappingNoExecute);
	if (npBuff != NULL) {
		ExFreePoolWithTag(npBuff, NPF_BUFFERED_WRITE_TAG);
	}
	NdisFreeMdl(pMdl); //Free MDL
}

NTSTATUS
_At_(*ppNBL, __drv_allocatesMem(mem))
NPF_AllocateNBL(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ __drv_aliasesMem PMDL pMdl,
	_In_ SIZE_T uDataLen,
	_Outptr_result_nullonfailure_ PNET_BUFFER_LIST *ppNBL
       )
{
	NTSTATUS Status = STATUS_SUCCESS;
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (pFiltMod->Loopback)
	{
		Status = FwpsAllocateNetBufferAndNetBufferList(pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
			0,
			pMdl,
			0,
			uDataLen,
			ppNBL);
		if (NT_SUCCESS(Status) && *ppNBL)
		{
			// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
			// FwpsAllocateNetBufferAndNetBufferList do not use __drv_aliasesMem for the 4th parameter,
			// even though it is just a wrapper for NdisAllocateNetBufferAndNetBufferList, which does alias the MDL.
			NPF_AnalysisAssumeAliased(pMdl);
			// WORKAROUND: FwpsAllocateNetBufferAndNetBufferList also does not have annotations for
			// allocating the NBL. This fake function will suppress the warning about it.
			*ppNBL = NPF_AnalysisAssumeAllocated(ppNBL);
		}
		else
		{
			// Can't indicate success if it didn't actually succeed.
			Status = NT_SUCCESS(Status) ? STATUS_INSUFFICIENT_RESOURCES : Status;
			*ppNBL = NULL;
		}
	}
	else
#endif
	{
		*ppNBL = NdisAllocateNetBufferAndNetBufferList(pFiltMod->PacketPool,
			sizeof(PACKET_RESERVED),
			0,
			pMdl,
			0,
			uDataLen);
		Status = *ppNBL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
	}
	return Status;
}
//-------------------------------------------------------------------

_Ret_range_(-1, 1)
static int NPF_GetIPVersion(
		_In_ PNPCAP_FILTER_MODULE pFiltMod,
		_In_reads_bytes_(buflen) PVOID pBuf,
		_In_ ULONG buflen)
{
	int ret = NPF_INJECT_OTHER;
	UINT uCmp = 0;

	if (pFiltMod->RawIP && NT_VERIFY(buflen > 1))
	{
		uCmp = *(PUCHAR)pBuf & 0xf0;
	}
	else if (pFiltMod->Loopback)
	{
		if (g_pDriverExtension->bDltNullMode)
		{
			uCmp = ((PDLT_NULL_HEADER)pBuf)->null_type;
		}
		else
		{
			uCmp = RtlUshortByteSwap(((PETHER_HEADER)pBuf)->ether_type);
		}
	}

	switch(uCmp)
	{
		case 0x40:
		case DLTNULLTYPE_IP:
		case ETHERTYPE_IP:
			ret = NPF_INJECT_IPV4;
			break;
		case 0x60:
		case DLTNULLTYPE_IPV6:
		case ETHERTYPE_IPV6:
			ret = NPF_INJECT_IPV6;
			break;
		default:
			ret = NPF_INJECT_OTHER;
			break;
	}
	return ret;
}

_Use_decl_annotations_
NTSTATUS
NPF_Write(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
	)
{
	POPEN_INSTANCE		Open;
	ULONG				SendFlags = 0;
	PNET_BUFFER_LIST	pNetBufferList = NULL;
	ULONG				NumSends;
	ULONG numSentPackets = 0;
	ULONG buflen = 0;
	PVOID pBuf = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	PMDL TmpMdl = NULL;
	BOOLEAN IrpWasPended = FALSE;
	int npf_inject_type = NPF_INJECT_OTHER;

	UNREFERENCED_PARAMETER(DeviceObject);
	TRACE_ENTER();

	/* Validate */
	Status = NPF_ValidateIoIrp(Irp, &Open, &pBuf, &buflen);
	if (Status != STATUS_SUCCESS)
	{
		Open = NULL;
		goto NPF_Write_End;
	}

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN))
	{
		// Write requires an attached adapter.
		Status = (Open->OpenStatus <= OpenDetached
					? STATUS_DEVICE_REMOVED
					: STATUS_CANCELLED);
		Open = NULL;
		goto NPF_Write_End;
	}

	// Failures after this point must call NPF_StopUsingOpenInstance
	NumSends = Open->Nwrites;
	if (NumSends == 0)
	{
		Status = STATUS_SUCCESS;
		goto NPF_Write_End;
	}

	if (buflen == 0)
	{
		Status = STATUS_INVALID_PARAMETER;
		goto NPF_Write_End;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->pFiltMod->MaxFrameSize == 0)
	{
		// TODO: better status code
		Status = STATUS_UNSUCCESSFUL;
		goto NPF_Write_End;
	}

	// Check that the frame size is smaller than the MTU
	if (buflen > Open->pFiltMod->MaxFrameSize)
	{
		// TODO: better status code
		Status = STATUS_UNSUCCESSFUL;
		goto NPF_Write_End;
	}

	INFO_DBG(
		"Max frame size = %u, packet size = %u",
		Open->pFiltMod->MaxFrameSize,
		buflen);

	// WinPcap emulation: loop back injected packets if anyone's listening.
	// Except when NPF_DISABLE_LOOPBACK is chosen, then don't loop back.
	if (!Open->SkipSentPackets)
	{
		SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;
	}

	npf_inject_type = NPF_GetIPVersion(Open->pFiltMod, pBuf, buflen);
	numSentPackets = 0;

	while (numSentPackets < NumSends)
	{
		if (NumSends - numSentPackets == 1) 
		{
			// Last packet; use the IRP's buffer and pend it.
			TmpMdl = Irp->MdlAddress;
			IoMarkIrpPending(Irp);
			IrpWasPended = TRUE;
		}
		else
		{
			// We will need to make a copy of the buffer for each additional send
			TmpMdl = NPF_CloneBufferToMdl(Open->pFiltMod, pBuf, buflen);
			if (TmpMdl == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
		}

		Status = NPF_AllocateNBL(Open->pFiltMod,
				TmpMdl,
				buflen,
				&pNetBufferList);

		if (!NT_SUCCESS(Status))
		{
			// Alloc failure, abandon ship
			break;
		}
		// Otherwise, TmpMdl is aliased via pNetBufferList
		TmpMdl = NULL;

		// Mark packet as necessary
		if (npf_inject_type == NPF_INJECT_IPV4)
		{
			NdisSetNblFlag(pNetBufferList, NDIS_NBL_FLAGS_IS_IPV4);
			NET_BUFFER_LIST_INFO(pNetBufferList, NetBufferListFrameType) = (PVOID)RtlUshortByteSwap(ETHERTYPE_IP);
		}
		else if (npf_inject_type == NPF_INJECT_IPV6)
		{
			NdisSetNblFlag(pNetBufferList, NDIS_NBL_FLAGS_IS_IPV6);
			NET_BUFFER_LIST_INFO(pNetBufferList, NetBufferListFrameType) = (PVOID)RtlUshortByteSwap(ETHERTYPE_IPV6);
		}

		RESERVED(pNetBufferList)->pState = NULL;
		if (IrpWasPended)
		{
			// This is the only NBL that uses the IRP's buffer. Let SendComplete know it should complete the IRP, too.
			RESERVED(pNetBufferList)->pIrp = Irp;
			RESERVED(pNetBufferList)->FreeBufAfterWrite = FALSE;
		}
		else
		{
			// This NBL uses our own buffer copy. SendComplete should free it, but not complete the IRP until we're done sending.
			RESERVED(pNetBufferList)->pIrp = NULL;
			RESERVED(pNetBufferList)->FreeBufAfterWrite = TRUE;
		}

		//receive the packets before sending them

		// Used to avoid capturing loopback injected traffic here because it's captured later, but now I do it here and avoid capturing it later.
		NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, NPF_IRQL_UNKNOWN);

		pNetBufferList->SourceHandle = Open->pFiltMod->AdapterHandle;

		// Recognize IEEE802.1Q tagged packet, as no many adapters support VLAN tag packet sending, no much use for end users,
		// and this code examines the data which lacks efficiency, so I left it commented, the sending part is also unfinished.
		// This code refers to Win10Pcap at https://github.com/SoftEtherVPN/Win10Pcap.
// 			if (Open->pFiltMod->Loopback == FALSE)
// 			{
// 				PUCHAR pHeaderBuffer;
// 				UINT iFres;
//
// 				BOOLEAN withVlanTag = FALSE;
// 				UINT VlanID = 0;
// 				UINT VlanUserPriority = 0;
// 				UINT VlanCanFormatID = 0;
//
// 				NdisQueryMdl(
// 					Irp->MdlAddress,
// 					&pHeaderBuffer,
// 					&iFres,
// 					NormalPagePriority);
//
// 				// Determine if the packet is IEEE802.1Q tagged packet.
// 				if (iFres >= 18)
// 				{
// 					if (pHeaderBuffer[12] == 0x81 && pHeaderBuffer[13] == 0x00)
// 					{
// 						USHORT pTmpVlanTag = 0;
//
// 						((UCHAR *)(&pTmpVlanTag))[0] = pHeaderBuffer[15];
// 						((UCHAR *)(&pTmpVlanTag))[1] = pHeaderBuffer[14];
//
// 						VlanID = pTmpVlanTag & 0x0FFF;
// 						VlanUserPriority = (pTmpVlanTag >> 13) & 0x07;
// 						VlanCanFormatID = (pTmpVlanTag >> 12) & 0x01;
//
// 						if (VlanID != 0)
// 						{
// 							withVlanTag = TRUE;
// 						}
// 					}
// 				}
// 			}

		//
		//  Call the MAC
		//
		INFO_DBG("NBL %p send: Open = %p, Irp = %p\n", pNetBufferList, Open, Irp);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (Open->pFiltMod->Loopback == TRUE)
		{
			Status = NPF_LoopbackSendNetBufferLists(Open,
				pNetBufferList);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
		}
		else
#endif
#ifdef HAVE_RX_SUPPORT
			if (Open->pFiltMod->SendToRxPath == TRUE)
			{
				INFO_DBG("NPF_Write::SendToRxPath, Open->pFiltMod->AdapterHandle=%p, pNetBufferList=%p\n", Open->pFiltMod->AdapterHandle, pNetBufferList);
				// pretend to receive these packets from network and indicate them to upper layers
				NdisFIndicateReceiveNetBufferLists(
					Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					1,
					0); // If NDIS_RECEIVE_FLAGS_RESOURCES, would need to free pNetBufferList after this.
				// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
				// NdisFIndicateReceiveNetBufferLists do not use __drv_aliasesMem for the 2nd parameter.
				// When Flags (5th parameter) do *not* have NDIS_RECEIVE_FLAGS_RESOURCES set, the NBL is
				// owned by NDIS until it is returned via NPF_ReturnEx (FilterReturnNetBufferLists handler)
				// Therefore we must not free it, and it is not leaking here.
				NPF_AnalysisAssumeAliased(pNetBufferList);
			}
			else
#endif
			{
				NdisFSendNetBufferLists(Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					SendFlags);
			}

		pNetBufferList = NULL;
		numSentPackets ++;
	}


NPF_Write_End:
	if (!NT_SUCCESS(Status))
	{
		WARNING_DBG("NBL %p failed: %#08x; IrpWasPended = %u\n", pNetBufferList, Status, IrpWasPended);
		// Failed somehow. Clean up.
		// If pNetBufferList is not NULL, we need to free it, which will also free TmpMdl
		if (pNetBufferList)
		{
			NPF_FreePackets(Open->pFiltMod, pNetBufferList);
		}
		// Otherwise, clean up TmpMdl directly
		else if (TmpMdl && !IrpWasPended)
		{
			NPF_FreeMdlAndBuffer(TmpMdl);
		}

		if (Open)
		{
			NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);
		}
		Irp->IoStatus.Status = Status;
		Irp->IoStatus.Information = numSentPackets > 0 ? buflen : 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	TRACE_EXIT();

	return (IrpWasPended ? STATUS_PENDING : Status);
}

//-------------------------------------------------------------------

_Use_decl_annotations_
NTSTATUS NPF_BufferedWrite(
	POPEN_INSTANCE Open,
	PUCHAR UserBuff,
	ULONG UserBuffSize,
	BOOLEAN Sync,
	PULONG_PTR Written)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PNET_BUFFER_LIST		pNetBufferList = NULL;
	ULONG					SendFlags = 0;
	UINT					i;
	LARGE_INTEGER			StartTicks = { 0 }, CurTicks, TargetTicks;
	LARGE_INTEGER			TimeFreq;
	struct timeval			BufStartTime = { 0 };
	LONGLONG prev_usec_diff = 0;
	struct dump_bpf_hdr* pHdr = NULL;
	PMDL					TmpMdl;

	TRACE_ENTER();

	INFO_DBG("NPF: BufferedWrite, UserBuff=%p, Size=%u\n", UserBuff, UserBuffSize);

	*Written = 0;

	if (!NPF_StartUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN))
	{
		TRACE_EXIT();
		return (Open->OpenStatus <= OpenDetached
					? STATUS_DEVICE_REMOVED
					: STATUS_CANCELLED);
	}
	NT_ASSERT(Open->pFiltMod != NULL);

	// Sanity check on the user buffer
	if (!NT_VERIFY(UserBuff != NULL) || UserBuffSize < sizeof(struct dump_bpf_hdr))
	{
		Status = STATUS_INVALID_PARAMETER;
		goto NPF_BufferedWrite_End;
	}

	// Check that the MaxFrameSize is correctly initialized
	if (Open->pFiltMod->MaxFrameSize == 0)
	{
		INFO_DBG("NPF_BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");
		Status = STATUS_UNSUCCESSFUL;
		goto NPF_BufferedWrite_End;
	}

	PNPF_BUFFERED_WRITE_STATE pState = ExAllocatePoolWithTag(NPF_NONPAGED, sizeof(NPF_BUFFERED_WRITE_STATE), NPF_BUFFERED_WRITE_TAG);
	if (!pState)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto NPF_BufferedWrite_End;
	}
	pState->PacketsPending = 0;
	NdisInitializeEvent(&pState->WriteCompleteEvent);
	NdisResetEvent(&pState->WriteCompleteEvent);

	// WinPcap emulation: loop back injected packets if anyone's listening.
	// Except when NPF_DISABLE_LOOPBACK is chosen, then don't loop back.
	if (!Open->SkipSentPackets)
	{
		SendFlags |= NDIS_SEND_FLAGS_CHECK_FOR_LOOPBACK;
	}


	pHdr = (struct dump_bpf_hdr *)(UserBuff);

	if (Sync)
	{
		// Retrieve the time references
		StartTicks = KeQueryPerformanceCounter(&TimeFreq);
		BufStartTime.tv_sec = pHdr->ts.tv_sec;
		BufStartTime.tv_usec = pHdr->ts.tv_usec;
	}

	//
	// Main loop: send the buffer to the wire
	//
	ULONG Pos = 0;
	while (TRUE)
	{
		if (Pos >= UserBuffSize)
		{
			// end of buffer
			break;
		}

		if (UserBuffSize - Pos < sizeof(*pHdr))
		{
			// Missing header
			INFO_DBG("NPF_BufferedWrite: not enough data for a dump_bpf_hdr, aborting write.\n");

			Status = STATUS_INVALID_USER_BUFFER;
			break;
		}
		pHdr = (struct dump_bpf_hdr *)(UserBuff + Pos);
		ULONG ulDataOffset = Pos + sizeof(*pHdr);

		if (pHdr->caplen == 0)
		{
			// Malformed header
			INFO_DBG("NPF_BufferedWrite: invalid caplen, aborting write.\n");

			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (pHdr->caplen > Open->pFiltMod->MaxFrameSize
			|| pHdr->caplen > (UserBuffSize - ulDataOffset))
		{
			Status = STATUS_PORT_MESSAGE_TOO_LONG;
			break;
		}

		int npf_inject_type = NPF_GetIPVersion(Open->pFiltMod, UserBuff + ulDataOffset, pHdr->caplen);

		/* Copy packet data to non-paged memory, otherwise we induce
		 * page faults in NIC drivers: http://issues.nmap.org/1398
		 * TODO: Try mapping the data without copying; system buffer ought to be nonpaged already with Buffered IO. */
		TmpMdl = NPF_CloneBufferToMdl(Open->pFiltMod, UserBuff + ulDataOffset, pHdr->caplen);

		if (TmpMdl == NULL)
		{
			// Unable to map the memory: packet lost
			INFO_DBG("NPF_BufferedWrite: unable to allocate the MDL.\n");

			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// Allocate a packet from our free list
		Status = NPF_AllocateNBL(Open->pFiltMod,
				TmpMdl,
				pHdr->caplen,
				&pNetBufferList);
		if (!NT_SUCCESS(Status))
		{
			//  No more free packets
			
			INFO_DBG("NPF_BufferedWrite: no more free packets, returning.\n");

			NPF_FreeMdlAndBuffer(TmpMdl);

			break;
		}
		NT_ASSERT(pNetBufferList != NULL);

		// Mark packet as necessary
		if (npf_inject_type == NPF_INJECT_IPV4)
		{
			NdisSetNblFlag(pNetBufferList, NDIS_NBL_FLAGS_IS_IPV4);
			NET_BUFFER_LIST_INFO(pNetBufferList, NetBufferListFrameType) = (PVOID)RtlUshortByteSwap(ETHERTYPE_IP);
		}
		else if (npf_inject_type == NPF_INJECT_IPV6)
		{
			NdisSetNblFlag(pNetBufferList, NDIS_NBL_FLAGS_IS_IPV6);
			NET_BUFFER_LIST_INFO(pNetBufferList, NetBufferListFrameType) = (PVOID)RtlUshortByteSwap(ETHERTYPE_IPV6);
		}

		// The packet has a buffer that needs to be freed after every single write
		RESERVED(pNetBufferList)->FreeBufAfterWrite = TRUE;
		RESERVED(pNetBufferList)->pIrp = NULL;
		RESERVED(pNetBufferList)->pState = pState;
		pNetBufferList->SourceHandle = Open->pFiltMod->AdapterHandle;

		TmpMdl->Next = NULL;

		if (Sync)
		{
			// Save the current time stamp counter
			CurTicks = KeQueryPerformanceCounter(&TimeFreq);
			// Time offset of this packet from the first one (usecs)
			LONGLONG usec_diff = ((LONGLONG)pHdr->ts.tv_sec - BufStartTime.tv_sec) * 1000000
				+ pHdr->ts.tv_usec - BufStartTime.tv_usec;
			if (usec_diff < prev_usec_diff) {
				// Parallel processing of packets can result in minor timestamp jitter.
				// If the difference is <1ms, warn in debug mode but just proceed with sending.
				// If the difference is >1ms, produce an error.
				WARNING_DBG("timestamp %08x.%08x out of order by %lld usecs!\n",
						pHdr->ts.tv_sec, pHdr->ts.tv_usec, prev_usec_diff - usec_diff);
				if (prev_usec_diff - usec_diff > 1000) {
					NPF_FreePackets(Open->pFiltMod, pNetBufferList);
					Status = RPC_NT_INVALID_TIMEOUT;
					break;
				}
				// else continue to send.
				// Do not overwrite prev_usec_diff, since we've already waited to sync with that timestamp.
			}
			else
			{
				// packet is in order; check if we should delay or return.
				prev_usec_diff = usec_diff;
				// Release the application if it has been or would be blocked for more than 1 second
				if (usec_diff > 1000000)
				{
					INFO_DBG("timestamp elapsed, returning.\n");

					NPF_FreePackets(Open->pFiltMod, pNetBufferList);
					break;
				}

				// Calculate the target QPC ticks to send the next packet
				TargetTicks.QuadPart = StartTicks.QuadPart + usec_diff * TimeFreq.QuadPart / 1000000;

				// If we need to wait, do so
				if (CurTicks.QuadPart < TargetTicks.QuadPart)
				{
					// whole microseconds remaining.
					// Explicit cast ok since condition above ensures this will be at most 1000000ms.
					i = (UINT)(((TargetTicks.QuadPart - CurTicks.QuadPart) * 1000000) / TimeFreq.QuadPart);
					NT_ASSERT(i < 1000000);
					if (i >= 50)
					{
						NdisMSleep(i);
					}
					else
					{
						NdisStallExecution(i);
					}
				}
			}
		}

		//receive the packets before sending them
		NPF_DoTap(Open->pFiltMod, pNetBufferList, Open, NPF_IRQL_UNKNOWN);

		NpfInterlockedIncrement(&pState->PacketsPending);
		NdisResetEvent(&pState->WriteCompleteEvent);
		//
		// Call the MAC
		//
		INFO_DBG("NBL %p Buffered send: Open = %p, pState = %p\n", pNetBufferList, Open, pState);
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
		if (Open->pFiltMod->Loopback == TRUE)
		{
			Status = NPF_LoopbackSendNetBufferLists(Open,
				pNetBufferList);
			if (!NT_SUCCESS(Status))
			{
				NpfInterlockedDecrement(&pState->PacketsPending);
				NPF_FreePackets(Open->pFiltMod, pNetBufferList);
				break;
			}
		}
		else
#endif
#ifdef HAVE_RX_SUPPORT
			if (Open->pFiltMod->SendToRxPath == TRUE)
			{
				INFO_DBG("NPF_BufferedWrite::SendToRxPath, Open->pFiltMod->AdapterHandle=%p, pNetBufferList=%p\n", Open->pFiltMod->AdapterHandle, pNetBufferList);
				// pretend to receive these packets from network and indicate them to upper layers
				NdisFIndicateReceiveNetBufferLists(
					Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					1,
					0); // If NDIS_RECEIVE_FLAGS_RESOURCES, would need to free pNetBufferList after this.
				// WORKAROUND: We are calling NPF_AnalysisAssumeAliased here because the annotations for
				// NdisFIndicateReceiveNetBufferLists do not use __drv_aliasesMem for the 2nd parameter.
				// When Flags (5th parameter) do *not* have NDIS_RECEIVE_FLAGS_RESOURCES set, the NBL is
				// owned by NDIS until it is returned via NPF_ReturnEx (FilterReturnNetBufferLists handler)
				// Therefore we must not free it, and it is not leaking here.
				NPF_AnalysisAssumeAliased(pNetBufferList);
			}
			else
#endif
			{
				NdisFSendNetBufferLists(Open->pFiltMod->AdapterHandle,
					pNetBufferList,
					NDIS_DEFAULT_PORT_NUMBER,
					SendFlags);
			}

		Pos = ulDataOffset + pHdr->caplen;
	}

	while (pState->PacketsPending > 0) {
		NdisWaitEvent(&pState->WriteCompleteEvent, 0);
	}
	ExFreePoolWithTag(pState, NPF_BUFFERED_WRITE_TAG);

	*Written = Pos;

NPF_BufferedWrite_End:
	NPF_StopUsingOpenInstance(Open, OpenRunning, NPF_IRQL_UNKNOWN);

	TRACE_EXIT();
	return Status;
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_FreePackets(
	PNPCAP_FILTER_MODULE pFiltMod,
	PNET_BUFFER_LIST    NetBufferLists
	)
	/*++

	Routine Description:

	Free our own initiated Net Buffer Lists.

	Arguments:

	NetBufferLists          - a chain of NBLs that are being freed

	Return Value:

	NONE

	--*/
{
	BOOLEAN				FreeBufAfterWrite;
	PNET_BUFFER_LIST    pNetBufList = NetBufferLists;
	PNET_BUFFER         Currbuff;

/*	TRACE_ENTER();*/

	FreeBufAfterWrite = RESERVED(pNetBufList)->FreeBufAfterWrite;

	if (FreeBufAfterWrite)
	{
		//
		// Packet sent by NPF_BufferedWrite()
		//

		//Free the NBL allocate by myself
		Currbuff = NET_BUFFER_LIST_FIRST_NB(pNetBufList);
		while (Currbuff)
		{
			NPF_FreeMdlAndBuffer(NET_BUFFER_FIRST_MDL(Currbuff));
			Currbuff = NET_BUFFER_NEXT_NB(Currbuff);
		}
	}

#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	if (pFiltMod->Loopback)
	{
		FwpsFreeNetBufferList(pNetBufList);
		// FwpsFreeNetBufferList lacks the __drv_freesMem SAL annotation needed
		NPF_AnalysisAssumeFreed(pNetBufList);
	}
	else
#endif
	{
		NdisFreeNetBufferList(pNetBufList); //Free NBL
	}

/*	TRACE_EXIT();*/
}

//-------------------------------------------------------------------

_Use_decl_annotations_
VOID
NPF_SendCompleteEx(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	ULONG               SendCompleteFlags
	)
/*++

Routine Description:

	Send complete handler

	This routine is invoked whenever the lower layer is finished processing 
	sent NET_BUFFER_LISTs.  If the filter does not need to be involved in the
	send path, you should remove this routine and the FilterSendNetBufferLists
	routine.  NDIS will pass along send packets on behalf of your filter more 
	efficiently than the filter can.

Arguments:

	FilterModuleContext     - our filter context
	NetBufferLists          - a chain of NBLs that are being returned to you
	SendCompleteFlags       - flags (see documentation)

Return Value:

	 NONE

--*/
{
	PNET_BUFFER_LIST    pNetBufList = NULL;
	PNET_BUFFER_LIST    pPrevNetBufList = NULL;
	PNPCAP_FILTER_MODULE pFiltMod = (PNPCAP_FILTER_MODULE) FilterModuleContext;
	BOOLEAN bAtDispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendCompleteFlags);

	TRACE_ENTER();
	/* This callback is used for NDIS LWF as well as WFP/loopback */

	//
	// If your filter injected any send packets into the datapath to be sent,
	// you must identify their NBLs here and remove them from the chain.  Do not
	// attempt to send-complete your NBLs up to the higher layer.
	//

	pNetBufList = NetBufferLists;
	while (pNetBufList != NULL)
	{
		// Keep track of this one
		PNET_BUFFER_LIST pNBL = pNetBufList;
		// Point to the next one
		pNetBufList = NET_BUFFER_LIST_NEXT_NBL(pNetBufList);

		if (pNBL->SourceHandle != pFiltMod->AdapterHandle)
		{
			// No match, just move down.
			pPrevNetBufList = pNBL;
			continue;
		}
		// this is our self-sent packets

		// Remove this one from the chain and move down.
		if (pPrevNetBufList == NULL) {
			// head of list, repoint NetBufferLists
			NetBufferLists = pNetBufList;
		}
		else {
			NET_BUFFER_LIST_NEXT_NBL(pPrevNetBufList) = pNetBufList;
		}
		NET_BUFFER_LIST_NEXT_NBL(pNBL) = NULL;

		PIRP pIrp = RESERVED(pNBL)->pIrp;
		PNPF_BUFFERED_WRITE_STATE pState = RESERVED(pNBL)->pState;
		INFO_DBG("NBL %p complete: pIrp = %p, pState = %p\n", pNBL, pIrp, pState);
		if (pIrp != NULL)
		{
			PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
			POPEN_INSTANCE pOpen = IrpSp->FileObject->FsContext;
			NT_ASSERT(pOpen->pFiltMod == pFiltMod);

			NPF_StopUsingOpenInstance(pOpen, OpenRunning, bAtDispatchLevel);

			NDIS_STATUS Status = NET_BUFFER_LIST_STATUS(pNBL);
			pIrp->IoStatus.Status = Status;
			if (NDIS_STATUS_SUCCESS == Status)
			{
				pIrp->IoStatus.Information = IrpSp->Parameters.Write.Length;
			}
			else
			{
				WARNING_DBG("NBL status = %#08x\n", Status);
				pIrp->IoStatus.Information = 0;
			}
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		}
		if (pState != NULL)
		{
			if (0 == NpfInterlockedDecrement(&pState->PacketsPending))
			{
				INFO_DBG("Buffered Write complete\n");
				NdisSetEvent(&pState->WriteCompleteEvent);
			}
		}

		NPF_FreePackets(pFiltMod, pNBL);
	}

	// Send complete any NBLS that are left (didn't originate with us)
	if (NetBufferLists != NULL) {
		NdisFSendNetBufferListsComplete(pFiltMod->AdapterHandle, NetBufferLists, SendCompleteFlags);
	}

	TRACE_EXIT();
}

//-------------------------------------------------------------------

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
void NTAPI NPF_NetworkInjectionComplete(
	_In_ VOID* pContext,
	_Inout_ NET_BUFFER_LIST* pNetBufferList,
	_In_ BOOLEAN dispatchLevel
	)
{
	TRACE_ENTER();

	/* This method should only be used for Loopback (for now, though see #516) */
	NT_ASSERT(((PNPCAP_FILTER_MODULE) pContext)->Loopback);

	// Don't need to Retreat the data offset since the completion/free functions ignore CurrentMdl
	// Call complete function manually just like NDIS callback.
	NPF_SendCompleteEx(pContext, pNetBufferList, dispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);

	TRACE_EXIT();
	return;
}

_Use_decl_annotations_
NTSTATUS
NPF_LoopbackSendNetBufferLists(
	POPEN_INSTANCE pOpen,
	PNET_BUFFER_LIST NetBufferList
	)
{
	ULONG bytesAdvanced = 0;
	HANDLE hInjectionHandle = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TRACE_ENTER();
	NT_ASSERT(pOpen->bLoopback);

	if (NdisTestNblFlag(NetBufferList, NDIS_NBL_FLAGS_IS_IPV4))
	{
		hInjectionHandle = g_pDriverExtension->hInject[NPF_INJECT_IPV4];
	}
	else if (NdisTestNblFlag(NetBufferList, NDIS_NBL_FLAGS_IS_IPV6))
	{
		hInjectionHandle = g_pDriverExtension->hInject[NPF_INJECT_IPV6];
	}
	else
	{
		INFO_DBG("NPF_LoopbackSendNetBufferLists: invalid NBL (NblFlags not IPv4 or IPv6)\n");
		TRACE_EXIT();
		return STATUS_PROTOCOL_NOT_SUPPORTED;
	}

	bytesAdvanced = g_pDriverExtension->bDltNullMode ? DLT_NULL_HDR_LEN : ETHER_HDR_LEN;

	if (!NT_VERIFY(hInjectionHandle != NULL))
	{
		INFO_DBG("NPF_LoopbackSendNetBufferLists: invalid injection handle\n");
		TRACE_EXIT();
		return STATUS_INVALID_HANDLE;
	}

	NdisAdvanceNetBufferListDataStart(NetBufferList, bytesAdvanced, FALSE, NULL);

	status = FwpsInjectNetworkSendAsync(hInjectionHandle,
			NULL,
			0,
			UNSPECIFIED_COMPARTMENT_ID,
			NetBufferList,
			NPF_NetworkInjectionComplete,
			pOpen->pFiltMod);
	if (NT_SUCCESS(status))
	{
		// Fwps* functions don't have annotations about aliasing or freeing memory. Have to do it ourselves.
		NPF_AnalysisAssumeAliased(NetBufferList);
	}
	else
	{
		WARNING_DBG("FwpsInjectNetworkSendAsync failed: %#08x; NBL = %p\n", status, NetBufferList);
	}

	TRACE_EXIT();
	return status;
}
#endif
