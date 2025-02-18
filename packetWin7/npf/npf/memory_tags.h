/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2025 by Nmap Software LLC ("The Nmap Project").  All
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
#ifndef __NPCAP_MEMORY_TAGS_H
#define __NPCAP_MEMORY_TAGS_H


// Npcap doesn't need executable allocations
#if(NTDDI_VERSION >= NTDDI_WIN8)
#define NPF_NONPAGED NonPagedPoolNx
#else
/* NonPagedPoolNx is not available for Win7, so avoid warning about it. */
#pragma warning(disable: 30030)
#define NPF_NONPAGED NonPagedPool
#endif
_Must_inspect_result_
_Success_(return != NULL)
__drv_allocatesMem(mem)
inline DECLSPEC_RESTRICT PVOID NPF_AllocateZeroNonpaged(SIZE_T NumBytes, ULONG Tag)
{
#if(NTDDI_VERSION < NTDDI_WIN10_VB) // Windows 10 2004
#pragma warning(suppress: 4996)
	PVOID ret = ExAllocatePoolWithTag(NPF_NONPAGED, NumBytes, Tag);
	if (ret != NULL)
	{
		RtlZeroMemory(ret, NumBytes);
	}
	return ret;
#else
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, NumBytes, Tag);
#endif
}

inline DECLSPEC_RESTRICT PVOID NPF_AllocateZeroPaged(SIZE_T NumBytes, ULONG Tag)
{
#if(NTDDI_VERSION < NTDDI_WIN10_VB) // Windows 10 2004
#pragma warning(suppress: 4996)
	PVOID ret = ExAllocatePoolWithTag(PagedPool, NumBytes, Tag);
	if (ret != NULL)
	{
		RtlZeroMemory(ret, NumBytes);
	}
	return ret;
#else
	return ExAllocatePool2(POOL_FLAG_PAGED, NumBytes, Tag);
#endif
}

// NPCAP_DRIVER_EXTENSION "NpDE"
#define NPF_DRIVER_EXTENSION_TAG 'EDpN'
// UNICODE_STRING::Buffer "NpUB"
#define NPF_UNICODE_BUFFER_TAG 'BUpN'
// Things that are freed within the same function they are allocated in.
// This should probably be used for PagedPool only. "NpST"
#define NPF_SHORT_TERM_TAG 'TSpN'
// BPF filter "NpPF"
#define NPF_BPF_TAG 'FPpN'
// User-submitted OID requests "NpoU"
#define NPF_USER_OID_TAG 'UopN'
// Internally-generated OID requests "NpoI"
#define NPF_INTERNAL_OID_TAG 'IopN'
// Cloned OID requests "NpoC"
#define NPF_CLONE_OID_TAG 'CopN'
// DEVICE_EXTENSION::InternalRequestPool "NpRP"
#define NPF_REQ_POOL_TAG 'PRpN'
// OPEN_INSTANCE "NpOP"
#define NPF_OPEN_TAG 'POpN'
// NPCAP_FILTER_MODULE "NpFM"
#define NPF_FILTMOD_TAG 'MFpN'
// NPCAP_NB_COPIES::Buffer packet data "NpPD"
#define NPF_PACKET_DATA_TAG 'DPpN'
// DEVICE_EXTENSION::NBLCopyPool "NpNL"
#define NPF_NBLC_POOL_TAG 'LNpN'
// DEVICE_EXTENSION::NBCopiesPool "NpNB"
#define NPF_NBC_POOL_TAG 'BNpN'
// DEVICE_EXTENSION::SrcNBPool "NpSN"
#define NPF_SRCNB_POOL_TAG 'NSpN'
// DEVICE_EXTENSION::Dot11HeaderPool and NPCAP_FILTER_MODULE::DataRateMappingTable "Np11"
#define NPF_DOT11_POOL_TAG '11pN'
// DEVICE_EXTENSION::CapturePool "NpCD"
#define NPF_CAP_POOL_TAG 'DCpN'
// NPF_BufferedWrite packet data "NpBW"
#define NPF_BUFFERED_WRITE_TAG 'WBpN'
// Loopback capture packet copy "NpBL"
#define NPF_LOOPBACK_COPY_TAG 'LBpN'
// NPCAP_FILTER_MODULE::PacketPool "NpPP"
#define NPF_PACKET_POOL_TAG 'PPpN'

#endif
