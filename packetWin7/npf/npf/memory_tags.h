/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
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

// UNICODE_STRING::Buffer
#define NPF_UNICODE_BUFFER_TAG 'BUpN'
// Things that are freed within the same function they are allocated in.
// This should probably be used for PagedPool only.
#define NPF_SHORT_TERM_TAG 'TSpN'
// BPF filter
#define NPF_BPF_TAG 'FPpN'
// User-submitted OID requests
#define NPF_USER_OID_TAG 'UopN'
// Internally-generated OID requests
#define NPF_INTERNAL_OID_TAG 'IopN'
// Cloned OID requests
#define NPF_CLONE_OID_TAG 'CopN'
// DEVICE_EXTENSION::InternalRequestPool
#define NPF_REQ_POOL_TAG 'PRpN'
// OPEN_INSTANCE
#define NPF_OPEN_TAG 'POpN'
// NPCAP_FILTER_MODULE
#define NPF_FILTMOD_TAG 'MFpN'
// DEVICE_EXTENSION::BufferPool
#define NPF_PACKET_DATA_TAG 'DPpN'
// DEVICE_EXTENSION::NBLCopyPool
#define NPF_NBLC_POOL_TAG 'LNpN'
// DEVICE_EXTENSION::NBCopiesPool
#define NPF_NBC_POOL_TAG 'BNpN'
// DEVICE_EXTENSION::SrcNBPool
#define NPF_SRCNB_POOL_TAG 'NSpN'
// DEVICE_EXTENSION::Dot11HeaderPool
#define NPF_DOT11_POOL_TAG '11pN'
// DEVICE_EXTENSION::CapturePool
#define NPF_CAP_POOL_TAG 'DCpN'
// NPF_BufferedWrite packet data
#define NPF_BUFFERED_WRITE_TAG 'WBpN'
// Loopback capture packet copy
#define NPF_LOOPBACK_COPY_TAG 'LBpN'
// NPCAP_FILTER_MODULE::PacketPool
#define NPF_PACKET_POOL_TAG 'PPpN'

#endif
