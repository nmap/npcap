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
#pragma warning(disable: 4005 4201 4324)

#ifndef _WIN64
	#define WIN32
#endif
#define WIN_NT_DRIVER

#define NTDDI_WIN7 0x06010000
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define NDIS_SUPPORT_NDIS620 1
#define NDIS620 1 // NDIS 6.2 version (for Windows 7 and later)
#else
#define NDIS_SUPPORT_NDIS6 1
#define NDIS60 1 // NDIS 6.0 version (for Windows Vista and later)
#endif

// Specify which version of the NDIS contract you will use here.
// In many cases, 6.0 is the best choice.  You only need to select a later
// version if you need a feature that is not available in 6.0.
//
// Legal values include:
//    6.0  Available starting with Windows Vista RTM
//    6.1  Available starting with Windows Vista SP1 / Windows Server 2008
//    6.20 Available starting with Windows 7 / Windows Server 2008 R2
//    6.30 Available starting with Windows 8 / Windows Server "8"
// Or, just use NDIS_FILTER_MAJOR_VERSION / NDIS_FILTER_MINOR_VERSION
// to pick up whatever version is defined by your build system
// (for example, "-DNDIS630").

#define NPF_ALLOC_TAG '1234'
#define NPF_REQUEST_ID '5678'

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

#define WIN9X_COMPAT_SPINLOCK

#include <ntddk.h>
#include <ndis.h>
#include <wmistr.h>
#include <wdmsec.h>
#include <wdmguid.h>
#include "debug.h"
#include "macros.h"
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

