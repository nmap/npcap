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
#ifndef _PROTINSTALL_H_
#define _PROTINSTALL_H_

// Copyright And Configuration Management ----------------------------------
//
//  			  NDISLWF String Definitions - ProtInstall.h
//
//  				Companion Sample Code for the Article
//
//  			  "Installing NDIS Protocols Programatically"
//  				   Published on http://www.ndis.com
//
//   Copyright (c) 2004-2006 Printing Communications Associates, Inc. (PCAUSA)
//  						http://www.pcausa.com
//
// GPL software is an abomination. Far from being free, it is available ONLY
// to members of the "GPL Club". If you don't want to join the club, then GPL
// software is poison.
//
// This software IS free software under the terms of a BSD-style license:
//
// The right to use this code in your own derivative works is granted so long
// as 1.) your own derivative works include significant modifications of your
// own, 2.) you retain the above copyright notices and this paragraph in its
// entirety within sources derived from this code.
//
// This product includes software developed by PCAUSA. The name of PCAUSA
// may not be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// End ---------------------------------------------------------------------

#pragma warning(disable: 4311 4312)

//
// ATTENTION!!!
// ------------
// If you make changes to the NDISLWF string definitions you must also make
// matching changes in this file.
//

////////////////////////////////////////////////////////////////////////////
//// Device Naming String Definitions
//

#include "..\..\Common\WpcapNames.h"

//
// Driver INF File and PnP ID Names
//
#ifdef UNICODE
#define NDISLWF_SERVICE_PNP_DEVICE_ID		NPF_ORGAN_NAME_WIDECHAR L"_" NPF_DRIVER_NAME_WIDECHAR
#define NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI	NDISLWF_SERVICE_PNP_DEVICE_ID L"_WIFI"

#define NDISLWF_SERVICE_INF_FILE			NPF_DRIVER_NAME_WIDECHAR
#define WFP_CALLOUT_INF_FILE				NDISLWF_SERVICE_INF_FILE L"_wfp"
#else
#define NDISLWF_SERVICE_PNP_DEVICE_ID		NPF_ORGAN_NAME "_" NPF_DRIVER_NAME
#define NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI	NDISLWF_SERVICE_PNP_DEVICE_ID "_WIFI"

#define NDISLWF_SERVICE_INF_FILE			NPF_DRIVER_NAME
#define WFP_CALLOUT_INF_FILE				NDISLWF_SERVICE_INF_FILE "_wfp"
#endif

#define APP_NAME							_T(NPF_DRIVER_NAME)

#ifdef __cplusplus
extern "C"
{
#endif

	BOOL InstallDriver();
	BOOL UninstallDriver();
	BOOL RenableBindings();

#ifdef __cplusplus
}
#endif

VOID ErrMsg(HRESULT hr, LPCTSTR  lpFmt, ...);

/////////////////////////////////////////////////////////////////////////////
//// Registry Key Strings
//

DWORD GetServiceInfFilePath(LPTSTR lpFilename, DWORD nSize);
DWORD GetWFPCalloutInfFilePath(LPTSTR lpFilename, DWORD nSize);
DWORD GetServiceSysFilePath(LPTSTR lpFilename, DWORD nSize);

#endif // _PROTINSTALL_H_
