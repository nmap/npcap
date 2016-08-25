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
#define NDISLWF_SERVICE_INF_FILE_WIFI		NDISLWF_SERVICE_INF_FILE L"_wifi"
#define WFP_CALLOUT_INF_FILE				NDISLWF_SERVICE_INF_FILE L"_wfp"
#else
#define NDISLWF_SERVICE_PNP_DEVICE_ID		NPF_ORGAN_NAME "_" NPF_DRIVER_NAME
#define NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI	NDISLWF_SERVICE_PNP_DEVICE_ID L"_WIFI"

#define NDISLWF_SERVICE_INF_FILE			NPF_DRIVER_NAME
#define NDISLWF_SERVICE_INF_FILE_WIFI		NDISLWF_SERVICE_INF_FILE "_wifi"
#define WFP_CALLOUT_INF_FILE				NDISLWF_SERVICE_INF_FILE "_wfp"
#endif

#define APP_NAME							_T(NPF_DRIVER_NAME)

#ifdef __cplusplus
extern "C"
{
#endif

	DWORD InstallDriver(BOOL bWifiOrNormal);
	DWORD UninstallDriver(BOOL bWifiOrNormal);
	BOOL RenableBindings(BOOL bWifiOrNormal);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////////////////
//// Registry Key Strings
//

DWORD GetServiceInfFilePath(LPTSTR lpFilename, DWORD nSize, BOOL bWifiOrNormal);
DWORD GetWFPCalloutInfFilePath(LPTSTR lpFilename, DWORD nSize);
DWORD GetServiceSysFilePath(LPTSTR lpFilename, DWORD nSize);

#endif // _PROTINSTALL_H_
