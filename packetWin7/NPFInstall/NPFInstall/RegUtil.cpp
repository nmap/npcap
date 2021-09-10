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
/*++

Module Name:

RegUtil.cpp

Abstract:

This is used for operating on registry.

--*/

#include <Netcfgx.h>

#include <iostream>
#include <atlbase.h> // CComPtr
#include <devguid.h> // GUID_DEVCLASS_NET, ...

#include "RegUtil.h"

#include "debug.h"

#define BUF_SIZE 255

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, LPCTSTR strDeviceName, DWORD dwSamDesired)
{
	LONG Status;
	HKEY hNpcapKey;

	TRACE_ENTER();
	TRACE_PRINT4("WriteStrToRegistry: executing, strSubKey = %s, strValueName = %s, strDeviceName = %s, dwSamDesired = 0x%08x.",
		strSubKey, strValueName, strDeviceName, dwSamDesired);

	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strSubKey, 0, dwSamDesired | KEY_WOW64_32KEY, &hNpcapKey);
	if (Status == ERROR_SUCCESS)
	{
		Status = RegSetValueEx(hNpcapKey, strValueName, 0, REG_SZ, (PBYTE)strDeviceName, (lstrlen(strDeviceName) + 1) * sizeof(TCHAR));
		if (Status != ERROR_SUCCESS)
		{
			TRACE_PRINT1("RegSetValueEx: error, errCode = 0x%08x.", Status);
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		RegCloseKey(hNpcapKey);
	}
	else
	{
		TRACE_PRINT1("RegOpenKeyEx: error, errCode = 0x%08x.", Status);
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}

BOOL IncrementRegistryDword(LPCTSTR strSubKey, LPCTSTR strValueName, DWORD maxValue)
{
	LONG Status;
	HKEY hNpcapKey;
	DWORD dwCurrent;
	DWORD dwSize;
	dwSize = sizeof(dwCurrent);

	TRACE_ENTER();
	TRACE_PRINT2("IncrementRegistryDword: executing, strSubKey = %s, strValueName = %s",
		strSubKey, strValueName);

	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strSubKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hNpcapKey);
	if (Status == ERROR_SUCCESS)
	{
		Status = RegGetValue(hNpcapKey, NULL, strValueName, RRF_RT_REG_DWORD, NULL, &dwCurrent, &dwSize);
		if (Status != ERROR_SUCCESS)
		{
			TRACE_PRINT1("RegGetValue: error, errCode = 0x%08x.", Status);
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		if (dwCurrent >= maxValue)
		{
			TRACE_PRINT2("Current value %d is greater than max value %d", dwCurrent, maxValue);
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		dwCurrent += 1;
		Status = RegSetValueEx(hNpcapKey, strValueName, 0, REG_DWORD, (PBYTE)&dwCurrent, sizeof(dwCurrent));
		if (Status != ERROR_SUCCESS)
		{
			TRACE_PRINT1("RegSetValueEx: error, errCode = 0x%08x.", Status);
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		RegCloseKey(hNpcapKey);
	}
	else
	{
		TRACE_PRINT1("RegOpenKeyEx: error, errCode = 0x%08x.", Status);
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}

BOOL DeleteValueFromRegistry(LPCTSTR strSubKey, LPCTSTR strValueName)
{
	LONG Status;
	HKEY hNpcapKey;

	TRACE_ENTER();
	TRACE_PRINT2("DeleteValueFromRegistry: executing, strSubKey = %s, strValueName = %s, dwSamDesired = 0x%08x.",
		strSubKey, strValueName);

	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strSubKey, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, &hNpcapKey);
	if (Status == ERROR_SUCCESS)
	{
		Status = RegDeleteValue(hNpcapKey, strValueName);
		if (Status != ERROR_SUCCESS)
		{
			TRACE_PRINT1("RegDeleteValue: error, errCode = 0x%08x.", Status);
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		RegCloseKey(hNpcapKey);
	}
	else
	{
		TRACE_PRINT1("RegOpenKeyEx: error, errCode = 0x%08x.", Status);
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}
