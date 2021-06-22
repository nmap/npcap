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

	CalloutInstall.cpp

Abstract:

	This is used for installing the Windows Filtering Platform (WFP) callout driver, for capturing the loopback traffic, the used INF file is: npf(npcap)_wfp.inf

--*/

#pragma comment(lib, "advpack.lib")

#include "CalloutInstall.h"
#include "ProtInstall.h"
#include "debug.h"

#include <advpub.h>
#include <tchar.h>

BOOL isFileExist(TCHAR szFileFullPath[])
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	TRACE_ENTER();

	hFind = FindFirstFile(szFileFullPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		TRACE_PRINT2("FindFirstFile: error, szFileFullPath = %s, errCode = 0x%08x.", szFileFullPath, GetLastError());
		TRACE_EXIT();
		return FALSE;
	}
	else
	{
		TRACE_PRINT1("FindFirstFile: succeed, szFileFullPath = %s.", szFileFullPath);
		FindClose(hFind);
		TRACE_EXIT();
		return TRUE;
	}
}

BOOL InstallWFPCallout()
{
	DWORD nResult;

	TRACE_ENTER();

	// Get Path to Service INF File
	// ----------------------------
	// The INF file is assumed to be in the same folder as this application...
	TCHAR szFileFullPath[_MAX_PATH];
	nResult = GetWFPCalloutInfFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		TRACE_PRINT("Unable to get WFP callout INF file path");
		TRACE_EXIT();
		return FALSE;
	}

	if (!isFileExist(szFileFullPath))
	{
		TRACE_PRINT("WFP callout INF file doesn't exist");
		TRACE_EXIT();
		return FALSE;
	}

	TCHAR szCmd[_MAX_PATH * 2];
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("%s,DefaultInstall,,36,N"), szFileFullPath);
	TRACE_PRINT1("LaunchINFSectionEx: executing, szCmd = %s.", szCmd);
	if (LaunchINFSectionEx(NULL, NULL, szCmd, 0) == E_FAIL)
	{
		TRACE_PRINT("WFP INF install failed!");
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}

BOOL UninstallWFPCallout()
{
	DWORD nResult;

	TRACE_ENTER();

	// Get Path to Service INF File
	// ----------------------------
	// The INF file is assumed to be in the same folder as this application...
	TCHAR szFileFullPath[_MAX_PATH];
	nResult = GetWFPCalloutInfFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		TRACE_PRINT("Unable to get WFP callout INF file path");
		TRACE_EXIT();
		return FALSE;
	}

	if (!isFileExist(szFileFullPath))
	{
		TRACE_PRINT("WFP callout INF file doesn't exist");
		TRACE_EXIT();
		return FALSE;
	}

	TCHAR szCmd[_MAX_PATH * 2];
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("%s,DefaultUninstall,,36,N"), szFileFullPath);
	TRACE_PRINT1("LaunchINFSectionEx: executing, szCmd = %s.", szCmd);
	if (LaunchINFSectionEx(NULL, NULL, szCmd, 0) == E_FAIL)
	{
		TRACE_PRINT("WFP INF removal failed!");
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}
