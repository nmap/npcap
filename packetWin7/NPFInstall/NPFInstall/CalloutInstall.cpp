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
/*++

Module Name:

	CalloutInstall.cpp

Abstract:

	This is used for installing the Windows Filtering Platform (WFP) callout driver, for capturing the loopback traffic, the used INF file is: npf(npcap)_wfp.inf

--*/

#include "CalloutInstall.h"
#include "ProtInstall.h"
#include "debug.h"

#include <SetupAPI.h>
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
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("DefaultInstall 132 %s"), szFileFullPath);
	InstallHinfSection(NULL, NULL, szCmd, 0);
	TRACE_PRINT1("InstallHinfSection: executing, szCmd = %s.", szCmd);

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
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("DefaultUninstall 132 %s"), szFileFullPath);
	InstallHinfSection(NULL, NULL, szCmd, 0);
	TRACE_PRINT1("InstallHinfSection: executing, szCmd = %s.", szCmd);

	TRACE_EXIT();
	return TRUE;
}
