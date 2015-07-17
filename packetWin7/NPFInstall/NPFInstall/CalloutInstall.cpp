/*++

Copyright (c) Nmap.org.  All rights reserved.

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

	hFind = FindFirstFile(szFileFullPath, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		//printf("Invalid File Handle. Get Last Error reports %d ", GetLastError());
		return FALSE;
	}
	else
	{
		//printf("The first file found is %s ", FindFileData.cFileName);
		FindClose(hFind);
		return TRUE;
	}
}

BOOL InstallWFPCallout()
{
	DWORD nResult;

	// Get Path to Service INF File
	// ----------------------------
	// The INF file is assumed to be in the same folder as this application...
	TCHAR szFileFullPath[_MAX_PATH];
	nResult = GetWFPCalloutInfFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		TRACE_PRINT("Unable to get WFP callout INF file path");
		return FALSE;
	}

	if (!isFileExist(szFileFullPath))
	{
		TRACE_PRINT("WFP callout INF file doesn't exist");
		return FALSE;
	}

	TCHAR szCmd[_MAX_PATH * 2];
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("DefaultInstall 132 %s"), szFileFullPath);
	InstallHinfSection(NULL, NULL, szCmd, 0);

	return TRUE;
}

BOOL UninstallWFPCallout()
{
	DWORD nResult;

	// Get Path to Service INF File
	// ----------------------------
	// The INF file is assumed to be in the same folder as this application...
	TCHAR szFileFullPath[_MAX_PATH];
	nResult = GetWFPCalloutInfFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		TRACE_PRINT("Unable to get WFP callout INF file path");
		return FALSE;
	}

	if (!isFileExist(szFileFullPath))
	{
		TRACE_PRINT("WFP callout INF file doesn't exist");
		return FALSE;
	}

	TCHAR szCmd[_MAX_PATH * 2];
	_stprintf_s(szCmd, _MAX_PATH * 2, TEXT("DefaultUninstall 132 %s"), szFileFullPath);
	InstallHinfSection(NULL, NULL, szCmd, 0);

	return TRUE;
}
