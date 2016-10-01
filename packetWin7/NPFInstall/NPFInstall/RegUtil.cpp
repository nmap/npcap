/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

RegUtil.cpp

Abstract:

This is used for operating on registry.

--*/

#pragma warning(disable: 4311 4312)

#include <Netcfgx.h>

#include <iostream>
#include <atlbase.h> // CComPtr
#include <devguid.h> // GUID_DEVCLASS_NET, ...

#include "RegUtil.h"
#include "RegKey.h"

#include "debug.h"

#define BUF_SIZE 255

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, LPCTSTR strDeviceName, DWORD dwSamDesired)
{
	LONG Status;
	HKEY hNpcapKey;

	TRACE_ENTER();
	TRACE_PRINT4("WriteStrToRegistry: executing, strSubKey = %ws, strValueName = %ws, strDeviceName = %ws, dwSamDesired = 0x%08x.",
		strSubKey, strValueName, strDeviceName, dwSamDesired);

	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strSubKey, 0, dwSamDesired, &hNpcapKey);
	if (Status == ERROR_SUCCESS)
	{
		Status = RegSetValueEx(hNpcapKey, strValueName, 0, REG_SZ, (PBYTE)strDeviceName, (lstrlen(strDeviceName) + 1) * sizeof(TCHAR));
		if (Status != ERROR_SUCCESS)
		{
			TRACE_PRINT1("RegSetValueEx: error, errCode = 0x%08x.", GetLastError());
			RegCloseKey(hNpcapKey);
			TRACE_EXIT();
			return FALSE;
		}
		RegCloseKey(hNpcapKey);
	}
	else
	{
		TRACE_PRINT1("RegOpenKeyEx: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}

tstring printAdapterNames(vector<tstring> nstr)
{
	tstring strResult;
	for (size_t i = 0; i < nstr.size(); i++)
	{
		if (i != 0)
		{
			strResult += _T(";");
		}
		strResult += nstr[i];
	}
	return strResult;
}

BOOL addNpcapFolderToPath()
{
	TRACE_ENTER();

	int iRes = ProcessRegistryTask(_T("PATH"), _T("C:\\Windows\\System32\\Npcap"), TRUE, TRUE, FALSE);
	if (iRes == 0)
	{
		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		TRACE_EXIT();
		return FALSE;
	}
}

BOOL removeNpcapFolderFromPath()
{
	TRACE_ENTER();

	int iRes = ProcessRegistryTask(_T("PATH"), _T("C:\\Windows\\System32\\Npcap"), FALSE, TRUE, FALSE);
	if (iRes == 0)
	{
		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		TRACE_EXIT();
		return FALSE;
	}
}
