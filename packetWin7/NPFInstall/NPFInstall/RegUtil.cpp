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

#define BUF_SIZE 255

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, LPCTSTR strDeviceName, DWORD dwSamDesired)
{
	LONG Status;
	HKEY hNpcapKey;

	Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, strSubKey, 0, dwSamDesired, &hNpcapKey);
	if (Status == ERROR_SUCCESS)
	{
		Status = RegSetValueEx(hNpcapKey, strValueName, 0, REG_SZ, (PBYTE)strDeviceName, (lstrlen(strDeviceName) + 1) * sizeof(TCHAR));
		if (Status != ERROR_SUCCESS)
		{
			_tprintf(_T("WriteStrToRegistry: 0x%08x\n"), GetLastError());
			RegCloseKey(hNpcapKey);
			return FALSE;
		}
		RegCloseKey(hNpcapKey);
	}
	else
	{
		_tprintf(_T("WriteStrToRegistry: 0x%08x\n"), GetLastError());
		return FALSE;
	}

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
