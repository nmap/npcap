/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

ProcessUtil.cpp

Abstract:

Get processes which are using Npcap DLLs.

--*/

#include <windows.h>
#include <psapi.h>
#include <tchar.h>

#include <algorithm>
#include <iostream>
#include <string>
using namespace std;

#include "ProcessUtil.h"

#define STRTOLOWER(x) std::transform(x.begin(), x.end(), x.begin(), ::tolower)
#define STRTOUPPER(x) std::transform(x.begin(), x.end(), x.begin(), ::toupper)


tstring getProcessName(HANDLE hProcess)
{
	tstring strResult;
	TCHAR pFullPath[_MAX_PATH] = _T("");
	TCHAR pDrive[_MAX_DRIVE];
	TCHAR pDir[_MAX_DIR];
	TCHAR pFilename[_MAX_FNAME];
	TCHAR pExt[_MAX_EXT];

	GetModuleFileNameEx(hProcess, NULL, pFullPath, MAX_PATH);

	_tsplitpath_s(pFullPath, pDrive, _MAX_DRIVE, pDir, _MAX_DIR, pFilename, _MAX_FNAME, pExt, _MAX_EXT);

	strResult = pFilename;
	strResult += pExt;
	return strResult;
}

BOOL checkModulePathName(tstring strModulePathName)
{
	size_t iStart = strModulePathName.find_last_of(_T('\\'));
	if (iStart == tstring::npos)
	{

		return FALSE;
	}
	else
	{
		tstring strModuleName = strModulePathName.substr(iStart + 1, tstring::npos);
		if (strModuleName == _T("wpcap.dll") || strModuleName == _T("packet.dll"))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}

	}
}

tstring enumDLLs(DWORD dwProcessID)
{
	tstring strProcessName = _T("");
	HMODULE hArrModules[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	// Print the process identifier.
	// _tprintf(_T("\nProcess ID: %u\n"), dwProcessID);

	// Get a list of all the modules in this process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);

	if (EnumProcessModules(hProcess, hArrModules, sizeof(hArrModules), &cbNeeded))
	{
		for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i ++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hArrModules[i], szModName, sizeof(szModName)))
			{
				// Print the module name and handle value.
				// _tprintf(_T("\t%s (0x%08p)\n"), szModName, hArrModules[i]);

				tstring strModulePathName = szModName;
				transform(strModulePathName.begin(), strModulePathName.end(), strModulePathName.begin(), ::tolower);
				// Print the module name and handle value.
				// _tprintf(_T("\t%s (0x%08p)\n"), strModulePathName.c_str(), hArrModules[i]);

				if (checkModulePathName(strModulePathName))
				{
					strProcessName = getProcessName(hProcess);
					// _tprintf(_T("\t%s, %s\n"), strModulePathName.c_str(), strProcessName.c_str());
				}
			}
		}
	}

	CloseHandle(hProcess);

	return strProcessName;
}

vector<tstring> enumProcesses()
{
	vector<tstring> strArrProcessNames;
	DWORD dwArrProcessIDs[2048];
	DWORD cbNeeded;
	DWORD cProcesses;

	// Get the list of process identifiers.
	if (!EnumProcesses(dwArrProcessIDs, sizeof(dwArrProcessIDs), &cbNeeded))
	{
		return strArrProcessNames;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Enumerate the DLL modules for each process.
	for (DWORD i = 0; i < cProcesses; i ++)
	{
		tstring strProcessName = enumDLLs(dwArrProcessIDs[i]);
		if (strProcessName != _T(""))
		{
			strArrProcessNames.push_back(strProcessName);
		}
	}

	return strArrProcessNames;
}

tstring getInUseProcesses()
{
	tstring strResult;
	vector<tstring> strArrProcessNames;
	
	strArrProcessNames = enumProcesses();

	for (size_t i = 0; i < strArrProcessNames.size(); i++)
	{
		strResult += strArrProcessNames[i];
		if (i != strArrProcessNames.size() - 1)
		{
			strResult += _T(", ");
		}
	}

	return strResult;
}
