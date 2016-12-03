/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

ProcessUtil.cpp

Abstract:

Get processes which are using Npcap DLLs.

--*/

#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <tchar.h>

#include <algorithm>
#include <iostream>
#include <string>
using namespace std;

#include "ProcessUtil.h"
#include "debug.h"


BOOL checkModulePathName(tstring strModulePathName)
{
	size_t iStart = strModulePathName.find_last_of(_T('\\'));
	if (iStart == tstring::npos)
	{
		TRACE_PRINT1("checkModulePathName::find_last_of: error, strModulePathName = %s.", strModulePathName.c_str());
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

BOOL enumDLLs(tstring strProcessName, DWORD dwProcessID)
{
	HMODULE hArrModules[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	// Print the process identifier.
	// _tprintf(_T("\nProcess ID: %u\n"), dwProcessID);

	// Get a list of all the modules in this process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
	if (!hProcess)
	{
		TRACE_PRINT3("enumDLLs::OpenProcess: error, errCode = 0x%08x, strProcessName = %s, dwProcessID = %d.", GetLastError(), strProcessName.c_str(), dwProcessID);
		_tprintf(_T("enumDLLs::OpenProcess: error, errCode = 0x % 08x, strProcessName = %s, dwProcessID = %d.\n"), GetLastError(), strProcessName.c_str(), dwProcessID);
		return FALSE;
	}

	if (EnumProcessModules(hProcess, hArrModules, sizeof(hArrModules), &cbNeeded))
	{
		for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i ++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hArrModules[i], szModName, sizeof(szModName)))
			{
				tstring strModulePathName = szModName;
				transform(strModulePathName.begin(), strModulePathName.end(), strModulePathName.begin(), ::tolower);

				if (checkModulePathName(strModulePathName))
				{
					TRACE_PRINT2("enumDLLs: succeed, strProcessName = %s, strModulePathName = %s.", strProcessName.c_str(), strModulePathName.c_str());
					// _tprintf(_T("enumDLLs: succeed, strProcessName = %s, strModulePathName = %s.\n"), strProcessName.c_str(), strModulePathName.c_str());
					return TRUE;
				}
				else
				{
					TRACE_PRINT1("enumDLLs: succeed, strProcessName = %s, strModulePathName = <NULL>.", strProcessName.c_str());
					// _tprintf(_T("enumDLLs: succeed, strProcessName = %s, strModulePathName = <NULL>.\n"), strProcessName.c_str());
				}
			}
		}
	}
	else
	{
		TRACE_PRINT1("EnumProcessModules: error, errCode = 0x%08x.", GetLastError());
		return FALSE;
	}

	CloseHandle(hProcess);

	return FALSE;
}

vector<tstring> enumProcesses()
{
	vector<tstring> strArrProcessNames;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot)
	{
		PROCESSENTRY32 PEInfo;
		PEInfo.dwSize = sizeof(PEInfo);
		BOOL bHasNextProcess = Process32First(hSnapshot, &PEInfo);
		bool found = false;
		while (bHasNextProcess)
		{
			bHasNextProcess = Process32Next(hSnapshot, &PEInfo);
			tstring strProcessName = PEInfo.szExeFile;
			// _tprintf(_T("szExeFile = %s, th32ProcessID = %d\n"), PEInfo.szExeFile, PEInfo.th32ProcessID);
			BOOL bHasNpcapDLL = enumDLLs(strProcessName, PEInfo.th32ProcessID);
			if (bHasNpcapDLL)
			{
				strArrProcessNames.push_back(strProcessName);
			}
		}

		CloseHandle(hSnapshot);
	}

	return strArrProcessNames;
}

tstring getInUseProcesses()
{
	TRACE_ENTER();

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

	TRACE_EXIT();
	return strResult;
}
