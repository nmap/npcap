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

#include "..\..\Common\WpcapNames.h"

#include "ProcessUtil.h"
#include "LoopbackRename2.h"
#include "debug.h"


tstring itos(int i)
{
	TCHAR buf[256];
	_itot_s(i, buf, 10);
	tstring res = buf;
	return res;
}

BOOL enableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	return TRUE;
}

tstring getFileProductName(tstring strFilePath)
{
	DWORD dwLen, dwUseless;
	LPTSTR lpVI;
	tstring strProductName = _T("");

	TRACE_ENTER();

	dwLen = GetFileVersionInfoSize((LPTSTR) strFilePath.c_str(), &dwUseless);
	if (dwLen == 0)
	{
		TRACE_PRINT1("GetFileVersionInfoSize: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return _T("");
	}

	lpVI = (LPTSTR)GlobalAlloc(GPTR, dwLen);
	if (lpVI)
	{
		BOOL bRet = FALSE;
		WORD* langInfo;
		UINT cbLang;
		TCHAR tszVerStrName[128];
		LPVOID lpt;
		UINT cbBufSize;

		GetFileVersionInfo((LPTSTR) strFilePath.c_str(), NULL, dwLen, lpVI);

		// Get the Product Name.
		// First, to get string information, we need to get language information.
		VerQueryValue(lpVI, _T("\\VarFileInfo\\Translation"), (LPVOID*)&langInfo, &cbLang);
		// Prepare the label -- default lang is bytes 0 & 1 of langInfo
		_stprintf_s(tszVerStrName, 128, _T("\\StringFileInfo\\%04x%04x\\%s"), langInfo[0], langInfo[1], _T("ProductName"));
		//Get the string from the resource data
		if (VerQueryValue(lpVI, tszVerStrName, &lpt, &cbBufSize))
		{
			strProductName.assign((LPTSTR)lpt);
		}
		else
		{
			TRACE_PRINT("VerQueryValue: error.");
		}
		//Cleanup
		GlobalFree((HGLOBAL)lpVI);

		TRACE_EXIT();
		return strProductName;
	}
	else
	{
		TRACE_PRINT1("GlobalAlloc: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return _T("");
	}
}

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
	BOOL bResult = FALSE;
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
		// _tprintf(_T("enumDLLs::OpenProcess: error, errCode = 0x%08x, strProcessName = %s, dwProcessID = %d.\n"), GetLastError(), strProcessName.c_str(), dwProcessID);
		return FALSE;
	}

	if (EnumProcessModulesEx(hProcess, hArrModules, sizeof(hArrModules), &cbNeeded, LIST_MODULES_ALL))
	{
		for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i ++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hArrModules[i], szModName, sizeof(szModName)))
			{
				tstring strModulePathName = szModName;
				transform(strModulePathName.begin(), strModulePathName.end(), strModulePathName.begin(), ::tolower);

// 				transform(strProcessName.begin(), strProcessName.end(), strProcessName.begin(), ::tolower);
// 				if (strProcessName != _T("nmap.exe"))
// 					continue;

				if (checkModulePathName(strModulePathName) && getFileProductName(strModulePathName) == _T(NPF_DRIVER_NAME_NORMAL))
				{
					TRACE_PRINT2("enumDLLs: succeed, strProcessName = %s, strModulePathName = %s.", strProcessName.c_str(), strModulePathName.c_str());
					// _tprintf(_T("enumDLLs: succeed, strProcessName = %s, strModulePathName = %s.\n"), strProcessName.c_str(), strModulePathName.c_str());
					bResult = TRUE;
				}
				else
				{
					// TRACE_PRINT2("enumDLLs: negative, strProcessName = %s, strModulePathName = %s.", strProcessName.c_str(), strModulePathName.c_str());
					// _tprintf(_T("enumDLLs: negative, strProcessName = %s, strModulePathName = %s.\n"), strProcessName.c_str(), strModulePathName.c_str());
				}
			}
		}
	}
	else
	{
		TRACE_PRINT1("EnumProcessModulesEx: error, errCode = 0x%08x.", GetLastError());
		return FALSE;
	}

	CloseHandle(hProcess);

	return bResult;
}

vector<tstring> enumProcesses()
{
	TRACE_ENTER();

	vector<tstring> strArrProcessNames;

	enableDebugPrivilege(TRUE);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot != INVALID_HANDLE_VALUE)
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
	else
	{
		TRACE_PRINT1("enumProcesses::CreateToolhelp32Snapshot: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return strArrProcessNames;
	}

	TRACE_EXIT();
	return strArrProcessNames;
}

vector<DWORD> enumProcesses_PID()
{
	TRACE_ENTER();

	vector<DWORD> strArrProcessIDs;

	enableDebugPrivilege(TRUE);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot != INVALID_HANDLE_VALUE)
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
				strArrProcessIDs.push_back(PEInfo.th32ProcessID);
			}
		}

		CloseHandle(hSnapshot);
	}
	else
	{
		TRACE_PRINT1("enumProcesses_PID::CreateToolhelp32Snapshot: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return strArrProcessIDs;
	}

	TRACE_EXIT();
	return strArrProcessIDs;
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

BOOL killProcess(DWORD dwProcessID)
{
	TRACE_ENTER();

	// When the all operation fail this function terminate the "winlogon" Process for force exit the system.
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
	if (!hProcess)
	{
		DWORD dwError = GetLastError();
		if (dwError == ERROR_INVALID_PARAMETER)
		{
			TRACE_PRINT1("killProcess: the process terminates itself, dwProcessID = %d.", dwProcessID);
			return TRUE;
		}
		else
		{
			TRACE_PRINT2("killProcess::OpenProcess: error, errCode = 0x%08x, dwProcessID = %d.", dwError, dwProcessID);
			return FALSE;
		}
	}
	
	BOOL bRes = TerminateProcess(hProcess, 0);
	if (!bRes)
	{
		TRACE_PRINT2("killProcess::TerminateProcess: error, errCode = 0x%08x, dwProcessID = %d.", GetLastError(), dwProcessID);
		TRACE_EXIT();
		return FALSE;
	}
	else
	{
		WaitForSingleObject(hProcess, 5000); // Make sure the process has terminated.
		TRACE_PRINT1("killProcess::TerminateProcess: succeeds, dwProcessID = %d.", dwProcessID);
		TRACE_EXIT();
		return TRUE;
	}
}

BOOL killInUseProcesses()
{
	TRACE_ENTER();

	BOOL bResult = TRUE;
	vector<DWORD> strArrProcessIDs;

	strArrProcessIDs = enumProcesses_PID();

	for (size_t i = 0; i < strArrProcessIDs.size(); i++)
	{
		if (!killProcess(strArrProcessIDs[i]))
		{
			bResult = FALSE;
		}
	}

	TRACE_EXIT();
	return bResult;
}

BOOL killProcess_Soft(DWORD dwProcessID)
{
	TRACE_ENTER();

	tstring strCommand = _T("taskkill /pid ");
	strCommand += itos(dwProcessID);

	tstring strResult = executeCommand((TCHAR*)strCommand.c_str());

	if (_tcsncmp(strResult.c_str(), _T("SUCCESS"), _tcslen(_T("SUCCESS"))) == 0)
	{
		TRACE_PRINT1("killProcess_Soft: gracefully kill process, bResult = 1, dwProcessID = %d.", dwProcessID);
		TRACE_EXIT();
		return TRUE;
	}
	else
	{
		TRACE_PRINT1("killProcess_Soft: gracefully kill process, bResult = 0, dwProcessID = %d.", dwProcessID);
		TRACE_EXIT();
		return FALSE;
	}
}

BOOL killInUseProcesses_Soft()
{
	TRACE_ENTER();

	BOOL bResult = TRUE;
	vector<DWORD> strArrProcessIDs;

	strArrProcessIDs = enumProcesses_PID();

	for (size_t i = 0; i < strArrProcessIDs.size(); i++)
	{
		if (!killProcess_Soft(strArrProcessIDs[i]))
		{
			bResult = FALSE;
		}
	}

	TRACE_EXIT();
	return bResult;
}

DWORD dwTimeout = 15000;

BOOL killProcess_Wait(DWORD dwProcessID)
{
	TRACE_ENTER();

	// When the all operation fail this function terminate the "winlogon" Process for force exit the system.
	HANDLE hProcess = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, dwProcessID);
	if (!hProcess)
	{
		DWORD dwError = GetLastError();
		if (dwError == ERROR_INVALID_PARAMETER)
		{
			TRACE_PRINT1("killProcess_Wait: the process terminates itself, dwProcessID = %d.", dwProcessID);
			return TRUE;
		}
		else
		{
			TRACE_PRINT2("killProcess_Wait::OpenProcess: error, errCode = 0x%08x, dwProcessID = %d.", dwError, dwProcessID);
			return FALSE;
		}
	}

	DWORD dwTickBefore = GetTickCount();
	if (WaitForSingleObject(hProcess, dwTimeout) != WAIT_OBJECT_0)
	{
		dwTimeout = 0;
		BOOL bRes = TerminateProcess(hProcess, 0);
		if (!bRes)
		{
			TRACE_PRINT2("killProcess_Wait::TerminateProcess: error, errCode = 0x%08x, dwProcessID = %d.", GetLastError(), dwProcessID);
			TRACE_EXIT();
			return FALSE;
		}
		else
		{
			WaitForSingleObject(hProcess, 5000); // Make sure the process has terminated.
			TRACE_PRINT1("killProcess_Wait::TerminateProcess: succeeds, dwProcessID = %d.", dwProcessID);
			TRACE_EXIT();
			return TRUE;
		}
	}

	DWORD dwTickAfter = GetTickCount();
	if (dwTimeout <= dwTickAfter - dwTickBefore)
	{
		dwTimeout = 0;
	}
	else
	{
		dwTimeout -= (dwTickAfter - dwTickBefore);
	}

	TRACE_PRINT2("killProcess_Wait: the process terminates itself, dwProcessID = %d, dwTimeout = %d.", dwProcessID, dwTimeout);
	TRACE_EXIT();
	return TRUE;
}

BOOL killInUseProcesses_Polite()
{
	TRACE_ENTER();

	BOOL bResult = TRUE;
	vector<DWORD> strArrProcessIDs;

	strArrProcessIDs = enumProcesses_PID();

	for (size_t i = 0; i < strArrProcessIDs.size(); i++)
	{
		if (!killProcess_Soft(strArrProcessIDs[i]))
		{
			killProcess(strArrProcessIDs[i]);
		}
	}

	for (size_t i = 0; i < strArrProcessIDs.size(); i++)
	{
		if (!killProcess_Wait(strArrProcessIDs[i]))
		{
			bResult = FALSE;
		}
	}

	TRACE_EXIT();
	return bResult;
}
