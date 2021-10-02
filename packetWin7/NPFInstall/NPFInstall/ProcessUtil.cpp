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
#include <set>
using namespace std;

#include "..\..\Common\WpcapNames.h"
#include "..\npf\npf\ioctls.h"

#include "ProcessUtil.h"
#include "LoopbackRename2.h"
#include "debug.h"

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
	HANDLE hHeap = NULL;
	tstring strProductName = _T("");

	TRACE_ENTER();

	dwLen = GetFileVersionInfoSize((LPTSTR) strFilePath.c_str(), &dwUseless);
	if (dwLen == 0)
	{
		TRACE_PRINT1("GetFileVersionInfoSize: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return _T("");
	}

	hHeap = GetProcessHeap();
	if (!hHeap)
	{
		TRACE_PRINT1("GetProcessHeap: error, errCode = 0x%08x.", GetLastError());
		TRACE_EXIT();
		return _T("");
	}

	lpVI = (LPTSTR)HeapAlloc(hHeap, 0, dwLen);
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
		HeapFree(hHeap, 0, lpVI);

		TRACE_EXIT();
		return strProductName;
	}
	else
	{
		TRACE_PRINT1("HeapAlloc: error, errCode = 0x%08x.", GetLastError());
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
		// Uninstaller renames X.dll to X.dll.del to avoid race condition
		if (strModuleName == _T("wpcap.dll") || strModuleName == _T("packet.dll")
			|| strModuleName == _T("wpcap.dll.del")
			|| strModuleName == _T("packet.dll.del"))
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
		for (DWORD i = 0; !bResult && i < cbNeeded / sizeof(HMODULE); i ++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hArrModules[i], szModName, MAX_PATH))
			{
				tstring strModulePathName = szModName;
				transform(strModulePathName.begin(), strModulePathName.end(), strModulePathName.begin(), ::tolower);

// 				transform(strProcessName.begin(), strProcessName.end(), strProcessName.begin(), ::tolower);
// 				if (strProcessName != _T("nmap.exe"))
// 					continue;

				if (checkModulePathName(strModulePathName) && (getFileProductName(strModulePathName) == _T(NPF_DRIVER_NAME_NORMAL)
				|| getFileProductName(strModulePathName) == _T("WinPcap")
						))
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

set<ULONG> getNpcapPIDs()
{
	set<ULONG> empty;
	DWORD dwLen = 1024;
	DWORD BytesReturned = 0;
	DWORD lasterr;
	HANDLE hHeap = GetProcessHeap();
	if (!hHeap)
	{
		TRACE_PRINT1("GetProcessHeap: error, errCode = 0x%08x.", GetLastError());
		return empty;
	}
	TRACE_ENTER();

	// Npcap 0.9995 and later will support this with just '\\.\Global\NPCAP' name,
	// but that crashes Npcap 0.9985 and earlier due to #1924.
	// Loopback adapter ought to be safe and present since 0.9983
	HANDLE hFile = CreateFile(L"\\\\.\\Global\\NPCAP\\Loopback", GENERIC_WRITE|GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
	if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
	{
		TRACE_PRINT("Npcap handle opened");
		PULONG pids = (PULONG)HeapAlloc(hHeap, 0, dwLen);
		if (!pids)
		{
			TRACE_PRINT1("HeapAlloc error 0x%08x", GetLastError());
			CloseHandle(hFile);
			TRACE_EXIT();
			return empty;
		}
		if (!DeviceIoControl(hFile, BIOCGETPIDS, NULL, 0, pids, dwLen, &BytesReturned, NULL))
		{
			lasterr = GetLastError();
			TRACE_PRINT2("BIOCGETPIDS failed. err=%08x, bytes=%08x", lasterr, BytesReturned);
			if (BytesReturned >= sizeof(ULONG) && lasterr == ERROR_MORE_DATA)
			{
				dwLen = (pids[0] + 1) * sizeof(ULONG);
				HeapFree(hHeap, 0, pids);
				pids = (PULONG)HeapAlloc(hHeap, 0, dwLen);
				if (!pids)
				{
					TRACE_PRINT1("HeapAlloc error 0x%08x", GetLastError());
					CloseHandle(hFile);
					TRACE_EXIT();
					return empty;
				}
				if (!DeviceIoControl(hFile, BIOCGETPIDS, NULL, 0, pids, dwLen, &BytesReturned, NULL))
				{
					lasterr = GetLastError();
					TRACE_PRINT2("BIOCGETPIDS failed. err=%08x, bytes=%08x", lasterr, BytesReturned);
					HeapFree(hHeap, 0, pids);
					CloseHandle(hFile);
					TRACE_EXIT();
					return empty;
				}
			}
			else
			{
				HeapFree(hHeap, 0, pids);
				CloseHandle(hFile);
				TRACE_EXIT();
				return empty;
			}
		}

		TRACE_PRINT2("BIOCGETPIDS returned %lu bytes, %lu pids", BytesReturned, BytesReturned < sizeof(ULONG) ? 0 : pids[0]);
		if (BytesReturned < sizeof(ULONG) || BytesReturned < sizeof(ULONG) * (pids[0] + 1))
		{
			HeapFree(hHeap, 0, pids);
			CloseHandle(hFile);
			TRACE_EXIT();
			return empty;
		}
		set<ULONG> Ret(pids+1, pids+pids[0]);
		HeapFree(hHeap, 0, pids);
		CloseHandle(hFile);
		TRACE_EXIT();
		return Ret;
	}
	TRACE_EXIT();
	return empty;
}

vector<tstring> enumProcesses()
{
	TRACE_ENTER();

	vector<tstring> strArrProcessNames;
	set<ULONG> pids = getNpcapPIDs();
	DWORD my_pid = GetCurrentProcessId();

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
			if (PEInfo.th32ProcessID == my_pid)
			{
				continue;
			}
			tstring strProcessName = PEInfo.szExeFile;
			if (pids.find(PEInfo.th32ProcessID) != pids.end()
					|| enumDLLs(strProcessName, PEInfo.th32ProcessID))
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
	set<ULONG> pids = getNpcapPIDs();
	DWORD my_pid = GetCurrentProcessId();

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
			if (PEInfo.th32ProcessID == my_pid)
			{
				continue;
			}
			tstring strProcessName = PEInfo.szExeFile;
			if (pids.find(PEInfo.th32ProcessID) != pids.end()
					|| enumDLLs(strProcessName, PEInfo.th32ProcessID))
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

	TCHAR buf[256];
	int rc = _sntprintf_s(buf, _countof(buf), _T("taskkill /pid %ul"), dwProcessID);
	if (rc <= 0) {
		TRACE_PRINT1("Can't convert process ID %d to string.", dwProcessID);
		TRACE_EXIT();
		return FALSE;
	}

	tstring strResult = executeCommand(buf);

	if (strResult.compare(0, _tcslen(_T("SUCCESS")), _T("SUCCESS")) == 0)
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
