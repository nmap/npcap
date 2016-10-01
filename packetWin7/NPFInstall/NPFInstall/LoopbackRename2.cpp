/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename2.cpp

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using netsh.exe tool, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".

This code is based on the Windows built-in netsh.exe tool.
--*/

#include "LoopbackRename2.h"

#include "debug.h"

// Depress the GetVersionEx() call warning.
#pragma warning (disable: 4996)

#define			NPCAP_LOOPBACK_INTERFACE_NAME_WIDECHAR		NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Loopback Adapter"
#define			NPCAP_LOOPBACK_INTERFACE_MTU				65536
#define			BUF_SIZE									255

vector<tstring> g_InterfaceNameList1;
vector<tstring> g_InterfaceNameList2;

tstring getNpcapLoopbackAdapterName()
{
	TRACE_ENTER();

	if (g_InterfaceNameList1.size() != g_InterfaceNameList2.size() - 1)
	{
		TRACE_PRINT2("getNpcapLoopbackAdapterName: error, g_InterfaceNameList1.size() = %d, g_InterfaceNameList2.size() = %d.",
			g_InterfaceNameList1.size(), g_InterfaceNameList2.size());
		TRACE_EXIT();
		return L"";
	}

	for (size_t i = 0; i < g_InterfaceNameList2.size(); i ++)
	{
		int found = 0;
		for (size_t j = 0; j < g_InterfaceNameList1.size(); j ++)
		{
			if (g_InterfaceNameList2[i].compare(g_InterfaceNameList1[j]) == 0)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
		{
			TRACE_PRINT1("getNpcapLoopbackAdapterName: found the new interface, i = %d.", i);
			TRACE_EXIT();
			return g_InterfaceNameList2[i];
		}
	}

	TRACE_PRINT("getNpcapLoopbackAdapterName: unknown error.");
	TRACE_EXIT();
	return L"";
}

wstring ANSIToUnicode(const string& str)
{
	size_t len = 0;
	len = str.length();
	int unicodeLen = ::MultiByteToWideChar(CP_ACP,
		0,
		str.c_str(),
		-1,
		NULL,
		0);
	wchar_t * pUnicode;
	pUnicode = new wchar_t[unicodeLen + 1];
	memset(pUnicode, 0, (unicodeLen + 1)*sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP,
		0,
		str.c_str(),
		-1,
		(LPWSTR) pUnicode,
		unicodeLen);
	wstring rt;
	rt = (wchar_t*) pUnicode;
	delete pUnicode;
	return rt;
}

tstring executeCommand(TCHAR* strCmd)
{
	TRACE_ENTER();
	TRACE_PRINT1("executeCommand: executing, strCmd = %ws.", strCmd);

	tstring result;
	char buffer[128];
	string tmp = "";

	FILE* pipe = _tpopen(strCmd, _T("r"));
	if (!pipe)
	{
		TRACE_PRINT1("_tpopen: error, errCode = 0x%08x.", errno);
		TRACE_EXIT();
		return L"";
	}

	while (!feof(pipe))
	{
		if (fgets(buffer, 128, pipe) != NULL)
			tmp += buffer;
	}
	_pclose(pipe);

#ifdef _UNICODE
	result = ANSIToUnicode(tmp);
#else
	result = tmp;
#endif

	TRACE_EXIT();
	return result;
}

// getInterfaceNamesFromNetshOutput() function is used to get interface names from string like below:
//
// Admin State    State          Type             Interface Name
// -------------------------------------------------------------------------
// Enabled        Connected      Dedicated        VMware Network Adapter VMnet1
// Enabled        Connected      Dedicated        VMware Network Adapter VMnet8
// Enabled        Connected      Dedicated        VMware Network Adapter VMnet2
// Enabled        Connected      Dedicated        VMware Network Adapter VMnet3
// Enabled        Connected      Dedicated        Wi-Fi
// Disabled       Disconnected   Dedicated        Ethernet
// Enabled        Connected      Dedicated        Npcap Loopback Adapter
//
vector<tstring> getInterfaceNamesFromNetshOutput(tstring strOutput)
{
	TRACE_ENTER();

	vector<tstring> nResults;
	size_t iLineStart;
	size_t iLineEnd = 0;
	size_t iStringStart;
	size_t iStringEnd;

	while (iLineEnd < strOutput.length() && strOutput[iLineEnd] == _T('\n'))
	{
		iLineEnd ++;
	}

	iLineEnd = strOutput.find(_T('\n'), iLineEnd);
	if (iLineEnd == tstring::npos)
	{
		TRACE_EXIT();
		return nResults;
	}
	iLineEnd ++;

	iLineEnd = strOutput.find(_T('\n'), iLineEnd);
	if (iLineEnd == tstring::npos)
	{
		TRACE_EXIT();
		return nResults;
	}

	iLineEnd ++;
	iLineStart = iLineEnd;

	while ((iLineEnd = strOutput.find(_T('\n'), iLineEnd)) != tstring::npos)
	{
		iStringEnd = iLineEnd;
		iStringStart = strOutput.rfind(_T("    "), iLineEnd);
		if (iStringStart < iLineStart)
		{
			TRACE_EXIT();
			return nResults;
		}
		else
		{
			iStringStart += wcslen(_T("    "));
		}

		tstring strInterfaceName = strOutput.substr(iStringStart, iStringEnd - iStringStart);
		nResults.push_back(strInterfaceName);

		iLineEnd ++;
		iLineStart = iLineEnd;
	}

	TRACE_EXIT();
	return nResults;
}

// getMajorVersionNumberFromVerOutput() function is used to get Windows major version number from string like below:
//
// Microsoft Windows [Version 6.3.9600]
//
// OR
//
// Microsoft Windows [Version 10.0.10102]
//
// The "standard" GetWindowsVersionEx() way doesn't work out on Win10, because it returns 6.3 (Win8) on Win10.
// wstring getMajorVersionNumberFromVerOutput(wstring strOutput)
// {
// 	size_t iStringStart;
// 	size_t iStringEnd;
//
// 	iStringStart = strOutput.find(L"Version");
// 	if (iStringStart == wstring::npos)
// 	{
// 		return L"";
// 	}
// 	iStringStart += 8;
//
// 	iStringEnd = strOutput.find(L'.', iStringStart);
// 	if (iStringEnd == wstring::npos)
// 	{
// 		return L"";
// 	}
//
// 	wstring strNumber = strOutput.substr(iStringStart, iStringEnd - iStringStart);
// 	return strNumber;
// }

void snapshotInterfaceListBeforeInstall()
{
	TRACE_ENTER();

	tstring cmd = executeCommand(_T("netsh.exe interface show interface"));
	g_InterfaceNameList1 = getInterfaceNamesFromNetshOutput(cmd);

	TRACE_EXIT();
}

void snapshotInterfaceListAfterInstall()
{
	TRACE_ENTER();

	tstring cmd = executeCommand(L"netsh.exe interface show interface");
	g_InterfaceNameList2 = getInterfaceNamesFromNetshOutput(cmd);

	TRACE_EXIT();
}

void PrepareRenameLoopbackNetwork2()
{
	TRACE_ENTER();

	snapshotInterfaceListBeforeInstall();

	TRACE_EXIT();
}

void changeLoopbackInterfaceMTU(tstring strInterfaceName)
{
	TRACE_ENTER();

	TCHAR renameCmd[MAX_PATH];
	_stprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface ipv4 set subinterface \"%s\" mtu=%d store=persistent"), strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);
	_stprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface ipv6 set subinterface \"%s\" mtu=%d store=persistent"), strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);

	TRACE_EXIT();
}

void renameLoopbackInterface(tstring strInterfaceName)
{
	TRACE_ENTER();

	TCHAR renameCmd[MAX_PATH];
	swprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface set interface name=\"%s\" newname=\"%ws\""), strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_NAME_WIDECHAR);
	executeCommand(renameCmd);

	TRACE_EXIT();
}

BOOL DoRenameLoopbackNetwork2()
{
	TRACE_ENTER();

	snapshotInterfaceListAfterInstall();
	tstring strOriginalInterfaceName = getNpcapLoopbackAdapterName();
	TRACE_PRINT1("getNpcapLoopbackAdapterName: executing, strOriginalInterfaceName = %ws.", strOriginalInterfaceName.c_str());
	if (strOriginalInterfaceName.compare(_T("")) == 0)
	{
		TRACE_PRINT("getNpcapLoopbackAdapterName: error, strOriginalInterfaceName = NULL.");
		TRACE_EXIT();
		return FALSE;
	}

	changeLoopbackInterfaceMTU(strOriginalInterfaceName);
	renameLoopbackInterface(strOriginalInterfaceName);

	TRACE_EXIT();
	return TRUE;
}

BOOL IsWindowsWin10()
{
	TRACE_ENTER();

	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);

	TRACE_PRINT1("GetVersionEx: osvi.dwMajorVersion = %d, expected value = 10.", osvi.dwMajorVersion);
	TRACE_EXIT();
	return osvi.dwMajorVersion >= 10;

// 	wstring cmd = executeCommand(L"ver");
// 	wstring strMajorVersionNumber = getMajorVersionNumberFromVerOutput(cmd);
// 	if (strMajorVersionNumber.compare(L"10") == 0)
// 	{
// 		return TRUE;
// 	}
// 	else
// 	{
// 		return FALSE;
// 	}
}