/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename2.cpp

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using netsh.exe tool, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".

This code is based on the Windows built-in netsh.exe tool.
--*/

#include <windows.h>
#include <vector>
using namespace std;

#include "LoopbackRename2.h"

#define			NPCAP_LOOPBACK_INTERFACE_NAME_WIDECHAR		NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Loopback Adapter"
#define			NPCAP_LOOPBACK_INTERFACE_MTU				65536
#define			BUF_SIZE									255

vector<wstring> g_InterfaceNameList1;
vector<wstring> g_InterfaceNameList2;

wstring getNpcapLoopbackAdapterName()
{
	if (g_InterfaceNameList1.size() != g_InterfaceNameList2.size() - 1)
	{
		return L"";
	}

	for (int i = 0; i < g_InterfaceNameList2.size(); i ++)
	{
		int found = 0;
		for (int j = 0; j < g_InterfaceNameList1.size(); j ++)
		{
			if (g_InterfaceNameList2[i].compare(g_InterfaceNameList1[j]) == 0)
			{
				found = 1;
				break;
			}
		}
		if (found == 0)
		{
			return g_InterfaceNameList2[i];
		}
	}

	return L"";
}

wstring ANSIToUnicode(const string& str)
{
	int len = 0;
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

wstring executeCommand(wchar_t* cmd)
{
	char buffer[128];
	string tmp = "";
	wstring result;

	FILE* pipe = _wpopen(cmd, L"r");
	if (!pipe)
	{
		return L"";
	}

	while (!feof(pipe))
	{
		if (fgets(buffer, 128, pipe) != NULL)
			tmp += buffer;
	}
	_pclose(pipe);

	result = ANSIToUnicode(tmp);

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
vector<wstring> getInterfaceNamesFromNetshOutput(wstring strOutput)
{
	vector<wstring> nResults;
	size_t iLineStart;
	size_t iLineEnd = 0;
	size_t iStringStart;
	size_t iStringEnd;

	while (iLineEnd < strOutput.length() && strOutput[iLineEnd] == L'\n')
	{
		iLineEnd ++;
	}

	iLineEnd = strOutput.find(L'\n', iLineEnd);
	if (iLineEnd == wstring::npos)
	{
		return nResults;
	}
	iLineEnd ++;

	iLineEnd = strOutput.find(L'\n', iLineEnd);
	if (iLineEnd == wstring::npos)
	{
		return nResults;
	}

	iLineEnd ++;
	iLineStart = iLineEnd;

	while ((iLineEnd = strOutput.find(L'\n', iLineEnd)) != wstring::npos)
	{
		iStringEnd = iLineEnd;
		iStringStart = strOutput.rfind(L"    ", iLineEnd);
		if (iStringStart < iLineStart)
		{
			return nResults;
		}
		else
		{
			iStringStart += wcslen(L"    ");
		}

		wstring strInterfaceName = strOutput.substr(iStringStart, iStringEnd - iStringStart);
		nResults.push_back(strInterfaceName);

		iLineEnd ++;
		iLineStart = iLineEnd;
	}

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
	wstring cmd = executeCommand(L"netsh.exe interface show interface");
	g_InterfaceNameList1 = getInterfaceNamesFromNetshOutput(cmd);
}

void snapshotInterfaceListAfterInstall()
{
	wstring cmd = executeCommand(L"netsh.exe interface show interface");
	g_InterfaceNameList2 = getInterfaceNamesFromNetshOutput(cmd);
}

void PrepareRenameLoopbackNetwork2()
{
	snapshotInterfaceListBeforeInstall();
}

void changeLoopbackInterfaceMTU(wstring strInterfaceName)
{
	wchar_t renameCmd[MAX_PATH];
	swprintf_s(renameCmd, MAX_PATH, L"netsh.exe interface ipv4 set subinterface \"%s\" mtu=%d store=persistent", strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);
	swprintf_s(renameCmd, MAX_PATH, L"netsh.exe interface ipv6 set subinterface \"%s\" mtu=%d store=persistent", strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);
}

void renameLoopbackInterface(wstring strInterfaceName)
{
	wchar_t renameCmd[MAX_PATH];
	swprintf_s(renameCmd, MAX_PATH, L"netsh.exe interface set interface name=\"%s\" newname=\"%s\"", strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_NAME_WIDECHAR);
	executeCommand(renameCmd);
}

BOOL DoRenameLoopbackNetwork2()
{
	snapshotInterfaceListAfterInstall();
	wstring strOriginalInterfaceName = getNpcapLoopbackAdapterName();
	if (strOriginalInterfaceName.compare(L"") == 0)
	{
		return FALSE;
	}

	changeLoopbackInterfaceMTU(strOriginalInterfaceName);
	renameLoopbackInterface(strOriginalInterfaceName);
	return TRUE;
}

BOOL IsWindowsWin10()
{
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
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