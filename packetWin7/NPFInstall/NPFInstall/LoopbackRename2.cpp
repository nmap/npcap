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

#define			NPCAP_LOOPBACK_INTERFACE_NAME			NPF_DRIVER_NAME_NORMAL " Loopback Adapter"
#define			BUF_SIZE								255

vector<string> g_InterfaceNameList1;
vector<string> g_InterfaceNameList2;

string getNpcapLoopbackAdapterName()
{
	if (g_InterfaceNameList1.size() != g_InterfaceNameList2.size() - 1)
	{
		return "";
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

	return "";
}

string executeCommand(char* cmd)
{
	FILE* pipe = _popen(cmd, "r");
	if (!pipe) return "ERROR";
	char buffer[128];
	string result = "";
	while(!feof(pipe)) {
		if(fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	_pclose(pipe);
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
vector<string> getInterfaceNamesFromNetshOutput(string strOutput)
{
	vector<string> nResults;
	size_t iLineStart;
	size_t iLineEnd = 0;
	size_t iStringStart;
	size_t iStringEnd;

	while (iLineEnd < strOutput.length() && strOutput[iLineEnd] == '\n')
	{
		iLineEnd ++;
	}

	iLineEnd = strOutput.find('\n', iLineEnd);
	if (iLineEnd == string::npos)
	{
		return nResults;
	}
	iLineEnd ++;

	iLineEnd = strOutput.find('\n', iLineEnd);
	if (iLineEnd == string::npos)
	{
		return nResults;
	}

	iLineEnd ++;
	iLineStart = iLineEnd;

	while ((iLineEnd = strOutput.find('\n', iLineEnd)) != string::npos)
	{
		iStringEnd = iLineEnd;
		iStringStart = strOutput.rfind("  ", iLineEnd);
		if (iStringStart < iLineStart)
		{
			return nResults;
		}
		else
		{
			iStringStart += 2;
		}

		string strInterfaceName = strOutput.substr(iStringStart, iStringEnd - iStringStart);
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
string getMajorVersionNumberFromVerOutput(string strOutput)
{
	size_t iStringStart;
	size_t iStringEnd;

	iStringStart = strOutput.find("Version");
	if (iStringStart == string::npos)
	{
		return "";
	}
	iStringStart += 8;

	iStringEnd = strOutput.find('.', iStringStart);
	if (iStringEnd == string::npos)
	{
		return "";
	}

	string strNumber = strOutput.substr(iStringStart, iStringEnd - iStringStart);
	return strNumber;
}

void snapshotInterfaceListBeforeInstall()
{
	string cmd = executeCommand("netsh.exe interface show interface");
	g_InterfaceNameList1 = getInterfaceNamesFromNetshOutput(cmd);
}

void snapshotInterfaceListAfterInstall()
{
	string cmd = executeCommand("netsh.exe interface show interface");
	g_InterfaceNameList2 = getInterfaceNamesFromNetshOutput(cmd);
}

void PrepareRenameLoopbackNetwork2()
{
	snapshotInterfaceListBeforeInstall();
}

BOOL DoRenameLoopbackNetwork2()
{
	snapshotInterfaceListAfterInstall();
	string strOriginalInterfaceName = getNpcapLoopbackAdapterName();
	if (strOriginalInterfaceName.compare("") == 0)
	{
		return FALSE;
	}

	char renameCmd[MAX_PATH];
	sprintf_s(renameCmd, MAX_PATH, "netsh.exe interface set interface name=\"%s\" newname=\"%s\"", strOriginalInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_NAME);
	executeCommand(renameCmd);
	return TRUE;
}

BOOL IsWindowsWin10()
{
// 	OSVERSIONINFO osvi;
// 	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
// 	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
// 	GetVersionEx(&osvi);
// 	return osvi.dwMajorVersion >= 10;

	string cmd = executeCommand("ver");
	string strMajorVersionNumber = getMajorVersionNumberFromVerOutput(cmd);
	if (strMajorVersionNumber.compare("10") == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}