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

    LoopbackRename2.cpp

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using netsh.exe tool, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".

This code is based on the Windows built-in netsh.exe tool.
--*/

#include "LoopbackRename2.h"

#include "debug.h"

#ifdef _UNICODE
#define			NPCAP_LOOPBACK_INTERFACE_NAME				NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Loopback Adapter"
#else
#define			NPCAP_LOOPBACK_INTERFACE_NAME				NPF_DRIVER_NAME_NORMAL " Loopback Adapter"
#endif
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
		return _T("");
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
	return _T("");
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
	delete[] pUnicode;
	return rt;
}

tstring executeCommand(TCHAR* strCmd)
{
	TRACE_ENTER();
	TRACE_PRINT1("executeCommand: executing, strCmd = %s.", strCmd);

	tstring result;
	string tmp = "";
	HANDLE g_hChildStd_OUT_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles can be inherited. 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for stdout
	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
	{
		DWORD error = ::GetLastError();
		TRACE_PRINT1("CreatePipe: error, errCode = 0x%08x.", error);
		TRACE_EXIT();
		return _T("");
	}

	// Set the read handle for stdout as not inheritable
	SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);

	// Set the process to use STD handles and the window to hidden
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdError = g_hChildStd_OUT_Wr;
	si.hStdOutput = g_hChildStd_OUT_Wr;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	// Create the process
	BOOL executed = ::CreateProcess(NULL, strCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	if (executed == FALSE)
	{
		DWORD error = ::GetLastError();
		TRACE_PRINT1("CreateProcess: error, errCode = 0x%08x.", error);
		TRACE_EXIT();
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_OUT_Rd);
		return _T("");
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// Release the write handle since we have handed it off
	CloseHandle(g_hChildStd_OUT_Wr);
	g_hChildStd_OUT_Wr = 0;

	// Read pipe
	char aBuf[2048 + 1];
	while (true)
	{
		DWORD dwRead = 0;
		BOOL status = ReadFile(g_hChildStd_OUT_Rd, aBuf, 2048, &dwRead, NULL);
		if (!status || dwRead == 0) {
			break;
		}
		aBuf[dwRead] = '\0';
		tmp += aBuf;
	}

	// Close read handle
	CloseHandle(g_hChildStd_OUT_Rd);

#ifdef _UNICODE
	result = ANSIToUnicode(tmp);
#else
	result = tmp;
#endif

	TRACE_PRINT1("executeCommand: result = %s.", result.c_str());

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

	iLineEnd = strOutput.find(_T('-'), iLineEnd);
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
		iStringStart = strOutput.rfind(_T("    "), iLineEnd);
		if (iStringStart < iLineStart)
		{
			TRACE_EXIT();
			return nResults;
		}
		else
		{
			iStringStart += _tcslen(_T("    "));
		}
		iStringEnd = strOutput.find_first_of(_T("\r\n"), iStringStart);

		tstring strInterfaceName = strOutput.substr(iStringStart, iStringEnd - iStringStart);
		TRACE_PRINT1("getInterfaceNamesFromNetshOutput: executing, strInterfaceName = %s.", strInterfaceName.c_str());
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
// tstring getMajorVersionNumberFromVerOutput(tstring strOutput)
// {
// 	size_t iStringStart;
// 	size_t iStringEnd;
//
// 	iStringStart = strOutput.find(_T("Version"));
// 	if (iStringStart == tstring::npos)
// 	{
// 		return _T("");
// 	}
// 	iStringStart += 8;
//
// 	iStringEnd = strOutput.find(_T('.'), iStringStart);
// 	if (iStringEnd == tstring::npos)
// 	{
// 		return _T("");
// 	}
//
// 	tstring strNumber = strOutput.substr(iStringStart, iStringEnd - iStringStart);
// 	return strNumber;
// }

void snapshotInterfaceListBeforeInstall()
{
	TRACE_ENTER();

	TCHAR cmdLine[] = _T("netsh.exe interface show interface");
	tstring cmd = executeCommand(cmdLine);
	g_InterfaceNameList1 = getInterfaceNamesFromNetshOutput(cmd);

	TRACE_EXIT();
}

void snapshotInterfaceListAfterInstall()
{
	TRACE_ENTER();

	TCHAR cmdLine[] = _T("netsh.exe interface show interface");
	tstring cmd = executeCommand(cmdLine);
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
	_stprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface ipv4 set subinterface \"%s\" mtu=%d store=persistent"), (LPCTSTR) strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);
	_stprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface ipv6 set subinterface \"%s\" mtu=%d store=persistent"), (LPCTSTR) strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_MTU);
	executeCommand(renameCmd);

	TRACE_EXIT();
}

void renameLoopbackInterface(tstring strInterfaceName)
{
	TRACE_ENTER();

	TCHAR renameCmd[MAX_PATH];
	_stprintf_s(renameCmd, MAX_PATH, _T("netsh.exe interface set interface name=\"%s\" newname=\"%s\""), (LPCTSTR) strInterfaceName.c_str(), NPCAP_LOOPBACK_INTERFACE_NAME);
	executeCommand(renameCmd);

	TRACE_EXIT();
}

BOOL DoRenameLoopbackNetwork2()
{
	TRACE_ENTER();

	snapshotInterfaceListAfterInstall();
	tstring strOriginalInterfaceName = getNpcapLoopbackAdapterName();
	TRACE_PRINT1("getNpcapLoopbackAdapterName: executing, strOriginalInterfaceName = %s.", strOriginalInterfaceName.c_str());
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
