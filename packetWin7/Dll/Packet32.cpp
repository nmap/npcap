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
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define UNICODE 1

#include <Packet32.h>
#include <tchar.h>
#include <strsafe.h>
#include <string>
#include <ntddndis.h>

#include "Packet32-Int.h"
#include "../npf/npf/ioctls.h"
#include <ws2tcpip.h>

#include <map>
using namespace std;

#include "debug.h"

#define BUFSIZE 512
#define MAX_SEM_COUNT 10
#define MAX_TRY_TIME 50
#define SLEEP_TIME 50


HANDLE g_hNpcapHelperPipe				=	INVALID_HANDLE_VALUE;	// Handle for NpcapHelper named pipe.
HANDLE g_hDllHandle						=	NULL;					// The handle to this DLL.

CHAR g_strLoopbackAdapterName[BUFSIZE]	= "";						// The name of "Npcap Loopback Adapter".
#define NPCAP_LOOPBACK_ADAPTER_BUILTIN "NPF_Loopback"
BOOLEAN g_bLoopbackSupport = TRUE;

map<string, int> g_nbAdapterMonitorModes;							// The states for all the wireless adapters that show whether it is in the monitor mode.

#define SERVICES_REG_KEY "SYSTEM\\CurrentControlSet\\Services\\"
#define NPCAP_SERVICE_REGISTRY_KEY SERVICES_REG_KEY NPF_DRIVER_NAME

#ifdef HAVE_AIRPCAP_API
#pragma message ("Compiling Packet.dll with support for AirPcap")
#endif

#if defined(HAVE_AIRPCAP_API)
#define LOAD_OPTIONAL_LIBRARIES
VOID PacketLoadLibrariesDynamically();
#endif

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif


#ifdef _DEBUG_TO_FILE
LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName);
#endif //_DEBUG_TO_FILE

#include <iphlpapi.h>

#include <WpcapNames.h>


//
// Current packet.dll version. It can be retrieved directly or through the PacketGetVersion() function.
//
char PacketLibraryVersion[64]; 

//
// Current driver version. It can be retrieved directly or through the PacketGetVersion() function.
//
char PacketDriverVersion[64]; 

//
// Current driver name ("NPF" or "NPCAP"). It can be retrieved directly or through the PacketGetVersion() function.
//
char PacketDriverName[64];


//
// Global adapters list related variables
//
extern ADINFO_LIST g_AdaptersInfoList;
extern HANDLE g_AdaptersInfoMutex;

#ifdef LOAD_OPTIONAL_LIBRARIES
//
// Dynamic dependencies variables and declarations
//
volatile LONG g_DynamicLibrariesLoaded = 0;
HANDLE g_DynamicLibrariesMutex;
#endif

#ifdef HAVE_AIRPCAP_API
// We dynamically load the Airpcap library in order link it only when it's present on the system
AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
AirpcapOpenHandler g_PAirpcapOpen;
AirpcapCloseHandler g_PAirpcapClose;
AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
AirpcapSetFilterHandler g_PAirpcapSetFilter;
AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
AirpcapReadHandler g_PAirpcapRead;
AirpcapGetStatsHandler g_PAirpcapGetStats;
AirpcapWriteHandler g_PAirpcapWrite;
#endif // HAVE_AIRPCAP_API

//
// Additions for WinPcap OEM
//
#ifdef WPCAP_OEM_UNLOAD_H
typedef BOOL (*WoemLeaveDllHandler)(void);
WoemLeaveDllHandler	g_WoemLeaveDllH = NULL;

__declspec (dllexport) VOID PacketRegWoemLeaveHandler(PVOID Handler)
{
	g_WoemLeaveDllH = Handler;
}
#endif // WPCAP_OEM_UNLOAD_H

//---------------------------------------------------------------------------

//
// This wrapper around loadlibrary appends the system folder (usually c:\windows\system32)
// to the relative path of the DLL, so that the DLL is always loaded from an absolute path
// (It's no longer possible to load airpcap.dll from the application folder).
// This solves the DLL Hijacking issue discovered in August 2010
// http://blog.metasploit.com/2010/08/exploiting-dll-hijacking-flaws.html
//
HMODULE LoadLibrarySafe(LPCTSTR lpFileName)
{
  TRACE_ENTER();

  TCHAR path[MAX_PATH+1] = { 0 };
  TCHAR fullFileName[MAX_PATH+1];
  UINT res;
  HMODULE hModule = NULL;
  DWORD err = ERROR_SUCCESS;
  do
  {
	res = GetSystemDirectory(path, MAX_PATH);

	if (res == 0)
	{
		//
		// some bad failure occurred;
		//
		err = GetLastError();
		break;
	}
	
	if (res > MAX_PATH)
	{
		//
		// the buffer was not big enough
		//
		err = (ERROR_INSUFFICIENT_BUFFER);
		break;
	}

	if (_tcslen(lpFileName) + 1 + res + 1 < MAX_PATH)
	{
		memcpy(fullFileName, path, res * sizeof(TCHAR));
		fullFileName[res] = _T('\\');
		memcpy(&fullFileName[res + 1], lpFileName, (_tcslen(lpFileName) + 1) * sizeof(TCHAR));

		hModule = LoadLibrary(fullFileName);
		err = GetLastError();
	}
	else
	{
		err = (ERROR_INSUFFICIENT_BUFFER);
	}

  }while(FALSE);

  TRACE_EXIT();
  SetLastError(err);
  return hModule;
}

static BOOL NpcapCreatePipe(const char *pipeName, HANDLE moduleName)
{
	const int pid = GetCurrentProcessId();
	char params[BUFSIZE];
	SHELLEXECUTEINFOA shExInfo = {};
	DWORD nResult;
	char lpFilename[BUFSIZE];
	char szDrive[BUFSIZE];
	char szDir[BUFSIZE];

	TRACE_ENTER();

	// Get Path to This Module
	nResult = GetModuleFileNameA((HMODULE) moduleName, lpFilename, BUFSIZE);
	if (nResult == 0)
	{
		nResult = GetLastError();
		TRACE_PRINT1("GetModuleFileNameA failed. GLE=%d\n", nResult);
		TRACE_EXIT();
		SetLastError(nResult);
		return FALSE;
	}
	_splitpath_s(lpFilename, szDrive, BUFSIZE, szDir, BUFSIZE, NULL, 0, NULL, 0);
	_makepath_s(lpFilename, BUFSIZE, szDrive, szDir, "NpcapHelper", ".exe");

	nResult = GetFileAttributesA(lpFilename);
	if (nResult == INVALID_FILE_ATTRIBUTES)
	{
		nResult = GetLastError();
		TRACE_PRINT2("GetFileAttributesA(%s) failed: %d", lpFilename, nResult);
		TRACE_EXIT();
		SetLastError(nResult);
		return FALSE;
	}
	if (nResult & FILE_ATTRIBUTE_DIRECTORY)
	{
		TRACE_PRINT1("%s is a directory.", lpFilename);
		TRACE_EXIT();
		SetLastError(ERROR_DIRECTORY_NOT_SUPPORTED);
		return FALSE;
	}

	sprintf_s(params, BUFSIZE, "%s %d", pipeName, pid);

	shExInfo.cbSize = sizeof(shExInfo);
	shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExInfo.hwnd = 0;
	shExInfo.lpVerb = "runas";				// Operation to perform
	shExInfo.lpFile = lpFilename;			// Application to start
	shExInfo.lpParameters = params;			// Additional parameters
	shExInfo.lpDirectory = 0;
	shExInfo.nShow = SW_SHOW;
	shExInfo.hInstApp = 0;

	if (!ShellExecuteExA(&shExInfo))
	{
		const DWORD dwError = GetLastError();
		if (dwError == ERROR_CANCELLED)
		{
			// The user refused to allow privileges elevation.
			// Do nothing ...
		}
		TRACE_EXIT();
		SetLastError(dwError);
		return FALSE;
	}
	else
	{
		TRACE_EXIT();
		if (shExInfo.hProcess)
			CloseHandle(shExInfo.hProcess);
		return TRUE;
	}
}

static HANDLE NpcapConnect(const char *pipeName)
{
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int tryTime = 0;
	char lpszPipename[BUFSIZE];
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

	sprintf_s(lpszPipename, BUFSIZE, "\\\\.\\pipe\\%s", pipeName);

	// Try to open a named pipe; wait for it, if necessary.
	while (tryTime < MAX_TRY_TIME)
	{
		hPipe = CreateFileA(
			lpszPipename,   // pipe name
			GENERIC_READ |  // read and write access
			GENERIC_WRITE,
			0,              // no sharing
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe
			0,              // default attributes
			NULL);          // no template file

		// Break if the pipe handle is valid.

		if (hPipe != INVALID_HANDLE_VALUE)
		{
			err = ERROR_SUCCESS;
			break;
		}
		else
		{
			err = GetLastError();
			tryTime++;
			Sleep(SLEEP_TIME);
		}
	}

	TRACE_EXIT();
	SetLastError(err);
	return hPipe;
}

static HANDLE NpcapRequestHandle(const char *sMsg, DWORD *pdwError)
{
	LPCSTR lpvMessage = sMsg;
	char  chBuf[BUFSIZE] = { 0 };
	BOOL   fSuccess = FALSE;
	DWORD  cbRead, cbToWrite, cbWritten, dwMode;
	HANDLE hPipe = g_hNpcapHelperPipe;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

	if (hPipe == INVALID_HANDLE_VALUE)
	{
		TRACE_EXIT();
		SetLastError(ERROR_PIPE_NOT_CONNECTED);
		return INVALID_HANDLE_VALUE;
	}

	// The pipe connected; change to message-read mode.
	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle
		&dwMode,  // new pipe mode
		NULL,     // don't set maximum bytes
		NULL);    // don't set maximum time
	if (!fSuccess)
	{
		err = GetLastError();
		TRACE_PRINT1("SetNamedPipeHandleState failed. GLE=%d\n", err);
		TRACE_EXIT();
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	// Send a message to the pipe server.

	cbToWrite = (DWORD) (strlen(lpvMessage) + 1)*sizeof(char);
	TRACE_PRINT2("\nSending %d byte message: \"%hs\"\n", cbToWrite, lpvMessage);

	fSuccess = WriteFile(
		hPipe,                  // pipe handle
		lpvMessage,             // message
		cbToWrite,              // message length
		&cbWritten,             // bytes written
		NULL);                  // not overlapped

	if (!fSuccess)
	{
		err = GetLastError();
		TRACE_PRINT1("WriteFile to pipe failed. GLE=%d\n", GetLastError());
		TRACE_EXIT();
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	TRACE_PRINT("Message sent to server, receiving reply as follows:\n");

	do
	{
		// Read from the pipe.

		fSuccess = ReadFile(
			hPipe,    // pipe handle
			chBuf,    // buffer to receive reply
			BUFSIZE*sizeof(char),  // size of buffer
			&cbRead,  // number of bytes read
			NULL);    // not overlapped

		if (!fSuccess && (err = GetLastError()) != ERROR_MORE_DATA)
			break;

		//printf("\"%s\"\n", chBuf );
	} while (!fSuccess);  // repeat loop if ERROR_MORE_DATA

	if (!fSuccess)
	{
		TRACE_PRINT1("ReadFile from pipe failed. GLE=%d\n", err);
		TRACE_EXIT();
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	//printf("\n<End of message, press ENTER to terminate connection and exit\n>");
	if (cbRead != 0)
	{
		HANDLE hd;
		_snscanf_s(chBuf, cbRead, "%p,%lu", &hd, pdwError);
		TRACE_PRINT1("Received Driver Handle: %0p\n", hd);
		TRACE_EXIT();
		SetLastError(ERROR_SUCCESS);
		return hd;
	}
	else
	{
		TRACE_EXIT();
		SetLastError(ERROR_NO_DATA);
		return INVALID_HANDLE_VALUE;
	}
}

static void NpcapGetLoopbackInterfaceName()
{
	TRACE_ENTER();

	HKEY hKey;
	DWORD type;
	char buffer[BUFSIZE];
	DWORD size = sizeof(buffer);
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NPCAP_SERVICE_REGISTRY_KEY "\\Parameters", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hKey, "LoopbackSupport", 0, &type,  (LPBYTE)buffer, &size) == ERROR_SUCCESS && type == REG_DWORD)
		{
			g_bLoopbackSupport = (0 != *((DWORD *) buffer));
		}
		size = sizeof(buffer);
		if (g_bLoopbackSupport && RegQueryValueExA(hKey, "LoopbackAdapter", 0, &type,  (LPBYTE)buffer, &size) == ERROR_SUCCESS && type == REG_SZ)
		{
			strncpy_s(g_strLoopbackAdapterName, 512, buffer, sizeof(g_strLoopbackAdapterName)/ sizeof(g_strLoopbackAdapterName[0]) - 1);
		}

		RegCloseKey(hKey);
	}

	TRACE_EXIT();
}

static BOOL NpcapIsAdminOnlyMode()
{
	TRACE_ENTER();

	static BOOLEAN cached = FALSE;
	static DWORD dwAdminOnlyMode = 0;
	DWORD size = sizeof(DWORD);
	LSTATUS status = ERROR_SUCCESS;

	if (!cached) {
		status = RegGetValue(HKEY_LOCAL_MACHINE, _T(NPCAP_SERVICE_REGISTRY_KEY "\\Parameters"), _T("AdminOnly"), RRF_RT_REG_DWORD, NULL, &dwAdminOnlyMode, &size);
		if (status != ERROR_SUCCESS) {
			TRACE_PRINT1("RegGetValue(Services\\Npcap\\Parameters\\AdminOnly) failed: %#x\n", status);
		}
		cached = TRUE;
	}
	TRACE_EXIT();
	return (dwAdminOnlyMode != 0);
}

static BOOL NpcapIsRunByAdmin()
{
	BOOL bIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;
	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

	TRACE_ENTER();

	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &bIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		TRACE_PRINT1("IsProcessRunningAsAdminMode failed. GLE=%d\n", dwError);
	}

	TRACE_PRINT1("IsProcessRunningAsAdminMode result: %hs\n", bIsRunAsAdmin ? "yes" : "no");
	TRACE_EXIT();
	SetLastError(dwError);
	return bIsRunAsAdmin;
}

static void NpcapStartHelper()
{
	TRACE_ENTER();

	// Only run this function once.
	// This may be a mistake; what if the helper gets killed?
	static BOOL NpcapHelperTried = FALSE;

	if (NpcapHelperTried)
	{
		TRACE_PRINT("NpcapHelper already tried\n");
		TRACE_EXIT();
		return;
	}

	// Don't try again.
	NpcapHelperTried = TRUE;

	// If it's already started, use that instead
	if (g_hNpcapHelperPipe != INVALID_HANDLE_VALUE)
	{
		TRACE_PRINT("NpcapHelper already started\n");
		TRACE_EXIT();
		return;
	}


	// Check if this process is running in Administrator mode.
	if (NpcapIsRunByAdmin())
	{
		TRACE_PRINT("Already running as admin.\n");
		TRACE_EXIT();
		return;
	}

	char pipeName[BUFSIZE];
	const int pid = GetCurrentProcessId();
	sprintf_s(pipeName, BUFSIZE, "npcap-%d", pid);
	if (NpcapCreatePipe(pipeName, g_hDllHandle))
	{
		g_hNpcapHelperPipe = NpcapConnect(pipeName);
		if (g_hNpcapHelperPipe == INVALID_HANDLE_VALUE)
		{
			TRACE_PRINT("Failed to connect to NpcapHelper.\n");
		}
	}
	else
	{
		TRACE_PRINT("NpcapCreatePipe failed.\n");
	}

	TRACE_EXIT();
}

static void NpcapStopHelper()
{
	TRACE_ENTER();

	if (g_hNpcapHelperPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_hNpcapHelperPipe);
		g_hNpcapHelperPipe = INVALID_HANDLE_VALUE;
	}

	TRACE_EXIT();
}

static PCHAR NpcapFormatAdapterName(LPCSTR AdapterName, LPCSTR prefix, BOOLEAN toupper)
{
	PCHAR outstr = NULL;
	const char *src = NULL;
	HRESULT hr = S_OK;
	TRACE_PRINT2("NpcapFormatAdapterName('%hs', '%hs')", AdapterName, prefix);

	do
	{
		src = strstr(AdapterName, "NPF");
		if (src)
		{
			src += 3;
			break;
		}

		src = strstr(AdapterName, "NPCAP");
		if (src)
		{
			src += 5;
			break;
		}

		TRACE_PRINT("'NPF' or 'NPCAP' not found");
		return NULL;
	} while (FALSE);

	if (src[0] != '_' && src[0] != '\\') // NPCAP_ or NPCAP\ are ok
	{
		TRACE_PRINT("'NPCAP' not followed by '_' or '\\'");
		return NULL;
	}
	src++; // Move past \ or _

	outstr = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ADAPTER_NAME_LENGTH);
	if (!outstr) {
		TRACE_PRINT("HeapAlloc failed");
		return NULL;
	}

	hr = StringCchPrintfA(outstr, ADAPTER_NAME_LENGTH, "%s%s", prefix, src);
	if (FAILED(hr))
	{
		TRACE_PRINT("Adapter name too long");
		HeapFree(GetProcessHeap(), 0, outstr);
		return NULL;
	}

	if (toupper && _strupr_s(outstr, ADAPTER_NAME_LENGTH))
	{
		TRACE_PRINT1("_strupr_s failed with %d", errno);
		HeapFree(GetProcessHeap(), 0, outstr);
		return NULL;
	}

	return outstr;
}

#define NPF_DECLARE_FORMAT_NAME(_Fn, _Prefix, _ToUpper) \
static PCHAR NpcapTranslateAdapterName_##_Fn(LPCSTR AdapterName) \
{ \
	return NpcapFormatAdapterName(AdapterName, _Prefix, _ToUpper); \
}

NPF_DECLARE_FORMAT_NAME(Standard2Wifi, NPF_DRIVER_COMPLETE_DEVICE_PREFIX NPF_DEVICE_NAMES_TAG_WIFI, TRUE)
NPF_DECLARE_FORMAT_NAME(Npf2Npcap, NPF_DRIVER_COMPLETE_DEVICE_PREFIX, TRUE)
NPF_DECLARE_FORMAT_NAME(Npcap2Npf, "\\Device\\NPF_", FALSE)

/*! 
  \brief The main dll function.
*/

BOOL APIENTRY DllMain(HANDLE DllHandle, DWORD Reason, LPVOID lpReserved)
{
	TRACE_ENTER();

	PADAPTER_INFO NewAdInfo;
	TCHAR DllFileName[MAX_PATH];
	g_hDllHandle = DllHandle;

	UNUSED(lpReserved);

    switch(Reason)
    {
	case DLL_PROCESS_ATTACH:

		TRACE_PRINT("************Packet32: DllMain************");

#ifdef _DEBUG_TO_FILEx
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" NPF_DRIVER_NAME,"npf.reg");
		
		// dump a bunch of registry keys useful for debug to file
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
			"adapters.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip",
			"tcpip.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
			"services.reg");

#endif

		// Create the mutex that will protect the adapter information list
		g_AdaptersInfoMutex = CreateMutex(NULL, FALSE, NULL);
		
#ifdef LOAD_OPTIONAL_LIBRARIES
		// Create the mutex that will protect the PacketLoadLibrariesDynamically() function		
		g_DynamicLibrariesMutex = CreateMutex(NULL, FALSE, NULL);
#endif

		//
		// Retrieve packet.dll version information from the file
		//
		// XXX We want to replace this with a constant. We leave it out for the moment
		if(GetModuleFileName((HMODULE) DllHandle, DllFileName, sizeof(DllFileName) / sizeof(DllFileName[0])) > 0)
		{
			PacketGetFileVersion(DllFileName, PacketLibraryVersion, sizeof(PacketLibraryVersion));
		}
		//
		// Retrieve NPF.sys version information from the file
		//
		// XXX We want to replace this with a constant. We leave it out for the moment
		// TODO fixme. Those hardcoded strings are terrible...
		PacketGetFileVersion(TEXT("drivers\\") TEXT(NPF_DRIVER_NAME) TEXT(".sys"), PacketDriverVersion, sizeof(PacketDriverVersion));
		strcpy_s(PacketDriverName, 64, NPF_DRIVER_NAME);

		// Get the name for "Npcap Loopback Adapter"
		NpcapGetLoopbackInterfaceName();
		
		break;
		
	case DLL_PROCESS_DETACH:

		CloseHandle(g_AdaptersInfoMutex);
		
		while(g_AdaptersInfoList.Adapters != NULL)
		{
			NewAdInfo = g_AdaptersInfoList.Adapters->Next;

			HeapFree(GetProcessHeap(), 0, g_AdaptersInfoList.Adapters);
			
			g_AdaptersInfoList.Adapters = NewAdInfo;
		}

		// NpcapHelper De-Initialization.
		NpcapStopHelper();

#ifdef WPCAP_OEM_UNLOAD_H 
		if(g_WoemLeaveDllH)
		{
			g_WoemLeaveDllH();
		}
#endif // WPCAP_OEM_UNLOAD_H

		break;
		
	default:
		break;
    }
	
	TRACE_EXIT();
    return TRUE;
}


#ifdef LOAD_OPTIONAL_LIBRARIES
/*! 
  \brief This function is used to dynamically load some of the libraries winpcap depends on, 
   and that are not guaranteed to be in the system
  \param cp A string containing the address.
  \return the converted 32-bit numeric address.

   Doesn't check to make sure the address is valid.
*/
VOID PacketLoadLibrariesDynamically()
{
#ifdef HAVE_AIRPCAP_API
	HMODULE AirpcapLib;
#endif // HAVE_AIRPCAP_API	

	TRACE_ENTER();

	//
	// Acquire the global mutex, so we wait until other threads are done
	//
	WaitForSingleObject(g_DynamicLibrariesMutex, INFINITE);

	//
	// Only the first thread should do the initialization
	//
	g_DynamicLibrariesLoaded++;

	if(g_DynamicLibrariesLoaded != 1)
	{
		ReleaseMutex(g_DynamicLibrariesMutex);
		TRACE_EXIT();
		return;
	}

#ifdef HAVE_AIRPCAP_API
	/* We dinamically load the airpcap library in order link it only when it's present on the system */
	if((AirpcapLib =  LoadLibrarySafe(TEXT("airpcap.dll"))) == NULL)
	{
		// Report the error but go on
		TRACE_PRINT("AirPcap library not found on this system");
	}
	else
	{
		//
		// Find the exports
		//
		g_PAirpcapGetLastError = (AirpcapGetLastErrorHandler) GetProcAddress(AirpcapLib, "AirpcapGetLastError");
		g_PAirpcapGetDeviceList = (AirpcapGetDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapGetDeviceList");
		g_PAirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) GetProcAddress(AirpcapLib, "AirpcapFreeDeviceList");
		g_PAirpcapOpen = (AirpcapOpenHandler) GetProcAddress(AirpcapLib, "AirpcapOpen");
		g_PAirpcapClose = (AirpcapCloseHandler) GetProcAddress(AirpcapLib, "AirpcapClose");
		g_PAirpcapGetLinkType = (AirpcapGetLinkTypeHandler) GetProcAddress(AirpcapLib, "AirpcapGetLinkType");
		g_PAirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) GetProcAddress(AirpcapLib, "AirpcapSetKernelBuffer");
		g_PAirpcapSetFilter = (AirpcapSetFilterHandler) GetProcAddress(AirpcapLib, "AirpcapSetFilter");
		g_PAirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) GetProcAddress(AirpcapLib, "AirpcapSetMinToCopy");
		g_PAirpcapGetReadEvent = (AirpcapGetReadEventHandler) GetProcAddress(AirpcapLib, "AirpcapGetReadEvent");
		g_PAirpcapRead = (AirpcapReadHandler) GetProcAddress(AirpcapLib, "AirpcapRead");
		g_PAirpcapGetStats = (AirpcapGetStatsHandler) GetProcAddress(AirpcapLib, "AirpcapGetStats");
		g_PAirpcapWrite = (AirpcapWriteHandler) GetProcAddress(AirpcapLib, "AirpcapWrite");

		//
		// Make sure that we found everything
		//
		if(g_PAirpcapGetLastError == NULL ||
			g_PAirpcapGetDeviceList == NULL ||
			g_PAirpcapFreeDeviceList == NULL ||
			g_PAirpcapClose == NULL ||
			g_PAirpcapGetLinkType == NULL ||
			g_PAirpcapSetKernelBuffer == NULL ||
			g_PAirpcapSetFilter == NULL ||
			g_PAirpcapSetMinToCopy == NULL ||
			g_PAirpcapGetReadEvent == NULL ||
			g_PAirpcapRead == NULL ||
			g_PAirpcapGetStats == NULL)
		{
			// No, something missing. A NULL g_PAirpcapOpen will disable airpcap adapters check
			g_PAirpcapOpen = NULL;
		}
	}
#endif // HAVE_AIRPCAP_API
	
	//
	// Done. Release the mutex and return
	//
	ReleaseMutex(g_DynamicLibrariesMutex);

	TRACE_EXIT();
	return;
}
#endif


/*! 
  \brief Converts an UNICODE string to ASCII. Uses the WideCharToMultiByte() system function.
  \param string The string to convert.
  \return The converted string.
*/
static PCHAR WChar2SChar(LPCWCH string)
{
	PCHAR TmpStr;
	TmpStr = (CHAR*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (DWORD)(wcslen(string)+2));

	if (TmpStr != NULL)
		WideCharToMultiByte(CP_ACP, 0, string, -1, TmpStr, (DWORD)(wcslen(string)+2), NULL, NULL);

	return TmpStr;
}

/*! 
  \brief Sets the maximum possible lookahead buffer for the driver's Packet_tap() function.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  The lookahead buffer is the portion of packet that Packet_tap() can access from the NIC driver's memory
  without performing a copy. This function tries to increase the size of that buffer.

  NOTE: this function is used for NPF adapters, only.
  Npcap NOTE: This may no longer be necessary. Testing required.
*/

BOOLEAN PacketSetMaxLookaheadsize (LPADAPTER AdapterObject)
{
	BOOLEAN    Status;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1] = { 0 };
	PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA)IoCtlBuffer;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();
	assert(!(AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF));

	if (AdapterObject->Flags & INFO_FLAG_NPCAP_LOOPBACK) {
		// Loopback adapter doesn't support this; fake success
		TRACE_EXIT();
		SetLastError(ERROR_SUCCESS);
		return TRUE;
	}
	
	//set the size of the lookahead buffer to the maximum available by the the NIC driver
	OidData->Oid=OID_GEN_MAXIMUM_LOOKAHEAD;
	OidData->Length=sizeof(ULONG);
	Status=PacketRequest(AdapterObject,FALSE,OidData);
	if (!Status) {
		err = GetLastError();
		TRACE_EXIT();
		SetLastError(err);
		return FALSE;
	}

	OidData->Oid=OID_GEN_CURRENT_LOOKAHEAD;
	Status=PacketRequest(AdapterObject,TRUE,OidData);	
	if (!Status) {
		err = GetLastError();
	}

	TRACE_EXIT();
	SetLastError(err);
	return Status;
}

/*! 
  \brief Allocates the read event associated with the capture instance, passes it down to the kernel driver
  and stores it in an _ADAPTER structure.
  \param AdapterObject Handle to the adapter.
  \return If the function succeeds, the return value is nonzero.

  This function is used by PacketOpenAdapter() to allocate the read event and pass it to the driver by means of an ioctl
  call and set it in the _ADAPTER structure pointed by AdapterObject.

  NOTE: this function is used for NPF adapters, only.
*/
BOOLEAN PacketSetReadEvt(LPADAPTER AdapterObject)
{
	DWORD BytesReturned;
	HANDLE hEvent;
	DWORD err = ERROR_SUCCESS;

 	TRACE_ENTER();
	assert(!(AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF));

	if (AdapterObject->ReadEvent != NULL)
	{
		TRACE_PRINT("ReadEvent is not NULL");
		SetLastError(ERROR_INVALID_FUNCTION);
		return FALSE;
	}

 	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (hEvent == NULL)
	{
		err = GetLastError();
		TRACE_PRINT("Error in CreateEvent");
 		TRACE_EXIT();
		SetLastError(err);
		return FALSE;
	}

	if(DeviceIoControl(AdapterObject->hFile,
			BIOCSETEVENTHANDLE,
			&hEvent,
			sizeof(hEvent),
			NULL,
			0,
			&BytesReturned,
			NULL)==FALSE) 
	{
		err = GetLastError();
		TRACE_PRINT("Error in DeviceIoControl");

		CloseHandle(hEvent);

		TRACE_EXIT();
		SetLastError(err);
		return FALSE;
	}

	AdapterObject->ReadEvent = hEvent;
	AdapterObject->ReadTimeOut=0;

	TRACE_EXIT();
	return TRUE;
}

/*! 
  \brief Dumps a registry key to disk in text format. Uses regedit.
  \param KeyName Name of the ket to dump. All its subkeys will be saved recursively.
  \param FileName Name of the file that will contain the dump.
  \return If the function succeeds, the return value is nonzero.

  For debugging purposes, we use this function to obtain some registry keys from the user's machine.
*/

#ifdef _DEBUG_TO_FILE

LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName)
{
	CHAR Command[256];

	TRACE_ENTER();
	StringCchPrintfA(Command, sizeof(Command), "regedit /e %s %s", FileName, KeyName);

	/// Let regedit do the dirty work for us
	system(Command);

	TRACE_EXIT();
	return TRUE;
}
#endif

/*! 
  \brief Returns the version of a dll or exe file 
  \param FileName Name of the file whose version has to be retrieved.
  \param VersionBuff Buffer that will contain the string with the file version.
  \param VersionBuffLen Length of the buffer poited by VersionBuff.
  \return If the function succeeds, the return value is TRUE.

  \note uses the GetFileVersionInfoSize() and GetFileVersionInfo() WIN32 API functions
*/
_Use_decl_annotations_
BOOL PacketGetFileVersion(LPCTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen)
{
    DWORD   dwVerInfoSize;  // Size of version information block
    DWORD   dwVerHnd=0;   // An 'ignored' parameter, always '0'
	LPTSTR   lpstrVffInfo;
	UINT	cbTranslate, dwBytes;
	TCHAR	SubBlock[64];
	PVOID	lpBuffer;
	PCHAR	TmpStr;
	DWORD err = ERROR_SUCCESS;
	
	// Structure used to store enumerated languages and code pages.
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	TRACE_ENTER();

	// Now lets dive in and pull out the version information:
	
    dwVerInfoSize = GetFileVersionInfoSize(FileName, &dwVerHnd);
	dwVerHnd = 0;
    if (dwVerInfoSize) 
	{
        lpstrVffInfo = (LPTSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwVerInfoSize);
		if (lpstrVffInfo == NULL)
		{
			err = GetLastError();
			TRACE_PRINT("PacketGetFileVersion: failed to allocate memory");
			TRACE_EXIT();
			SetLastError(err);
			return FALSE;
		}

		if(!GetFileVersionInfo(FileName, dwVerHnd, dwVerInfoSize, lpstrVffInfo)) 
		{
			err = GetLastError();
			TRACE_PRINT1("PacketGetFileVersion: failed to call GetFileVersionInfo: %d", err);
			HeapFree(GetProcessHeap(), 0, lpstrVffInfo);
			TRACE_EXIT();
			SetLastError(err);
			return FALSE;
		}

		// Read the list of languages and code pages.
		if(!VerQueryValue(lpstrVffInfo,	TEXT("\\VarFileInfo\\Translation"),	(LPVOID*)&lpTranslate, &cbTranslate))
		{
			err = GetLastError();
			TRACE_PRINT1("PacketGetFileVersion: failed to call VerQueryValue: %d", err);
			HeapFree(GetProcessHeap(), 0, lpstrVffInfo);
			TRACE_EXIT();
			SetLastError(err);
			return FALSE;
		}
		
		// Create the file version string for the first (i.e. the only one) language.
		StringCchPrintf(SubBlock,
			sizeof(SubBlock)/sizeof(SubBlock[0]),
			(TCHAR*)TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
			(*lpTranslate).wLanguage,
			(*lpTranslate).wCodePage);
		
		// Retrieve the file version string for the language.
		if(!VerQueryValue(lpstrVffInfo, SubBlock, &lpBuffer, &dwBytes))
		{
			err = GetLastError();
			TRACE_PRINT1("PacketGetFileVersion: failed to call VerQueryValue: %d", err);
			HeapFree(GetProcessHeap(), 0, lpstrVffInfo);
			TRACE_EXIT();
			SetLastError(err);
			return FALSE;
		}

		// Convert to ASCII
		TmpStr = WChar2SChar((PWCHAR) lpBuffer);

		if(strlen(TmpStr) >= VersionBuffLen)
		{
			TRACE_PRINT("PacketGetFileVersion: Input buffer too small");
			HeapFree(GetProcessHeap(), 0, lpstrVffInfo);
			HeapFree(GetProcessHeap(), 0, TmpStr);
			TRACE_EXIT();
			SetLastError(ERROR_BUFFER_OVERFLOW);
			return FALSE;
		}

		StringCchCopyA(VersionBuff, VersionBuffLen, TmpStr);

		HeapFree(GetProcessHeap(), 0, lpstrVffInfo);
		HeapFree(GetProcessHeap(), 0, TmpStr);
		
	  } 
	else 
	{
		err = GetLastError();
		TRACE_PRINT1("PacketGetFileVersion: failed to call GetFileVersionInfoSize, LastError = %8.8x", err);
		TRACE_EXIT();
		SetLastError(err);
		return FALSE;
	
	} 
	
	TRACE_EXIT();
	return TRUE;
}

BOOL PacketStartService()
{
	DWORD error = ERROR_SUCCESS;
	BOOL Result;
	SC_HANDLE svcHandle = NULL;
	SC_HANDLE scmHandle = NULL;
	LONG KeyRes;
	HKEY PathKey;
	SERVICE_STATUS SStat;
	BOOL QuerySStat;
	static BOOL ServiceStartAttempted = FALSE;

	TRACE_ENTER();
	if (ServiceStartAttempted) {
		TRACE_PRINT("PacketStartService: Already tried once.");
		TRACE_EXIT();
		return TRUE;
	}

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

	if (scmHandle == NULL)
	{
		error = GetLastError();
		TRACE_PRINT1("OpenSCManager failed! LastError=%8.8x", error);
		Result = FALSE;
	}
	else
	{
		// check if the NPF registry key is already present
		// this means that the driver is already installed and that we don't need to call PacketInstallDriver
		KeyRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			SERVICES_REG_KEY NPF_DRIVER_NAME,
			0,
			KEY_READ | KEY_WOW64_32KEY,
			&PathKey);

		if (KeyRes != ERROR_SUCCESS)
		{
			Result = FALSE;
#ifdef NPCAP_PACKET_INSTALL_SERVICE
			TRACE_PRINT("NPF registry key not present, trying to install the driver.");
			Result = InstallDriver();
#endif
		}
		else
		{
			TRACE_PRINT("NPF registry key present, driver is installed.");
			Result = TRUE;
			RegCloseKey(PathKey);
		}

		if (Result)
		{
			TRACE_PRINT("Trying to see if the NPF service is running...");
			svcHandle = OpenServiceA(scmHandle, NPF_DRIVER_NAME, SERVICE_START | SERVICE_QUERY_STATUS);

			if (svcHandle != NULL)
			{
				QuerySStat = QueryServiceStatus(svcHandle, &SStat);

#ifdef _DBG				
				switch (SStat.dwCurrentState)
				{
				case SERVICE_CONTINUE_PENDING:
					TRACE_PRINT("The status of the driver is: SERVICE_CONTINUE_PENDING");
					break;
				case SERVICE_PAUSE_PENDING:
					TRACE_PRINT("The status of the driver is: SERVICE_PAUSE_PENDING");
					break;
				case SERVICE_PAUSED:
					TRACE_PRINT("The status of the driver is: SERVICE_PAUSED");
					break;
				case SERVICE_RUNNING:
					TRACE_PRINT("The status of the driver is: SERVICE_RUNNING");
					break;
				case SERVICE_START_PENDING:
					TRACE_PRINT("The status of the driver is: SERVICE_START_PENDING");
					break;
				case SERVICE_STOP_PENDING:
					TRACE_PRINT("The status of the driver is: SERVICE_STOP_PENDING");
					break;
				case SERVICE_STOPPED:
					TRACE_PRINT("The status of the driver is: SERVICE_STOPPED");
					break;

				default:
					TRACE_PRINT("The status of the driver is: unknown");
					break;
				}
#endif

				if (!QuerySStat || SStat.dwCurrentState != SERVICE_RUNNING)
				{
					TRACE_PRINT("Driver NPF not running. Calling startservice");
					if (StartService(svcHandle, 0, NULL) == 0)
					{
						error = GetLastError();
						if (error != ERROR_SERVICE_ALREADY_RUNNING && error != ERROR_ALREADY_EXISTS)
						{
							TRACE_PRINT1("StartService failed, LastError=%8.8x", error);
							Result = FALSE;
						}
					}
				}

				CloseServiceHandle(svcHandle);
				svcHandle = NULL;

			}
			else
			{
				error = GetLastError();
				TRACE_PRINT1("OpenService failed! Error=%8.8x", error);
				Result = FALSE;
			}
		}
		else
		{
			error = GetLastError();
			TRACE_PRINT1("InstallDriver failed! Error=%8.8x", error);
			Result = FALSE;
		}
	}

	if (scmHandle != NULL) CloseServiceHandle(scmHandle);

	ServiceStartAttempted = TRUE;
	TRACE_EXIT();
	SetLastError(error);
	return Result;
}

_Use_decl_annotations_
HANDLE PacketGetAdapterHandle(PCCH AdapterNameA)
{
	CHAR SymbolicLinkA[MAX_PATH] = {0};
	HRESULT hrStatus = S_OK;
	DWORD err = ERROR_SUCCESS;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	// Create the NPF device name from the original device name
	TRACE_ENTER();

	TRACE_PRINT1("Trying to open adapter %hs", AdapterNameA);

#define DEVICE_PREFIX "\\Device\\"

	if (strlen(AdapterNameA) <= strlen(DEVICE_PREFIX))
	{
		TRACE_PRINT("Device name too short.");
		TRACE_EXIT();
		SetLastError(ERROR_INVALID_NAME);
		return INVALID_HANDLE_VALUE;
	}
	hrStatus = StringCchPrintfA(SymbolicLinkA, MAX_PATH, "\\\\.\\Global\\%s", AdapterNameA + strlen(DEVICE_PREFIX));
	if (FAILED(hrStatus))
	{
		TRACE_PRINT1("Failed to format symbolic link: %08x", hrStatus);
		TRACE_EXIT();
		// STRSAFE_E_INSUFFICIENT_BUFFER
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return INVALID_HANDLE_VALUE;
	}

	// Start the driver service and/or Helper if needed
	PacketStartService();

	// Try NpcapHelper to request handle if we are in Non-Admin mode.
	if (NpcapIsAdminOnlyMode())
	{
		if (g_hNpcapHelperPipe == INVALID_HANDLE_VALUE)
		{
			// NpcapHelper Initialization, used for accessing the driver with Administrator privilege.
			NpcapStartHelper();
			if (g_hNpcapHelperPipe == INVALID_HANDLE_VALUE)
			{
				err = GetLastError();
				TRACE_PRINT("Could not contact NpcapHelper");
				TRACE_EXIT();
				SetLastError(err);
				return INVALID_HANDLE_VALUE;
			}
		}
		hFile = NpcapRequestHandle(SymbolicLinkA, &err);
		TRACE_PRINT1("Driver handle from NpcapHelper = %08x", hFile);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			TRACE_PRINT1("ErrorCode = %d", err);
			SetLastError(err);
			return INVALID_HANDLE_VALUE;
		}
	}
	else
	{
		// Try if it is possible to open the adapter immediately
		hFile = CreateFileA(SymbolicLinkA, GENERIC_WRITE | GENERIC_READ,
				0, NULL, OPEN_EXISTING, 0, 0);
		err = GetLastError();
		TRACE_PRINT2("SymbolicLinkA = %hs, hFile = %08x", SymbolicLinkA, hFile);
	}
	TRACE_EXIT();
	SetLastError(err);
	return hFile;
}

/*!
  \brief Opens an adapter using the NPF device driver.
  \param AdapterName A string containing the name of the device to open.
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter()
*/
_Ret_maybenull_
LPADAPTER PacketOpenAdapterNPF(_In_ PCCH AdapterNameA)
{
	DWORD error;
	LPADAPTER lpAdapter;

	TRACE_ENTER();

	lpAdapter=(LPADAPTER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADAPTER));
	if (lpAdapter==NULL)
	{
		error=GetLastError();
		TRACE_PRINT("PacketOpenAdapterNPF: HeapAlloc Failed to allocate the ADAPTER structure");
		TRACE_EXIT();
		SetLastError(error);
		return NULL;
	}

	if (g_bLoopbackSupport && PacketIsLoopbackAdapter(AdapterNameA)) {
		lpAdapter->Flags |= INFO_FLAG_NPCAP_LOOPBACK;
	}

	lpAdapter->NumWrites=1;

	lpAdapter->hFile = PacketGetAdapterHandle(AdapterNameA);

	do {
		error=GetLastError();
		if (lpAdapter->hFile == INVALID_HANDLE_VALUE)
		{
			TRACE_PRINT("PacketOpenAdapterNPF: Failed to get adapter handle");
			break;
		}

		if (FAILED(StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterNameA)))
		{
			error = ERROR_BUFFER_OVERFLOW;
			TRACE_PRINT("PacketOpenAdapterNPF: Unable to copy adapter name");
			break;
		}

		if(!PacketSetReadEvt(lpAdapter)) {
			error=GetLastError();
			TRACE_PRINT("PacketOpenAdapterNPF: Unable to open the read event");
			break;
		}

		if (!PacketSetMaxLookaheadsize(lpAdapter)) {
			error=GetLastError();
			TRACE_PRINT("PacketOpenAdapterNPF: Unable to set lookahead");
			// We do not consider this a failure. Would like to avoid it for loopback, though.
			// break;
		}
		//
		// Indicate that this is a device managed by NPF.sys
		//
		lpAdapter->Flags = INFO_FLAG_NDIS_ADAPTER;


		TRACE_PRINT("Successfully opened adapter");
		TRACE_EXIT();
		return lpAdapter;
	} while (FALSE);

	TRACE_PRINT1("PacketOpenAdapterNPF: LastError= %8.8x",error);
	PacketCloseAdapter(lpAdapter);

	//set the error to the one on which we failed
	TRACE_EXIT();
	SetLastError(error);
	return NULL;
}

/*! 
  \brief Opens an adapter using the aircap dll.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter()
*/
#ifdef HAVE_AIRPCAP_API
static BOOLEAN IsAirpcapName(LPCSTR AdapterName)
{
	static PCCH airpcap_prefix = "\\\\.\\airpcap";
	return (strncmp(AdapterName, airpcap_prefix, sizeof(airpcap_prefix) - 1) == 0);
}

static LPADAPTER PacketOpenAdapterAirpcap(LPCSTR AdapterName)
{
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
    LPADAPTER lpAdapter;

	TRACE_ENTER();

	//
	// Make sure that the airpcap API has been linked
	//
	if(!g_PAirpcapOpen)
	{
		TRACE_EXIT();
		return NULL;
	}
	
	lpAdapter = (LPADAPTER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADAPTER));
	if (lpAdapter == NULL)
	{
		TRACE_EXIT();
		return NULL;
	}

	//
	// Indicate that this is a aircap card
	//
	lpAdapter->Flags = INFO_FLAG_AIRPCAP_CARD;
		  
	//
	// Open the adapter
	//
	lpAdapter->AirpcapAd = g_PAirpcapOpen(AdapterName, Ebuf);
	
	if(lpAdapter->AirpcapAd == NULL)
	{
		HeapFree(GetProcessHeap(), 0, lpAdapter);
		TRACE_EXIT();
		return NULL;					
	}
		  				
	StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterName);
	
	TRACE_EXIT();
	return lpAdapter;
}
#endif // HAVE_AIRPCAP_API


//---------------------------------------------------------------------------
// PUBLIC API
//---------------------------------------------------------------------------

/** @ingroup packetapi
 *  @{
 */

/** @defgroup packet32 Packet.dll exported functions and variables
 *  @{
 */

/*! 
  \brief Return a string with the dll version.
  \return A char pointer to the version of the library.
*/
LPCSTR PacketGetVersion()
{
	TRACE_ENTER();
	TRACE_EXIT();
	return PacketLibraryVersion;
}

/*! 
  \brief Return a string with the version of the device driver.
  \return A char pointer to the version of the driver.
*/
LPCSTR PacketGetDriverVersion()
{
	TRACE_ENTER();
	TRACE_EXIT();
	return PacketDriverVersion;
}

/*!
\brief Return a string with the name of the device driver.
\return A char pointer to the version of the driver.
*/
LPCSTR PacketGetDriverName()
{
	TRACE_ENTER();
	TRACE_EXIT();
	return PacketDriverName;
}

/*! 
  \brief Stops and unloads the WinPcap device driver.
  \return If the function succeeds, the return value is nonzero, otherwise it is zero.

  This function can be used to unload the driver from memory when the application no more needs it.
  Note that the driver is physically stopped and unloaded only when all the files on its devices 
  are closed, i.e. when all the applications that use WinPcap close all their adapters.
*/
BOOL PacketStopDriver()
{
	SC_HANDLE		scmHandle;
    SC_HANDLE       schService;
    BOOL            ret;
    SERVICE_STATUS  serviceStatus;
    DWORD err = ERROR_SUCCESS;

 	TRACE_ENTER();
 
 	ret = FALSE;

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	
	if(scmHandle != NULL){
		
		TRACE_PRINT("Opened the SCM");
		
		schService = OpenServiceA (scmHandle,
			NPF_DRIVER_NAME,
			SERVICE_STOP
			);
		
		if (schService != NULL)
		{
			TRACE_PRINT("Opened the NPF service in the SCM");

			ret = ControlService (schService,
				SERVICE_CONTROL_STOP,
				&serviceStatus
				);
			if (!ret)
			{
				err = GetLastError();
				TRACE_PRINT("Failed to stop the NPF service");
			}
			else
			{
				TRACE_PRINT("NPF service stopped");
			}
			
			CloseServiceHandle (schService);
			
			CloseServiceHandle(scmHandle);
			
		}
		else {
			err = GetLastError();
		}
	}
	else {
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
	return ret;
}

/*! 
  \brief Opens an adapter.
  \param AdapterName A string containing the name of the device to open. 
   Use the PacketGetAdapterNames() function to retrieve the list of available devices.
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.
*/
_Use_decl_annotations_
LPADAPTER PacketOpenAdapter(PCCH AdapterNameWA)
{
    LPADAPTER lpAdapter = NULL;
	PCHAR AdapterNameA = NULL;
	PCHAR TranslatedAdapterNameA = NULL;
	PCHAR WifiAdapterNameA = NULL;
	
	DWORD dwLastError = ERROR_SUCCESS;
 
 	TRACE_ENTER();	
 
	TRACE_PRINT_OS_INFO();
	
	TRACE_PRINT2("Packet DLL version %hs, Driver version %hs", PacketLibraryVersion, PacketDriverVersion);

#ifdef LOAD_OPTIONAL_LIBRARIES
	//
	// Check the presence on some libraries we rely on, and load them if we found them
	//
	PacketLoadLibrariesDynamically();
#endif

	//
	// Ugly heuristic to detect if the adapter is ASCII
	//
	if(AdapterNameWA[1]==0)
	{	
		//
		// Unicode
		//
		const size_t bufferSize = wcslen((PCWCHAR)AdapterNameWA) + 1;
		
		AdapterNameA = (PCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);

		if (AdapterNameA == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return NULL;
		}

		StringCchPrintfA(AdapterNameA, bufferSize, "%ws", (PWCHAR)AdapterNameWA);
		AdapterNameWA = AdapterNameA;
	}

	// Translate the adapter name string's "NPF_{XXX}" to "NPCAP_{XXX}" for compatibility with WinPcap, because some user softwares hard-coded the "NPF_" string
	TranslatedAdapterNameA = NpcapTranslateAdapterName_Npf2Npcap(AdapterNameWA);
	if (TranslatedAdapterNameA)
	{
		AdapterNameWA = TranslatedAdapterNameA;
	}

	do
	{

#ifdef HAVE_AIRPCAP_API
		if(IsAirpcapName(AdapterNameWA))
		{
			//
			// This is an airpcap card. Open it using the airpcap api
			//								
			lpAdapter = PacketOpenAdapterAirpcap(AdapterNameWA);
			
			if(lpAdapter == NULL)
			{
				dwLastError = ERROR_BAD_UNIT;
				break;
			}

			//
			// Airpcap provides a read event
			//
			if(!g_PAirpcapGetReadEvent(lpAdapter->AirpcapAd, &lpAdapter->ReadEvent))
			{
				PacketCloseAdapter(lpAdapter);
				dwLastError = ERROR_BAD_UNIT;
			}
			else
			{
				dwLastError = ERROR_SUCCESS;
			}
			
			break;
		}
#endif // HAVE_AIRPCAP_API

		if (g_nbAdapterMonitorModes[AdapterNameWA] != 0)
		{
			TRACE_PRINT("Try to open in monitor mode");
			WifiAdapterNameA = NpcapTranslateAdapterName_Standard2Wifi(AdapterNameWA);
			if (WifiAdapterNameA != NULL)
			{
				lpAdapter = PacketOpenAdapterNPF(WifiAdapterNameA);
				if (lpAdapter == NULL)
				{
					dwLastError = GetLastError();
				}
				else
				{
					lpAdapter->Flags |= INFO_FLAG_NPCAP_DOT11;
					break;
				}
			}
		}
		if (lpAdapter == NULL)
		{
			// monitor mode failed or not available.
			TRACE_PRINT("Normal NPF adapter, trying to open it...");
			lpAdapter = PacketOpenAdapterNPF(AdapterNameWA);
			if (lpAdapter == NULL)
			{
				dwLastError = GetLastError();
			}
		}

	}while(FALSE);

	ReleaseMutex(g_AdaptersInfoMutex);

	if (NULL != AdapterNameA) HeapFree(GetProcessHeap(), 0, AdapterNameA);
	if (NULL != WifiAdapterNameA) HeapFree(GetProcessHeap(), 0, WifiAdapterNameA);
	if (NULL != TranslatedAdapterNameA) HeapFree(GetProcessHeap(), 0, TranslatedAdapterNameA);


	if (dwLastError != ERROR_SUCCESS)
	{
		TRACE_EXIT();
		SetLastError(dwLastError);

		return NULL;
	}
	else
	{
		TRACE_EXIT();

		return lpAdapter;
	}

}

/*! 
  \brief Closes an adapter.
  \param lpAdapter the pointer to the adapter to close. 

  PacketCloseAdapter closes the given adapter and frees the associated ADAPTER structure
*/
_Use_decl_annotations_
VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
	TRACE_ENTER();
	if(!lpAdapter)
	{
        TRACE_PRINT("PacketCloseAdapter: attempt to close a NULL adapter");
		TRACE_EXIT();
		return;
	}

#ifdef HAVE_AIRPCAP_API
	if(lpAdapter->Flags & INFO_FLAG_AIRPCAP_CARD)
		{
			g_PAirpcapClose(lpAdapter->AirpcapAd);
			HeapFree(GetProcessHeap(), 0, lpAdapter);
			TRACE_EXIT();
			return;
		}
#endif // HAVE_AIRPCAP_API

	if (lpAdapter->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Trying to close an unknown adapter type (%u)", lpAdapter->Flags);
	}
	else
	{
		if (lpAdapter->ReadEvent != NULL) {
			SetEvent(lpAdapter->ReadEvent);
			CloseHandle(lpAdapter->ReadEvent);
			lpAdapter->ReadEvent = NULL;
		}
		if (lpAdapter->hFile != INVALID_HANDLE_VALUE && lpAdapter->hFile != NULL) {
			CloseHandle(lpAdapter->hFile);
		}
		HeapFree(GetProcessHeap(), 0, lpAdapter);
	}

	TRACE_EXIT();
}

/*! 
  \brief Allocates a _PACKET structure.
  \return On succeess, the return value is the pointer to a _PACKET structure otherwise the 
   return value is NULL.

  The structure returned will be passed to the PacketReceivePacket() function to receive the
  packets from the driver.

  \warning The Buffer field of the _PACKET structure is not set by this function. 
  The buffer \b must be allocated by the application, and associated to the PACKET structure 
  with a call to PacketInitPacket.
*/
LPPACKET PacketAllocatePacket(void)
{
    LPPACKET    lpPacket;
    DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();
    
	lpPacket=(LPPACKET)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PACKET));
    if (lpPacket==NULL)
    {
	    err = GetLastError();
        TRACE_PRINT("PacketAllocatePacket: HeapAlloc Failed");
    }

	TRACE_EXIT();
	SetLastError(err);
	return lpPacket;
}

/*! 
  \brief Frees a _PACKET structure.
  \param lpPacket The structure to free. 

  \warning the user-allocated buffer associated with the _PACKET structure is not deallocated 
  by this function and \b must be explicitly deallocated by the programmer.

*/
_Use_decl_annotations_
VOID PacketFreePacket(LPPACKET lpPacket)

{
	TRACE_ENTER();
	HeapFree(GetProcessHeap(), 0, lpPacket);
	TRACE_EXIT();
}

/*! 
  \brief Initializes a _PACKET structure.
  \param lpPacket The structure to initialize. 
  \param Buffer A pointer to a user-allocated buffer that will contain the captured data.
  \param Length the length of the buffer. This is the maximum buffer size that will be 
   transferred from the driver to the application using a single read.

  \note the size of the buffer associated with the PACKET structure is a parameter that can sensibly 
  influence the performance of the capture process, since this buffer will contain the packets received
  from the the driver. The driver is able to return several packets using a single read call 
  (see the PacketReceivePacket() function for details), and the number of packets transferable to the 
  application in a call is limited only by the size of the buffer associated with the PACKET structure
  passed to PacketReceivePacket(). Therefore setting a big buffer with PacketInitPacket can noticeably 
  decrease the number of system calls, reducing the impcat of the capture process on the processor.
*/

_Use_decl_annotations_
VOID PacketInitPacket(LPPACKET lpPacket,PVOID Buffer,UINT Length)

{
	TRACE_ENTER();

    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;

	TRACE_EXIT();
}

/*! 
  \brief Read data (packets or statistics) from the NPF driver.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter from which 
   the data is received.
  \param lpPacket Pointer to a PACKET structure that will contain the data.
  \param Sync This parameter is deprecated and will be ignored. It is present for compatibility with 
   older applications.
  \return If the function succeeds, the return value is nonzero.

  The data received with this function can be a group of packets or a static on the network traffic, 
  depending on the working mode of the driver. The working mode can be set with the PacketSetMode() 
  function. Give a look at that function if you are interested in the format used to return statistics 
  values, here only the normal capture mode will be described.

  The number of packets received with this function is variable. It depends on the number of packets 
  currently stored in the driver’s buffer, on the size of these packets and on the size of the buffer 
  associated to the lpPacket parameter. The following figure shows the format used by the driver to pass 
  packets to the application. 

  \image html encoding.gif "method used to encode the packets"

  Packets are stored in the buffer associated with the lpPacket _PACKET structure. The Length field of
  that structure is updated with the amount of data copied in the buffer. Each packet has a header
  consisting in a bpf_hdr structure that defines its length and contains its timestamp. A padding field 
  is used to word-align the data in the buffer (to speed up the access to the packets). The bh_datalen 
  and bh_hdrlen fields of the bpf_hdr structures should be used to extract the packets from the buffer. 
  
  Examples can be seen either in the TestApp sample application (see the \ref packetsamps page) provided
  in the developer's pack, or in the pcap_read() function of wpcap.
*/
_Use_decl_annotations_
BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	BOOLEAN res;
	DWORD err = ERROR_SUCCESS;

	UNUSED(Sync);

	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		//
		// Wait for data, only if the user requested us to do that
		//
		if((int)AdapterObject->ReadTimeOut != -1)
		{
			WaitForSingleObject(AdapterObject->ReadEvent, (AdapterObject->ReadTimeOut==0)? INFINITE: AdapterObject->ReadTimeOut);
		}

		//
		// Read the data.
		// g_PAirpcapRead always returns immediately.
		//
		res = (BOOLEAN)g_PAirpcapRead(AdapterObject->AirpcapAd, 
				(PUCHAR) lpPacket->Buffer, 
				lpPacket->Length, 
				&lpPacket->ulBytesReceived);

		err = GetLastError();
		TRACE_EXIT();
		SetLastError(err);
		return res;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to read on an unknown device type (%u)", AdapterObject->Flags);
		res = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		if((int)AdapterObject->ReadTimeOut != -1)
			WaitForSingleObject(AdapterObject->ReadEvent, (AdapterObject->ReadTimeOut==0)?INFINITE:AdapterObject->ReadTimeOut);
	
		res = (BOOLEAN)ReadFile(AdapterObject->hFile, lpPacket->Buffer, lpPacket->Length, &lpPacket->ulBytesReceived,NULL);
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
	return res;
}

/*! 
  \brief Sends one (or more) copies of a packet to the network.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter that will 
   send the packets.
  \param lpPacket Pointer to a PACKET structure with the packet to send.
  \param Sync This parameter is deprecated and will be ignored. It is present for compatibility with 
   older applications.
  \return If the function succeeds, the return value is nonzero.

  This function is used to send a raw packet to the network. 'Raw packet' means that the programmer 
  will have to include the protocol headers, since the packet is sent to the network 'as is'. 
  The CRC needs not to be calculated and put at the end of the packet, because it will be transparently 
  added by the network interface.

  The behavior of this function is influenced by the PacketSetNumWrites() function. With PacketSetNumWrites(),
  it is possible to change the number of times a single write must be repeated. The default is 1, 
  i.e. every call to PacketSendPacket() will correspond to one packet sent to the network. If this number is
  greater than 1, for example 1000, every raw packet written by the application will be sent 1000 times on 
  the network. This feature mitigates the overhead of the context switches and therefore can be used to generate 
  high speed traffic. It is particularly useful for tools that test networks, routers, and servers and need 
  to obtain high network loads.
  The optimized sending process is still limited to one packet at a time: for the moment it cannot be used 
  to send a buffer with multiple packets.

  \note The ability to write multiple packets is currently present only in the Windows NTx version of the 
  packet driver. In Windows 95/98/ME it is emulated at user level in packet.dll. This means that an application
  that uses the multiple write method will run in Windows 9x as well, but its performance will be very low 
  compared to the one of WindowsNTx.
*/
_Use_decl_annotations_
BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
    DWORD        BytesTransfered;
	BOOLEAN		Result;    
	DWORD err = ERROR_SUCCESS;
	TRACE_ENTER();

	UNUSED(Sync);

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		if(g_PAirpcapWrite)
		{
			Result = (BOOLEAN)g_PAirpcapWrite(AdapterObject->AirpcapAd, (PCHAR) lpPacket->Buffer, lpPacket->Length);
			
			err = GetLastError();
			TRACE_EXIT();
			SetLastError(err);
			return Result;
		}
		else
		{
			TRACE_PRINT("Transmission not supported with this version of AirPcap");

			TRACE_EXIT();
			SetLastError(ERROR_NOT_SUPPORTED);
			return FALSE;
		}
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to write on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		Result = (BOOLEAN)WriteFile(AdapterObject->hFile,lpPacket->Buffer,lpPacket->Length,&BytesTransfered,NULL);
		err = GetLastError();
	}

	TRACE_EXIT();
	SetLastError(err);
	return Result;
}

/*! 
  \brief Sends a buffer of packets to the network.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter that will 
   send the packets.
  \param PacketBuff Pointer to buffer with the packets to send.
  \param Size Size of the buffer pointed by the PacketBuff argument.
  \param Sync if TRUE, the packets are sent respecting the timestamps. If FALSE, the packets are sent as
         fast as possible
  \return The amount of bytes actually sent. If the return value is smaller than the Size parameter, an
          error occurred during the send. The error can be caused by a driver/adapter problem or by an
		  inconsistent/bogus packet buffer.

  This function is used to send a buffer of raw packets to the network. The buffer can contain an arbitrary
  number of raw packets, each of which preceded by a dump_bpf_hdr structure. The dump_bpf_hdr is the same used
  by WinPcap and libpcap to store the packets in a file, therefore sending a capture file is straightforward.
  'Raw packets' means that the sending application will have to include the protocol headers, since every packet 
  is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be 
  transparently added by the network interface.

  \note Using this function if more efficient than issuing a series of PacketSendPacket(), because the packets are
  buffered in the kernel driver, so the number of context switches is reduced.

  \note When Sync is set to TRUE, the packets are synchronized in the kernel with a high precision timestamp.
  This requires a remarkable amount of CPU, but allows to send the packets with a precision of some microseconds
  (depending on the precision of the performance counter of the machine). Such a precision cannot be reached 
  sending the packets separately with PacketSendPacket().
*/
_Use_decl_annotations_
INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
    BOOLEAN			Res;
    C_ASSERT(sizeof(DWORD) == sizeof(ULONG));
    DWORD			BytesTransfered, TotBytesTransfered=0;
	struct timeval	BufStartTime = {};
	LARGE_INTEGER	StartTicks = {}, CurTicks = {}, TargetTicks = {}, TimeFreq = {};
	TIMECAPS tcap = {};
	DWORD err = ERROR_SUCCESS;
	struct dump_bpf_hdr *pHdr = NULL;
	LONGLONG prev_usec_diff = 0;

	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		TRACE_PRINT("PacketSendPackets: packet sending not allowed on airpcap adapters");
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return 0;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to write on an unknown device type (%u)", AdapterObject->Flags);
		err = (ERROR_BAD_DEV_TYPE);
		TotBytesTransfered = 0;
	}
	else
	{
		pHdr = (struct dump_bpf_hdr *)PacketBuff;
		if (Sync)
		{
			// Obtain starting timestamp of the buffer
			BufStartTime.tv_sec = pHdr->ts.tv_sec;
			BufStartTime.tv_usec = pHdr->ts.tv_usec;

			// Request highest resolution of sleep timer
			if (MMSYSERR_NOERROR == timeGetDevCaps(&tcap, sizeof(tcap))) {
				timeBeginPeriod(tcap.wPeriodMin);
			}
			else {
				tcap.wPeriodMin = 0;
			}

			// Retrieve the reference time counters
			QueryPerformanceCounter(&StartTicks);
			QueryPerformanceFrequency(&TimeFreq);
		}

		do{
			// Send the data to the driver
			Res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
				(Sync)?BIOCSENDPACKETSSYNC:BIOCSENDPACKETSNOSYNC,
				(PCHAR) pHdr,
				Size - TotBytesTransfered,
				NULL,
				0,
				&BytesTransfered,
				NULL);

			// Exit from the loop on error
			if(Res != TRUE) {
				err = GetLastError();
				if (err == RPC_S_INVALID_TIMEOUT) {
					err = ERROR_INVALID_TIME;
				}
				break;
			}

			TotBytesTransfered += BytesTransfered;

			// Exit from the loop if we have transferred everything
			if(TotBytesTransfered >= Size)
				break;

			// If there's less than a packet header remaining, exit and error
			if (Size < TotBytesTransfered + sizeof(struct dump_bpf_hdr)) {
				err = ERROR_INVALID_PARAMETER;
				break;
			}

			pHdr = (struct dump_bpf_hdr *)((PCHAR)pHdr + BytesTransfered);

			if (Sync)
			{
				QueryPerformanceCounter(&CurTicks);
				LONGLONG usec_diff = ((LONGLONG)pHdr->ts.tv_sec - BufStartTime.tv_sec) * 1000000
					+ pHdr->ts.tv_usec - BufStartTime.tv_usec;
				if (usec_diff < prev_usec_diff) {
					// Timestamps out of order
					err = ERROR_INVALID_TIME;
					break;
				}
				prev_usec_diff = usec_diff;

				// calculate the target QPC ticks to send the next packet
				TargetTicks.QuadPart = StartTicks.QuadPart + (usec_diff * TimeFreq.QuadPart) / 1000000;

				if (CurTicks.QuadPart < TargetTicks.QuadPart)
				{
					// calculate how much time is left to wait (milliseconds)
					LONGLONG msec_diff = (TargetTicks.QuadPart - CurTicks.QuadPart) * 1000 / TimeFreq.QuadPart;
					// Weirdly-huge intervals would lead to integer overflow or infinite sleep.
					if (msec_diff >= MAXDWORD || msec_diff == INFINITE) {
						err = ERROR_INVALID_TIME;
						break;
					}

					// Wait until the time interval has elapsed.  Intervals less than 1ms are assumed to be
					// lost in IRP processing, thread scheduling, and other jitter.
					if (msec_diff > 0) {
						Sleep((DWORD)msec_diff);
					}
				}
			}

		}
		while(TRUE);

		if (Sync && tcap.wPeriodMin > 0) {
			timeEndPeriod(tcap.wPeriodMin);
		}
	}

	TRACE_EXIT();
	SetLastError(err);
	return TotBytesTransfered;
}

/*! 
  \brief Defines the minimum amount of data that will be received in a read.
  \param AdapterObject Pointer to an _ADAPTER structure
  \param nbytes the minimum amount of data in the kernel buffer that will cause the driver to
   release a read on this adapter.
  \return If the function succeeds, the return value is nonzero.

  In presence of a large value for nbytes, the kernel waits for the arrival of several packets before 
  copying the data to the user. This guarantees a low number of system calls, i.e. lower processor usage, 
  i.e. better performance, which is a good setting for applications like sniffers. Vice versa, a small value 
  means that the kernel will copy the packets as soon as the application is ready to receive them. This is 
  suggested for real time applications (like, for example, a bridge) that need the better responsiveness from 
  the kernel.

  \b note: this function has effect only in Windows NTx. The driver for Windows 9x doesn't offer 
  this possibility, therefore PacketSetMinToCopy is implemented under these systems only for compatibility.
*/

_Use_decl_annotations_
BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();
	
#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetMinToCopy(AdapterObject->AirpcapAd, nbytes);

		err = GetLastError();
		TRACE_EXIT();
		SetLastError(err);
		return Result;
	}
#endif // HAVE_AIRPCAP_API
	
	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to set mintocopy on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSMINTOCOPY,&nbytes,4,NULL,0,&BytesReturned,NULL);
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
	return Result; 		
}

/*!
  \brief Sets the working mode of an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param mode The new working mode of the adapter.
  \return If the function succeeds, the return value is nonzero.

  The device driver of Npcap has 2 working modes:
  - Capture mode (mode = PACKET_MODE_CAPT): normal capture mode. The packets transiting on the wire are copied
   to the application when PacketReceivePacket() is called. This is the default working mode of an adapter.
  - Statistical mode (mode = PACKET_MODE_STAT): programmable statistical mode. PacketReceivePacket() returns, at
   precise intervals, statistics values on the network traffic. The interval between the statistic samples is 
   by default 1 second but it can be set to any other value (with a 1 ms precision) with the 
   PacketSetReadTimeout() function. The data returned by PacketReceivePacket() when the adapter is in statistical
   mode is shown in the following figure:<p>
   	 \image html stats.gif "data structure returned by statistical mode"
   Two 64-bit counters are provided: the number of packets and the amount of bytes that satisfy a filter 
   previously set with PacketSetBPF(). If no filter has been set, all the packets are counted. The counters are 
   encapsulated in a bpf_hdr structure, so that they will be parsed correctly by libpcap. Statistical mode has a 
   very low impact on system performance compared to capture mode. 
   Look at the NetMeter example in the 
   Npcap SDK to see how to use statistics mode.
*/
_Use_decl_annotations_
BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;

   TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
   if (AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
   {
	   if (mode == PACKET_MODE_CAPT)
	   {
		   Result = TRUE;
	   }
	   else
	   {
		   Result = FALSE;
		   err = ERROR_NOT_SUPPORTED;
	   }

	   TRACE_EXIT();
	   SetLastError(err);
	   return Result;
   }
#endif //HAVE_AIRPCAP_API

   if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
   {
	   TRACE_PRINT1("Request to set mode on an unknown device type (%u)", AdapterObject->Flags);
	   Result = FALSE;
	   err = ERROR_NOT_SUPPORTED;
   }
   else
   {
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSMODE,&mode,4,NULL,0,&BytesReturned,NULL);
		err = GetLastError();
   }

   TRACE_EXIT();
   SetLastError(err);
   return Result;

}

/*!
  Dump mode functions not supported by Npcap
*/

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	TRACE_ENTER();
	UNREFERENCED_PARAMETER(AdapterObject);
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(len);
	TRACE_EXIT();
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}
BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	TRACE_ENTER();
	UNREFERENCED_PARAMETER(AdapterObject);
	UNREFERENCED_PARAMETER(maxfilesize);
	UNREFERENCED_PARAMETER(maxnpacks);
	TRACE_EXIT();
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}
BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	TRACE_ENTER();
	UNREFERENCED_PARAMETER(AdapterObject);
	UNREFERENCED_PARAMETER(sync);
	TRACE_EXIT();
	SetLastError(ERROR_NOT_SUPPORTED);
	return FALSE;
}

/*!
  \brief Returns the notification event associated with the read calls on an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \return The handle of the event that the driver signals when some data is available in the kernel buffer.

  The event returned by this function is signaled by the driver if:
  - The adapter pointed by AdapterObject is in capture mode and an amount of data greater or equal 
  than the one set with the PacketSetMinToCopy() function is received from the network.
  - The adapter is removed from the system.
  - The kernel buffer is full.

  As long as the event is in a signaled state, a call to PacketReceivePacket() will return immediately.
  Otherwise, PacketReceivePacket() itself will wait on the event to be signaled, until the timeout set by
  PacketSetReadTimeout() expires.
  The event can be passed to standard Win32 functions (like WaitForSingleObject or WaitForMultipleObjects) 
  to wait until the driver's buffer contains some data. It is particularly useful in GUI applications that 
  need to wait concurrently on several events.

*/
_Use_decl_annotations_
HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
	TRACE_ENTER();
	TRACE_EXIT();
    return AdapterObject->ReadEvent;
}

/*!
  \brief Sets the number of times a single packet written with PacketSendPacket() will be repeated on the network.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param nwrites Number of copies of a packet that will be physically sent by the interface.
  \return If the function succeeds, the return value is nonzero.

	See PacketSendPacket() for details.
*/
_Use_decl_annotations_
BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

	if(AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT("PacketSetNumWrites: not allowed on non-NPF adapters");
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

    Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSWRITEREP,&nwrites,4,NULL,0,&BytesReturned,NULL);
    err = GetLastError();

	TRACE_EXIT();
	SetLastError(err);
	return Result;
}

/*!
  \brief Sets the timeout after which a read on an adapter returns.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param timeout indicates the timeout, in milliseconds, after which a call to PacketReceivePacket() on 
  the adapter pointed by AdapterObject will be released, also if no packets have been captured by the driver. 
  Setting timeout to 0 means no timeout, i.e. PacketReceivePacket() never returns if no packet arrives.  
  A timeout of -1 causes PacketReceivePacket() to always return immediately.
  \return If the function succeeds, the return value is nonzero.

  \note This function works also if the adapter is working in statistics mode, and can be used to set the 
  time interval between two statistic reports.
*/
_Use_decl_annotations_
BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;
	
	TRACE_ENTER();

	AdapterObject->ReadTimeOut = timeout;

#ifdef HAVE_AIRPCAP_API
	//
	// Timeout with AirPcap is handled at user level
	//
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		TRACE_EXIT();
		return TRUE;
	}
#endif // HAVE_AIRPCAP_API

	if(AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		//
		// if we are here, it's an unsupported ADAPTER type!
		//
		TRACE_PRINT1("Request to set read timeout on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		Result = TRUE;
	}

	TRACE_EXIT();
	SetLastError(err);
	return Result;
	
}

/*!
  \brief Sets the size of the kernel-level buffer associated with a capture.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param dim New size of the buffer, in \b kilobytes.
  \return The function returns TRUE if successfully completed, FALSE if there is not enough memory to 
   allocate the new buffer.

  When a new dimension is set, the data in the old buffer is discarded and the packets stored in it are 
  lost. 
  
  Note: the dimension of the kernel buffer affects heavily the performances of the capture process.
  An adequate buffer in the driver is able to keep the packets while the application is busy, compensating 
  the delays of the application and avoiding the loss of packets during bursts or high network activity. 
  The buffer size is set to 0 when an instance of the driver is opened: the programmer should remember to 
  set it to a proper value. As an example, wpcap sets the buffer size to 1MB at the beginning of a capture.
*/
_Use_decl_annotations_
BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetKernelBuffer(AdapterObject->AirpcapAd, dim);
		err = GetLastError();
		
		TRACE_EXIT();
		SetLastError(err);
		return Result;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to set buf size on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSETBUFFERSIZE,&dim,sizeof(dim),NULL,0,&BytesReturned,NULL);
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
	return Result;
}

/*!
  \brief Sets a kernel-level packet filter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param fp Pointer to a filtering program that will be associated with this capture or monitoring 
  instance and that will be executed on every incoming packet.
  \return This function returns TRUE if the filter is set successfully, FALSE if an error occurs 
   or if the filter program is not accepted after a safeness check by the driver.  The driver performs 
   the check in order to avoid system crashes due to buggy or malicious filters, and it rejects non
   conformat filters.

  This function associates a new BPF filter to the adapter AdapterObject. The filter, pointed by fp, is a 
  set of bpf_insn instructions.

  A filter can be automatically created by using the pcap_compile() function of wpcap. This function 
  converts a human readable text expression with the tcpdump/libpcap syntax (see the manual of WinDump at 
  http://www.winpcap.org/windump for details) into a BPF program. If your program doesn't link wpcap, but 
  you need to know the code of a particular filter, you can run WinDump with the -d or -dd or -ddd 
  flags to obtain the pseudocode.

*/
_Use_decl_annotations_
BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	DWORD err = ERROR_SUCCESS;
	
	TRACE_ENTER();
	
#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetFilter(AdapterObject->AirpcapAd, 
			(char*)fp->bf_insns,
			fp->bf_len * sizeof(struct bpf_insn));
		err = GetLastError();

		TRACE_EXIT();
		SetLastError(err);
		return Result;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Request to set BPF filter on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSETF,(char*)fp->bf_insns,fp->bf_len*sizeof(struct bpf_insn),NULL,0,&BytesReturned,NULL);
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
	return Result;
}

/*!
  \brief Sets the behavior of the NPF driver with packets sent by itself: capture or drop.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param LoopbackBehavior Can be one of the following:
	- \ref NPF_ENABLE_LOOPBACK
	- \ref NPF_DISABLE_LOOPBACK
  \return If the function succeeds, the return value is nonzero.

  \note: when opened, adapters have loopback capture \b enabled.
*/
_Use_decl_annotations_
BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	DWORD BytesReturned;
	BOOLEAN result;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT("PacketSetLoopbackBehavior: not allowed on non-NPF adapters");
	
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}


	result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
		BIOCISETLOBBEH,
		&LoopbackBehavior,
		sizeof(UINT),
		NULL,
		0,
		&BytesReturned,
		NULL);
	err = GetLastError();

	TRACE_EXIT();
	SetLastError(err);
	return result;
}

/*!
\brief Sets the timestamp mode of an adapter handle.
\param AdapterObject Pointer to an _ADAPTER structure.
\param mode The new timestamp mode from the TIMESTAMPMODE_* definitions
\return TRUE if the function succeeds, FALSE otherwise.
*/
_Use_decl_annotations_
BOOLEAN PacketSetTimestampMode(LPADAPTER AdapterObject, ULONG mode)
{
	DWORD BytesReturned;
	BOOLEAN result;
	DWORD err = ERROR_SUCCESS;

	TRACE_ENTER();

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT("PacketSetTimestampMode: not allowed on non-NPF adapters");
	
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}


	result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
		BIOCSTIMESTAMPMODE,
		&mode,
		sizeof(ULONG),
		NULL,
		0,
		&BytesReturned,
		NULL);
	err = GetLastError();

	TRACE_EXIT();
	SetLastError(err);
	return result;
}

/*!
  \brief Retrieve the list of supported timestamp modes on an adapter
  \param pModes User allocated array that will be filled with the available timestamp modes. First element is the length of the array.
  \return If the function succeeds, the return value is nonzero. If the return value is zero, pModes[0] contains 
          the number of ULONGs that are needed to contain the timestamp mode list.
	  */
_Use_decl_annotations_
BOOLEAN PacketGetTimestampModes(LPADAPTER AdapterObject, PULONG pModes)
{
	BOOLEAN result = FALSE;
	DWORD BytesReturned = 0;
	DWORD err = ERROR_SUCCESS;
	TRACE_ENTER();

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		*pModes = 0;
		TRACE_PRINT("PacketGetTimestampMode: not allowed on non-NPF adapters");
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

	result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
			BIOCGTIMESTAMPMODES,
			NULL,
			0,
			pModes,
			pModes[0] * sizeof(ULONG),
			&BytesReturned,
			NULL);
	err = GetLastError();
	if (err != ERROR_MORE_DATA && BytesReturned != ((ULONGLONG)pModes[0] + 1) * sizeof(ULONG))
	{
		TRACE_PRINT2("PacketGetTimestampModes: Got %d bytes but expected %d!", BytesReturned, (pModes[0] + 1) * sizeof(ULONG));
		// Have to adjust to avoid reading bad data.
		pModes[0] = (BytesReturned / sizeof(ULONG)) - 1;
	}
	TRACE_EXIT();
	SetLastError(err);
	return result;
}

/*!
  \brief Sets the snap len on the adapters that allow it.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param snaplen Desired snap len for this capture.
  \return If the function succeeds, the return value is nonzero and specifies the actual snaplen that 
   the card is using. If the function fails or if the card does't allow to set sna length, the return 
   value is 0.

  The snap len is the amount of packet that is actually captured by the interface and received by the
  application. Some interfaces allow to capture only a portion of any packet for performance reasons.

  \note: the return value can be different from the snaplen parameter, for example some boards round the
  snaplen to 4 bytes.
*/
_Use_decl_annotations_
INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{
	INT Result;

	TRACE_ENTER();

	UNUSED(snaplen);
	UNUSED(AdapterObject);

	Result = 0;

	TRACE_EXIT();
	return Result;

}

/*!
  \brief Returns a couple of statistic values about the current capture session.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param s Pointer to a user provided bpf_stat structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero.

  With this function, the programmer can know the value of two internal variables of the driver:

  - the number of packets that have been received by the adapter AdapterObject, starting at the 
   time in which it was opened with PacketOpenAdapter. 
  - the number of packets that have been dropped by the driver. A packet is dropped when the kernel
   buffer associated with the adapter is full. 
*/
_Use_decl_annotations_
BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	DWORD err = ERROR_SUCCESS;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications
	
	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		AirpcapStats tas;

		Res = (BOOLEAN)g_PAirpcapGetStats(AdapterObject->AirpcapAd, &tas);
		
		if (Res)
		{
			//
			// Do NOT write this value. This function is probably called with a small structure, old style, containing only the first three fields recv, drop, ifdrop
			//
//			s->bs_capt = tas.Capt;
			s->bs_drop = tas.Drops;
			s->bs_recv = tas.Recvs;
			s->ps_ifdrop = tas.IfDrops;
		}
		else
		{
			err = GetLastError();
		}

		TRACE_EXIT();
		SetLastError(err);
		return Res;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{	
		TRACE_PRINT1("Request to obtain statistics on an unknown device type (%u)", AdapterObject->Flags);
		Res = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
			Res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
			BIOCGSTATS,
			NULL,
			0,
			&tmpstat,
			sizeof(struct bpf_stat),
			&BytesReturned,
			NULL);
		

		if (Res)
		{
			// Copy only the first two values retrieved from the driver
			s->bs_recv = tmpstat.bs_recv;
			s->bs_drop = tmpstat.bs_drop;
		}
		else
		{
			err = GetLastError();
		}

	}

	TRACE_EXIT();
	SetLastError(err);
	return Res;

}

/*!
  \brief Returns statistic values about the current capture session. Enhanced version of PacketGetStats().
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param s Pointer to a user provided bpf_stat structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero.

  With this function, the programmer can retireve the sname values provided by PacketGetStats(), plus:

  - the number of drops by interface (not yet supported, always 0). 
  - the number of packets that reached the application, i.e that were accepted by the kernel filter and
  that fitted in the kernel buffer. 
*/
_Use_decl_annotations_
BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	DWORD err = ERROR_SUCCESS;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications

	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		AirpcapStats tas;

		Res = (BOOLEAN)g_PAirpcapGetStats(AdapterObject->AirpcapAd, &tas);
		
		if (Res)
		{
			s->bs_capt = tas.Capt;
			s->bs_drop = tas.Drops;
			s->bs_recv = tas.Recvs;
			s->ps_ifdrop = tas.IfDrops;
		}
		else
		{
			err = GetLastError();
		}

		TRACE_EXIT();
		SetLastError(err);
		return Res;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{	
		TRACE_PRINT1("Request to obtain statistics on an unknown device type (%u)", AdapterObject->Flags);
		Res = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
			Res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
			BIOCGSTATS,
			NULL,
			0,
			&tmpstat,
			sizeof(struct bpf_stat),
			&BytesReturned,
			NULL);
		

		if (Res)
		{
			s->bs_recv = tmpstat.bs_recv;
			s->bs_drop = tmpstat.bs_drop;
			s->ps_ifdrop = tmpstat.ps_ifdrop;
			s->bs_capt = tmpstat.bs_capt;
		}
		else
		{
			err = GetLastError();
		}
	}

	TRACE_EXIT();
	SetLastError(err);
	return Res;

}

_Success_(return == ERROR_SUCCESS)
static DWORD PacketRequestHelper(
		_In_ HANDLE hAdapter,
		_In_ BOOLEAN Set,
		_In_ PPACKET_OID_DATA OidData)
{
	DWORD BytesReturned = 0;
	DWORD err = ERROR_SUCCESS;
	if(!DeviceIoControl(hAdapter, (DWORD) (Set ? BIOCSETOID : BIOCQUERYOID),
                           OidData, sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
			   OidData, sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
			   &BytesReturned, NULL))
	{
		err = GetLastError();
	}
	TRACE_PRINT4("PacketRequest: OID = 0x%.08x, Length = %d, Set = %d, ErrCode = 0x%.08x",
			OidData->Oid,
			OidData->Length,
			Set,
			err & ~(1 << 29));
	return err;
}

/*!
  \brief Performs a query/set operation on an internal variable of the network card driver.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param Set Determines if the operation is a set (Set=TRUE) or a query (Set=FALSE).
  \param OidData A pointer to a _PACKET_OID_DATA structure that contains or receives the data.
  \return If the function succeeds, the return value is nonzero.

  \note not all the network adapters implement all the query/set functions. There is a set of mandatory 
  OID functions that is granted to be present on all the adapters, and a set of facultative functions, not 
  provided by all the cards (see the Microsoft DDKs to see which functions are mandatory). If you use a 
  facultative function, be careful to enclose it in an if statement to check the result.
*/
_Use_decl_annotations_
BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData)
{
	DWORD err = ERROR_SUCCESS;
	TRACE_ENTER();

	if(AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT("PacketRequest not supported on non-NPF adapters.");
		TRACE_EXIT();
		SetLastError(ERROR_NOT_SUPPORTED);
		return FALSE;
	}

	err = PacketRequestHelper(AdapterObject->hFile, Set, OidData);

	TRACE_EXIT();
	SetLastError(err);
	return (err == ERROR_SUCCESS);
}

/*!
  \brief Sets a hardware filter on the incoming packets.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param Filter The identifier of the filter.
  \return If the function succeeds, the return value is nonzero.

  The filter defined with this filter is evaluated by the network card, at a level that is under the NPF
  device driver. Here is a list of the most useful hardware filters (A complete list can be found in ntddndis.h):

  - NDIS_PACKET_TYPE_PROMISCUOUS: sets promiscuous mode. Every incoming packet is accepted by the adapter. 
  - NDIS_PACKET_TYPE_DIRECTED: only packets directed to the workstation's adapter are accepted. 
  - NDIS_PACKET_TYPE_BROADCAST: only broadcast packets are accepted. 
  - NDIS_PACKET_TYPE_MULTICAST: only multicast packets belonging to groups of which this adapter is a member are accepted. 
  - NDIS_PACKET_TYPE_ALL_MULTICAST: every multicast packet is accepted. 
  - NDIS_PACKET_TYPE_ALL_LOCAL: all local packets, i.e. NDIS_PACKET_TYPE_DIRECTED + NDIS_PACKET_TYPE_BROADCAST + NDIS_PACKET_TYPE_MULTICAST 
*/
_Use_decl_annotations_
BOOLEAN PacketSetHwFilter(LPADAPTER  AdapterObject,ULONG Filter)
{
    BOOLEAN    Status;
    DWORD err = ERROR_SUCCESS;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1] = { 0 };
    PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA) IoCtlBuffer;
	
	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		// Airpcap for the moment is always in promiscuous mode, and ignores any other filters
		return TRUE;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags & INFO_FLAG_MASK_NOT_NPF)
	{
		TRACE_PRINT1("Setting HW filter not supported on this adapter type (%u)", AdapterObject->Flags);
		Status = FALSE;
		err = ERROR_NOT_SUPPORTED;
	}
	else
	{
		OidData->Oid = OID_GEN_CURRENT_PACKET_FILTER;
		OidData->Length = sizeof(ULONG);
	    *((PULONG) OidData->Data) = Filter;
		Status = PacketRequest(AdapterObject, TRUE, OidData);
		err = GetLastError();
	}
	
	TRACE_EXIT();
	SetLastError(err);
    return Status;
}

/*!
  \brief Retrieve the list of available network adapters and their description.
  \param pStr User allocated string that will be filled with the names of the adapters.
  \param BufferSize Length of the buffer pointed by pStr. If the function fails, this variable contains the 
         number of bytes that are needed to contain the adapter list.
  \return If the function succeeds, the return value is nonzero. If the return value is zero, BufferSize contains 
          the number of bytes that are needed to contain the adapter list.

  Usually, this is the first function that should be used to communicate with the driver.
  It returns the names of the adapters installed on the system <B>and supported by WinPcap</B>. 
  After the names of the adapters, pStr contains a string that describes each of them.

  After a call to PacketGetAdapterNames pStr contains, in succession:
  - a variable number of ASCII strings, each with the names of an adapter, separated by a "\0"
  - a double "\0"
  - a number of ASCII strings, each with the description of an adapter, separated by a "\0". The number 
   of descriptions is the same of the one of names. The first description corresponds to the first name, and
   so on.
  - a double "\0". 
*/

_Use_decl_annotations_
BOOLEAN PacketGetAdapterNames(PCHAR pStr, PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 0;
	DWORD dwError = ERROR_SUCCESS;

	TRACE_ENTER();

	if (BufferSize == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	TRACE_PRINT_OS_INFO();

	TRACE_PRINT2("Packet DLL version %hs, Driver version %hs", PacketLibraryVersion, PacketDriverVersion);

	TRACE_PRINT1("PacketGetAdapterNames: BufferSize=%u", *BufferSize);


#ifdef LOAD_OPTIONAL_LIBRARIES
	//
	// Check the presence on some libraries we rely on, and load them if we found them
	//f
	PacketLoadLibrariesDynamically();
#endif

	//d
	// Create the adapter information list
	//
	TRACE_PRINT("Populating the adapter list...");

	dwError = PacketPopulateAdaptersInfoList();

	if(dwError != ERROR_SUCCESS) 
	{
		*BufferSize = 0;

		TRACE_PRINT("No adapters found in the system. Failing.");
 	
 		TRACE_EXIT();
		SetLastError(dwError);
		return FALSE;		// No adapters to return
	}

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	SizeNeeded = g_AdaptersInfoList.NamesLen + g_AdaptersInfoList.DescsLen;
	// Check that we don't overflow the buffer.
	if (pStr == NULL || SizeNeeded > *BufferSize)
	{
		ReleaseMutex(g_AdaptersInfoMutex);

		TRACE_PRINT2("PacketGetAdapterNames: input buffer too small (%u) need %u bytes", pStr ? *BufferSize : 0, SizeNeeded);
 
		*BufferSize = SizeNeeded;  // Report the required size

		TRACE_EXIT();
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	// Leave 1 byte each for empty-string list terminators
	size_t cchNamesRemaining = g_AdaptersInfoList.NamesLen - 1;
	size_t cchDescsRemaining = g_AdaptersInfoList.DescsLen - 1;
	PCHAR pNames = pStr;
	PCHAR pDescs = pStr + g_AdaptersInfoList.NamesLen;
	HRESULT hrStatus = S_OK;
	// Copy the information
	for(TAdInfo = g_AdaptersInfoList.Adapters; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		// Translate the adapter name string's "NPCAP_{XXX}" to "NPF_{XXX}" for compatibility with WinPcap, because some user softwares hard-coded the "NPF_" string
		// NOTE: This is only safe because NPF is shorter than NPCAP. We'll have to fix up the lengths later...
		PCHAR TranslatedName = NpcapTranslateAdapterName_Npcap2Npf(TAdInfo->Name);
		// Copy the name
		hrStatus = StringCchCopyExA(
				pNames, 
				cchNamesRemaining, 
				TranslatedName ? TranslatedName : TAdInfo->Name,
				&pNames, // Receives pointer to null terminator at the end of the name
				&cchNamesRemaining, // Receives unused chars *including* null terminator.
				0);
		if (TranslatedName) {
			HeapFree(GetProcessHeap(), 0, TranslatedName);
		}
		if (FAILED(hrStatus)) {
			break;
		}
		// skip null terminator
		pNames++;
		cchNamesRemaining--;

		// Copy the description
		hrStatus = StringCchCopyExA(
				pDescs,
				cchDescsRemaining,
				TAdInfo->Description,
				&pDescs,
				&cchDescsRemaining,
				0);
		if (FAILED(hrStatus)) {
			break;
		}
		// skip null terminator
		pDescs++;
		cchDescsRemaining--;
	}
	// Check that all copies succeeded
	if (FAILED(hrStatus)) {
		ReleaseMutex(g_AdaptersInfoMutex);

		TRACE_PRINT1("PacketGetAdapterNames: Copy of data failed: %08x", hrStatus);
 
		*BufferSize = SizeNeeded;  // Report the required size

		TRACE_EXIT();
		SetLastError(hrStatus == STRSAFE_E_INSUFFICIENT_BUFFER ? ERROR_INSUFFICIENT_BUFFER : ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// End each list with a null (empty string)
	*pNames = '\0';
	*pDescs = '\0';

	// If we had leftover space for descriptions, adjust reported size (unexpected)
	SizeNeeded -= (ULONG) cchDescsRemaining;

	// If the names took up less space than we anticipated (due to Npcap2Npf translation)
	// then we need to shift the descriptions to the left.
	if (cchNamesRemaining > 0) {
		// Copy from the original descriptions offset, shifting left by the remaining amount.
		for (ULONG i = g_AdaptersInfoList.NamesLen; i < SizeNeeded; i++) {
			pStr[i - cchNamesRemaining] = pStr[i];
		}
		// Adjust reported size
		SizeNeeded -= (ULONG) cchNamesRemaining;
	}

	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_EXIT();
	return TRUE;
}

/*!
  \brief Returns comprehensive information the addresses of an adapter.
  \param AdapterName String that contains the name of the adapter.
  \param buffer A user allocated array of npf_if_addr that will be filled by the function.
  \param NEntries Size of the array (in npf_if_addr).
  \return If the function succeeds, the return value is nonzero.

  This function grabs from the registry information like the IP addresses, the netmasks 
  and the broadcast addresses of an interface. The buffer passed by the user is filled with 
  npf_if_addr structures, each of which contains the data for a single address. If the buffer
  is full, the reaming addresses are dropeed, therefore set its dimension to sizeof(npf_if_addr)
  if you want only the first address.
*/
_Use_decl_annotations_
BOOLEAN PacketGetNetInfoEx(PCCH AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	static ULONG MaxGAABufLen = ADAPTERS_ADDRESSES_INITIAL_BUFFER_SIZE;
	ULONG BufLen = MaxGAABufLen;
	PIP_ADAPTER_ADDRESSES AdBuffer = NULL, TmpAddr = NULL;
	PCHAR Tname = NULL;
	BOOLEAN Res = FALSE;
	DWORD err = ERROR_SUCCESS;
	static npf_if_addr loopback_addrs[2] = {0};
	static BOOLEAN loopback_addrs_init = FALSE;

	TRACE_ENTER();

	// Provide conversion for backward compatibility
	if(AdapterName[1] == 0)
	{
		Tname = WChar2SChar((PWCHAR)AdapterName);
		AdapterName = Tname;
	}

#ifdef HAVE_AIRPCAP_API
	// Airpcap devices don't have network addresses
	if (IsAirpcapName(AdapterName)) {
		*NEntries = 0;
		Res = TRUE;
		goto END_PacketGetNetInfoEx;
	}
#endif

	if (PacketIsLoopbackAdapter(AdapterName))
	{
		if (!loopback_addrs_init) {
			struct sockaddr_in *pV4 = (struct sockaddr_in *)&loopback_addrs[0].IPAddress;
			pV4->sin_family = AF_INET;
			if (1 > InetPtonA(AF_INET, "127.0.0.1", &pV4->sin_addr)) {
				goto END_PacketGetNetInfoEx;
			}

			pV4 = (struct sockaddr_in*)&loopback_addrs[0].SubnetMask;
			pV4->sin_family = AF_INET;
			if (1 > InetPtonA(AF_INET, "255.0.0.0", &pV4->sin_addr)) {
				goto END_PacketGetNetInfoEx;
			}

			struct sockaddr_in6 *pV6 = (struct sockaddr_in6 *)&loopback_addrs[1].IPAddress;
			pV6->sin6_family = AF_INET6;
			pV6->sin6_scope_struct.Level = ScopeLevelLink;
			if (1 > InetPtonA(AF_INET6, "::1", &pV6->sin6_addr)) {
				goto END_PacketGetNetInfoEx;
			}

			pV6 = (struct sockaddr_in6*)&loopback_addrs[1].SubnetMask;
			pV6->sin6_family = AF_INET6;
			pV6->sin6_scope_struct.Level = ScopeLevelLink;
			memset(&pV6->sin6_addr, 0xff, sizeof(IN6_ADDR));

			loopback_addrs_init = TRUE;
		}
		*NEntries = min(2, *NEntries);
		for (int i=0; i < *NEntries; i++) {
			buffer[i] = loopback_addrs[i];
		}
		Res = TRUE;
		goto END_PacketGetNetInfoEx;
	}

	PCCH AdapterGuid = strchr(AdapterName, '{');
	if (AdapterGuid == NULL)
	{
		goto END_PacketGetNetInfoEx;
	}

	AdBuffer = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufLen);
	if (AdBuffer == NULL)
	{
		goto END_PacketGetNetInfoEx;
	}
	ULONG RetVal = ERROR_SUCCESS;
	for (int i = 0; i < ADAPTERS_ADDRESSES_MAX_TRIES; i++)
	{

		RetVal = GetAdaptersAddresses(AF_UNSPEC,
			GAA_FLAG_SKIP_DNS_INFO | // Undocumented, reported to help avoid errors on Win10 1809
			// We don't use any of these features:
			GAA_FLAG_SKIP_DNS_SERVER |
			GAA_FLAG_SKIP_ANYCAST |
			GAA_FLAG_SKIP_MULTICAST |
			GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, AdBuffer, &BufLen);
		if (RetVal == ERROR_BUFFER_OVERFLOW)
		{
			TRACE_PRINT("PacketGetNetInfoEx: GetAdaptersAddresses Too small buffer");
			TmpAddr = (PIP_ADAPTER_ADDRESSES)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AdBuffer, BufLen);
			if (TmpAddr == NULL)
			{
				goto END_PacketGetNetInfoEx;
			}
			AdBuffer = TmpAddr;
		}
		else
		{
			err = GetLastError();
			break;
		}
	}

	if (RetVal != ERROR_SUCCESS)
	{
		goto END_PacketGetNetInfoEx;
	}


	//
	// Now obtain the information about this adapter
	//
	for (TmpAddr=AdBuffer; TmpAddr != NULL; TmpAddr = TmpAddr->Next)
	{
		// If the adapter matches, copy its addresses.
		if(_stricmp(TmpAddr->AdapterName, AdapterGuid) == 0)
		{
			Res = TRUE;
			PIP_ADAPTER_UNICAST_ADDRESS pAddr = TmpAddr->FirstUnicastAddress;
			LONG numEntries = 0;
			while (pAddr != NULL && numEntries < *NEntries)
			{
				ULONG ul = 0;
				npf_if_addr *pItem = &buffer[numEntries];

				const int AddrLen = pAddr->Address.iSockaddrLength;
				memcpy(&pItem->IPAddress, pAddr->Address.lpSockaddr, AddrLen);
				struct sockaddr_storage *IfAddr = (struct sockaddr_storage *)pAddr->Address.lpSockaddr;
				struct sockaddr_storage* Subnet = (struct sockaddr_storage *)&pItem->SubnetMask;
				struct sockaddr_storage* Broadcast = (struct sockaddr_storage *)&pItem->Broadcast;
				Subnet->ss_family = Broadcast->ss_family = IfAddr->ss_family;
				if (IfAddr->ss_family == AF_INET && pAddr->OnLinkPrefixLength <= 32)
				{
					((struct sockaddr_in *)Subnet)->sin_addr.S_un.S_addr = ul = htonl(0xffffffff << (32 - pAddr->OnLinkPrefixLength));
					((struct sockaddr_in *)Broadcast)->sin_addr.S_un.S_addr = ~ul | ((struct sockaddr_in *)IfAddr)->sin_addr.S_un.S_addr;
				}
				else if (IfAddr->ss_family == AF_INET6 && pAddr->OnLinkPrefixLength <= 128)
				{
					memset(&((struct sockaddr_in6*)Broadcast)->sin6_addr, 0xff, sizeof(IN6_ADDR));
					for (int i = pAddr->OnLinkPrefixLength, j = 0; i > 0; i-=16, j++)
					{
						if (i > 16)
						{
							((struct sockaddr_in6*)Subnet)->sin6_addr.u.Word[j] = 0xffff;
							((struct sockaddr_in6*)Broadcast)->sin6_addr.u.Word[j] = ((struct sockaddr_in6*)IfAddr)->sin6_addr.u.Word[j];
						}
						else
						{
							const WORD mask = htons(0xffff << (16 - i));
							((struct sockaddr_in6*)Subnet)->sin6_addr.u.Word[j] = mask;
							((struct sockaddr_in6*)Broadcast)->sin6_addr.u.Word[j] = ~mask | ((struct sockaddr_in6*)IfAddr)->sin6_addr.u.Word[j];
						}
					}
				}
				else
				{
					// else unsupported address family, no broadcast or netmask
					Subnet->ss_family = Broadcast->ss_family = 0;
				}

				pAddr = pAddr->Next;
			}
			*NEntries = min(numEntries, *NEntries);
			break;
		}
	}
	
END_PacketGetNetInfoEx:
	if (!Res) {
		if (err == ERROR_SUCCESS)
			err = ERROR_BAD_UNIT;
		*NEntries = 0;
	}

	if(Tname)
		HeapFree(GetProcessHeap(), 0, Tname);
	if(AdBuffer)
		HeapFree(GetProcessHeap(), 0, AdBuffer);

	// Avoid minimizing buffer length in case new info is added.
	InterlockedMax(&MaxGAABufLen, BufLen);

	TRACE_EXIT();
	SetLastError(err);
	return Res;
}

/*! 
  \brief Returns information about the MAC type of an adapter.
  \param AdapterObject The adapter on which information is needed.
  \param type Pointer to a NetType structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero, otherwise the return value is zero.

  This function return the link layer and the speed (in bps) of an opened adapter.
  The LinkType field of the type parameter can have one of the following values:

  - NdisMedium802_3: Ethernet (802.3) 
  - NdisMediumWan: WAN 
  - NdisMedium802_5: Token Ring (802.5) 
  - NdisMediumFddi: FDDI 
  - NdisMediumAtm: ATM 
  - NdisMediumArcnet878_2: ARCNET (878.2) 
*/
_Use_decl_annotations_
BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
	DWORD err = ERROR_SUCCESS;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA)+sizeof(NDIS_LINK_SPEED)] = {0};

	TRACE_ENTER();
	if (type == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	assert(AdapterObject->Name[0] != '\0');

#ifdef HAVE_AIRPCAP_API
	PAirpcapHandle AirpcapAd = PacketGetAirPcapHandle(AdapterObject);
	AirpcapLinkType AirpcapLinkLayer;
	if (AirpcapAd)  {
		type->LinkType = (UINT)NdisMediumNull; // Note: custom linktype, NDIS doesn't provide an equivalent
		if (g_PAirpcapGetLinkType(AirpcapAd, &AirpcapLinkLayer)) {
			switch(AirpcapLinkLayer)
			{
				case AIRPCAP_LT_802_11:
					type->LinkType = (UINT)NdisMediumBare80211;
					break;
				case AIRPCAP_LT_802_11_PLUS_RADIO:
					type->LinkType = (UINT)NdisMediumRadio80211;
					break;
				case AIRPCAP_LT_802_11_PLUS_PPI:
					type->LinkType = (UINT)NdisMediumPpi;
					break;
				default:
					break;
			}
		}
		//
		// For the moment, we always set the speed to 54Mbps, since the speed is not channel-specific,
		// but per packet
		//
		type->LinkSpeed = 54000000;
	}
	else
#endif // HAVE_AIRPCAP_API
	{
		// If this is our loopback adapter, use static values.
		if (AdapterObject->Flags & INFO_FLAG_NPCAP_LOOPBACK) {
			type->LinkType = (UINT) NdisMediumNull;
			type->LinkSpeed = 10 * 1000 * 1000; //we emulate a fake 10MBit Ethernet
		}
		// request the media type from the driver
		else do
		{
			// Request the link speed
			PPACKET_OID_DATA OidData = (PPACKET_OID_DATA) IoCtlBuffer;
			//get the link-layer speed
			OidData->Oid = OID_GEN_LINK_SPEED_EX;
			OidData->Length = sizeof(NDIS_LINK_SPEED);
			if (!PacketRequest(AdapterObject, FALSE, OidData)) {
				err = GetLastError();
				TRACE_PRINT1("PacketRequest(OID_GEN_LINK_SPEED_EX) error: %d", err);
				break;
			}
			else {
				PNDIS_LINK_SPEED NdisSpeed = (PNDIS_LINK_SPEED)OidData->Data;
				// Average of Xmit and Rcv speeds is historical. Maybe we should report min instead?
				type->LinkSpeed = (NdisSpeed->XmitLinkSpeed + NdisSpeed->RcvLinkSpeed) / 2;
			}

			// If this is a WIFI_ adapter, change the link type.
			if (AdapterObject->Flags & INFO_FLAG_NPCAP_DOT11) {
				type->LinkType = (UINT)NdisMediumRadio80211;
			}
			else {
				ZeroMemory(IoCtlBuffer, sizeof(IoCtlBuffer));
				//get the link-layer type
				OidData->Oid = OID_GEN_MEDIA_IN_USE;
				OidData->Length = sizeof (ULONG);
				if (!PacketRequest(AdapterObject, FALSE, OidData)) {
					err = GetLastError();
					TRACE_PRINT1("PacketGetLinkLayerFromRegistry error: %d", err);
					break;
				}
				else {
					type->LinkType=*((UINT*)OidData->Data);
				}
			}
		} while (FALSE);
	}

	TRACE_EXIT();
	SetLastError(err);
	return (err == ERROR_SUCCESS);
}

/*! 
  \brief Returns whether an adapter is the Npcap Loopback Adapter
  \param AdapterObject The adapter on which information is needed.
  \return TRUE if yes, FALSE if no.

  Other software loopback adapters may exist, but they will not be identified with this function.
*/
_Use_decl_annotations_
BOOLEAN PacketIsLoopbackAdapter(PCCH AdapterName)
{
	BOOLEAN ret;

	TRACE_ENTER();

	if (strlen(AdapterName) < sizeof(DEVICE_PREFIX)) {
		// The adapter name is too short.
		ret = FALSE;
	}
	// Compare to NPF_Loopback
	else if (_stricmp(AdapterName + sizeof(DEVICE_PREFIX) - 1, NPCAP_LOOPBACK_ADAPTER_BUILTIN) == 0 ||
			// or compare to value in Registry, if it's found and long enough.
			(strlen(g_strLoopbackAdapterName) > sizeof(DEVICE_PREFIX) &&
			 strlen(AdapterName) > sizeof(DEVICE_PREFIX) - 1 + sizeof(NPF_DEVICE_NAMES_PREFIX) &&
			 _stricmp(g_strLoopbackAdapterName + sizeof(DEVICE_PREFIX) - 1,
				 AdapterName + sizeof(DEVICE_PREFIX) - 1 + sizeof(NPF_DEVICE_NAMES_PREFIX) - 1) == 0)
	   )
	{
		ret = TRUE;
	}
	else
	{
		ret = FALSE;
	}

	TRACE_EXIT();
	return ret;
}

/*!
\brief Returns whether a wireless adapter supports monitor mode.
\param AdapterObject The adapter on which information is needed.
\return 1 if yes, 0 if no, -1 if the function fails.
*/
_Use_decl_annotations_
int PacketIsMonitorModeSupported(PCCH AdapterName)
{
	HANDLE hAdapter;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA) + sizeof(DOT11_OPERATION_MODE_CAPABILITY) - 1] = { 0 };
	PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA)IoCtlBuffer;
	PDOT11_OPERATION_MODE_CAPABILITY pOperationModeCapability;
	int mode;
	PCHAR WifiAdapterName;
	DWORD dwResult = ERROR_INVALID_DATA;

	TRACE_ENTER();

	WifiAdapterName = NpcapTranslateAdapterName_Standard2Wifi(AdapterName);
	if (!WifiAdapterName)
	{
		TRACE_PRINT("PacketIsMonitorModeSupported failed, NpcapTranslateAdapterName_Standard2Wifi error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}

	hAdapter = PacketGetAdapterHandle(WifiAdapterName);
	if (hAdapter == INVALID_HANDLE_VALUE)
	{
		dwResult = GetLastError();
		TRACE_PRINT("PacketIsMonitorModeSupported failed, PacketGetAdapterHandle error");
		TRACE_EXIT();
		HeapFree(GetProcessHeap(), 0, WifiAdapterName);
		SetLastError(dwResult);
		return -1;
	}

	OidData->Oid = OID_DOT11_OPERATION_MODE_CAPABILITY;
	OidData->Length = sizeof(DOT11_OPERATION_MODE_CAPABILITY);
	dwResult = PacketRequestHelper(hAdapter, FALSE, OidData);
	if (dwResult == ERROR_SUCCESS)
	{
		pOperationModeCapability = (PDOT11_OPERATION_MODE_CAPABILITY) OidData->Data;
		if ((pOperationModeCapability->uOpModeCapability & DOT11_OPERATION_MODE_NETWORK_MONITOR) == DOT11_OPERATION_MODE_NETWORK_MONITOR)
		{
			mode = 1;
		}
		else
		{
			mode = 0;
		}
	}
	else
	{
		TRACE_PRINT("PacketIsMonitorModeSupported failed, PacketRequest error");
		mode = -1;
	}

	CloseHandle(hAdapter);

	TRACE_PRINT2("PacketIsMonitorModeSupported: AdapterName = %hs, mode = %d", AdapterName, mode);

	TRACE_EXIT();
	SetLastError(dwResult);
	return mode;
}

/*!
\brief Sets the operation mode of an adapter.
\param AdapterObject Pointer to an _ADAPTER structure.
\param mode The new operation mode of the adapter, 1 for monitor mode, 0 for managed mode.
\return 1 if the function succeeds, 0 if monitor mode is not supported, -1 if the function fails with other errors.
*/
_Use_decl_annotations_
int PacketSetMonitorMode(PCCH AdapterName, int mode)
{
	int rval = 0;
	DWORD dwResult = ERROR_INVALID_DATA;
	PCHAR TranslatedAdapterName;
	PCHAR WifiAdapterName;
	HANDLE hAdapter = INVALID_HANDLE_VALUE;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA) + sizeof(DOT11_CURRENT_OPERATION_MODE) - 1] = { 0 };
	PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA)IoCtlBuffer;
	PDOT11_CURRENT_OPERATION_MODE pOpMode = (PDOT11_CURRENT_OPERATION_MODE)OidData->Data;

	TRACE_ENTER();

	WifiAdapterName = NpcapTranslateAdapterName_Standard2Wifi(AdapterName);
	if (!WifiAdapterName)
	{
		TRACE_PRINT("PacketSetMonitorMode failed, NpcapTranslateAdapterName_Standard2Wifi error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}

	hAdapter = PacketGetAdapterHandle(WifiAdapterName);
	if (hAdapter == INVALID_HANDLE_VALUE)
	{
		dwResult = GetLastError();
		HeapFree(GetProcessHeap(), 0, WifiAdapterName);
		TRACE_PRINT("PacketSetMonitorMode failed, PacketGetAdapterHandle error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}

	const ULONG ulOperationMode = mode ? DOT11_OPERATION_MODE_NETWORK_MONITOR : DOT11_OPERATION_MODE_EXTENSIBLE_STATION;
	OidData->Oid = OID_DOT11_CURRENT_OPERATION_MODE;
	OidData->Length = sizeof(DOT11_CURRENT_OPERATION_MODE);
	pOpMode->uCurrentOpMode = ulOperationMode;
	dwResult = PacketRequestHelper(hAdapter, TRUE, OidData);

#ifndef NDIS_STATUS_INVALID_DATA
#define NDIS_STATUS_INVALID_DATA                ((NDIS_STATUS)0xC0010015L)
#define NDIS_STATUS_INVALID_OID                 ((NDIS_STATUS)0xC0010017L)
#endif
	switch (dwResult)
	{
		case ERROR_SUCCESS:
			rval = 1;
			// Update the adapter's monitor mode in the global map.
			TranslatedAdapterName = NpcapTranslateAdapterName_Npf2Npcap(AdapterName);
			if (TranslatedAdapterName)
			{
				g_nbAdapterMonitorModes[TranslatedAdapterName] = mode;
				HeapFree(GetProcessHeap(), 0, TranslatedAdapterName);
			}
		case NDIS_STATUS_INVALID_DATA:
		case NDIS_STATUS_INVALID_OID:
			// Monitor mode is not supported.
			rval = 0;
			break;
		default:
			TRACE_PRINT("PacketSetMonitorMode failed, PacketRequest error");
			rval = -1;
			break;
	}

	HeapFree(GetProcessHeap(), 0, WifiAdapterName);
	TRACE_EXIT();
	SetLastError(dwResult);
	return rval;
}

/*!
\brief Determine if the operation mode of an adapter is monitor mode.
\param AdapterObject Pointer to an _ADAPTER structure.
\param mode The new operation mode of the adapter, 1 for monitor mode, 0 for managed mode.
\return 1 if it's monitor mode, 0 if it's not monitor mode, -1 if the function fails.
*/
_Use_decl_annotations_
int PacketGetMonitorMode(PCCH AdapterName)
{
	int mode;
	HANDLE hAdapter = INVALID_HANDLE_VALUE;
	DWORD dwResult = ERROR_INVALID_DATA;
	CHAR IoCtlBuffer[sizeof(PACKET_OID_DATA) + sizeof(DOT11_CURRENT_OPERATION_MODE) - 1] = { 0 };
	PPACKET_OID_DATA  OidData = (PPACKET_OID_DATA)IoCtlBuffer;
	PDOT11_CURRENT_OPERATION_MODE pOperationMode = (PDOT11_CURRENT_OPERATION_MODE)OidData->Data;
	PCHAR TranslatedAdapterName;
	PCHAR WifiAdapterName;

	TRACE_ENTER();

	WifiAdapterName = NpcapTranslateAdapterName_Standard2Wifi(AdapterName);
	if (!WifiAdapterName)
	{
		TRACE_PRINT("PacketGetMonitorMode failed, NpcapTranslateAdapterName_Standard2Wifi error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}

	hAdapter = PacketGetAdapterHandle(WifiAdapterName);
	if (hAdapter == INVALID_HANDLE_VALUE)
	{
		dwResult = GetLastError();
		HeapFree(GetProcessHeap(), 0, WifiAdapterName);
		TRACE_PRINT("PacketSetMonitorMode failed, PacketGetAdapterHandle error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}

	OidData->Oid = OID_DOT11_CURRENT_OPERATION_MODE;
	OidData->Length = sizeof(DOT11_CURRENT_OPERATION_MODE);
	dwResult = PacketRequestHelper(hAdapter, FALSE, OidData);

	if (dwResult != ERROR_SUCCESS)
	{
		HeapFree(GetProcessHeap(), 0, WifiAdapterName);
		TRACE_PRINT("PacketGetMonitorMode failed, PacketRequest error");
		TRACE_EXIT();
		SetLastError(dwResult);
		return -1;
	}
	mode = (pOperationMode->uCurrentOpMode == DOT11_OPERATION_MODE_NETWORK_MONITOR) ? 1 : 0;

	TranslatedAdapterName = NpcapTranslateAdapterName_Npf2Npcap(AdapterName);
	if (TranslatedAdapterName)
	{
		// Update the adapter's monitor mode in the global map.
		g_nbAdapterMonitorModes[TranslatedAdapterName] = mode;
		HeapFree(GetProcessHeap(), 0, TranslatedAdapterName);
	}

	HeapFree(GetProcessHeap(), 0, WifiAdapterName);
	TRACE_EXIT();
	return mode;
}

/*!
  \brief Returns the AirPcap handler associated with an adapter. This handler can be used to change
           the wireless-related settings of the CACE Technologies AirPcap wireless capture adapters.
  \param AdapterObject the open adapter whose AirPcap handler is needed.
  \return a pointer to an open AirPcap handle, used internally by the adapter pointed by AdapterObject.
          NULL if the libpcap adapter doesn't have wireless support through AirPcap.

  PacketGetAirPcapHandle() allows to obtain the airpcap handle of an open adapter. This handle can be used with
  the AirPcap API functions to perform wireless-releated operations, e.g. changing the channel or enabling 
  WEP decryption. For more details about the AirPcap wireless capture adapters, see 
  http://www.cacetech.com/products/airpcap.htm.
*/
_Use_decl_annotations_
PAirpcapHandle PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
	PAirpcapHandle handle = NULL;
	TRACE_ENTER();

#ifdef HAVE_AIRPCAP_API
	if (AdapterObject->Flags & INFO_FLAG_AIRPCAP_CARD)
	{
		handle = AdapterObject->AirpcapAd;
	}
#else
	UNUSED(AdapterObject);
#endif // HAVE_AIRPCAP_API

	TRACE_EXIT();
	return handle;
}

/* @} */
