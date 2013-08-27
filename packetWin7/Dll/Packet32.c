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

#pragma warning (disable : 4127)  //conditional expression is constant. Used for do{}while(FALSE) loops.

#if (MSC_VER < 1300)
#pragma warning (disable : 4710) // inline function not expanded. used for strsafe functions
#endif

#include <Packet32.h>
#include <tchar.h>
#include <strsafe.h>

#include "ProtInstall.h"
#include "Packet32-Int.h"
#include "../npf/npf/ioctls.h"

#ifdef HAVE_WANPACKET_API
#include "wanpacket/wanpacket.h"
#endif //HAVE_WANPACKET_API

#include "debug.h"

BOOL bUseNPF60 = FALSE;

#ifdef _WINNT4
#if (defined(HAVE_NPFIM_API) || defined(HAVE_WANPACKET_API) || defined (HAVE_AIRPCAP_API) || defined(HAVE_IPHELPER_API))
#error Do not enable _WINNT4 with any other API
#endif
#endif //_WINNT4

#ifdef _WINNT4
#pragma message ("Compiling Packet.dll for WINNT4 only")
#endif

#ifdef HAVE_AIRPCAP_API
#pragma message ("Compiling Packet.dll with support for AirPcap")
#endif

#ifdef HAVE_NPFIM_API
#pragma message ("Compiling Packet.dll with support for NpfIm driver")
#endif

#ifdef HAVE_DAG_API
#pragma message ("Compiling Packet.dll with support for DAG cards")
#endif

#ifdef HAVE_WANPACKET_API
#pragma message ("Compiling Packet.dll with support for WanPacket (aka Dialup thru NetMon)")
#endif

#ifdef HAVE_IPHELPER_API
#pragma message ("Compiling Packet.dll with support from IP helper API for API addresses")
#endif

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif


#ifdef _DEBUG_TO_FILE
LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName);
CHAR g_LogFileName[1024] = "winpcap_debug.txt";
#endif //_DEBUG_TO_FILE

#include <windows.h>
#include <windowsx.h>
#include <iphlpapi.h>
#include <ipifcons.h>

#include <WpcapNames.h>

//
// Current packet.dll Version. It can be retrieved directly or through the PacketGetVersion() function.
//
char PacketLibraryVersion[64]; 

//
// Current NPF.sys Version. It can be retrieved directly or through the PacketGetVersion() function.
//
char PacketDriverVersion[64]; 

//
// WinPcap global registry key
//
//WCHAR g_WinPcapKeyBuffer[MAX_WINPCAP_KEY_CHARS];
//HKEY g_WinpcapKey = NULL;

//
// Global adapters list related variables
//
extern PADAPTER_INFO g_AdaptersInfoList;
extern HANDLE g_AdaptersInfoMutex;

#ifdef HAVE_IPHELPER_API
typedef VOID (*GAAHandler)(
  ULONG,
  DWORD,
  PVOID,
  PIP_ADAPTER_ADDRESSES,
  PULONG);
GAAHandler g_GetAdaptersAddressesPointer = NULL;
#endif // HAVE_IPHELPER_API

//
// Dynamic dependencies variables and declarations
//
volatile LONG g_DynamicLibrariesLoaded = 0;
HANDLE g_DynamicLibrariesMutex;

#ifdef HAVE_AIRPCAP_API
// We load dinamically the dag library in order link it only when it's present on the system
AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
AirpcapGetDeviceListHandler g_PAirpcapGetDeviceList;
AirpcapFreeDeviceListHandler g_PAirpcapFreeDeviceList;
AirpcapOpenHandler g_PAirpcapOpen;
AirpcapCloseHandler g_PAirpcapClose;
AirpcapGetLinkTypeHandler g_PAirpcapGetLinkType;
AirpcapSetKernelBufferHandler g_PAirpcapSetKernelBuffer;
AirpcapSetFilterHandler g_PAirpcapSetFilter;
AirpcapGetMacAddressHandler g_PAirpcapGetMacAddress;
AirpcapSetMinToCopyHandler g_PAirpcapSetMinToCopy;
AirpcapGetReadEventHandler g_PAirpcapGetReadEvent;
AirpcapReadHandler g_PAirpcapRead;
AirpcapGetStatsHandler g_PAirpcapGetStats;
AirpcapWriteHandler g_PAirpcapWrite;
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_DAG_API
// We load dinamically the dag library in order link it only when it's present on the system
dagc_open_handler g_p_dagc_open = NULL;
dagc_close_handler g_p_dagc_close = NULL;
dagc_getlinktype_handler g_p_dagc_getlinktype = NULL;
dagc_getlinkspeed_handler g_p_dagc_getlinkspeed = NULL;
dagc_getfcslen_handler g_p_dagc_getfcslen = NULL;
dagc_receive_handler g_p_dagc_receive = NULL;
dagc_wait_handler g_p_dagc_wait = NULL;
dagc_stats_handler g_p_dagc_stats = NULL;
dagc_setsnaplen_handler g_p_dagc_setsnaplen = NULL;
dagc_finddevs_handler g_p_dagc_finddevs = NULL;
dagc_freedevs_handler g_p_dagc_freedevs = NULL;
#endif // HAVE_DAG_API

BOOLEAN PacketAddAdapterDag(PCHAR name, PCHAR description, BOOLEAN IsAFile);

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

#ifndef _WINNT4
//
// This wrapper around loadlibrary appends the system folder (usually c:\windows\system32)
// to the relative path of the DLL, so that the DLL is always loaded from an absolute path
// (It's no longer possible to load airpcap.dll from the application folder).
// This solves the DLL Hijacking issue discovered in August 2010
// http://blog.metasploit.com/2010/08/exploiting-dll-hijacking-flaws.html
//
HMODULE LoadLibrarySafe(LPCTSTR lpFileName)
{
  TCHAR path[MAX_PATH];
  TCHAR fullFileName[MAX_PATH];
  UINT res;
  HMODULE hModule = NULL;
  do
  {
	res = GetSystemDirectory(path, MAX_PATH);

	if (res == 0)
	{
		//
		// some bad failure occurred;
		//
		break;
	}
	
	if (res > MAX_PATH)
	{
		//
		// the buffer was not big enough
		//
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		break;
	}

	if (res + 1 + _tcslen(lpFileName) + 1 < MAX_PATH)
	{
		memcpy(fullFileName, path, res * sizeof(TCHAR));
		fullFileName[res] = _T('\\');
		memcpy(&fullFileName[res + 1], lpFileName, (_tcslen(lpFileName) + 1) * sizeof(TCHAR));

		hModule = LoadLibrary(fullFileName);
	}
	else
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	}

  }while(FALSE);

  return hModule;
}
#endif

/*! 
  \brief The main dll function.
*/

BOOL APIENTRY DllMain(HANDLE DllHandle,DWORD Reason,LPVOID lpReserved)
{
    BOOLEAN Status=TRUE;
	PADAPTER_INFO NewAdInfo;
	TCHAR DllFileName[MAX_PATH];

	UNUSED(lpReserved);

#ifdef NDIS6X
	bUseNPF60 = TRUE;
#else
	bUseNPF60 = FALSE;
#endif

    switch(Reason)
    {
	case DLL_PROCESS_ATTACH:

		TRACE_PRINT_DLLMAIN("************Packet32: DllMain************");

#if 0
#ifdef WPCAP_OEM
#ifdef HAVE_WANPACKET_API
		LoadNdisNpp(Reason);
#endif // HAVE_WANPACKET_API
#endif // WPCAP_OEM 
#endif

#ifdef _DEBUG_TO_FILE
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
		
		// Create the mutex that will protect the PacketLoadLibrariesDynamically() function		
		g_DynamicLibrariesMutex = CreateMutex(NULL, FALSE, NULL);

		//
		// Retrieve packet.dll version information from the file
		//
		// XXX We want to replace this with a constant. We leave it out for the moment
		if(GetModuleFileName(DllHandle, DllFileName, sizeof(DllFileName) / sizeof(DllFileName[0])) > 0)
		{
			PacketGetFileVersion(DllFileName, PacketLibraryVersion, sizeof(PacketLibraryVersion));
		}
		//
		// Retrieve NPF.sys version information from the file
		//
		// XXX We want to replace this with a constant. We leave it out for the moment
		// TODO fixme. Those hardcoded strings are terrible...
		PacketGetFileVersion(TEXT("drivers\\") TEXT(NPF_DRIVER_NAME) TEXT(".sys"), PacketDriverVersion, sizeof(PacketDriverVersion));
		
		break;
		
	case DLL_PROCESS_DETACH:

		CloseHandle(g_AdaptersInfoMutex);
		
		g_AdaptersInfoList;
		
		while(g_AdaptersInfoList != NULL)
		{
			PNPF_IF_ADDRESS_ITEM pCursor, pNext;

			NewAdInfo = g_AdaptersInfoList->Next;

			pCursor = g_AdaptersInfoList->pNetworkAddresses;

			while(pCursor != NULL)
			{
				pNext = pCursor->Next;
				GlobalFreePtr(pCursor);
				pCursor = pNext;
			}

			GlobalFreePtr(g_AdaptersInfoList);
			
			g_AdaptersInfoList = NewAdInfo;
		}

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
	
    return Status;
}


/*! 
  \brief This function is used to dynamically load some of the libraries winpcap depends on, 
   and that are not guaranteed to be in the system
  \param cp A string containing the address.
  \return the converted 32-bit numeric address.

   Doesn't check to make sure the address is valid.
*/
VOID PacketLoadLibrariesDynamically()
{
#ifdef HAVE_IPHELPER_API
	HMODULE IPHMod;
#endif // HAVE_IPHELPER_API

#ifdef HAVE_AIRPCAP_API
	HMODULE AirpcapLib;
#endif // HAVE_DAG_API	

#ifdef HAVE_DAG_API
	HMODULE DagcLib;
#endif // HAVE_DAG_API

	TRACE_ENTER("PacketLoadLibrariesDynamically");

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
		TRACE_EXIT("PacketLoadLibrariesDynamically");
		return;
	}

	//
	// Locate GetAdaptersAddresses dinamically since it is not present in Win2k
	//

#ifdef HAVE_IPHELPER_API
	IPHMod = GetModuleHandle(TEXT("Iphlpapi"));
	if (IPHMod != NULL)
	{
		g_GetAdaptersAddressesPointer = (GAAHandler) GetProcAddress(IPHMod ,"GetAdaptersAddresses");
	}
#endif // HAVE_IPHELPER_API
	
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
		g_PAirpcapGetMacAddress = (AirpcapGetMacAddressHandler) GetProcAddress(AirpcapLib, "AirpcapGetMacAddress");
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
			g_PAirpcapGetMacAddress == NULL ||
			g_PAirpcapSetMinToCopy == NULL ||
			g_PAirpcapGetReadEvent == NULL ||
			g_PAirpcapRead == NULL ||
			g_PAirpcapGetStats == NULL)
		{
			// No, something missing. A NULL g_PAirpcapOpen will disable airpcap adapters check
			g_PAirpcapOpen = NULL;
		}
	}
#endif // HAVE_DAG_API
	
#ifdef HAVE_DAG_API
	/* We dinamically load the dag library in order link it only when it's present on the system */
	if((DagcLib =  LoadLibrarySafe(TEXT("dagc.dll"))) == NULL)
	{
		// Report the error but go on
		TRACE_PRINT("dag capture library not found on this system");
	}
	else
	{
		g_p_dagc_open = (dagc_open_handler) GetProcAddress(DagcLib, "dagc_open");
		g_p_dagc_close = (dagc_close_handler) GetProcAddress(DagcLib, "dagc_close");
		g_p_dagc_setsnaplen = (dagc_setsnaplen_handler) GetProcAddress(DagcLib, "dagc_setsnaplen");
		g_p_dagc_getlinktype = (dagc_getlinktype_handler) GetProcAddress(DagcLib, "dagc_getlinktype");
		g_p_dagc_getlinkspeed = (dagc_getlinkspeed_handler) GetProcAddress(DagcLib, "dagc_getlinkspeed");
		g_p_dagc_getfcslen = (dagc_getfcslen_handler) GetProcAddress(DagcLib, "dagc_getfcslen");
		g_p_dagc_receive = (dagc_receive_handler) GetProcAddress(DagcLib, "dagc_receive");
		g_p_dagc_wait = (dagc_wait_handler) GetProcAddress(DagcLib, "dagc_wait");
		g_p_dagc_stats = (dagc_stats_handler) GetProcAddress(DagcLib, "dagc_stats");
		g_p_dagc_finddevs = (dagc_finddevs_handler) GetProcAddress(DagcLib, "dagc_finddevs");
		g_p_dagc_freedevs = (dagc_freedevs_handler) GetProcAddress(DagcLib, "dagc_freedevs");
	}
#endif /* HAVE_DAG_API */

#ifdef HAVE_NPFIM_API
	if (LoadNpfImDll() == FALSE)
	{
		TRACE_PRINT("Failed loading NpfIm extension");
	}
#endif //HAVE_NPFIM_API


	//
	// Done. Release the mutex and return
	//
	ReleaseMutex(g_DynamicLibrariesMutex);

	TRACE_EXIT("PacketLoadLibrariesDynamically");
	return;
}

/*
BOOLEAN QueryWinPcapRegistryStringA(CHAR *SubKeyName,
								 CHAR *Value,
								 UINT *pValueLen,
								 CHAR *DefaultVal)
{
#ifdef WPCAP_OEM
	DWORD Type;
	LONG QveRes;
	HKEY hWinPcapKey;
	
	if (QveRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
			WINPCAP_INSTANCE_KEY,
			0,
			KEY_ALL_ACCESS,
			&hWinPcapKey) != ERROR_SUCCESS)
	{
		*pValueLen = 0;
		
		SetLastError(QveRes);

		return FALSE;
	}

	//
	// Query the requested value
	//
	QveRes = RegQueryValueExA(hWinPcapKey,
		SubKeyName,
		NULL,
		&Type,
		Value,
		pValueLen);

	RegCloseKey(hWinPcapKey);

	if (QveRes == ERROR_SUCCESS)
	{
		//let's check that the key is text
		if (Type != REG_SZ)
		{
			*pValueLen = 0;
			
			SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}
		else
		{
			//success!
			return TRUE;
		}
	}
	else
	if (QveRes == ERROR_MORE_DATA)
	{
		//
		//the needed bytes are already set by RegQueryValueExA
		//

		SetLastError(QveRes);
		return FALSE;
	}
	else
	{
		//
		//print the error
		//
		ODSEx("QueryWinpcapRegistryKey, RegQueryValueEx failed, code %d",QveRes);
		//
		//JUST CONTINUE WITH THE DEFAULT VALUE
		//
	}

#endif // WPCAP_OEM

	if ((*pValueLen) < strlen(DefaultVal) + 1)
	{
		memcpy(Value, DefaultVal, *pValueLen - 1);
		Value[*pValueLen - 1] = '\0';
		*pValueLen = strlen(DefaultVal) + 1;
		SetLastError(ERROR_MORE_DATA);
		return FALSE;
	}
	else
	{
		strcpy(Value, DefaultVal);
		*pValueLen = strlen(DefaultVal) + 1;
		return TRUE;
	}

}
						
BOOLEAN QueryWinPcapRegistryStringW(WCHAR *SubKeyName,
								 WCHAR *Value,
								 UINT *pValueLen,
								 WCHAR *DefaultVal)
{
#ifdef WPCAP_OEM
	DWORD Type;
	LONG QveRes;
	HKEY hWinPcapKey;
	DWORD InternalLenBytes;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
			WINPCAP_INSTANCE_KEY_WIDECHAR,
			0,
			KEY_ALL_ACCESS,
			&hWinPcapKey) != ERROR_SUCCESS)
	{
		*pValueLen = 0;
		return FALSE;
	}

	InternalLenBytes = *pValueLen * 2;
	
	//
	// Query the requested value
	//
	QveRes = RegQueryValueExW(hWinPcapKey,
		SubKeyName,
		NULL,
		&Type,
		(LPBYTE)Value,
		&InternalLenBytes);

	RegCloseKey(hWinPcapKey);

	if (QveRes == ERROR_SUCCESS)
	{
		//let's check that the key is text
		if (Type != REG_SZ)
		{
			*pValueLen = 0;
			SetLastError(ERROR_INVALID_DATA);
			return FALSE;
		}
		else
		{
			//success!
			*pValueLen = wcslen(Value) + 1;
		
			return TRUE;
		}
	}
	else
	if (QveRes == ERROR_MORE_DATA)
	{
		//
		//the needed bytes are not set by RegQueryValueExW
		//
		
		//the +1 is needed to round the needed buffer size (in WCHARs) to a number of WCHARs that will fit
		//the number of needed bytes. In any case if it's a W string, the number of needed bytes should always be even!

		*pValueLen = (InternalLenBytes + 1) / 2;

		SetLastError(ERROR_MORE_DATA);
		return FALSE;
	}
	else
	{
		//
		//print the error
		//
		ODSEx("QueryWinpcapRegistryKey, RegQueryValueEx failed, code %d\n",QveRes);
		//
		//JUST CONTINUE WITH THE DEFAULT VALUE
		//
	}

#endif // WPCAP_OEM

	if (*pValueLen < wcslen(DefaultVal) + 1)
	{
		memcpy(Value, DefaultVal, (*pValueLen  - 1) * 2);
		Value[*pValueLen - 1] = '\0';
		*pValueLen = wcslen(DefaultVal) + 1;
		SetLastError(ERROR_MORE_DATA);
		return FALSE;
	}
	else
	{
		wcscpy(Value, DefaultVal);
		*pValueLen = wcslen(DefaultVal) + 1;
		return TRUE;
	}

}

*/

/*! 
  \brief Convert a Unicode dotted-quad to a 32-bit IP address.
  \param cp A string containing the address.
  \return the converted 32-bit numeric address.

   Doesn't check to make sure the address is valid.
*/
ULONG inet_addrU(const WCHAR *cp)
{
	ULONG val, part;
	WCHAR c;
	int i;

	val = 0;
	for (i = 0; i < 4; i++) {
		part = 0;
		while ((c = *cp++) != '\0' && c != '.') {
			if (c < '0' || c > '9')
				return (ULONG)-1;
			part = part*10 + (c - '0');
		}
		if (part > 255)
			return (ULONG)-1;	
		val = val | (part << i*8);
		if (i == 3) {
			if (c != '\0')
				return (ULONG)-1;	// extra gunk at end of string 
		} else {
			if (c == '\0')
				return (ULONG)-1;	// string ends early 
		}
	}
	return val;
}

/*! 
  \brief Converts an ASCII string to UNICODE. Uses the MultiByteToWideChar() system function.
  \param string The string to convert.
  \return The converted string.
*/
static PWCHAR SChar2WChar(PCHAR string)
{
	PWCHAR TmpStr;
	TmpStr = (WCHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (DWORD)(strlen(string)+2)*sizeof(WCHAR));

	MultiByteToWideChar(CP_ACP, 0, string, -1, TmpStr, (DWORD)(strlen(string)+2));

	return TmpStr;
}

/*! 
  \brief Converts an UNICODE string to ASCII. Uses the WideCharToMultiByte() system function.
  \param string The string to convert.
  \return The converted string.
*/
static PCHAR WChar2SChar(PWCHAR string)
{
	PCHAR TmpStr;
	TmpStr = (CHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (DWORD)(wcslen(string)+2));

	// Conver to ASCII
	WideCharToMultiByte(
		CP_ACP,
		0,
		string,
		-1,
		TmpStr,
		(DWORD)(wcslen(string)+2),          // size of buffer
		NULL,
		NULL);

	return TmpStr;
}

/*! 
  \brief Sets the maximum possible lookahead buffer for the driver's Packet_tap() function.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  The lookahead buffer is the portion of packet that Packet_tap() can access from the NIC driver's memory
  without performing a copy. This function tries to increase the size of that buffer.

  NOTE: this function is used for NPF adapters, only.
*/

BOOLEAN PacketSetMaxLookaheadsize (LPADAPTER AdapterObject)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;

	TRACE_ENTER("PacketSetMaxLookaheadsize");

    OidData = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
        TRACE_PRINT("PacketSetMaxLookaheadsize failed");
        Status = FALSE;
    }
	else
	{
		//set the size of the lookahead buffer to the maximum available by the the NIC driver
		OidData->Oid=OID_GEN_MAXIMUM_LOOKAHEAD;
		OidData->Length=sizeof(ULONG);
		Status=PacketRequest(AdapterObject,FALSE,OidData);
		OidData->Oid=OID_GEN_CURRENT_LOOKAHEAD;
		Status=PacketRequest(AdapterObject,TRUE,OidData);
		GlobalFreePtr(OidData);
	}

	TRACE_EXIT("PacketSetMaxLookaheadsize");
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

 	TRACE_ENTER("PacketSetReadEvt");

	if (AdapterObject->ReadEvent != NULL)
	{
		SetLastError(ERROR_INVALID_FUNCTION);
		return FALSE;
	}

 	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (hEvent == NULL)
	{
		//SetLastError done by CreateEvent	
 		TRACE_EXIT("PacketSetReadEvt");
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
		DWORD dwLastError = GetLastError();

		CloseHandle(hEvent);

		SetLastError(dwLastError);

		TRACE_EXIT("PacketSetReadEvt");
		return FALSE;
	}

	AdapterObject->ReadEvent = hEvent;
	AdapterObject->ReadTimeOut=0;

	TRACE_EXIT("PacketSetReadEvt");
	return TRUE;
}

/*! 
  \brief Installs the NPF device driver.
  \return If the function succeeds, the return value is nonzero.

  This function installs the driver's service in the system using the CreateService function.
*/

BOOLEAN PacketInstallDriver()
{
	BOOLEAN result = FALSE;
	ULONG err = 0;
	SC_HANDLE svcHandle;
	SC_HANDLE scmHandle;
//  
//	Old registry based WinPcap names
//
//	CHAR driverName[MAX_WINPCAP_KEY_CHARS];
//	CHAR driverDesc[MAX_WINPCAP_KEY_CHARS];
//	CHAR driverLocation[MAX_WINPCAP_KEY_CHARS;
//	UINT len;

	CHAR driverName[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_NAME;
	CHAR driverDesc[MAX_WINPCAP_KEY_CHARS] = NPF_SERVICE_DESC;
	CHAR driverLocation[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_COMPLETE_PATH;

 	TRACE_ENTER("PacketInstallDriver");

//  
//	Old registry based WinPcap names
//
//	len = sizeof(driverName)/sizeof(driverName[0]);
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_NAME_REG_KEY, driverName, &len, NPF_DRIVER_NAME) == FALSE && len == 0)
//		return FALSE;
//
//	len = sizeof(driverDesc)/sizeof(driverDesc[0]);
//	if (QueryWinPcapRegistryStringA(NPF_SERVICE_DESC_REG_KEY, driverDesc, &len, NPF_SERVICE_DESC) == FALSE && len == 0)
//		return FALSE;
//
//	len = sizeof(driverLocation)/sizeof(driverLocation[0]);
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_COMPLETE_PATH_REG_KEY, driverLocation, &len, NPF_DRIVER_COMPLETE_PATH) == FALSE && len == 0)
//		return FALSE;
	
	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle == NULL)
		return FALSE;

	svcHandle = CreateServiceA(scmHandle, 
		driverName,
		driverDesc,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driverLocation,
		NULL, NULL, NULL, NULL, NULL);
	if (svcHandle == NULL) 
	{
		err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) 
		{
			TRACE_PRINT("Service npf.sys already exists");
			//npf.sys already existed
			err = 0;
			result = TRUE;
		}
	}
	else 
	{
		TRACE_PRINT("Created service for npf.sys");
		//Created service for npf.sys
		result = TRUE;
	}

	if (svcHandle != NULL)
		CloseServiceHandle(svcHandle);

	if(result == FALSE)
	{
		TRACE_PRINT1("PacketInstallDriver failed, Error=%u",err);
	}

	CloseServiceHandle(scmHandle);
	SetLastError(err);
	TRACE_EXIT("PacketInstallDriver");
	return result;
	
}

BOOLEAN PacketInstallDriver60()
{
	BOOLEAN result = FALSE;
	TRACE_ENTER("PacketInstallDriver60");

	result = (BOOLEAN) InstallDriver();

	TRACE_EXIT("PacketInstallDriver60");
	return result;
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

	TRACE_ENTER("PacketDumpRegistryKey");
	StringCchPrintfA(Command, sizeof(Command), "regedit /e %s %s", FileName, KeyName);

	/// Let regedit do the dirty work for us
	system(Command);

	TRACE_EXIT("PacketDumpRegistryKey");
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
BOOL PacketGetFileVersion(LPTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen)
{
    DWORD   dwVerInfoSize;  // Size of version information block
    DWORD   dwVerHnd=0;   // An 'ignored' parameter, always '0'
	LPTSTR   lpstrVffInfo;
	UINT	cbTranslate, dwBytes;
	TCHAR	SubBlock[64];
	PVOID	lpBuffer;
	PCHAR	TmpStr;
	DWORD aaa;
	
	// Structure used to store enumerated languages and code pages.
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	TRACE_ENTER("PacketGetFileVersion");

	// Now lets dive in and pull out the version information:
	
    dwVerInfoSize = GetFileVersionInfoSize(FileName, &dwVerHnd);
	if (dwVerInfoSize == 0)
	{
		aaa = GetLastError();
		aaa = aaa;
	}

    if (dwVerInfoSize) 
	{
        lpstrVffInfo = GlobalAllocPtr(GMEM_MOVEABLE, dwVerInfoSize);
		if (lpstrVffInfo == NULL)
		{
			TRACE_PRINT("PacketGetFileVersion: failed to allocate memory");
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		if(!GetFileVersionInfo(FileName, dwVerHnd, dwVerInfoSize, lpstrVffInfo)) 
		{
			TRACE_PRINT("PacketGetFileVersion: failed to call GetFileVersionInfo");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		// Read the list of languages and code pages.
		if(!VerQueryValue(lpstrVffInfo,	TEXT("\\VarFileInfo\\Translation"),	(LPVOID*)&lpTranslate, &cbTranslate))
		{
			TRACE_PRINT("PacketGetFileVersion: failed to call VerQueryValue");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
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
			TRACE_PRINT("PacketGetFileVersion: failed to call VerQueryValue");
            GlobalFreePtr(lpstrVffInfo);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		// Convert to ASCII
		TmpStr = WChar2SChar(lpBuffer);

		if(strlen(TmpStr) >= VersionBuffLen)
		{
			TRACE_PRINT("PacketGetFileVersion: Input buffer too small");
            GlobalFreePtr(lpstrVffInfo);
            GlobalFreePtr(TmpStr);
			TRACE_EXIT("PacketGetFileVersion");
			return FALSE;
		}

		StringCchCopyA(VersionBuff, VersionBuffLen, TmpStr);

        GlobalFreePtr(lpstrVffInfo);
        GlobalFreePtr(TmpStr);
		
	  } 
	else 
	{
		TRACE_PRINT1("PacketGetFileVersion: failed to call GetFileVersionInfoSize, LastError = %8.8x", GetLastError());
		TRACE_EXIT("PacketGetFileVersion");
		return FALSE;
	
	} 
	
	TRACE_EXIT("PacketGetFileVersion");
	return TRUE;
}

/*! 
  \brief Opens an adapter using the NPF device driver.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter() and AddAdapter()
*/
LPADAPTER PacketOpenAdapterNPF(PCHAR AdapterNameA)
{
    LPADAPTER lpAdapter;
    BOOL Result;
	DWORD error;
	SC_HANDLE svcHandle = NULL;
	SC_HANDLE scmHandle = NULL;
	LONG KeyRes;
	HKEY PathKey;
	SERVICE_STATUS SStat;
	BOOL QuerySStat;
	CHAR SymbolicLinkA[MAX_PATH];
//  
//	Old registry based WinPcap names
//
//	CHAR	NpfDriverName[MAX_WINPCAP_KEY_CHARS];
//	UINT	RegQueryLen;

	CHAR	NpfDriverName[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_NAME;
	CHAR	NpfServiceLocation[MAX_WINPCAP_KEY_CHARS];

	// Create the NPF device name from the original device name
	TRACE_ENTER("PacketOpenAdapterNPF");
	
	TRACE_PRINT1("Trying to open adapter %s", AdapterNameA);

	scmHandle = OpenSCManager(NULL, NULL, GENERIC_READ);
		
	if(scmHandle == NULL)
	{
		error = GetLastError();
		TRACE_PRINT1("OpenSCManager failed! LastError=%8.8x", error);
	}
	else
	{
//  
//	Old registry based WinPcap names
//
//		RegQueryLen = sizeof(NpfDriverName)/sizeof(NpfDriverName[0]);
//		if (QueryWinPcapRegistryStringA(NPF_DRIVER_NAME_REG_KEY, NpfDriverName, &RegQueryLen, NPF_DRIVER_NAME) == FALSE && RegQueryLen == 0)
//		{
//			//just use an empty string string for the service name
//			NpfDriverName[0] = '\0';
//		}
		
		//
		// Create the name of the registry key containing the service.
		//
		StringCchPrintfA(NpfServiceLocation, sizeof(NpfServiceLocation), "SYSTEM\\CurrentControlSet\\Services\\%s", NpfDriverName);

		// check if the NPF registry key is already present
		// this means that the driver is already installed and that we don't need to call PacketInstallDriver
		KeyRes=RegOpenKeyExA(HKEY_LOCAL_MACHINE,
			NpfServiceLocation,
			0,
			KEY_READ,
			&PathKey);
		
		if(KeyRes != ERROR_SUCCESS)
		{
 			TRACE_PRINT("NPF registry key not present, trying to install the driver.");
			if (bUseNPF60)
			{
				Result = PacketInstallDriver60();
			}
			else
			{
				Result = PacketInstallDriver();
			}
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
			svcHandle = OpenServiceA(scmHandle, NpfDriverName, SERVICE_START | SERVICE_QUERY_STATUS );

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

				if(!QuerySStat || SStat.dwCurrentState != SERVICE_RUNNING)
				{
					TRACE_PRINT("Driver NPF not running. Calling startservice");
					if (StartService(svcHandle, 0, NULL)==0)
					{ 
						error = GetLastError();
						if(error!=ERROR_SERVICE_ALREADY_RUNNING && error!=ERROR_ALREADY_EXISTS)
						{
							SetLastError(error);
							if (scmHandle != NULL) 
								CloseServiceHandle(scmHandle);
							error = GetLastError();
							TRACE_PRINT1("PacketOpenAdapterNPF: StartService failed, LastError=%8.8x",error);
							TRACE_EXIT("PacketOpenAdapterNPF");
							SetLastError(error);
							return NULL;
						}
					}				
				}

				CloseServiceHandle( svcHandle );
       			svcHandle = NULL;

			}
			else
			{
				error = GetLastError();
				TRACE_PRINT1("OpenService failed! Error=%8.8x", error);
				SetLastError(error);
			}
		}
		else
		{
			if(KeyRes != ERROR_SUCCESS)
				if (bUseNPF60)
				{
					Result = PacketInstallDriver60();
				}
				else
				{
					Result = PacketInstallDriver();
				}
			else
				Result = TRUE;
			
			if (Result) {
				
				svcHandle = OpenServiceA(scmHandle,
					NpfDriverName,
					SERVICE_START);
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
					
					if(!QuerySStat || SStat.dwCurrentState != SERVICE_RUNNING){
						
						TRACE_PRINT("Calling startservice");
						
						if (StartService(svcHandle, 0, NULL)==0){ 
							error = GetLastError();
							if(error!=ERROR_SERVICE_ALREADY_RUNNING && error!=ERROR_ALREADY_EXISTS)
							{
								if (scmHandle != NULL) CloseServiceHandle(scmHandle);
								TRACE_PRINT1("PacketOpenAdapterNPF: StartService failed, LastError=%8.8x",error);
								TRACE_EXIT("PacketOpenAdapterNPF");
								SetLastError(error);
								return NULL;
							}
						}
					}
				    
					CloseServiceHandle( svcHandle );
					svcHandle = NULL;

				}
				else{
					error = GetLastError();
					TRACE_PRINT1("OpenService failed! LastError=%8.8x", error);
					SetLastError(error);
				}
			}
		}
	}

    if (scmHandle != NULL) CloseServiceHandle(scmHandle);

	lpAdapter=(LPADAPTER)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(ADAPTER));
	if (lpAdapter==NULL)
	{
		TRACE_PRINT("PacketOpenAdapterNPF: GlobalAlloc Failed to allocate the ADAPTER structure");
		error=GetLastError();
		//set the error to the one on which we failed
		TRACE_EXIT("PacketOpenAdapterNPF");
		SetLastError(error);
		return NULL;
	}

	lpAdapter->NumWrites=1;

#define DEVICE_PREFIX "\\Device\\"

	if (LOWORD(GetVersion()) == 4)
	{
		if (strlen(AdapterNameA) > strlen(DEVICE_PREFIX))
		{
			StringCchPrintfA(SymbolicLinkA, MAX_PATH, "\\\\.\\%s", AdapterNameA + strlen(DEVICE_PREFIX));
		}
		else
		{
			ZeroMemory(SymbolicLinkA, sizeof(SymbolicLinkA));
		}
	}
 	else
	{
		if (strlen(AdapterNameA) > strlen(DEVICE_PREFIX))
		{
			StringCchPrintfA(SymbolicLinkA, MAX_PATH, "\\\\.\\Global\\%s", AdapterNameA + strlen(DEVICE_PREFIX));
		}
		else
		{
			ZeroMemory(SymbolicLinkA, sizeof(SymbolicLinkA));
		}
	}

	//
	// NOTE GV 20061114 This is a sort of breaking change. In the past we were putting what
	// we could fit inside this variable. Now we simply put NOTHING. It's just useless
	//
	ZeroMemory(lpAdapter->SymbolicLink, sizeof(lpAdapter->SymbolicLink));

	//try if it is possible to open the adapter immediately
	lpAdapter->hFile=CreateFileA(SymbolicLinkA,GENERIC_WRITE | GENERIC_READ,
		0,NULL,OPEN_EXISTING,0,0);
	
	if (lpAdapter->hFile != INVALID_HANDLE_VALUE) 
	{

		if(PacketSetReadEvt(lpAdapter)==FALSE){
			error=GetLastError();
			TRACE_PRINT("PacketOpenAdapterNPF: Unable to open the read event");
			CloseHandle(lpAdapter->hFile);
			GlobalFreePtr(lpAdapter);
			//set the error to the one on which we failed
		    
			TRACE_PRINT1("PacketOpenAdapterNPF: PacketSetReadEvt failed, LastError=%8.8x",error);
			TRACE_EXIT("PacketOpenAdapterNPF");


			SetLastError(error);
			return NULL;
		}		
		
		PacketSetMaxLookaheadsize(lpAdapter);

		//
		// Indicate that this is a device managed by NPF.sys
		//
		lpAdapter->Flags = INFO_FLAG_NDIS_ADAPTER;


		StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterNameA);

		TRACE_PRINT("Successfully opened adapter");
		TRACE_EXIT("PacketOpenAdapterNPF");
		return lpAdapter;
	}

	error=GetLastError();
	GlobalFreePtr(lpAdapter);
	//set the error to the one on which we failed
    TRACE_PRINT1("PacketOpenAdapterNPF: CreateFile failed, LastError= %8.8x",error);
	TRACE_EXIT("PacketOpenAdapterNPF");
	SetLastError(error);
	return NULL;
}

#ifdef HAVE_WANPACKET_API
static LPADAPTER PacketOpenAdapterWanPacket(PCHAR AdapterName)
{
	LPADAPTER lpAdapter = NULL;
	DWORD dwLastError = ERROR_SUCCESS;

	TRACE_ENTER("PacketOpenAdapterWanPacket");

	TRACE_PRINT("Opening a NDISWAN adapter...");

	do
	{
		//
		// This is a wan adapter. Open it using the netmon API
		//			
		lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
			sizeof(ADAPTER));

		if (lpAdapter == NULL)
		{
			TRACE_PRINT("GlobalAlloc failed allocating memory for the ADAPTER structure. Failing (BAD_UNIT).");
			dwLastError = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		lpAdapter->Flags = INFO_FLAG_NDISWAN_ADAPTER;

		TRACE_PRINT("Trying to open the Wan Adapter through WanPacket.dll...");

		// Open the adapter
		lpAdapter->pWanAdapter = WanPacketOpenAdapter();

		if (lpAdapter->pWanAdapter == NULL)
		{
			TRACE_PRINT("WanPacketOpenAdapter failed. Failing. (BAD_UNIT)");
			dwLastError = ERROR_BAD_UNIT;
			break;
		}

		StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterName);

		lpAdapter->ReadEvent = WanPacketGetReadEvent(lpAdapter->pWanAdapter);

		TRACE_PRINT("Successfully opened the Wan Adapter.");

	}while(FALSE);

	if (dwLastError == ERROR_SUCCESS)
	{
		TRACE_EXIT("PacketOpenAdapterWanPacket");
		return lpAdapter;
	}
	else
	{
		if (lpAdapter != NULL) GlobalFree(lpAdapter);
		
		TRACE_EXIT("PacketOpenAdapterWanPacket");
		SetLastError(dwLastError);
		return NULL;
	}
}
#endif //HAVE_WANPACKET_API

/*! 
  \brief Opens an adapter using the aircap dll.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter()
*/
#ifdef HAVE_AIRPCAP_API
static LPADAPTER PacketOpenAdapterAirpcap(PCHAR AdapterName)
{
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
    LPADAPTER lpAdapter;

	//
	// Make sure that the airpcap API has been linked
	//
	if(!g_PAirpcapOpen)
	{
		return NULL;
	}
	
	lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
		sizeof(ADAPTER));
	if (lpAdapter == NULL)
	{
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
		GlobalFreePtr(lpAdapter);
		return NULL;					
	}
		  				
	StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterName);
	
	return lpAdapter;
}
#endif // HAVE_AIRPCAP_API


#ifdef HAVE_NPFIM_API
static LPADAPTER PacketOpenAdapterNpfIm(PCHAR AdapterName)
{
    LPADAPTER lpAdapter;

	lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
		sizeof(ADAPTER));
	if (lpAdapter == NULL)
	{
		return NULL;
	}

	//
	// Indicate that this is a aircap card
	//
	lpAdapter->Flags = INFO_FLAG_NPFIM_DEVICE;
		  
	//
	// Open the adapter
	//

	if (g_NpfImHandlers.NpfImOpenDevice(AdapterName, (NPF_IM_DEV_HANDLE*)&lpAdapter->NpfImHandle) == FALSE)
	{
		GlobalFreePtr(lpAdapter);
		return NULL;					
	}
		  				
	StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterName);
	
	return lpAdapter;
}
#endif // HAVE_NpfIm_API


/*! 
  \brief Opens an adapter using the DAG capture API.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter()
*/
#ifdef HAVE_DAG_API
static LPADAPTER PacketOpenAdapterDAG(PCHAR AdapterName, BOOLEAN IsAFile)
{
	CHAR DagEbuf[DAGC_ERRBUF_SIZE];
    LPADAPTER lpAdapter;
	LONG	status;
	HKEY dagkey;
	DWORD lptype;
	DWORD fpc;
	DWORD lpcbdata = sizeof(fpc);
	WCHAR keyname[512];
	PWCHAR tsn;

	TRACE_ENTER("PacketOpenAdapterDAG");

	
	lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
		sizeof(ADAPTER));
	if (lpAdapter == NULL)
	{
		TRACE_PRINT("GlobalAlloc failed allocating memory for the ADAPTER structure");
		TRACE_EXIT("PacketOpenAdapterDAG");
		return NULL;
	}

	if(IsAFile)
	{
		// We must add an entry to the adapter description list, otherwise many function will not
		// be able to work
		if(!PacketAddAdapterDag(AdapterName, "DAG file", IsAFile))
		{
			TRACE_PRINT("Failed adding the Dag file to the list of adapters");
			TRACE_EXIT("PacketOpenAdapterDAG");
			GlobalFreePtr(lpAdapter);
			return NULL;					
		}

		// Flag that this is a DAG file
		lpAdapter->Flags = INFO_FLAG_DAG_FILE;
	}
	else
	{
		// Flag that this is a DAG card
		lpAdapter->Flags = INFO_FLAG_DAG_CARD;
	}

	//
	// See if the user is asking for fast capture with this device
	//

	lpAdapter->DagFastProcess = FALSE;

	tsn = (strstr(strlwr((char*)AdapterName), "dag") != NULL)?
		SChar2WChar(strstr(strlwr((char*)AdapterName), "dag")):
		L"";

	StringCchPrintfW(keyname, sizeof(keyname)/sizeof(keyname[0]), L"%s\\CardParams\\%ws", 
		L"SYSTEM\\CurrentControlSet\\Services\\DAG",
		tsn);

	GlobalFreePtr(tsn);

	do
	{
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0 , KEY_READ, &dagkey);
		if(status != ERROR_SUCCESS)
			break;
		
		status = RegQueryValueEx(dagkey,
			L"FastCap",
			NULL,
			&lptype,
			(LPBYTE)&fpc,
			&lpcbdata);
		
		if(status == ERROR_SUCCESS)
			lpAdapter->DagFastProcess = fpc;
		
		RegCloseKey(dagkey);
	}
	while(FALSE);
		  

	TRACE_PRINT("Trying to open the DAG device...");
	//
	// Open the card
	//
	lpAdapter->pDagCard = g_p_dagc_open(AdapterName,
	 0, 
	 DagEbuf);
	
	if(lpAdapter->pDagCard == NULL)
	{
		TRACE_PRINT("Failed opening the DAG device");
		TRACE_EXIT("PacketOpenAdapterDAG");
		GlobalFreePtr(lpAdapter);
		return NULL;					
	}
		  
	lpAdapter->DagFcsLen = g_p_dagc_getfcslen(lpAdapter->pDagCard);
				
	StringCchCopyA(lpAdapter->Name, ADAPTER_NAME_LENGTH, AdapterName);
	
	// XXX we could create the read event here
	TRACE_PRINT("Successfully opened the DAG device");
	TRACE_EXIT("PacketOpenAdapterDAG");

	return lpAdapter;
}
#endif // HAVE_DAG_API


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
PCHAR PacketGetVersion()
{
	TRACE_ENTER("PacketGetVersion");
	TRACE_EXIT("PacketGetVersion");
	return PacketLibraryVersion;
}

/*! 
  \brief Return a string with the version of the NPF.sys device driver.
  \return A char pointer to the version of the driver.
*/
PCHAR PacketGetDriverVersion()
{
	TRACE_ENTER("PacketGetDriverVersion");
	TRACE_EXIT("PacketGetDriverVersion");
	return PacketDriverVersion;
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
	CHAR	NpfDriverName[MAX_WINPCAP_KEY_CHARS] = NPF_DRIVER_NAME;

//  
//	Old registry based WinPcap names
//
//	CHAR	NpfDriverName[MAX_WINPCAP_KEY_CHARS];
//	UINT	RegQueryLen;

 	TRACE_ENTER("PacketStopDriver");
 
 	ret = FALSE;

//  
//	Old registry based WinPcap names
//
//	// Create the NPF device name from the original device name
//	RegQueryLen = sizeof(NpfDriverName)/sizeof(NpfDriverName[0]);
//	
//	if (QueryWinPcapRegistryStringA(NPF_DRIVER_NAME_REG_KEY, NpfDriverName, &RegQueryLen, NPF_DRIVER_NAME) == FALSE && RegQueryLen == 0)
//		return FALSE;

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle != NULL){
		
		TRACE_PRINT("Opened the SCM");
		
		schService = OpenServiceA (scmHandle,
			NpfDriverName,
			SERVICE_ALL_ACCESS
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
				TRACE_PRINT("Failed to stop the NPF service");
			}
			else
			{
				TRACE_PRINT("NPF service stopped");
			}
			
			CloseServiceHandle (schService);
			
			CloseServiceHandle(scmHandle);
			
		}
	}
	
	TRACE_EXIT("PacketStopDriver");
	return ret;
}

BOOL PacketStopDriver60()
{
	BOOL result;
	TRACE_ENTER("PacketStopDriver60");

	result = (BOOL) UninstallDriver();

	TRACE_EXIT("PacketStopDriver60");

	return result;
}

/*! 
  \brief Opens an adapter.
  \param AdapterName A string containing the name of the device to open. 
   Use the PacketGetAdapterNames() function to retrieve the list of available devices.
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.
*/
LPADAPTER PacketOpenAdapter(PCHAR AdapterNameWA)
{
    LPADAPTER lpAdapter = NULL;
	PCHAR AdapterNameA = NULL;
	BOOL bFreeAdapterNameA;
#ifndef _WINNT4
	PADAPTER_INFO TAdInfo;
#endif //_WINNT4
	
	DWORD dwLastError = ERROR_SUCCESS;
 
 	TRACE_ENTER("PacketOpenAdapter");	
 
	TRACE_PRINT_OS_INFO();
	
	TRACE_PRINT2("Packet DLL version %s, Driver version %s", PacketLibraryVersion, PacketDriverVersion);

	//
	// Check the presence on some libraries we rely on, and load them if we found them
	//
	PacketLoadLibrariesDynamically();

	//
	// Ugly heuristic to detect if the adapter is ASCII
	//
	if(AdapterNameWA[1]!=0)
	{ 
		//
		// ASCII
		//
		bFreeAdapterNameA = FALSE;
		AdapterNameA = AdapterNameWA;
	} 
	else 
	{	
		//
		// Unicode
		//
		size_t bufferSize = wcslen((PWCHAR)AdapterNameWA) + 1;
		
		AdapterNameA = GlobalAllocPtr(GPTR, bufferSize);

		if (AdapterNameA == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return NULL;
		}

		StringCchPrintfA(AdapterNameA, bufferSize, "%ws", (PWCHAR)AdapterNameWA);
		bFreeAdapterNameA = TRUE;
	}

#ifndef _WINNT4
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
#endif // not WINNT4

	do
	{

#ifndef _WINNT4
		//
		// Windows NT4 does not have support for the various nifty
		// adapters supported from 2000 on (airpcap, ndiswan, npfim...)
		// so we just skip all the magic of the global adapter list, 
		// and try to open the adapter with PacketOpenAdapterNPF at
		// the end of this big function!
		//

		//
		// If we are here it's because we need to update the list
		// 


		TRACE_PRINT("Looking for the adapter in our list 1st time...");

		// Find the PADAPTER_INFO structure associated with this adapter 
		TAdInfo = PacketFindAdInfo(AdapterNameA);
		if(TAdInfo == NULL)
		{
			TRACE_PRINT("Adapter not found in our list. Try to refresh the list.");

			PacketUpdateAdInfo(AdapterNameA);
			TAdInfo = PacketFindAdInfo(AdapterNameA);

			TRACE_PRINT("Looking for the adapter in our list 2nd time...");
		}

		if(TAdInfo == NULL)
		{
#ifdef HAVE_DAG_API
			TRACE_PRINT("Adapter not found in our list. Try to open it as a DAG/ERF file...");

			//can be an ERF file?
			lpAdapter = PacketOpenAdapterDAG(AdapterNameA, TRUE);
#endif // HAVE_DAG_API

			if (lpAdapter == NULL)
			{
				TRACE_PRINT("Failed to open it as a DAG/ERF file, failing with ERROR_BAD_UNIT");
				dwLastError = ERROR_BAD_UNIT; //this is the best we can do....
			}
			else
			{
				TRACE_PRINT("Opened the adapter as a DAG/ERF file.");
			}

			break;
		}

		TRACE_PRINT("Adapter found in our list. Check adapter type and see if it's actually supported.");

#ifdef HAVE_WANPACKET_API
		if(TAdInfo->Flags == INFO_FLAG_NDISWAN_ADAPTER)
		{
			lpAdapter = PacketOpenAdapterWanPacket(AdapterNameA);

			if (lpAdapter == NULL)
			{
				dwLastError = GetLastError();
			}

			break;
		}
#endif //HAVE_WANPACKET_API

#ifdef HAVE_AIRPCAP_API
		if(TAdInfo->Flags == INFO_FLAG_AIRPCAP_CARD)
		{
			//
			// This is an airpcap card. Open it using the airpcap api
			//								
			lpAdapter = PacketOpenAdapterAirpcap(AdapterNameA);
			
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

#ifdef HAVE_NPFIM_API
		if(TAdInfo->Flags == INFO_FLAG_NPFIM_DEVICE)
		{
			//
			// This is an airpcap card. Open it using the airpcap api
			//								
			lpAdapter = PacketOpenAdapterNpfIm(AdapterNameA);

			if(lpAdapter == NULL)
			{
				dwLastError = ERROR_BAD_UNIT;
				break;
			}

			//
			// NpfIm provides a read event
			//
			if(!g_NpfImHandlers.NpfImGetCaptureReadEvent((NPF_IM_DEV_HANDLE)lpAdapter->NpfImHandle, &lpAdapter->ReadEvent))
			{
				dwLastError = GetLastError();
				PacketCloseAdapter(lpAdapter);
			}
			else
			{
				dwLastError = ERROR_SUCCESS;
			}

			break;
		}
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
		if(TAdInfo->Flags == INFO_FLAG_DAG_CARD)
		{
			TRACE_PRINT("Opening a DAG adapter...");
			//
			// This is a Dag card. Open it using the dagc API
			//								
			lpAdapter = PacketOpenAdapterDAG(AdapterNameA, FALSE);
			if (lpAdapter == NULL)
			{
				TRACE_PRINT("Failed opening the DAG adapter with PacketOpenAdapterDAG. Failing. (BAD_UNIT)");
				dwLastError = ERROR_BAD_UNIT;
			}
			else
			{
				dwLastError = ERROR_SUCCESS;
			}

			break;
		}
#endif // HAVE_DAG_API

		if(TAdInfo->Flags == INFO_FLAG_DONT_EXPORT)
		{
			//
			// The adapter is flagged as not exported, probably because it's broken 
			// or incompatible with WinPcap. We end here with an error.
			//
			TRACE_PRINT1("Trying to open the adapter %s which is flagged as not exported. Failing (BAD_UNIT)", AdapterNameA);
			dwLastError = ERROR_BAD_UNIT;
			
			break;
		}

		if (TAdInfo->Flags != INFO_FLAG_NDIS_ADAPTER)
		{
			TRACE_PRINT1("Trying to open the adapter with an unknown flag type %u", TAdInfo->Flags);
			dwLastError = ERROR_BAD_UNIT;
			
			break;
		}

#endif // not _WINNT4

		//
		// This is the only code executed on NT4
		//
		// Windows NT4 does not have support for the various nifty
		// adapters supported from 2000 on (airpcap, ndiswan, npfim...)
		// so we just skip all the magic of the global adapter list, 
		// and try to open the adapter with PacketOpenAdapterNPF at
		// the end of this big function!
		//
		TRACE_PRINT("Normal NPF adapter, trying to open it...");
		lpAdapter = PacketOpenAdapterNPF(AdapterNameA);
		if (lpAdapter == NULL)
		{
			dwLastError = GetLastError();
		}

	}while(FALSE);

#ifndef _WINNT4
	ReleaseMutex(g_AdaptersInfoMutex);
#endif

	if (bFreeAdapterNameA) GlobalFree(AdapterNameA);


	if (dwLastError != ERROR_SUCCESS)
	{
		TRACE_EXIT("PacketOpenAdapter");
		SetLastError(dwLastError);

		return NULL;
	}
	else
	{
		TRACE_EXIT("PacketOpenAdapter");

		return lpAdapter;
	}

}

/*! 
  \brief Closes an adapter.
  \param lpAdapter the pointer to the adapter to close. 

  PacketCloseAdapter closes the given adapter and frees the associated ADAPTER structure
*/
VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
	TRACE_ENTER("PacketCloseAdapter");
	if(!lpAdapter)
	{
        TRACE_PRINT("PacketCloseAdapter: attempt to close a NULL adapter");
		TRACE_EXIT("PacketCloseAdapter");
		return;
	}

#ifdef HAVE_WANPACKET_API
	if (lpAdapter->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		TRACE_PRINT("Closing a WAN adapter through WanPacket...");
		WanPacketCloseAdapter(lpAdapter->pWanAdapter);
		GlobalFreePtr(lpAdapter);
		return;
	}
#endif

#ifdef HAVE_AIRPCAP_API
	if(lpAdapter->Flags == INFO_FLAG_AIRPCAP_CARD)
		{
			g_PAirpcapClose(lpAdapter->AirpcapAd);
			GlobalFreePtr(lpAdapter);
			return;
		}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(lpAdapter->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		g_NpfImHandlers.NpfImCloseDevice(lpAdapter->NpfImHandle);
		GlobalFreePtr(lpAdapter);
		return;
	}
#endif

#ifdef HAVE_DAG_API
	if(lpAdapter->Flags & INFO_FLAG_DAG_FILE ||  lpAdapter->Flags & INFO_FLAG_DAG_CARD)
	{
		TRACE_PRINT("Closing a DAG file...");
		if(lpAdapter->Flags & INFO_FLAG_DAG_FILE & ~INFO_FLAG_DAG_CARD)
		{
			// This is a file. We must remove the entry in the adapter description list
		PacketUpdateAdInfo(lpAdapter->Name);
		}
		g_p_dagc_close(lpAdapter->pDagCard);
	    GlobalFreePtr(lpAdapter);
		return;
	}
#endif // HAVE_DAG_API

	if (lpAdapter->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT1("Trying to close an unknown adapter type (%u)", lpAdapter->Flags);
	}
	else
	{
		SetEvent(lpAdapter->ReadEvent);
	    CloseHandle(lpAdapter->ReadEvent);
		CloseHandle(lpAdapter->hFile);
		GlobalFreePtr(lpAdapter);
		TRACE_EXIT("PacketCloseAdapter");
	}

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

	TRACE_ENTER("PacketAllocatePacket");
    
	lpPacket=(LPPACKET)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,sizeof(PACKET));
    if (lpPacket==NULL)
    {
        TRACE_PRINT("PacketAllocatePacket: GlobalAlloc Failed");
    }

	TRACE_EXIT("PacketAllocatePacket");
    
	return lpPacket;
}

/*! 
  \brief Frees a _PACKET structure.
  \param lpPacket The structure to free. 

  \warning the user-allocated buffer associated with the _PACKET structure is not deallocated 
  by this function and \b must be explicitly deallocated by the programmer.

*/
VOID PacketFreePacket(LPPACKET lpPacket)

{
	TRACE_ENTER("PacketFreePacket");
    GlobalFreePtr(lpPacket);
	TRACE_EXIT("PacketFreePacket");
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

VOID PacketInitPacket(LPPACKET lpPacket,PVOID Buffer,UINT Length)

{
	TRACE_ENTER("PacketInitPacket");

    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;

	TRACE_EXIT("PacketInitPacket");
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
BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	BOOLEAN res;

	UNUSED(Sync);

	TRACE_ENTER("PacketReceivePacket");
#ifdef HAVE_WANPACKET_API
	
	if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		lpPacket->ulBytesReceived = WanPacketReceivePacket(AdapterObject->pWanAdapter, lpPacket->Buffer, lpPacket->Length);

		TRACE_EXIT("PacketReceivePacket");
		return TRUE;
	}
#endif //HAVE_WANPACKET_API

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
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
				lpPacket->Buffer, 
				lpPacket->Length, 
				&lpPacket->ulBytesReceived);

		TRACE_EXIT("PacketReceivePacket");

		return res;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		//
		// Read the data.
		// NpfImReceivePacket performs its own wait internally.
		//
	
		res = (BOOLEAN)g_NpfImHandlers.NpfImReceivePackets(AdapterObject->NpfImHandle,
				lpPacket->Buffer, 
				lpPacket->Length, 
				&lpPacket->ulBytesReceived);

		TRACE_EXIT("PacketReceivePacket");

		return res;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
	if((AdapterObject->Flags & INFO_FLAG_DAG_CARD) || (AdapterObject->Flags & INFO_FLAG_DAG_FILE))
	{
		g_p_dagc_wait(AdapterObject->pDagCard, &AdapterObject->DagReadTimeout);

		res = (BOOLEAN)(g_p_dagc_receive(AdapterObject->pDagCard, (u_char**)&AdapterObject->DagBuffer, (u_int*)&lpPacket->ulBytesReceived) == 0);
		
		TRACE_EXIT("PacketReceivePacket");
		return res;
	}
#endif // HAVE_DAG_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		if((int)AdapterObject->ReadTimeOut != -1)
			WaitForSingleObject(AdapterObject->ReadEvent, (AdapterObject->ReadTimeOut==0)?INFINITE:AdapterObject->ReadTimeOut);
	
		res = (BOOLEAN)ReadFile(AdapterObject->hFile, lpPacket->Buffer, lpPacket->Length, &lpPacket->ulBytesReceived,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to read on an unknown device type (%u)", AdapterObject->Flags);
		res = FALSE;
	}
	
	TRACE_EXIT("PacketReceivePacket");
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
BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
    DWORD        BytesTransfered;
	BOOLEAN		Result;    
	TRACE_ENTER("PacketSendPacket");

	UNUSED(Sync);

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		if(g_PAirpcapWrite)
		{
			Result = (BOOLEAN)g_PAirpcapWrite(AdapterObject->AirpcapAd, lpPacket->Buffer, lpPacket->Length);
			TRACE_EXIT("PacketSetMinToCopy");
			
			return Result;
		}
		else
		{
			TRACE_EXIT("PacketSetMinToCopy");
			TRACE_PRINT("Transmission not supported with this version of AirPcap");

			return FALSE;
		}
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_WANPACKET_API
	if(AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		TRACE_PRINT("PacketSendPacket: packet sending not allowed on wan adapters");

		TRACE_EXIT("PacketSendPacket");
		return FALSE;
	}
#endif // HAVE_WANPACKET_API
		
#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		TRACE_PRINT("PacketSendPacket: packet sending not allowed on NPFIM adapters");

		TRACE_EXIT("PacketSendPacket");
		return FALSE;
	}
#endif //HAVE_NPFIM_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		Result = (BOOLEAN)WriteFile(AdapterObject->hFile,lpPacket->Buffer,lpPacket->Length,&BytesTransfered,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to write on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
	}

	TRACE_EXIT("PacketSendPacket");
	return Result;
}

/*!
  \brief Header associated to a packet in the driver's buffer when the driver is in dump mode.
  Similar to the bpf_hdr structure, but simpler.
*/
struct sf_pkthdr {
    struct timeval	ts;			///< time stamp
    UINT			caplen;		///< Length of captured portion. The captured portion can be different from 
								///< the original packet, because it is possible (with a proper filter) to 
								///< instruct the driver to capture only a portion of the packets. 
    UINT			len;		///< Length of the original packet (off wire).
};


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

  \note When Sync is set to TRUE, the packets are synchronized in the kerenl with a high precision timestamp.
  This requires a remarkable amount of CPU, but allows to send the packets with a precision of some microseconds
  (depending on the precision of the performance counter of the machine). Such a precision cannot be reached 
  sending the packets separately with PacketSendPacket().
*/
INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
    BOOLEAN			Res;
    DWORD			BytesTransfered, TotBytesTransfered=0;
	struct timeval	BufStartTime;
	LARGE_INTEGER	StartTicks, CurTicks, TargetTicks, TimeFreq;


	TRACE_ENTER("PacketSendPackets");

#ifdef HAVE_WANPACKET_API
	if(AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		TRACE_PRINT("PacketSendPackets: packet sending not allowed on wan adapters");
		TRACE_EXIT("PacketSendPackets");
		return 0;
	}
#endif // HAVE_WANPACKET_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		TRACE_PRINT("PacketSendPackets: packet sending not allowed on npfim adapters");
		TRACE_EXIT("PacketSendPackets");
		return 0;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		TRACE_PRINT("PacketSendPackets: packet sending not allowed on airpcap adapters");
		TRACE_EXIT("PacketSendPackets");
		return 0;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		// Obtain starting timestamp of the buffer
		BufStartTime.tv_sec = ((struct timeval*)(PacketBuff))->tv_sec;
		BufStartTime.tv_usec = ((struct timeval*)(PacketBuff))->tv_usec;

		// Retrieve the reference time counters
		QueryPerformanceCounter(&StartTicks);
		QueryPerformanceFrequency(&TimeFreq);

		CurTicks.QuadPart = StartTicks.QuadPart;

		do{
			// Send the data to the driver
			//TODO Res is NEVER checked, this is REALLY bad.
			Res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
				(Sync)?BIOCSENDPACKETSSYNC:BIOCSENDPACKETSNOSYNC,
				(PCHAR)PacketBuff + TotBytesTransfered,
				Size - TotBytesTransfered,
				NULL,
				0,
				&BytesTransfered,
				NULL);

			// Exit from the loop on error
			if(Res != TRUE)
				break;

			TotBytesTransfered += BytesTransfered;

			// Exit from the loop if we have transferred everything
			if(TotBytesTransfered >= Size)
				break;

			// calculate the time interval to wait before sending the next packet
			TargetTicks.QuadPart = StartTicks.QuadPart +
			(LONGLONG)
			((((struct timeval*)((PCHAR)PacketBuff + TotBytesTransfered))->tv_sec - BufStartTime.tv_sec) * 1000000 +
			(((struct timeval*)((PCHAR)PacketBuff + TotBytesTransfered))->tv_usec - BufStartTime.tv_usec)) *
			(TimeFreq.QuadPart) / 1000000;
			
			// Wait until the time interval has elapsed
			while( CurTicks.QuadPart <= TargetTicks.QuadPart )
				QueryPerformanceCounter(&CurTicks);

		}
		while(TRUE);
	}
	else
	{
		TRACE_PRINT1("Request to write on an unknown device type (%u)", AdapterObject->Flags);
		TotBytesTransfered = 0;
	}

	TRACE_EXIT("PacketSendPackets");

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

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	TRACE_ENTER("PacketSetMinToCopy");
	
#ifdef HAVE_WANPACKET_API
	if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		Result = WanPacketSetMinToCopy(AdapterObject->pWanAdapter, nbytes);
		TRACE_EXIT("PacketSetMinToCopy");
		
		return Result;
	}
#endif //HAVE_WANPACKET_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		Result = (BOOLEAN)g_NpfImHandlers.NpfImSetMinToCopy(AdapterObject->NpfImHandle, nbytes);
		TRACE_EXIT("PacketSetMinToCopy");
		
		return Result;
	}
#endif // HAVE_NPFIM_API
	
#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetMinToCopy(AdapterObject->AirpcapAd, nbytes);
		TRACE_EXIT("PacketSetMinToCopy");
		
		return Result;
	}
#endif // HAVE_AIRPCAP_API
	
#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		TRACE_EXIT("PacketSetMinToCopy");
		// No mintocopy with DAGs
		return TRUE;
	}
#endif // HAVE_DAG_API
		
	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSMINTOCOPY,&nbytes,4,NULL,0,&BytesReturned,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to set mintocopy on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
	}
	
	TRACE_EXIT("PacketSetMinToCopy");
		
	return Result; 		
}

/*!
  \brief Sets the working mode of an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param mode The new working mode of the adapter.
  \return If the function succeeds, the return value is nonzero.

  The device driver of WinPcap has 4 working modes:
  - Capture mode (mode = PACKET_MODE_CAPT): normal capture mode. The packets transiting on the wire are copied
   to the application when PacketReceivePacket() is called. This is the default working mode of an adapter.
  - Statistical mode (mode = PACKET_MODE_STAT): programmable statistical mode. PacketReceivePacket() returns, at
   precise intervals, statics values on the network traffic. The interval between the statistic samples is 
   by default 1 second but it can be set to any other value (with a 1 ms precision) with the 
   PacketSetReadTimeout() function. The data returned by PacketReceivePacket() when the adapter is in statistical
   mode is shown in the following figure:<p>
   	 \image html stats.gif "data structure returned by statistical mode"
   Two 64-bit counters are provided: the number of packets and the amount of bytes that satisfy a filter 
   previously set with PacketSetBPF(). If no filter has been set, all the packets are counted. The counters are 
   encapsulated in a bpf_hdr structure, so that they will be parsed correctly by wpcap. Statistical mode has a 
   very low impact on system performance compared to capture mode. 
  - Dump mode (mode = PACKET_MODE_DUMP): the packets are dumped to disk by the driver, in libpcap format. This
   method is much faster than saving the packets after having captured them. No data is returned 
   by PacketReceivePacket(). If the application sets a filter with PacketSetBPF(), only the packets that satisfy
   this filter are dumped to disk.
  - Statitical Dump mode (mode = PACKET_MODE_STAT_DUMP): the packets are dumped to disk by the driver, in libpcap 
   format, like in dump mode. PacketReceivePacket() returns, at precise intervals, statics values on the 
   network traffic and on the amount of data saved to file, in a way similar to statistical mode.
   The data returned by PacketReceivePacket() when the adapter is in statistical dump mode is shown in 
   the following figure:<p>   
	 \image html dump.gif "data structure returned by statistical dump mode"
   Three 64-bit counters are provided: the number of packets accepted, the amount of bytes accepted and the 
   effective amount of data (including headers) dumped to file. If no filter has been set, all the packets are 
   dumped to disk. The counters are encapsulated in a bpf_hdr structure, so that they will be parsed correctly 
   by wpcap.
   Look at the NetMeter example in the 
   WinPcap developer's pack to see how to use statistics mode.
*/
BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
	DWORD BytesReturned;
	BOOLEAN Result;

   TRACE_ENTER("PacketSetMode");

#ifdef HAVE_WANPACKET_API
   if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
   {
	   Result = WanPacketSetMode(AdapterObject->pWanAdapter, mode);
	   TRACE_EXIT("PacketSetMode");

	   return Result;
   }
#endif // HAVE_WANPACKET_API
   
#ifdef HAVE_AIRPCAP_API
   if (AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
   {
	   if (mode == PACKET_MODE_CAPT)
	   {
		   Result = TRUE;
	   }
	   else
	   {
		   Result = FALSE;
	   }

	   TRACE_EXIT("PacketSetMode");

	   return Result;
   }
#endif //HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
   if (AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
   {
	   if (mode == PACKET_MODE_CAPT)
	   {
		   Result = TRUE;
	   }
	   else
	   {
		   Result = FALSE;
	   }

	   TRACE_EXIT("PacketSetMode");

	   return Result;
   }
#endif //HAVE_NPFIM_API

   if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
   {
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSMODE,&mode,4,NULL,0,&BytesReturned,NULL);
   }
   else
   {
	   TRACE_PRINT1("Request to set mode on an unknown device type (%u)", AdapterObject->Flags);
	   Result = FALSE;
   }

   TRACE_EXIT("PacketSetMode");

   return Result;

}

/*!
  \brief Sets the name of the file that will receive the packet when the adapter is in dump mode.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param name the file name, in ASCII or UNICODE.
  \param len the length of the buffer containing the name, in bytes.
  \return If the function succeeds, the return value is nonzero.

  This function defines the file name that the driver will open to store the packets on disk when 
  it works in dump mode. The adapter must be in dump mode, i.e. PacketSetMode() should have been
  called previously with mode = PACKET_MODE_DUMP. otherwise this function will fail.
  If PacketSetDumpName was already invoked on the adapter pointed by AdapterObject, the driver 
  closes the old file and opens the new one.
*/

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	DWORD		BytesReturned;
	WCHAR	*FileName;
	BOOLEAN	res;
	WCHAR	NameWithPath[1024];
	int		TStrLen;
	WCHAR	*NamePos;

	TRACE_ENTER("PacketSetDumpName");

	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketSetDumpName: not allowed on non-NPF adapters");
		TRACE_EXIT("PacketSetDumpName");
		return FALSE;
	}

	if(((PUCHAR)name)[1]!=0 && len>1){ //ASCII
		FileName=SChar2WChar(name);
		len*=2;
	} 
	else {	//Unicode
		FileName=name;
	}

	TStrLen=GetFullPathName(FileName,1024,NameWithPath,&NamePos);

	len=TStrLen*2+2;  //add the terminating null character

	// Try to catch malformed strings
	if(len>2048){
		if(((PUCHAR)name)[1]!=0 && len>1) GlobalFreePtr(FileName);

		TRACE_EXIT("PacketSetDumpName");

		return FALSE;
	}

    res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSETDUMPFILENAME,NameWithPath,len,NULL,0,&BytesReturned,NULL);
	if(((PUCHAR)name)[1]!=0 && len>1) GlobalFreePtr(FileName);

	TRACE_EXIT("PacketSetDumpName");
	return res;
}

/*
  \brief Set the dump mode limits.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param maxfilesize The maximum dimension of the dump file, in bytes. 0 means no limit.
  \param maxnpacks The maximum number of packets contained in the dump file. 0 means no limit.
  \return If the function succeeds, the return value is nonzero.

  This function sets the limits after which the NPF driver stops to save the packets to file when an adapter
  is in dump mode. This allows to limit the dump file to a precise number of bytes or packets, avoiding that
  very long dumps fill the disk space. If both maxfilesize and maxnpacks are set, the dump is stopped when
  the first of the two is reached.

  \note When a limit is reached, the dump is stopped, but the file remains opened. In order to flush 
  correctly the data and access the file consistently, you need to close the adapter with PacketCloseAdapter().
*/
BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	DWORD		BytesReturned;
	UINT valbuff[2];
	BOOLEAN Result;

	TRACE_ENTER("PacketSetDumpLimits");

	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketSetDumpLimits: not allowed on non-NPF adapters");
		TRACE_EXIT("PacketSetDumpLimits");
		return FALSE;
	}

	valbuff[0] = maxfilesize;
	valbuff[1] = maxnpacks;

    Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
		BIOCSETDUMPLIMITS,
		valbuff,
		sizeof valbuff,
		NULL,
		0,
		&BytesReturned,
		NULL);	

	TRACE_EXIT("PacketSetDumpLimits");

	return Result;

}

/*!
  \brief Returns the status of the kernel dump process, i.e. tells if one of the limits defined with PacketSetDumpLimits() was reached.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param sync if TRUE, the function blocks until the dump is finished, otherwise it returns immediately.
  \return TRUE if the dump is ended, FALSE otherwise.

  PacketIsDumpEnded() informs the user about the limits that were set with a previous call to 
  PacketSetDumpLimits().

  \warning If no calls to PacketSetDumpLimits() were performed or if the dump process has no limits 
  (i.e. if the arguments of the last call to PacketSetDumpLimits() were both 0), setting sync to TRUE will
  block the application on this call forever.
*/
BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	DWORD		BytesReturned;
	int		IsDumpEnded;
	BOOLEAN	res;

	TRACE_ENTER("PacketIsDumpEnded");

	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketIsDumpEnded: not allowed on non-NPF adapters");
	
		TRACE_EXIT("PacketIsDumpEnded");
		
		return FALSE;
	}

	if(sync)
		WaitForSingleObject(AdapterObject->ReadEvent, INFINITE);

    res = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
		BIOCISDUMPENDED,
		NULL,
		0,
		&IsDumpEnded,
		4,
		&BytesReturned,
		NULL);

	TRACE_EXIT("PacketIsDumpEnded");

	if(res == FALSE) return TRUE; // If the IOCTL returns an error we consider the dump finished

	return (BOOLEAN)IsDumpEnded;
}

/*!
  \brief Returns the notification event associated with the read calls on an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \return The handle of the event that the driver signals when some data is available in the kernel buffer.

  The event returned by this function is signaled by the driver if:
  - The adapter pointed by AdapterObject is in capture mode and an amount of data greater or equal 
  than the one set with the PacketSetMinToCopy() function is received from the network.
  - the adapter pointed by AdapterObject is in capture mode, no data has been received from the network
   but the the timeout set with the PacketSetReadTimeout() function has elapsed.
  - the adapter pointed by AdapterObject is in statics mode and the the timeout set with the 
   PacketSetReadTimeout() function has elapsed. This means that a new statistic sample is available.

  In every case, a call to PacketReceivePacket() will return immediately.
  The event can be passed to standard Win32 functions (like WaitForSingleObject or WaitForMultipleObjects) 
  to wait until the driver's buffer contains some data. It is particularly useful in GUI applications that 
  need to wait concurrently on several events.

*/
HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
	TRACE_ENTER("PacketGetReadEvent");
	TRACE_EXIT("PacketGetReadEvent");
    return AdapterObject->ReadEvent;
}

/*!
  \brief Sets the number of times a single packet written with PacketSendPacket() will be repeated on the network.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param nwrites Number of copies of a packet that will be physically sent by the interface.
  \return If the function succeeds, the return value is nonzero.

	See PacketSendPacket() for details.
*/
BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
	DWORD BytesReturned;
	BOOLEAN Result;

	TRACE_ENTER("PacketSetNumWrites");

	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketSetNumWrites: not allowed on non-NPF adapters");
		TRACE_EXIT("PacketSetNumWrites");
		return FALSE;
	}

    Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSWRITEREP,&nwrites,4,NULL,0,&BytesReturned,NULL);

	TRACE_EXIT("PacketSetNumWrites");

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
BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
	BOOLEAN Result;
	
	TRACE_ENTER("PacketSetReadTimeout");

	AdapterObject->ReadTimeOut = timeout;

#ifdef HAVE_WANPACKET_API
	if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		Result = WanPacketSetReadTimeout(AdapterObject->pWanAdapter,timeout);
		
		TRACE_EXIT("PacketSetReadTimeout");
		
		return Result;
	}
#endif // HAVE_WANPACKET_API

#ifdef HAVE_NPFIM_API
	if (AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		//
		// convert the timestamps to Windows like format (0 = immediate, -1(INFINITE) = infinite)
		//
		if (timeout == -1) timeout = 0;
		else if (timeout == 0) timeout = INFINITE;
        
		Result = (BOOLEAN)g_NpfImHandlers.NpfImSetReadTimeout(AdapterObject->NpfImHandle, timeout);
		TRACE_EXIT("PacketSetReadTimeout");
		return Result;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_AIRPCAP_API
	//
	// Timeout with AirPcap is handled at user level
	//
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		TRACE_EXIT("PacketSetReadTimeout");
		return TRUE;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_DAG_API
	// Under DAG, we simply store the timeout value and then 
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		if(timeout == -1)
		{
			// tell DAG card to return immediately
			AdapterObject->DagReadTimeout.tv_sec = 0;
			AdapterObject->DagReadTimeout.tv_usec = 0;
		}
		else
		{
			if(timeout == 0)
			{
				// tell the DAG card to wait forvever
				AdapterObject->DagReadTimeout.tv_sec = -1;
				AdapterObject->DagReadTimeout.tv_usec = -1;
			}
			else
			{
				// Set the timeout for the DAG card
				AdapterObject->DagReadTimeout.tv_sec = timeout / 1000;
				AdapterObject->DagReadTimeout.tv_usec = (timeout * 1000) % 1000000;
			}
		}			
		
		TRACE_EXIT("PacketSetReadTimeout");
		return TRUE;
	}
#endif // HAVE_DAG_API

	if(AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		Result = TRUE;
	}
	else
	{
		//
		// if we are here, it's an unsupported ADAPTER type!
		//
		TRACE_PRINT1("Request to set read timeout on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
	}

	TRACE_EXIT("PacketSetReadTimeout");
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
BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
	DWORD BytesReturned;
	BOOLEAN Result;

	TRACE_ENTER("PacketSetBuff");

#ifdef HAVE_WANPACKET_API
	if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
        Result = WanPacketSetBufferSize(AdapterObject->pWanAdapter, dim);
		
		TRACE_EXIT("PacketSetBuff");
		return Result;
	}
#endif

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetKernelBuffer(AdapterObject->AirpcapAd, dim);
		
		TRACE_EXIT("PacketSetBuff");
		return Result;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		Result = (BOOLEAN)g_NpfImHandlers.NpfImSetCaptureBufferSize(AdapterObject->NpfImHandle, dim);

		TRACE_EXIT("PacketSetBuff");
		return Result;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
	if(AdapterObject->Flags == INFO_FLAG_DAG_CARD)
	{
		// We can't change DAG buffers
		TRACE_EXIT("PacketSetBuff");
		return TRUE;
	}
#endif // HAVE_DAG_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSETBUFFERSIZE,&dim,sizeof(dim),NULL,0,&BytesReturned,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to set buf size on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
	}
	
	TRACE_EXIT("PacketSetBuff");

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
BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
	DWORD BytesReturned;
	BOOLEAN Result;
	
	TRACE_ENTER("PacketSetBpf");
	
#ifdef HAVE_WANPACKET_API
	if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		Result = WanPacketSetBpfFilter(AdapterObject->pWanAdapter, (PUCHAR)fp->bf_insns, fp->bf_len * sizeof(struct bpf_insn));
		TRACE_EXIT("PacketSetBpf");
		return Result;
	}
#endif

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		Result = (BOOLEAN)g_PAirpcapSetFilter(AdapterObject->AirpcapAd, 
			(char*)fp->bf_insns,
			fp->bf_len * sizeof(struct bpf_insn));

		TRACE_EXIT("PacketSetBpf");
		return Result;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		Result = (BOOLEAN)g_NpfImHandlers.NpfImSetBpfFilter(AdapterObject->NpfImHandle,
			fp->bf_insns,
			fp->bf_len * sizeof(struct bpf_insn));

		TRACE_EXIT("PacketSetBpf");
		return TRUE;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		// Delegate the filtering to higher layers since it's too expensive here
		TRACE_EXIT("PacketSetBpf");
		return TRUE;
	}
#endif // HAVE_DAG_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		Result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,BIOCSETF,(char*)fp->bf_insns,fp->bf_len*sizeof(struct bpf_insn),NULL,0,&BytesReturned,NULL);
	}
	else
	{
		TRACE_PRINT1("Request to set BPF filter on an unknown device type (%u)", AdapterObject->Flags);
		Result = FALSE;
	}
	
	TRACE_EXIT("PacketSetBpf");
		
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
BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	DWORD BytesReturned;
	BOOLEAN result;

	TRACE_ENTER("PacketSetLoopbackBehavior");

	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketSetLoopbackBehavior: not allowed on non-NPF adapters");
	
		TRACE_EXIT("PacketSetLoopbackBehavior");
		
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

	TRACE_EXIT("PacketSetLoopbackBehavior");
		
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
INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{
	INT Result;

	TRACE_ENTER("PacketSetSnapLen");

	UNUSED(snaplen);
	UNUSED(AdapterObject);

#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
		Result = g_p_dagc_setsnaplen(AdapterObject->pDagCard, snaplen);
	else
#endif // HAVE_DAG_API
		Result = 0;

	TRACE_EXIT("PacketSetSnapLen");

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
BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications
	
	TRACE_ENTER("PacketGetStats");

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
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

		TRACE_EXIT("PacketGetStats");
		return Res;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		ULONGLONG stats[7];
		DWORD neededBytes;

		Res = (BOOLEAN)g_NpfImHandlers.NpfImGetCaptureStatistics(AdapterObject->NpfImHandle, stats, sizeof(stats), &neededBytes);

		if (Res)
		{
//			if (stats[NPFIM_CAPTURE_STATS_RECEIVED] < 0xFFFFFFFF)
//				s->bs_capt = (UINT)stats[NPFIM_CAPTURE_STATS_RECEIVED];
//			else
//				s->bs_capt = 0xFFFFFFFF;

			if (stats[NPFIM_CAPTURE_STATS_DROPPED_FILTER] < 0xFFFFFFFF)
				s->bs_drop = (UINT)stats[NPFIM_CAPTURE_STATS_DROPPED_FILTER];
			else
				s->bs_drop = 0xFFFFFFFF;

			if (stats[NPFIM_CAPTURE_STATS_ACCEPTED] < 0xFFFFFFFF)
				s->bs_recv = (UINT)stats[NPFIM_CAPTURE_STATS_ACCEPTED];
			else
				s->bs_recv = 0xFFFFFFFF;
			
			s->ps_ifdrop = 0;
		}

		TRACE_EXIT("PacketGetStats");
		return Res;
	}
#endif // HAVE_AIRPCAP_API


#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		dagc_stats_t DagStats;
		
		// Note: DAG cards are currently very limited from the statistics reporting point of view,
		// so most of the values returned by dagc_stats() are zero at the moment
		if(g_p_dagc_stats(AdapterObject->pDagCard, &DagStats) == 0)
		{
			// XXX: Only copy the dropped packets for now, since the received counter is not supported by
			// DAGS at the moment

			s->bs_recv = (ULONG)DagStats.received;
			s->bs_drop = (ULONG)DagStats.dropped;
			TRACE_EXIT("PacketGetStats");
			return TRUE;
		}
		else
		{
			TRACE_EXIT("PacketGetStats");
			return FALSE;
		}
	}

#endif // HAVE_DAG_API

#ifdef HAVE_WANPACKET_API	
	if ( AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
			Res = WanPacketGetStats(AdapterObject->pWanAdapter, (PVOID)&tmpstat);

			// Copy only the first two values retrieved from the driver
			s->bs_recv = tmpstat.bs_recv;
			s->bs_drop = tmpstat.bs_drop;
		
			TRACE_EXIT("PacketGetStats");
	
			return Res;	
	}

#endif // HAVE_WANPACKET_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
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

	}
	else
	{	
		TRACE_PRINT1("Request to obtain statistics on an unknown device type (%u)", AdapterObject->Flags);
		Res = FALSE;
	}
	TRACE_EXIT("PacketGetStats");
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
BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications

	TRACE_ENTER("PacketGetStatsEx");

#ifdef HAVE_DAG_API
	if(AdapterObject->Flags == INFO_FLAG_DAG_CARD)
	{
		dagc_stats_t DagStats;

		// Note: DAG cards are currently very limited from the statistics reporting point of view,
		// so most of the values returned by dagc_stats() are zero at the moment
		g_p_dagc_stats(AdapterObject->pDagCard, &DagStats);
		s->bs_recv = (ULONG)DagStats.received;
		s->bs_drop = (ULONG)DagStats.dropped;
		s->ps_ifdrop = 0;
		s->bs_capt = (ULONG)DagStats.captured;

		TRACE_EXIT("PacketGetStatsEx");
		return TRUE;

	}
#endif // HAVE_DAG_API

#ifdef HAVE_WANPACKET_API
	if(AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		Res = WanPacketGetStats(AdapterObject->pWanAdapter, (PVOID)&tmpstat);
		TRACE_EXIT("PacketGetStatsEx");
		return Res;
	}
#endif // HAVE_WANPACKET_API

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
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

		TRACE_EXIT("PacketGetStatsEx");
		return Res;
	}
#endif // HAVE_AIRPCAP_API

	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
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
	}
	else
	{	
		TRACE_PRINT1("Request to obtain statistics on an unknown device type (%u)", AdapterObject->Flags);
		Res = FALSE;
	}
	TRACE_EXIT("PacketGetStatsEx");
	return Res;

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
BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData)
{
    DWORD		BytesReturned;
    BOOLEAN		Result;

	TRACE_ENTER("PacketRequest");

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		if (Set)
		{
			TRACE_PRINT("PacketRequest SET not supported on NPFIM devices");
			TRACE_EXIT("PacketRequest");
			return FALSE;
		}

		Result = (BOOLEAN)g_NpfImHandlers.NpfImIssueQueryOid(AdapterObject->NpfImHandle,
			OidData->Oid,
			OidData->Data,
			&OidData->Length);

		TRACE_EXIT("PacketRequest");
		return Result;
	}
#endif

	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		TRACE_PRINT("PacketRequest not supported on non-NPF/NPFIM adapters.");
		TRACE_EXIT("PacketRequest");
		return FALSE;
	}

	Result=(BOOLEAN)DeviceIoControl(AdapterObject->hFile,(DWORD) Set ? (DWORD)BIOCSETOID : (DWORD)BIOCQUERYOID,
                           OidData,sizeof(PACKET_OID_DATA)-1+OidData->Length,OidData,
                           sizeof(PACKET_OID_DATA)-1+OidData->Length,&BytesReturned,NULL);
    
	// output some debug info
	TRACE_PRINT4("PacketRequest, OID=%.08x Length=%.05d Set=%.04d Res=%.04d",
		OidData->Oid,
		OidData->Length,
		Set,
		Result);

	TRACE_EXIT("PacketRequest");
	return Result;
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
BOOLEAN PacketSetHwFilter(LPADAPTER  AdapterObject,ULONG Filter)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;
	
	TRACE_ENTER("PacketSetHwFilter");

#ifdef HAVE_AIRPCAP_API
	if(AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		// Airpcap for the moment is always in promiscuous mode, and ignores any other filters
		return TRUE;
	}
#endif // HAVE_AIRPCAP_API

#ifdef HAVE_NPFIM_API
	if(AdapterObject->Flags == INFO_FLAG_NPFIM_DEVICE)
	{
		return TRUE;
	}
#endif // HAVE_NPFIM_API

#ifdef HAVE_WANPACKET_API
	if(AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
	{
		TRACE_EXIT("PacketSetHwFilter");
		return TRUE;
	}
#endif // HAVE_WANPACKET_API
    
	if (AdapterObject->Flags == INFO_FLAG_NDIS_ADAPTER)
	{
		OidData=GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
		if (OidData == NULL) {
	        TRACE_PRINT("PacketSetHwFilter: GlobalAlloc Failed");
			TRACE_EXIT("PacketSetHwFilter");
	        return FALSE;
		}
		OidData->Oid=OID_GEN_CURRENT_PACKET_FILTER;
		OidData->Length=sizeof(ULONG);
	    *((PULONG)OidData->Data)=Filter;
		Status=PacketRequest(AdapterObject,TRUE,OidData);
		GlobalFreePtr(OidData);
	}
	else
	{
		TRACE_PRINT1("Setting HW filter not supported on this adapter type (%u)", AdapterObject->Flags);
		Status = FALSE;
	}
	
	TRACE_EXIT("PacketSetHwFilter");
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
   of descriptions is the same of the one of names. The fisrt description corresponds to the first name, and
   so on.
  - a double "\0". 
*/

BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 0;
	ULONG	SizeNames = 0;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;

	TRACE_ENTER("PacketGetAdapterNames");

	TRACE_PRINT_OS_INFO();

	TRACE_PRINT2("Packet DLL version %s, Driver version %s", PacketLibraryVersion, PacketDriverVersion);

	TRACE_PRINT1("PacketGetAdapterNames: BufferSize=%u", *BufferSize);


	//
	// Check the presence on some libraries we rely on, and load them if we found them
	//f
	PacketLoadLibrariesDynamically();

	//d
	// Create the adapter information list
	//
	TRACE_PRINT("Populating the adapter list...");

	PacketPopulateAdaptersInfoList();

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);

	if(!g_AdaptersInfoList) 
	{
		ReleaseMutex(g_AdaptersInfoMutex);
		*BufferSize = 0;

		TRACE_PRINT("No adapters found in the system. Failing.");
		
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
 	
 		TRACE_EXIT("PacketGetAdapterNames");
		return FALSE;		// No adapters to return
	}

	// 
	// First scan of the list to calculate the offsets and check the sizes
	//
	for(TAdInfo = g_AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Update the size variables
			SizeNeeded += (ULONG)strlen(TAdInfo->Name) + (ULONG)strlen(TAdInfo->Description) + 2;
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
		}
	}

	// Check that we don't overflow the buffer.
	// Note: 2 is the number of additional separators needed inside the list
	if(SizeNeeded + 2 > *BufferSize || pStr == NULL)
	{
		ReleaseMutex(g_AdaptersInfoMutex);

 		TRACE_PRINT1("PacketGetAdapterNames: input buffer too small, we need %u bytes", *BufferSize);
 
		*BufferSize = SizeNeeded + 2;  // Report the required size

 		TRACE_EXIT("PacketGetAdapterNames");
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	OffDescriptions = SizeNames + 1;

	// 
	// Second scan of the list to copy the information
	//
	for(TAdInfo = g_AdaptersInfoList, SizeNames = 0, SizeDesc = 0; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Copy the data
			StringCchCopyA(
				((PCHAR)pStr) + SizeNames, 
				*BufferSize - SizeNames, 
				TAdInfo->Name);
			StringCchCopyA(
				((PCHAR)pStr) + OffDescriptions + SizeDesc, 
				*BufferSize - OffDescriptions - SizeDesc,
				TAdInfo->Description);

			// Update the size variables
			SizeNames += (ULONG)strlen(TAdInfo->Name) + 1;
			SizeDesc += (ULONG)strlen(TAdInfo->Description) + 1;
		}
	}

	// Separate the two lists
	((PCHAR)pStr)[SizeNames] = 0;

	// End the list with a further \0
	((PCHAR)pStr)[SizeNeeded + 1] = 0;


	ReleaseMutex(g_AdaptersInfoMutex);
	TRACE_EXIT("PacketGetAdapterNames");
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
BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	PADAPTER_INFO TAdInfo;
	PCHAR Tname;
	BOOLEAN Res, FreeBuff;

	TRACE_ENTER("PacketGetNetInfoEx");

	// Provide conversion for backward compatibility
	if(AdapterName[1] != 0)
	{ //ASCII
		Tname = AdapterName;
		FreeBuff = FALSE;
	}
	else
	{
		Tname = WChar2SChar((PWCHAR)AdapterName);
		FreeBuff = TRUE;
	}

	//
	// Update the information about this adapter
	//
	if(!PacketUpdateAdInfo(Tname))
	{
		TRACE_PRINT("PacketGetNetInfoEx. Failed updating the adapter list. Failing.");
		if(FreeBuff)
			GlobalFreePtr(Tname);

		TRACE_EXIT("PacketGetNetInfoEx");
		
		return FALSE;
	}
	
	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(Tname);

	if(TAdInfo != NULL)
	{
		LONG numEntries = 0, i;
		PNPF_IF_ADDRESS_ITEM pCursor;
		TRACE_PRINT("Adapter found.");

		pCursor = TAdInfo->pNetworkAddresses;

		while(pCursor != NULL)
		{
			numEntries ++;
			pCursor = pCursor->Next;
		}

		if (numEntries < *NEntries)
		{
			*NEntries = numEntries;
		}

		pCursor = TAdInfo->pNetworkAddresses;
		for (i = 0; (i < *NEntries) && (pCursor != NULL); i++)
		{
			buffer[i] = pCursor->Addr;
			pCursor = pCursor->Next;
		}

		Res = TRUE;
	}
	else
	{
		TRACE_PRINT("PacketGetNetInfoEx: Adapter not found");
		Res = FALSE;
	}
	
	ReleaseMutex(g_AdaptersInfoMutex);
	
	if(FreeBuff)GlobalFreePtr(Tname);
	
	TRACE_EXIT("PacketGetNetInfoEx");
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
BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
	PADAPTER_INFO TAdInfo;
	BOOLEAN ret;	
	TRACE_ENTER("PacketGetNetType");

	WaitForSingleObject(g_AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(AdapterObject->Name);

	if(TAdInfo != NULL)
	{
		TRACE_PRINT("Adapter found");
		// Copy the data
		memcpy(type, &(TAdInfo->LinkLayer), sizeof(struct NetType));
		ret = TRUE;
	}
	else
	{
		TRACE_PRINT("PacketGetNetType: Adapter not found");
		ret =  FALSE;
	}

	ReleaseMutex(g_AdaptersInfoMutex);

	TRACE_EXIT("PacketGetNetType");
	return ret;
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
PAirpcapHandle PacketGetAirPcapHandle(LPADAPTER AdapterObject)
{
	PAirpcapHandle handle = NULL;
	TRACE_ENTER("PacketGetAirPcapHandle");

#ifdef HAVE_AIRPCAP_API
	if (AdapterObject->Flags == INFO_FLAG_AIRPCAP_CARD)
	{
		handle = AdapterObject->AirpcapAd;
	}
#else
	UNUSED(AdapterObject);
#endif // HAVE_AIRPCAP_API

	TRACE_EXIT("PacketGetAirPcapHandle");
	return handle;
}

/* @} */
