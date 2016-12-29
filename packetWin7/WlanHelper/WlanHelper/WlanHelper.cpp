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
// WlanHelper.cpp : Defines the entry point for the console application.
//

// #include "stdafx.h"

#include "..\..\..\version.h"

#include <stdio.h>
#include <tchar.h>

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wlanapi.h>

#include "Tool.h"

// MAKEINTRESOURCE() returns an LPTSTR, but GetProcAddress()
// expects LPSTR even in UNICODE, so using MAKEINTRESOURCEA()...
#ifdef UNICODE
#define MAKEINTRESOURCEA_T(a, u) MAKEINTRESOURCEA(u)
#else
#define MAKEINTRESOURCEA_T(a, u) MAKEINTRESOURCEA(a)
#endif

BOOL myGUIDFromString(LPCTSTR psz, LPGUID pguid)
{
	BOOL bRet = FALSE;

	typedef BOOL(WINAPI *LPFN_GUIDFromString)(LPCTSTR, LPGUID);
	LPFN_GUIDFromString pGUIDFromString = NULL;

	HINSTANCE hInst = LoadLibrary(TEXT("shell32.dll"));
	if (hInst)
	{
		pGUIDFromString = (LPFN_GUIDFromString)GetProcAddress(hInst, MAKEINTRESOURCEA_T(703, 704));
		if (pGUIDFromString)
			bRet = pGUIDFromString(psz, pguid);
		FreeLibrary(hInst);
	}

	if (!pGUIDFromString)
	{
		hInst = LoadLibrary(TEXT("Shlwapi.dll"));
		if (hInst)
		{
			pGUIDFromString = (LPFN_GUIDFromString)GetProcAddress(hInst, MAKEINTRESOURCEA_T(269, 270));
			if (pGUIDFromString)
				bRet = pGUIDFromString(psz, pguid);
			FreeLibrary(hInst);
		}
	}

	return bRet;
}

#define WLAN_CLIENT_VERSION_VISTA 2

DWORD SetInterface(WLAN_INTF_OPCODE opcode, PVOID* pData, GUID* InterfaceGuid)
{
	DWORD dwResult = 0;
	HANDLE hClient = NULL;
	DWORD dwCurVersion = 0;
	DWORD outsize = 0;

	// Open Handle for the set operation
	dwResult = WlanOpenHandle(WLAN_CLIENT_VERSION_VISTA, NULL, &dwCurVersion, &hClient);
	dwResult = WlanSetInterface(hClient, InterfaceGuid, opcode, sizeof(ULONG), pData, NULL);
	WlanCloseHandle(hClient, NULL);

	return dwResult;
}

DWORD GetInterface(WLAN_INTF_OPCODE opcode, PVOID* pData, GUID* InterfaceGuid)
{
	DWORD dwResult = 0;
	HANDLE hClient = NULL;
	DWORD dwCurVersion = 0;
	DWORD outsize = 0;
	WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;

	// Open Handle for the set operation
	dwResult = WlanOpenHandle(WLAN_CLIENT_VERSION_VISTA, NULL, &dwCurVersion, &hClient);
	dwResult = WlanQueryInterface(hClient, InterfaceGuid, opcode, NULL, &outsize, pData, &opCode);
	WlanCloseHandle(hClient, NULL);

	return dwResult;
}

// enumerate wireless interfaces
UINT EnumInterface(HANDLE hClient, WLAN_INTERFACE_INFO sInfo[64])
{
	DWORD dwError = ERROR_SUCCESS;
	PWLAN_INTERFACE_INFO_LIST pIntfList = NULL;
	UINT i = 0;

	__try
	{
		// enumerate wireless interfaces
		if ((dwError = WlanEnumInterfaces(
			hClient,
			NULL,               // reserved
			&pIntfList
			)) != ERROR_SUCCESS)
		{
			__leave;
		}

		// print out interface information
		for (i = 0; i < pIntfList->dwNumberOfItems; i++)
		{
			memcpy(&sInfo[i], &pIntfList->InterfaceInfo[i], sizeof(WLAN_INTERFACE_INFO));
		}

		return pIntfList->dwNumberOfItems;
	}
	__finally
	{
		// clean up
		if (pIntfList != NULL)
		{
			WlanFreeMemory(pIntfList);
		}
	}
	return 0;
}

// open a WLAN client handle and check version
DWORD
OpenHandleAndCheckVersion(
PHANDLE phClient
)
{
	DWORD dwError = ERROR_SUCCESS;
	DWORD dwServiceVersion;
	HANDLE hClient = NULL;

	__try
	{
		*phClient = NULL;

		// open a handle to the service
		if ((dwError = WlanOpenHandle(
			WLAN_API_VERSION,
			NULL,               // reserved
			&dwServiceVersion,
			&hClient
			)) != ERROR_SUCCESS)
		{
			__leave;
		}

		// check service version
		if (WLAN_API_VERSION_MAJOR(dwServiceVersion) < WLAN_API_VERSION_MAJOR(WLAN_API_VERSION_2_0))
		{
			// No-op, because the version check is for demonstration purpose only.
			// You can add your own logic here.
		}

		*phClient = hClient;

		// set hClient to NULL so it will not be closed
		hClient = NULL;
	}
	__finally
	{
		if (hClient != NULL)
		{
			// clean up
			WlanCloseHandle(
				hClient,
				NULL            // reserved
				);
		}
	}

	return dwError;
}

// get interface state string
LPTSTR
GetInterfaceStateString(__in WLAN_INTERFACE_STATE wlanInterfaceState)
{
	LPTSTR strRetCode;

	switch (wlanInterfaceState)
	{
	case wlan_interface_state_not_ready:
		strRetCode = _T("\"not ready\"");
		break;
	case wlan_interface_state_connected:
		strRetCode = _T("\"connected\"");
		break;
	case wlan_interface_state_ad_hoc_network_formed:
		strRetCode = _T("\"ad hoc network formed\"");
		break;
	case wlan_interface_state_disconnecting:
		strRetCode = _T("\"disconnecting\"");
		break;
	case wlan_interface_state_disconnected:
		strRetCode = _T("\"disconnected\"");
		break;
	case wlan_interface_state_associating:
		strRetCode = _T("\"associating\"");
		break;
	case wlan_interface_state_discovering:
		strRetCode = _T("\"discovering\"");
		break;
	case wlan_interface_state_authenticating:
		strRetCode = _T("\"authenticating\"");
		break;
	default:
		strRetCode = _T("\"invalid interface state\"");
	}

	return strRetCode;
}

// get interface operation mode string
LPTSTR
GetInterfaceOperationModeString(__in ULONG wlanInterfaceOperationMode)
{
	LPTSTR strRetCode;

	switch (wlanInterfaceOperationMode)
	{
	case DOT11_OPERATION_MODE_EXTENSIBLE_STATION:
		strRetCode = _T("\"Extensible Station (ExtSTA)\"");
		break;
	case DOT11_OPERATION_MODE_NETWORK_MONITOR:
		strRetCode = _T("\"Network Monitor (NetMon)\"");
		break;
	case DOT11_OPERATION_MODE_EXTENSIBLE_AP:
		strRetCode = _T("\"Extensible Access Point (ExtAP)\"");
		break;
	default:
		strRetCode = _T("\"invalid interface operation mode\"");
	}

	return strRetCode;
}

int MainInteractive()
{
	HANDLE hClient = NULL;
	WLAN_INTERFACE_INFO sInfo[64];
	RPC_TSTR strGuid = NULL;

	TCHAR szBuffer[256];
	DWORD dwRead;
	if (OpenHandleAndCheckVersion(&hClient) != ERROR_SUCCESS)
	{
		_tsystem(_T("PAUSE"));
		return -1;
	}

	UINT nCount = EnumInterface(hClient, sInfo);
	for (UINT i = 0; i < nCount; ++i)
	{
		if (UuidToString(&sInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
		{
			ULONG ulOperationMode = -1;
			PULONG pOperationMode;
			DWORD dwResult = GetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&pOperationMode, &sInfo[i].InterfaceGuid);
			if (dwResult != ERROR_SUCCESS)
			{
				_tprintf(_T("GetInterface error, error code = %d\n"), dwResult);
				_tsystem(_T("PAUSE"));
			}
			else
			{
				ulOperationMode = *pOperationMode;
				WlanFreeMemory(pOperationMode);
			}

			_tprintf(_T("%d. %s\n\tName: %s\n\tDescription: %s\n\tState: %s\n\tOperation Mode: %s\n"),
				i,
				strGuid,
				getAdapterNameFromGuid((TCHAR*) strGuid).c_str(),
				sInfo[i].strInterfaceDescription,
				GetInterfaceStateString(sInfo[i].isState),
				GetInterfaceOperationModeString(ulOperationMode));

			RpcStringFree(&strGuid);
		}
	}

	UINT nChoice = 0;
	GUID ChoiceGUID;
	LPGUID pChoiceGUID = NULL;
	_tprintf(_T("Enter the choice (0, 1,..) of the wireless card you want to operate on:\n"));

	if (ReadConsole(GetStdHandle(STD_INPUT_HANDLE), szBuffer, _countof(szBuffer), &dwRead, NULL) == FALSE)
	{
		_putts(_T("Error input."));
		_tsystem(_T("PAUSE"));
		return -1;
	}
	szBuffer[dwRead] = 0;

	// TCHAR *aaa = _T("42dfd47a-2764-43ac-b58e-3df569c447da");
	// dwRead = sizeof(aaa);

	TCHAR buf[256];
	_stprintf_s(buf, 256, _T("{%s}"), szBuffer);

	if (dwRead > 32)
	{
		if (myGUIDFromString(buf, &ChoiceGUID) != TRUE)
		{
			_tprintf(_T("UuidFromString error, error code = %d\n"), -1);
			_tsystem(_T("PAUSE"));
		}
		else
		{
			pChoiceGUID = &ChoiceGUID;
		}
	}
	else
	{
		nChoice = _ttoi(szBuffer);

		if (nChoice > nCount)
		{
			_putts(_T("No such index."));
			_tsystem(_T("PAUSE"));
			return -1;
		}

		pChoiceGUID = &sInfo[nChoice].InterfaceGuid;
	}

	UINT nSTate = 0;
	ULONG ulOperationMode = -1;
	_tprintf(_T("Enter the operation mode (0, 1 or 2) you want to switch to for the chosen wireless card:\n"));
	_tprintf(_T("0: Extensible Station (ExtSTA)\n1: Network Monitor (NetMon)\n2: Extensible Access Point (ExtAP)\n"));

	if (ReadConsole(GetStdHandle(STD_INPUT_HANDLE), szBuffer, _countof(szBuffer), &dwRead, NULL) == FALSE)
	{
		_putts(_T("Error input."));
		_tsystem(_T("PAUSE"));
		return -1;
	}
	szBuffer[dwRead] = 0;
	nSTate = _ttoi(szBuffer);

	if (nSTate != 0 && nSTate != 1 && nSTate != 2)
	{
		_putts(_T("Only 0, 1 and 2 are valid inputs."));
		_tsystem(_T("PAUSE"));
		return -1;
	}
	if (nSTate == 0)
	{
		ulOperationMode = DOT11_OPERATION_MODE_EXTENSIBLE_STATION;
	}
	else if (nSTate == 1)
	{
		ulOperationMode = DOT11_OPERATION_MODE_NETWORK_MONITOR;
	}
	else // nSTate == 2
	{
		ulOperationMode = DOT11_OPERATION_MODE_EXTENSIBLE_AP;
	}

	DWORD dwResult = SetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&ulOperationMode, pChoiceGUID);
	if (dwResult != ERROR_SUCCESS)
	{
		_tprintf(_T("SetInterface error, error code = %d\n"), dwResult);
		_tsystem(_T("PAUSE"));
	}
	else
	{
		_tprintf(_T("SetInterface success!\n"));
	}

	return 0;
}

tstring getGuidFromAdapterName_Wrapper(tstring strGUID)
{
	if (_tcslen(strGUID.c_str()) == _tcslen(_T("42dfd47a-2764-43ac-b58e-3df569c447da")) && strGUID[8] == _T('-') && strGUID[13] == _T('-') && strGUID[18] == _T('-') && strGUID[23] == _T('-'))
	{
		return strGUID;
	}
	else
	{
		return getGuidFromAdapterName(strGUID);
	}
}

BOOL GetWlanOperationMode(tstring strGUID, tstring &strMode)
{
	strGUID = _T("{") + strGUID + _T("}");

	GUID ChoiceGUID;
	if (myGUIDFromString(strGUID.c_str(), &ChoiceGUID) != TRUE)
	{
		_tprintf(_T("Error: GetWlanOperationMode::myGUIDFromString error\n"));
		return FALSE;
	}

	ULONG ulOperationMode = -1;
	PULONG pOperationMode;
	DWORD dwResult = GetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&pOperationMode, &ChoiceGUID);
	if (dwResult != ERROR_SUCCESS)
	{
		LPTSTR strErrorText = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, dwResult, 0, (PTSTR)&strErrorText, 0, NULL);
		if (strErrorText[_tcslen(strErrorText) - 2] == _T('\r') && strErrorText[_tcslen(strErrorText) - 1] == _T('\n'))
		{
			strErrorText[_tcslen(strErrorText) - 2] = 0x0;
			strErrorText[_tcslen(strErrorText) - 1] = 0x0;
		}

		_tprintf(_T("Error: GetWlanOperationMode::GetInterface error, error code = %d (%s)\n"), dwResult, strErrorText);
		return FALSE;
	}
	else
	{
		ulOperationMode = *pOperationMode;
		WlanFreeMemory(pOperationMode);
	}

	strMode = OperationMode2String(ulOperationMode);
	
	return TRUE;
}

BOOL SetWlanOperationMode(tstring strGUID, tstring strMode)
{
	strGUID = _T("{") + strGUID + _T("}");

	GUID ChoiceGUID;
	if (myGUIDFromString(strGUID.c_str(), &ChoiceGUID) != TRUE)
	{
		_tprintf(_T("Error: SetWlanOperationMode::myGUIDFromString error\n"));
		return FALSE;
	}

	ULONG ulOperationMode = String2OperationMode(strMode);
	if (ulOperationMode == DOT11_OPERATION_MODE_UNKNOWN)
	{
		_tprintf(_T("Error: SetWlanOperationMode::String2OperationMode error, unknown mode: %s\n"), strMode.c_str());
		return FALSE;
	}

	DWORD dwResult = SetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&ulOperationMode, &ChoiceGUID);
	if (dwResult != ERROR_SUCCESS)
	{
		LPTSTR strErrorText = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, dwResult, 0, (PTSTR)&strErrorText, 0, NULL);
		if (strErrorText[_tcslen(strErrorText) - 2] == _T('\r') && strErrorText[_tcslen(strErrorText) - 1] == _T('\n'))
		{
			strErrorText[_tcslen(strErrorText) - 2] = 0x0;
			strErrorText[_tcslen(strErrorText) - 1] = 0x0;
		}

		_tprintf(_T("Error: SetWlanOperationMode::SetInterface error, error code = %d (%s)\n"), dwResult, strErrorText);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

#define STR_COMMAND_USAGE \
_T("WlanHelper for Npcap ") _T(WINPCAP_VER_STRING) _T(" ( http://npcap.org )\n")\
_T("Usage: WlanHelper [Commands]\n")\
_T("   or: WlanHelper {Interface Name or GUID} [Options]\n")\
_T("\n")\
_T("OPTIONS:\n")\
_T("  mode\t\t\t\t\t: Get interface operation mode\n")\
_T("  mode <managed|monitor|master|..>\t: Set interface operation mode\n")\
_T("  modes\t\t\t\t\t: Get all operation modes supported by the interface, comma-separated\n")\
_T("  channel\t\t\t\t: Get interface channel\n")\
_T("  channel <1-14>\t\t\t: Set interface channel (only works in monitor mode)\n")\
_T("  freq\t\t\t\t\t: Get interface frequency\n")\
_T("  freq <VALUE>\t\t\t\t: Set interface frequency (only works in monitor mode)\n")\
_T("  modu\t\t\t\t\t: Get interface modulation\n")\
_T("  modu <dsss|fhss|irbaseband|ofdm|hrdsss|erp|ht|vht|ihv (VALUE)|..>\t: Set interface modulation\n")\
_T("  modus\t\t\t\t\t: Get all modulations supported by the interface, comma-separated\n")\
_T("\n")\
_T("COMMANDS:\n")\
_T("  -i\t\t\t\t\t: Enter the interactive mode\n")\
_T("  -h\t\t\t\t\t: Print this help summary page\n")\
_T("\n")\
_T("OPERATION MODES:\n")\
_T("  managed\t: The Extensible Station (ExtSTA) operation mode\n")\
_T("  monitor\t: The Network Monitor (NetMon) operation mode\n")\
_T("  master\t: The Extensible Access Point (ExtAP) operation mode (supported from Windows 7 and later)\n")\
_T("  wfd_device\t: The Wi-Fi Direct Device operation mode (supported from Windows 8 and later)\n")\
_T("  wfd_owner\t: The Wi-Fi Direct Group Owner operation mode (supported from Windows 8 and later)\n")\
_T("  wfd_client\t: The Wi-Fi Direct Client operation mode (supported from Windows 8 and later)\n")\
_T("\n")\
_T("802.11 MODULATIONS (https://en.wikipedia.org/wiki/IEEE_802.11):\n")\
_T("  802.11-1997\t: dsss, fhss\n")\
_T("  802.11a\t: ofdm\n")\
_T("  802.11b\t: dsss\n")\
_T("  802.11g\t: ofdm\n")\
_T("  802.11n\t: mimo-ofdm\n")\
_T("  802.11ac\t: mimo-ofdm\n")\
_T("\n")\
_T("EXAMPLES:\n")\
_T("  WlanHelper Wi-Fi mode\n")\
_T("  WlanHelper 42dfd47a-2764-43ac-b58e-3df569c447da channel 11\n")\
_T("  WlanHelper 42dfd47a-2764-43ac-b58e-3df569c447da freq 2\n")\
_T("  WlanHelper \"Wireless Network Connection\" mode monitor\n")\
_T("\n")\
_T("SEE THE MAN PAGE (https://github.com/nmap/npcap) FOR MORE OPTIONS AND EXAMPLES\n")

#define STR_INVALID_PARAMETER _T("Error: invalid parameter, type in \"WlanHelper -h\" for help.\n")

int _tmain(int argc, _TCHAR* argv[])
{
	SetConsoleTitle(_T("WlanHelper for Npcap ") _T(WINPCAP_VER_STRING) _T(" (http://npcap.org)"));
	vector<tstring> strArgs;
	for (int i = 0; i < argc; i++)
	{
		strArgs.push_back(argv[i]);
	}
	
	if (argc == 1)
	{
		_tprintf(STR_COMMAND_USAGE);
		return -1;
	}
	else if (argc == 2)
	{
		if (strArgs[1] ==_T("-h") || strArgs[1] == _T("--help"))
		{
			_tprintf(STR_COMMAND_USAGE);
			return -1;
		}
		else if (strArgs[1] == _T("-i"))
		{
			_tprintf(_T("WlanHelper [Interactive Mode]:\n****************************************************\n"));
			return MainInteractive();
		}
		else
		{
			_tprintf(STR_INVALID_PARAMETER);
			return -1;
		}
	}
	else if (argc == 3)
	{
		if (strArgs[2] == _T("mode"))
		{
			tstring strMode;
			if (GetCurrentOperationMode(getGuidFromAdapterName_Wrapper(strArgs[1]), strMode))
			{
				_tprintf(_T("%s\n"), strMode.c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modes"))
		{
			tstring strModes;
			if (GetOperationModeCapability(getGuidFromAdapterName_Wrapper(strArgs[1]), strModes))
			{
				_tprintf(_T("%s\n"), strModes.c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modes-monitor"))
		{
			tstring strModes;
			if (IsMonitorModeSupported(getGuidFromAdapterName_Wrapper(strArgs[1])))
			{
				_tprintf(_T("%d\n"), TRUE);
				return 0;
			}
			else
			{
				_tprintf(_T("%d\n"), FALSE);
				return 0;
			}
		}
		else if (strArgs[2] == _T("channel"))
		{
			ULONG ulChannel;
			if (GetCurrentChannel(getGuidFromAdapterName_Wrapper(strArgs[1]), ulChannel))
			{
				_tprintf(_T("%u\n"), ulChannel);
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("freq"))
		{
			ULONG ulFrequency;
			if (GetCurrentFrequency(getGuidFromAdapterName_Wrapper(strArgs[1]), ulFrequency))
			{
				_tprintf(_T("%u\n"), ulFrequency);
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modus"))
		{
			vector<tstring> nstrPhyTypes;
			if (GetSupportedPhyTypes(getGuidFromAdapterName_Wrapper(strArgs[1]), nstrPhyTypes))
			{
				_tprintf(_T("%s\n"), printArray(nstrPhyTypes).c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modus2"))
		{
			vector<tstring> nstrPhyList;
			if (GetDesiredPhyList(getGuidFromAdapterName_Wrapper(strArgs[1]), nstrPhyList))
			{
				_tprintf(_T("%s\n"), printArray(nstrPhyList).c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modu"))
		{
			tstring ulPhyID;
			if (GetCurrentPhyID(getGuidFromAdapterName_Wrapper(strArgs[1]), ulPhyID))
			{
				_tprintf(_T("%s\n"), ulPhyID.c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else
		{
			_tprintf(STR_INVALID_PARAMETER);
			return -1;
		}
	}
	else if (argc == 4)
	{
		if (strArgs[2] == _T("mode"))
		{
			if (SetWlanOperationMode(getGuidFromAdapterName_Wrapper(strArgs[1]), strArgs[3]))
			{
				_tprintf(_T("Success\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("channel"))
		{
			int ulChannel = _ttoi(strArgs[3].c_str());
			if (SetCurrentChannel(getGuidFromAdapterName_Wrapper(strArgs[1]), ulChannel))
			{
				_tprintf(_T("Success\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("freq"))
		{
			int ulFrequency = _ttoi(strArgs[3].c_str());
			if (SetCurrentFrequency(getGuidFromAdapterName_Wrapper(strArgs[1]), ulFrequency))
			{
				_tprintf(_T("Success\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else if (strArgs[2] == _T("modu"))
		{
			if (SetCurrentPhyID(getGuidFromAdapterName_Wrapper(strArgs[1]), strArgs[3]))
			{
				_tprintf(_T("Success\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Failure\n"));
				return -1;
			}
		}
		else
		{
			_tprintf(STR_INVALID_PARAMETER);
			return -1;
		}
	}
	else
	{
		_tprintf(_T("Error: too many parameters.\n"));
		return -1;
	}

	return 0;
}

