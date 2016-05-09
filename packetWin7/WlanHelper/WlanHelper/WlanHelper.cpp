// WlanHelper.cpp : Defines the entry point for the console application.
//

// #include "stdafx.h"
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
LPWSTR
GetInterfaceStateString(__in WLAN_INTERFACE_STATE wlanInterfaceState)
{
	LPWSTR strRetCode;

	switch (wlanInterfaceState)
	{
	case wlan_interface_state_not_ready:
		strRetCode = L"\"not ready\"";
		break;
	case wlan_interface_state_connected:
		strRetCode = L"\"connected\"";
		break;
	case wlan_interface_state_ad_hoc_network_formed:
		strRetCode = L"\"ad hoc network formed\"";
		break;
	case wlan_interface_state_disconnecting:
		strRetCode = L"\"disconnecting\"";
		break;
	case wlan_interface_state_disconnected:
		strRetCode = L"\"disconnected\"";
		break;
	case wlan_interface_state_associating:
		strRetCode = L"\"associating\"";
		break;
	case wlan_interface_state_discovering:
		strRetCode = L"\"discovering\"";
		break;
	case wlan_interface_state_authenticating:
		strRetCode = L"\"authenticating\"";
		break;
	default:
		strRetCode = L"\"invalid interface state\"";
	}

	return strRetCode;
}

// get interface operation mode string
LPWSTR
GetInterfaceOperationModeString(__in ULONG wlanInterfaceOperationMode)
{
	LPWSTR strRetCode;

	switch (wlanInterfaceOperationMode)
	{
	case DOT11_OPERATION_MODE_EXTENSIBLE_STATION:
		strRetCode = L"\"Extensible Station (ExtSTA)\"";
		break;
	case DOT11_OPERATION_MODE_NETWORK_MONITOR:
		strRetCode = L"\"Network Monitor (NetMon)\"";
		break;
	case DOT11_OPERATION_MODE_EXTENSIBLE_AP:
		strRetCode = L"\"Extensible Access Point (ExtAP)\"";
		break;
	default:
		strRetCode = L"\"invalid interface operation mode\"";
	}

	return strRetCode;
}

int MainInteractive()
{
	HANDLE hClient = NULL;
	WLAN_INTERFACE_INFO sInfo[64];
	RPC_CSTR strGuid = NULL;

	TCHAR szBuffer[256];
	DWORD dwRead;
	if (OpenHandleAndCheckVersion(&hClient) != ERROR_SUCCESS)
	{
		system("PAUSE");
		return -1;
	}

	UINT nCount = EnumInterface(hClient, sInfo);
	for (UINT i = 0; i < nCount; ++i)
	{
		if (UuidToStringA(&sInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
		{
			ULONG ulOperationMode = -1;
			PULONG pOperationMode;
			DWORD dwResult = GetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&pOperationMode, &sInfo[i].InterfaceGuid);
			if (dwResult != ERROR_SUCCESS)
			{
				printf("GetInterface error, error code = %d\n", dwResult);
				system("PAUSE");
			}
			else
			{
				ulOperationMode = *pOperationMode;
				WlanFreeMemory(pOperationMode);
			}

			printf(("%d. %s\n\tDescription: %S\n\tState: %S\n\tOperation Mode: %S\n"),
				i,
				strGuid,
				sInfo[i].strInterfaceDescription,
				GetInterfaceStateString(sInfo[i].isState),
				GetInterfaceOperationModeString(ulOperationMode));

			RpcStringFreeA(&strGuid);
		}
	}

	UINT nChoice = 0;
	GUID ChoiceGUID;
	LPGUID pChoiceGUID = NULL;
	printf("Enter the choice (0, 1,..) of the wireless card you want to operate on:\n");

	if (ReadConsole(GetStdHandle(STD_INPUT_HANDLE), szBuffer, _countof(szBuffer), &dwRead, NULL) == FALSE)
	{
		puts("Error input.");
		system("PAUSE");
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
			printf("UuidFromString error, error code = %d\n", -1);
			system("PAUSE");
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
			puts("No such index.");
			system("PAUSE");
			return -1;
		}

		pChoiceGUID = &sInfo[nChoice].InterfaceGuid;
	}

	UINT nSTate = 0;
	ULONG ulOperationMode = -1;
	printf("Enter the operation mode (0, 1 or 2) you want to switch to for the chosen wireless card:\n");
	printf("0: Extensible Station (ExtSTA)\n1: Network Monitor (NetMon)\n2: Extensible Access Point (ExtAP)\n");

	if (ReadConsole(GetStdHandle(STD_INPUT_HANDLE), szBuffer, _countof(szBuffer), &dwRead, NULL) == FALSE)
	{
		puts("Error input.");
		system("PAUSE");
		return -1;
	}
	szBuffer[dwRead] = 0;
	nSTate = _ttoi(szBuffer);

	if (nSTate != 0 && nSTate != 1 && nSTate != 2)
	{
		puts("Only 0, 1 and 2 are valid inputs.");
		system("PAUSE");
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
		printf("SetInterface error, error code = %d\n", dwResult);
		system("PAUSE");
	}
	else
	{
		printf("SetInterface success!\n");
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
		_tprintf(_T("Error: UuidFromString error, error code = %d\n"), -1);
		return FALSE;
	}

	ULONG ulOperationMode = -1;
	PULONG pOperationMode;
	DWORD dwResult = GetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&pOperationMode, &ChoiceGUID);
	if (dwResult != ERROR_SUCCESS)
	{
		_tprintf(_T("Error: GetInterface error, error code = %d\n"), dwResult);
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
		_tprintf(_T("Error: UuidFromString error, error code = %d\n"), -1);
		return FALSE;
	}

	ULONG ulOperationMode = String2OperationMode(strMode);
	if (ulOperationMode == DOT11_OPERATION_MODE_UNKNOWN)
	{
		_tprintf(_T("Error: SetWlanOperationMode error, unknown mode: %s\n"), strMode);
		return FALSE;
	}

	DWORD dwResult = SetInterface(wlan_intf_opcode_current_operation_mode, (PVOID*)&ulOperationMode, &ChoiceGUID);
	if (dwResult != ERROR_SUCCESS)
	{
		_tprintf(_T("Error: SetInterface error, error code = %d\n"), dwResult);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

#define STR_COMMAND_USAGE _T("\
WlanHelper for Npcap 0.07 (http://npcap.org)\n\
Usage: WlanHelper {Interface Name or GUID} [Options]\n\
Options:\n\
  mode: get interface mode\n\
  mode <managed|monitor|master|wfd_device|wfd_owner|wfd_client>: set interface mode\n\
  channel: get interface channel\n\
  channel <1-11>: set interface channel (only works at monitor mode)\n\
  freq: get interface frequency\n\
  freq <0-200>: set interface frequency (only works at monitor mode)\n\
\n\
Operation Modes:\n\
  managed - the Extensible Station (ExtSTA) operation mode\n\
  monitor - the Network Monitor (NetMon) operation mode\n\
  master - the Extensible Access Point (ExtAP) operation mode (supported for Windows 7 and later)\n\
  wfd_device - the Wi-Fi Direct Device operation mode (supported for Windows 8 and later)\n\
  wfd_owner - the Wi-Fi Direct Group Owner operation mode (supported for Windows 8 and later)\n\
  wfd_client - the Wi-Fi Direct Client operation mode (supported for Windows 8 and later)\n\
")
#define STR_INVALID_PARAMETER _T("Error: invalid parameter, type in \"WlanHelper -h\" for help.\n")

int _tmain(int argc, _TCHAR* argv[])
{
	SetConsoleTitle(_T("WlanHelper Tool for Npcap [www.npcap.org]"));
	vector<tstring> strArgs;
	for (int i = 0; i < argc; i++)
	{
		strArgs.push_back(argv[i]);
	}
	
	if (argc == 1)
	{
		_tprintf(_T("WlanHelper [Interactive Mode]:\n****************************************************\n"));
		return MainInteractive();
	}
	else if (argc == 2)
	{
		if (strArgs[1] ==_T("-h"))
		{
			_tprintf(STR_COMMAND_USAGE);
			return -1;
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
				_tprintf("%s\n", strMode.c_str());
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
			ULONG ulChannel;
			if (GetCurrentChannel(getGuidFromAdapterName_Wrapper(strArgs[1]), ulChannel))
			{
				_tprintf("%u\n", ulChannel);
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
				_tprintf("%u\n", ulFrequency);
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
			if (SetCurrentOperationMode(getGuidFromAdapterName_Wrapper(strArgs[1]), strArgs[3]))
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
			int ulChannel = atoi(strArgs[3].c_str());
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
			int ulFrequency = atoi(strArgs[3].c_str());
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

