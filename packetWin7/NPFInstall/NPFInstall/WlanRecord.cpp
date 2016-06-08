// WlanRecord.cpp
//

#include <stdio.h>
#include <tchar.h>

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wlanapi.h>
#include "WlanRecord.h"
#include "RegUtil.h"


HINSTANCE hinstLib = NULL;
typedef DWORD
(WINAPI *MY_WLANOPENHANDLE)(
_In_ DWORD dwClientVersion,
_Reserved_ PVOID pReserved,
_Out_ PDWORD pdwNegotiatedVersion,
_Out_ PHANDLE phClientHandle
);

typedef DWORD
(WINAPI *MY_WLANCLOSEHANDLE)(
_In_ HANDLE hClientHandle,
_Reserved_ PVOID pReserved
);

typedef DWORD
(WINAPI *MY_WLANENUMINTERFACES)(
_In_ HANDLE hClientHandle,
_Reserved_ PVOID pReserved,
_Outptr_ PWLAN_INTERFACE_INFO_LIST *ppInterfaceList
);

typedef VOID
(WINAPI *MY_WLANFREEMEMORY)(
_In_ PVOID pMemory
);

MY_WLANOPENHANDLE My_WlanOpenHandle = NULL;
MY_WLANCLOSEHANDLE My_WlanCloseHandle = NULL;
MY_WLANENUMINTERFACES My_WlanEnumInterfaces = NULL;
MY_WLANFREEMEMORY My_WlanFreeMemory = NULL;

BOOL initWlanFunctions()
{
	BOOL bRet;

	// Get a handle to the packet DLL module.
	hinstLib = LoadLibrary(TEXT("wlanapi.dll"));

	// If the handle is valid, try to get the function address.  
	if (hinstLib != NULL)
	{
		My_WlanOpenHandle = (MY_WLANOPENHANDLE)GetProcAddress(hinstLib, "WlanOpenHandle");
		My_WlanCloseHandle = (MY_WLANCLOSEHANDLE)GetProcAddress(hinstLib, "WlanCloseHandle");
		My_WlanEnumInterfaces = (MY_WLANENUMINTERFACES)GetProcAddress(hinstLib, "WlanEnumInterfaces");
		My_WlanFreeMemory = (MY_WLANFREEMEMORY)GetProcAddress(hinstLib, "WlanFreeMemory");
		// If the function address is valid, call the function.  

		if (My_WlanOpenHandle != NULL &&
			My_WlanCloseHandle != NULL &&
			My_WlanEnumInterfaces != NULL &&
			My_WlanFreeMemory != NULL)
		{
			bRet = TRUE;
		}
		else
		{
			bRet = FALSE;
		}


	}
	else
	{
		bRet = FALSE;
	}

	return bRet;
}

tstring printArray(vector<tstring> nstr)
{
	tstring strResult;
	for (size_t i = 0; i < nstr.size(); i++)
	{
		if (i != 0)
		{
			strResult += _T(", ");
		}
		strResult += nstr[i];
	}
	return strResult;
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
		if ((dwError = My_WlanEnumInterfaces(
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
			My_WlanFreeMemory(pIntfList);
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
		if ((dwError = My_WlanOpenHandle(
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
			My_WlanCloseHandle(
				hClient,
				NULL            // reserved
				);
		}
	}

	return dwError;
}

vector<tstring> getWlanAdapterGuids()
{
	HANDLE hClient = NULL;
	WLAN_INTERFACE_INFO sInfo[64];
	RPC_TSTR strGuid = NULL;
	vector<tstring> nstrWlanAdapterGuids;

	if (!initWlanFunctions())
	{
		_tprintf(_T("getWlanAdapterGuids::initWlanFunctions error.\n"));
		return nstrWlanAdapterGuids;
	}

	if (OpenHandleAndCheckVersion(&hClient) != ERROR_SUCCESS)
	{
		_tprintf(_T("getWlanAdapterGuids::OpenHandleAndCheckVersion error.\n"));
		return nstrWlanAdapterGuids;
	}

	UINT nCount = EnumInterface(hClient, sInfo);
	for (UINT i = 0; i < nCount; ++i)
	{
		if (UuidToString(&sInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
		{
			nstrWlanAdapterGuids.push_back((TCHAR*) strGuid);
			RpcStringFree(&strGuid);
		}
	}

	return nstrWlanAdapterGuids;
}

BOOL AddFlagToRegistry_Dot11Adapters(LPCTSTR strDeviceName)
{
	return WriteStrToRegistry(NPCAP_SERVICE_REG_KEY_NAME, NPCAP_REG_DOT11_VALUE_NAME, strDeviceName, KEY_WRITE);
}

BOOL writeWlanAdapterGuidsToRegistry()
{
	vector<tstring> nstrWlanAdapterGuids = getWlanAdapterGuids();
	if (nstrWlanAdapterGuids.size() == 0)
	{
		return FALSE;
	}

	for (size_t i = 0; i < nstrWlanAdapterGuids.size(); i++)
	{
		nstrWlanAdapterGuids[i] = _T("\\Device\\{") + nstrWlanAdapterGuids[i] + _T("}");
	}

	tstring strGuidText = printAdapterNames(nstrWlanAdapterGuids);
	return AddFlagToRegistry_Dot11Adapters(strGuidText.c_str());

}