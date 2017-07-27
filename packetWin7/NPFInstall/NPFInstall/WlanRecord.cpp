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

#include "debug.h"

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

	TRACE_ENTER();

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
			TRACE_PRINT1("GetProcAddress: error, errCode = 0x%08x.", GetLastError());
			bRet = FALSE;
		}
	}
	else
	{
		TRACE_PRINT1("LoadLibrary: error, errCode = 0x%08x.", GetLastError());
		bRet = FALSE;
	}

	TRACE_EXIT();
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
	TRACE_ENTER();

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
			TRACE_PRINT1("My_WlanEnumInterfaces: error, errCode = 0x%08x.", dwError);
			__leave;
		}

		// print out interface information
		for (i = 0; i < pIntfList->dwNumberOfItems; i++)
		{
			memcpy(&sInfo[i], &pIntfList->InterfaceInfo[i], sizeof(WLAN_INTERFACE_INFO));
		}

		TRACE_PRINT1("My_WlanEnumInterfaces: pIntfList->dwNumberOfItems = %d.", pIntfList->dwNumberOfItems);
		TRACE_EXIT();
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

	TRACE_PRINT1("My_WlanEnumInterfaces: pIntfList->dwNumberOfItems = %d.", pIntfList->dwNumberOfItems);
	TRACE_EXIT();
	return 0;
}

// open a WLAN client handle and check version
DWORD
OpenHandleAndCheckVersion(
PHANDLE phClient
)
{
	TRACE_ENTER();

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
			TRACE_PRINT1("My_WlanOpenHandle: error, errCode = 0x%08x.", dwError);
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

	TRACE_EXIT();
	return dwError;
}

vector<tstring> getWlanAdapterGuids()
{
	TRACE_ENTER();

	HANDLE hClient = NULL;
	WLAN_INTERFACE_INFO sInfo[64];
	RPC_TSTR strGuid = NULL;
	vector<tstring> nstrWlanAdapterGuids;

	if (!initWlanFunctions())
	{
		TRACE_PRINT("initWlanFunctions: error.");
		TRACE_EXIT();
		return nstrWlanAdapterGuids;
	}

	if (OpenHandleAndCheckVersion(&hClient) != ERROR_SUCCESS)
	{
		TRACE_PRINT("OpenHandleAndCheckVersion: error.");
		TRACE_EXIT();
		return nstrWlanAdapterGuids;
	}

	UINT nCount = EnumInterface(hClient, sInfo);
	for (UINT i = 0; i < nCount; ++i)
	{
		if (UuidToString(&sInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
		{
			TRACE_PRINT1("EnumInterface: executing, strGuid = %s.", (TCHAR*) strGuid);
			nstrWlanAdapterGuids.push_back((TCHAR*) strGuid);
			RpcStringFree(&strGuid);
		}
	}

	TRACE_EXIT();
	return nstrWlanAdapterGuids;
}

BOOL AddFlagToRegistry_Dot11Adapters(LPCTSTR strDeviceName)
{
	TRACE_ENTER();
	TRACE_EXIT();
	return WriteStrToRegistry(NPCAP_SERVICE_REG_KEY_NAME _T("\\Parameters"), NPCAP_REG_DOT11_VALUE_NAME, strDeviceName, KEY_WRITE);
}

BOOL writeWlanAdapterGuidsToRegistry()
{
	TRACE_ENTER();

	vector<tstring> nstrWlanAdapterGuids = getWlanAdapterGuids();
	if (nstrWlanAdapterGuids.size() == 0)
	{
		TRACE_PRINT1("getWlanAdapterGuids: error, nstrWlanAdapterGuids.size() = %d.", nstrWlanAdapterGuids.size());
		TRACE_EXIT();
		return FALSE;
	}

	for (size_t i = 0; i < nstrWlanAdapterGuids.size(); i++)
	{
		nstrWlanAdapterGuids[i] = _T("\\Device\\{") + nstrWlanAdapterGuids[i] + _T("}");
	}

	tstring strGuidText = printAdapterNames(nstrWlanAdapterGuids);

	TRACE_PRINT1("AddFlagToRegistry_Dot11Adapters: executing, strGuidText = %s.", strGuidText.c_str());
	TRACE_EXIT();
	return AddFlagToRegistry_Dot11Adapters(strGuidText.c_str());

}
