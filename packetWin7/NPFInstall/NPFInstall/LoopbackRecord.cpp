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
/*++

Module Name:

	LoopbackRecord.cpp

Abstract:

	This is used for enumerating our "Npcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" or "Local Network Area" to "Npcap Loopback Adapter".
	Also, we need to make a flag in registry to let the Npcap driver know that "this adapter is ours", so send the loopback traffic to it.

--*/

#pragma warning(disable: 4311 4312)

#include <Netcfgx.h>

#include <iostream>
#include <atlbase.h> // CComPtr
#include <devguid.h> // GUID_DEVCLASS_NET, ...

#include "LoopbackRecord.h"
#include "LoopbackRename.h"
#include "RegUtil.h"

#include "debug.h"

#define			NPCAP_LOOPBACK_ADAPTER_NAME				NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Loopback Adapter"
#define			NPCAP_LOOPBACK_APP_NAME					NPF_DRIVER_NAME_NORMAL_WIDECHAR L"_Loopback"

int g_NpcapAdapterID = -1;

// RAII helper class
class COM
{
public:
	COM();
	~COM();
};

COM::COM()
{
	TRACE_ENTER();

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

	if(!SUCCEEDED(hr))
	{
		TRACE_PRINT1("CoInitializeEx: error, errCode = 0x%08x.", hr);
	}

	TRACE_EXIT();
}

COM::~COM()
{
	TRACE_ENTER();

	CoUninitialize();

	TRACE_EXIT();
}

// RAII helper class
class NetCfg
{
	CComPtr<INetCfg> m_pINetCfg;
	CComPtr<INetCfgLock> m_pLock;

public:
	NetCfg();
	~NetCfg();

	// Displays all network adapters, clients, transport protocols and services.
	// For each client, transport protocol and service (network features) 
	//    shows adpater(s) they are bound to.
	BOOL GetNetworkConfiguration(); 
};

NetCfg::NetCfg() : m_pINetCfg(0)
{
	TRACE_ENTER();

	HRESULT hr = S_OK;

	hr = m_pINetCfg.CoCreateInstance(CLSID_CNetCfg);

	if(!SUCCEEDED(hr))
	{
		TRACE_PRINT1("INetCfg::CoCreateInstance: error, errCode = 0x%08x.", hr);
		throw 1;
	}

	hr = m_pINetCfg.QueryInterface(&m_pLock);

	if (!SUCCEEDED(hr))
	{
		TRACE_PRINT1("INetCfg::QueryInterface: error, errCode = 0x%08x.", hr);
		throw 2;
	}

	// Note that this call can block.
	hr = m_pLock->AcquireWriteLock(INFINITE, NPCAP_LOOPBACK_APP_NAME, NULL);
	if (!SUCCEEDED(hr))
	{
		TRACE_PRINT1("INetCfgLock::AcquireWriteLock: error, errCode = 0x%08x.", hr);
		throw 3;
	}

	hr = m_pINetCfg->Initialize(NULL);

	if(!SUCCEEDED(hr))
	{
		TRACE_PRINT1("INetCfg::Initialize: error, errCode = 0x%08x.", hr);
		throw 4;
	}

	TRACE_EXIT();
}

NetCfg::~NetCfg()
{
	TRACE_ENTER();

	HRESULT hr = S_OK;

	if(m_pINetCfg)
	{
		hr = m_pINetCfg->Uninitialize();
		if(!SUCCEEDED(hr))
		{
			TRACE_PRINT1("INetCfg::Uninitialize: error, errCode = 0x%08x.", hr);
		}

		hr = m_pLock->ReleaseWriteLock();
		if (!SUCCEEDED(hr))
		{
			TRACE_PRINT1("INetCfgLock::ReleaseWriteLock: error, errCode = 0x%08x.", hr);
		}
	}

	TRACE_EXIT();
}

BOOL EnumerateComponents(CComPtr<INetCfg>& pINetCfg, const GUID* pguidClass)
{
	TRACE_ENTER();

	/*	cout << "\n\nEnumerating " << GUID2Str(pguidClass) << " class:\n" << endl;*/

	// IEnumNetCfgComponent provides methods that enumerate the INetCfgComponent interfaces 
	// for network components of a particular type installed on the operating system. 
	// Types of network components include network cards, protocols, services, and clients.
	CComPtr<IEnumNetCfgComponent> pIEnumNetCfgComponent;

	// get enumeration containing network components of the provided class (GUID)
	HRESULT hr = pINetCfg->EnumComponents(pguidClass, &pIEnumNetCfgComponent);

	if(!SUCCEEDED(hr))
	{
		TRACE_PRINT1("INetCfg::EnumComponents: error, errCode = 0x%08x.", hr);
		throw 1;
	} 

	// INetCfgComponent interface provides methods that control and retrieve 
	// information about a network component.
	CComPtr<INetCfgComponent> pINetCfgComponent;

	unsigned int nIndex = 1;
	BOOL bFound = FALSE;
	BOOL bFailed = FALSE;
	// retrieve the next specified number of INetCfgComponent interfaces in the enumeration sequence.
	while(pIEnumNetCfgComponent->Next(1, &pINetCfgComponent, 0) == S_OK)
	{
		/*		cout << GUID2Desc(pguidClass) << " "<< nIndex++ << ":\n";*/

// 		LPWSTR pszDisplayName = NULL;
// 		pINetCfgComponent->GetDisplayName(&pszDisplayName);
// 		wcout << L"\tDisplay name: " << wstring(pszDisplayName) << L'\n';
// 		CoTaskMemFree(pszDisplayName);

		LPWSTR pszBindName = NULL;
		pINetCfgComponent->GetBindName(&pszBindName);
//		wcout << L"\tBind name: " << wstring(pszBindName) << L'\n';

// 		DWORD dwCharacteristics = 0;
// 		pINetCfgComponent->GetCharacteristics(&dwCharacteristics);
// 		cout << "\tCharacteristics: " << dwCharacteristics << '\n';
// 
// 		GUID guid;  
// 		pINetCfgComponent->GetClassGuid(&guid);
// 		cout << "\tClass GUID: " << guid.Data1 << '-' << guid.Data2 << '-'
// 			<< guid.Data3 << '-' << (unsigned int) guid.Data4 << '\n';
// 
// 		ULONG ulDeviceStatus = 0;
// 		pINetCfgComponent->GetDeviceStatus(&ulDeviceStatus);
// 		cout << "\tDevice Status: " << ulDeviceStatus << '\n';
// 
// 		LPWSTR pszHelpText = NULL;
// 		pINetCfgComponent->GetHelpText(&pszHelpText);
// 		wcout << L"\tHelp Text: " << wstring(pszHelpText) << L'\n';
// 		CoTaskMemFree(pszHelpText);
// 
// 		LPWSTR pszID = NULL;
// 		pINetCfgComponent->GetId(&pszID);
// 		wcout << L"\tID: " << wstring(pszID) << L'\n';
// 		CoTaskMemFree(pszID);
// 
// 		pINetCfgComponent->GetInstanceGuid(&guid);
// 		cout << "\tInstance GUID: " << guid.Data1 << '-' << guid.Data2 << '-'
// 			<< guid.Data3 << '-' << (unsigned int) guid.Data4 << '\n';

		LPWSTR pszPndDevNodeId = NULL;
		pINetCfgComponent->GetPnpDevNodeId(&pszPndDevNodeId);
//		wcout << L"\tPNP Device Node ID: " << wstring(pszPndDevNodeId) << L'\n';

		int iDevID = getIntDevID(pszPndDevNodeId);
		TRACE_PRINT4("INetCfgComponent::GetPnpDevNodeId: executing, pszPndDevNodeId = %s, iDevID = %d, g_NpcapAdapterID = %d, pszBindName = %ws.",
			pszPndDevNodeId, iDevID, g_NpcapAdapterID, pszBindName);
		if (g_NpcapAdapterID == iDevID)
		{
			bFound = TRUE;

			TRACE_PRINT2("INetCfgComponent::SetDisplayName: executing, g_NpcapAdapterID = iDevID = %d, pszBindName = %ws.", g_NpcapAdapterID, pszBindName);
			hr = pINetCfgComponent->SetDisplayName(NPCAP_LOOPBACK_ADAPTER_NAME);

			if (hr != S_OK)
			{
				TRACE_PRINT1("INetCfgComponent::SetDisplayName: error, errCode = 0x%08x.", hr);
				bFailed = TRUE;
			}

			if (!AddFlagToRegistry(pszBindName))
			{
				TRACE_PRINT1("AddFlagToRegistry: error, pszBindName = %ws.", pszBindName);
				bFailed = TRUE;
			}

 			if (!AddFlagToRegistry_Service(pszBindName))
 			{
 				bFailed = TRUE;
 			}

			if (!RenameLoopbackNetwork(pszBindName))
			{
				TRACE_PRINT1("RenameLoopbackNetwork: error, pszBindName = %ws.", pszBindName);
				bFailed = TRUE;
			}
		}

		CoTaskMemFree(pszBindName);
		CoTaskMemFree(pszPndDevNodeId);
		pINetCfgComponent.Release();

		if (bFound)
		{
			TRACE_EXIT();
			return !bFailed;
		}
	}

	TRACE_EXIT();
	return FALSE;
}

BOOL NetCfg::GetNetworkConfiguration()
{
	TRACE_ENTER();
	// get enumeration containing GUID_DEVCLASS_NET class of network components
	TRACE_EXIT();
	return EnumerateComponents(m_pINetCfg, &GUID_DEVCLASS_NET);
}

int getIntDevID(TCHAR strDevID[]) //DevID is in form like: "ROOT\\NET\\0008"
{
	TRACE_ENTER();

	int iDevID = -1;
	int iMatched = _stscanf_s(strDevID, _T("ROOT\\NET\\%04d"), &iDevID);
	TRACE_PRINT2("_stscanf_s: iMatched = %d, iDevID = %d.", iMatched, iDevID);
	if (iMatched != 1)
		iDevID = -1;

	TRACE_EXIT();
	return iDevID;
}

BOOL AddFlagToRegistry(tstring strDeviceName)
{
	TRACE_ENTER();
	TRACE_EXIT();
	return WriteStrToRegistry(NPCAP_REG_KEY_NAME, NPCAP_REG_LOOPBACK_VALUE_NAME, tstring(_T("\\Device\\") + strDeviceName).c_str(), KEY_WRITE | KEY_WOW64_32KEY);
}

BOOL AddFlagToRegistry_Service(tstring strDeviceName)
{
	TRACE_ENTER();
	TRACE_EXIT();
	return WriteStrToRegistry(NPCAP_SERVICE_REG_KEY_NAME _T("\\Parameters"), NPCAP_REG_LOOPBACK_VALUE_NAME, tstring(_T("\\Device\\") + strDeviceName).c_str(), KEY_WRITE);
}

BOOL RecordLoopbackDevice(int iNpcapAdapterID)
{
	TRACE_ENTER();

	g_NpcapAdapterID = iNpcapAdapterID;

	try
	{
		COM com;
		NetCfg netCfg;
		if (!netCfg.GetNetworkConfiguration())
		{
			TRACE_PRINT("NetCfg::GetNetworkConfiguration: error.");
			TRACE_EXIT();
			return FALSE;
		}
	}
	catch(...)
	{
		TRACE_PRINT("NetCfg::GetNetworkConfiguration: error (exception).");
		TRACE_EXIT();
		return FALSE;
	}

	TRACE_EXIT();
	return TRUE;
}
