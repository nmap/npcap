/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename.cpp

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".
    Also, we need to make a flag in registry to let the Npcap driver know that "this adapter is ours", so send the loopback traffic to it.

This code is modified based on example: https://msdn.microsoft.com/en-us/library/windows/desktop/aa364686.aspx
--*/

#pragma warning(disable: 4311 4312)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <netcon.h>
#include <stdio.h>

#include "LoopbackRename.h"

#include "debug.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define			NPCAP_LOOPBACK_INTERFACE_NAME			NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Loopback Adapter"
#define			BUF_SIZE								255

BOOL DoTheWork(INetSharingManager *pNSM, TCHAR strDeviceName[])
{
	TRACE_ENTER();

	// add a port mapping to every firewalled or shared connection 
	BOOL bFound = FALSE;
	BOOL bError = FALSE;
	INetSharingEveryConnectionCollection * pNSECC = NULL;
	HRESULT hr = pNSM->get_EnumEveryConnection (&pNSECC);
	if (!pNSECC)
	{
		TRACE_PRINT1("INetSharingManager::get_EnumEveryConnection: error, errCode = 0x%08x.", hr);
	}
	else {

		// enumerate connections
		IEnumVARIANT * pEV = NULL;
		IUnknown * pUnk = NULL;
		hr = pNSECC->get__NewEnum (&pUnk);
		if (pUnk) {
			hr = pUnk->QueryInterface (__uuidof(IEnumVARIANT),
				(void**)&pEV);
			pUnk->Release();
		}
		else
		{
			TRACE_PRINT1("INetSharingEveryConnectionCollection::get__NewEnum: error, errCode = 0x%08x.", hr);
		}

		if (pEV) {
			VARIANT v;
			VariantInit (&v);

			while ((S_OK == pEV->Next (1, &v, NULL)) && (bFound == FALSE)) {
				if (V_VT (&v) == VT_UNKNOWN) {
					INetConnection * pNC = NULL;
					V_UNKNOWN (&v)->QueryInterface (__uuidof(INetConnection),
						(void**)&pNC);
					if (pNC) {
						NETCON_PROPERTIES *pNETCON_PROPERTIES;
						pNC->GetProperties(&pNETCON_PROPERTIES);

						TCHAR currentGUID[BUF_SIZE];
						GUID guid = pNETCON_PROPERTIES->guidId;
						_stprintf_s(currentGUID, BUF_SIZE, _T("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"),
							guid.Data1, guid.Data2, guid.Data3, 
							guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
							guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

						if (_tcscmp(currentGUID, strDeviceName) == 0)
						{
							TRACE_PRINT2("INetConnection::Rename: executing, currentGUID = strDeviceName = %s, pszwNewName = %s.", currentGUID, NPCAP_LOOPBACK_INTERFACE_NAME);

							hr = pNC->Rename(NPCAP_LOOPBACK_INTERFACE_NAME);
							bFound = TRUE;
							if (hr == HRESULT_FROM_WIN32(ERROR_TRANSACTIONAL_CONFLICT))
							{
								TRACE_PRINT1("INetConnection::Rename: error, errCode = 0x%08x.", hr);
								bError = TRUE;
							}
							else if (hr != S_OK)
							{
								TRACE_PRINT1("INetConnection::Rename: error, errCode = 0x%08x.", hr);
								bError = TRUE;
							}
							else
							{
								bError = FALSE;
							}
						}
						
						pNC->Release();
					}
				}
				VariantClear(&v);
			}
			pEV->Release();
		}
		pNSECC->Release();
	}
	
	if (!bFound)
	{
		TRACE_PRINT("DoTheWork: error, bFound = 0.");
		TRACE_EXIT();
		return FALSE;
	}
	else
	{
		TRACE_EXIT();
		return !bError;
	}
}

BOOL RenameLoopbackNetwork(TCHAR strDeviceName[])
{
	TRACE_ENTER();

	BOOL bResult = FALSE;
/*	CoInitialize (NULL);*/

	// init security to enum RAS connections
	CoInitializeSecurity (NULL, -1, NULL, NULL, 
		RPC_C_AUTHN_LEVEL_PKT, 
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);

	INetSharingManager * pNSM = NULL;    
	HRESULT hr = ::CoCreateInstance (__uuidof(NetSharingManager),
		NULL,
		CLSCTX_ALL,
		__uuidof(INetSharingManager),
		(void**)&pNSM);
	if (!pNSM)
	{
		TRACE_PRINT1("CoCreateInstance: error, errCode = 0x%08x.", hr);
		TRACE_EXIT();
		return bResult;
	}
	else {

		// add a port mapping to every shared or firewalled connection.
		bResult = DoTheWork(pNSM, strDeviceName);

		pNSM->Release();
	}

/*	CoUninitialize ();*/

	TRACE_EXIT();
	return bResult;
}