/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename.cpp

Abstract:

    This is used for enumerating our "NPcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" to "NPcap Loopback Adapter".
    Also, we need to make a flag in registry to let the NPcap driver know that "this adapter is ours", so send the loopback traffic to it.

This code is modified based on example: https://msdn.microsoft.com/en-us/library/windows/desktop/aa364686.aspx
--*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <netcon.h>
#include <stdio.h>

#include "LoopbackRename.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#define BUF_SIZE 255
#define NPCAP_LOOPBACK_INTERFACE_NAME L"NPcap Loopback Adapter"

// as in winsock.h
#define NAT_PROTOCOL_TCP 6

BOOL DoTheWork(INetSharingManager *pNSM, wchar_t strDeviceName[])
{   // add a port mapping to every firewalled or shared connection 
	BOOL bFound = FALSE;
	INetSharingEveryConnectionCollection * pNSECC = NULL;
	HRESULT hr = pNSM->get_EnumEveryConnection (&pNSECC);
	if (!pNSECC)
		wprintf (L"failed to get EveryConnectionCollection!\r\n");
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

						wchar_t currentGUID[BUF_SIZE];
						GUID guid = pNETCON_PROPERTIES->guidId;
						wsprintf(currentGUID, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", 
							guid.Data1, guid.Data2, guid.Data3, 
							guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
							guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

						if (wcscmp(currentGUID, strDeviceName) == 0)
						{
							pNC->Rename(NPCAP_LOOPBACK_INTERFACE_NAME);
							bFound = TRUE;
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
	
	return bFound;
}

BOOL RenameLoopbackNetwork(wchar_t strDeviceName[])
{
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
		wprintf (L"failed to create NetSharingManager object\r\n");
		return bResult;
	}
	else {

		// add a port mapping to every shared or firewalled connection.
		bResult = DoTheWork(pNSM, strDeviceName);

		pNSM->Release();
	}

/*	CoUninitialize ();*/

	return bResult;
}