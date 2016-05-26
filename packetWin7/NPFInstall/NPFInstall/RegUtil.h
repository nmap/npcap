/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

RegUtil.h

Abstract:

This is used for operating on registry.

--*/

#include <vector>
using namespace std;

#include "..\..\Common\WpcapNames.h"

#define		NPF_SOFT_REGISTRY_NAME_T			_T(NPF_SOFT_REGISTRY_NAME)
#define		NPF_DRIVER_NAME_SMALL_T				_T(NPF_DRIVER_NAME_SMALL)
#define		NPCAP_REG_KEY_NAME					_T("SOFTWARE\\") NPF_SOFT_REGISTRY_NAME_T
#define		NPCAP_SERVICE_REG_KEY_NAME			_T("SYSTEM\\CurrentControlSet\\Services\\") NPF_DRIVER_NAME_SMALL_T
#define		NPCAP_REG_LOOPBACK_VALUE_NAME		_T("LoopbackAdapter")
#define		NPCAP_REG_DOT11_VALUE_NAME		_T("Dot11Adapters")

typedef std::basic_string<TCHAR> tstring;

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, LPCTSTR strDeviceName, DWORD dwSamDesired);

tstring printAdapterNames(vector<tstring> nstr);
