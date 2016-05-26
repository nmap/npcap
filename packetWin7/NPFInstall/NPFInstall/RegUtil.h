/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

RegUtil.h

Abstract:

This is used for operating on registry.

--*/

#include <vector>
using namespace std;

#ifdef UNICODE
#define		NPF_SOFT_REGISTRY_NAME_T			NPF_SOFT_REGISTRY_NAME_WIDECHAR
#define		NPF_DRIVER_NAME_SMALL_T				NPF_DRIVER_NAME_SMALL_WIDECHAR
#else
#define		NPF_SOFT_REGISTRY_NAME_T			NPF_SOFT_REGISTRY_NAME
#define		NPF_DRIVER_NAME_SMALL_T				NPF_DRIVER_NAME_SMALL
#endif

#define		NPCAP_REG_KEY_NAME					_T("SOFTWARE\\") NPF_SOFT_REGISTRY_NAME_T
#define		NPCAP_SERVICE_REG_KEY_NAME			_T("SYSTEM\\CurrentControlSet\\Services\\") NPF_DRIVER_NAME_SMALL_T
#define		NPCAP_REG_LOOPBACK_VALUE_NAME		_T("Loopback")

typedef std::basic_string<TCHAR> tstring;

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, TCHAR strDeviceName[], DWORD dwSamDesired);

tstring printAdapterNames(vector<tstring> nstr);
