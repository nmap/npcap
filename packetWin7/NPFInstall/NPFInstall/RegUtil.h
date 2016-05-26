/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

RegUtil.h

Abstract:

This is used for operating on registry.

--*/

BOOL WriteStrToRegistry(LPCTSTR strSubKey, LPCTSTR strValueName, TCHAR strDeviceName[], DWORD dwSamDesired);