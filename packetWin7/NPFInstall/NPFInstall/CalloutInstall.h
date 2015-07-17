/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

	CalloutInstall.h

Abstract:

	This is used for installing the Windows Filtering Platform (WFP) callout driver, for capturing the loopback traffic, the used INF file is: npf(npcap)_wfp.inf

--*/
#include <windows.h>

BOOL isFileExist(TCHAR szFileFullPath[]);

BOOL InstallWFPCallout();

BOOL UninstallWFPCallout();
