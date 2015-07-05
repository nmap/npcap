/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackInstall.h

Abstract:

    Device Console header

--*/

#pragma warning(disable: 4311 4312)

#include <windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <setupapi.h>
#include <regstr.h>
#include <infstr.h>
#include <cfgmgr32.h>
#include <string.h>
#include <malloc.h>
#include <newdev.h>
#include <objbase.h>

#include "msg.h"
#include "rc_ids.h"

//
// Devcon.exe command line flags
//
#define DEVCON_FLAG_FORCE       0x00000001

void FormatToStream(_In_ FILE * stream, _In_ DWORD fmt,...);

//
// UpdateDriverForPlugAndPlayDevices
//
typedef BOOL (WINAPI *UpdateDriverForPlugAndPlayDevicesProto)(_In_opt_ HWND hwndParent,
															  _In_ LPCTSTR HardwareId,
															  _In_ LPCTSTR FullInfPath,
															  _In_ DWORD InstallFlags,
															  _Out_opt_ PBOOL bRebootRequired
															  );

#ifdef _UNICODE
#define UPDATEDRIVERFORPLUGANDPLAYDEVICES "UpdateDriverForPlugAndPlayDevicesW"
#define SETUPUNINSTALLOEMINF "SetupUninstallOEMInfW"
#else
#define UPDATEDRIVERFORPLUGANDPLAYDEVICES "UpdateDriverForPlugAndPlayDevicesA"
#define SETUPUNINSTALLOEMINF "SetupUninstallOEMInfA"
#endif

//
// exit codes
//
#define EXIT_OK      (0)
#define EXIT_REBOOT  (1)
#define EXIT_FAIL    (2)
#define EXIT_USAGE   (3)

//
// Declarations
//
void FormatToStream(_In_ FILE * stream, _In_ DWORD fmt,...);
int cmdStatus(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[]);
int cmdUpdate(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[]);
int cmdInstall(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[]);
int cmdRemove(_In_ LPCTSTR BaseName, _In_opt_ LPCTSTR Machine, _In_ DWORD Flags, _In_ int argc, _In_reads_(argc) PTSTR argv[]);
typedef int (*CallbackFunc)(_In_ HDEVINFO Devs, _In_ PSP_DEVINFO_DATA DevInfo, _In_ DWORD Index, _In_ LPVOID Context);

BOOL ListLoopbackAdapters();
BOOL GetLoopbackINFFilePath(TCHAR strLoopbackInfPath[]);
BOOL GetConfigFilePath(char strConfigPath[]);
BOOL InstallLoopbackDeviceInternal();
BOOL RemoveLoopbackDeviceInternal(int iDevID);
BOOL SaveDevIDToFile(int iDevID);
int LoadDevIDFromFile();
BOOL InstallLoopbackAdapter();
BOOL UninstallLoopbackAdapter();
