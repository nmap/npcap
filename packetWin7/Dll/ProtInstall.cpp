// ProtInstall.cpp : Defines the entry point for the console application.
//

#include "netcfgapi.h"
#include "ProtInstall.h"

#include "debug.h"

// Copyright And Configuration Management ----------------------------------
//
//  			 NDISPROT Software Installer - ProtInstall.cpp
//
//  				Companion Sample Code for the Article
//
//  			  "Installing NDIS Protocols Programatically"
//  				   Published on http://www.ndis.com
//
//   Copyright (c) 2004-2006 Printing Communications Associates, Inc. (PCAUSA)
//  						http://www.pcausa.com
//
// GPL software is an abomination. Far from being free, it is available ONLY
// to members of the "GPL Club". If you don't want to join the club, then GPL
// software is poison.
//
// This software IS free software under the terms of a BSD-style license:
//
// The right to use this code in your own derivative works is granted so long
// as 1.) your own derivative works include significant modifications of your
// own, 2.) you retain the above copyright notices and this paragraph in its
// entirety within sources derived from this code.
//
// This product includes software developed by PCAUSA. The name of PCAUSA
// may not be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// End ---------------------------------------------------------------------

BOOLEAN bVerbose = TRUE;

//
// Function:  ErrMsg
//
// Purpose:   Insert text for each network component type.
//
// Arguments:
//    hr  [in]  Error code.
//
// Returns:   None.
//
// Notes:
//
VOID ErrMsg(HRESULT hr, LPCTSTR  lpFmt, ...)
{
	LPTSTR lpSysMsg;
	TCHAR buf[400];
	ULONG offset;
	va_list vArgList; 

	if (hr != 0)
	{
		_stprintf(buf, _T("Error %#lx: "), hr);
	}
	else
	{
		buf[0] = 0;
	}

	offset = (ULONG) _tcslen(buf);

	va_start(vArgList, lpFmt);

	_vstprintf(buf + offset, lpFmt, vArgList);

	va_end(vArgList);

	if (hr != 0)
	{
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpSysMsg, 0, NULL);

		if (lpSysMsg)
		{
			offset = (ULONG) _tcslen(buf);

			_stprintf(buf + offset, L"\n\nPossible cause:\n\n");

			offset = (ULONG) _tcslen(buf);

			_tcscat(buf + offset, lpSysMsg);

			LocalFree((HLOCAL)lpSysMsg);
		}
	}

	//_tprintf( buf );
	TRACE_PRINT(buf);

	return;
}

DWORD GetServiceInfFilePath(LPTSTR lpFilename, DWORD nSize)
{
	// Get Path to This Module
	DWORD nResult;
	TCHAR szDrive[_MAX_DRIVE];
	TCHAR szDir[_MAX_DIR];

	nResult = GetModuleFileName(NULL, lpFilename, nSize);

	if (nResult == 0)
	{
		return 0;
	}

	_tsplitpath(lpFilename, szDrive, szDir, NULL, NULL);

	_tmakepath(lpFilename, szDrive, szDir, NDISLWF_SERVICE_INF_FILE, _T(".inf"));

	return (DWORD)_tcslen(lpFilename);
}

DWORD GetServiceSysFilePath(LPTSTR lpFilename, DWORD nSize)
{
	// Get Path to This Module
	DWORD nResult;
	TCHAR szDrive[_MAX_DRIVE];
	TCHAR szDir[_MAX_DIR];

	nResult = GetModuleFileName(NULL, lpFilename, nSize);

	if (nResult == 0)
	{
		return 0;
	}

	_tsplitpath(lpFilename, szDrive, szDir, NULL, NULL);

	_tmakepath(lpFilename, szDrive, szDir, NDISLWF_SERVICE_INF_FILE, _T(".sys"));

	return (DWORD)_tcslen(lpFilename);
}

//
// Function:  InstallSpecifiedComponent
//
// Purpose:   Install a network component from an INF file.
//
// Arguments:
//    lpszInfFile [in]  INF file.
//    lpszPnpID   [in]  PnpID of the network component to install.
//    pguidClass  [in]  Class GUID of the network component.
//
// Returns:   None.
//
// Notes:
//

HRESULT InstallSpecifiedComponent(LPTSTR lpszInfFile, LPTSTR lpszPnpID, const GUID* pguidClass)
{
	INetCfg* pnc;
	LPTSTR lpszApp;
	HRESULT hr;

	hr = HrGetINetCfg(TRUE, APP_NAME, &pnc, &lpszApp);

	if (hr == S_OK)
	{
		//
		// Install the network component.
		//
		hr = HrInstallNetComponent(pnc, lpszPnpID, pguidClass, lpszInfFile);

		if ((hr == S_OK) || (hr == NETCFG_S_REBOOT))
		{
			hr = pnc->Apply();
		}
		else
		{
			if (hr != HRESULT_FROM_WIN32(ERROR_CANCELLED))
			{
				ErrMsg(hr, L"Couldn't install the network component.");
			}
		}

		HrReleaseINetCfg(pnc, TRUE);
	}
	else
	{
		if ((hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp)
		{
			ErrMsg(hr, L"%s currently holds the lock, try later.", lpszApp);

			CoTaskMemFree(lpszApp);
		}
		else
		{
			ErrMsg(hr, L"Couldn't the get notify object interface.");
		}
	}

	return hr;
}

DWORD InstallDriver()
{
	DWORD nResult;
	TRACE_ENTER("InstallDriver");

	// Get Path to Service INF File
	// ----------------------------
	// The INF file is assumed to be in the same folder as this application...
	TCHAR szFileFullPath[_MAX_PATH];

	nResult = GetServiceInfFilePath(szFileFullPath, MAX_PATH);

	if (nResult == 0)
	{
		TRACE_PRINT("Unable to get INF file path");
		return 0;
	}

	//_tprintf( _T("INF Path: %s\n"), szFileFullPath );

	HRESULT hr = S_OK;

	//_tprintf( _T("PnpID: %s\n"), NDISPROT_SERVICE_PNP_DEVICE_ID );

	hr = InstallSpecifiedComponent(szFileFullPath, NDISLWF_SERVICE_PNP_DEVICE_ID, &GUID_DEVCLASS_NETSERVICE);

	if (hr != S_OK)
	{
		ErrMsg(hr, L"InstallSpecifiedComponent\n");
		TRACE_EXIT("InstallDriver");
		return 0;
	}

	TRACE_EXIT("InstallDriver");
	return 1;
}

DWORD UninstallDriver()
{
	TRACE_ENTER("UninstallDriver");
	//_tprintf( _T("Uninstalling %s...\n"), NDISPROT_FRIENDLY_NAME );

// 	int nResult = MessageBox(NULL, _T("Uninstalling Driver..."), NDISPROT_FRIENDLY_NAME, MB_OKCANCEL | MB_ICONINFORMATION);
// 
// 	if (nResult != IDOK)
// 	{
// 		return 0;
// 	}

	INetCfg* pnc;
	INetCfgComponent* pncc;
	INetCfgClass* pncClass;
	INetCfgClassSetup* pncClassSetup;
	LPTSTR lpszApp;
	GUID guidClass;
	OBO_TOKEN obo;
	HRESULT hr;

	hr = HrGetINetCfg(TRUE, APP_NAME, &pnc, &lpszApp);

	if (hr == S_OK)
	{
		//
		// Get a reference to the network component to uninstall.
		//
		hr = pnc->FindComponent(NDISLWF_SERVICE_PNP_DEVICE_ID, &pncc);

		if (hr == S_OK)
		{
			//
			// Get the class GUID.
			//
			hr = pncc->GetClassGuid(&guidClass);

			if (hr == S_OK)
			{
				//
				// Get a reference to component's class.
				//

				hr = pnc->QueryNetCfgClass(&guidClass, IID_INetCfgClass, (PVOID *)&pncClass);
				if (hr == S_OK)
				{
					//
					// Get the setup interface.
					//

					hr = pncClass->QueryInterface(IID_INetCfgClassSetup, (LPVOID *)&pncClassSetup);

					if (hr == S_OK)
					{
						//
						// Uninstall the component.
						//

						ZeroMemory(&obo, sizeof(OBO_TOKEN));

						obo.Type = OBO_USER;

						hr = pncClassSetup->DeInstall(pncc, &obo, NULL);
						if ((hr == S_OK) || (hr == NETCFG_S_REBOOT))
						{
							hr = pnc->Apply();

							if ((hr != S_OK) && (hr != NETCFG_S_REBOOT))
							{
								ErrMsg(hr, L"Couldn't apply the changes after"
									L" uninstalling %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
							}
							else
							{
								TRACE_EXIT("UninstallDriver");
								return 1;
							}
						}
						else
						{
							ErrMsg(hr, L"Failed to uninstall %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
						}

						ReleaseRef(pncClassSetup);
					}
					else
					{
						ErrMsg(hr, L"Couldn't get an interface to setup class.");
					}

					ReleaseRef(pncClass);
				}
				else
				{
					ErrMsg(hr, L"Couldn't get a pointer to class interface "
						L"of %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
				}
			}
			else
			{
				ErrMsg(hr, L"Couldn't get the class guid of %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
			}

			ReleaseRef(pncc);
		}
		else
		{
			ErrMsg(hr, L"Couldn't get an interface pointer to %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
		}

		HrReleaseINetCfg(pnc, TRUE);
	}
	else
	{
		if ((hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp)
		{
			ErrMsg(hr, L"%s currently holds the lock, try later.", lpszApp);

			CoTaskMemFree(lpszApp);
		}
		else
		{
			ErrMsg(hr, L"Couldn't get the notify object interface.");
		}
	}

	TRACE_EXIT("UninstallDriver");
	return 0;
}

// int _tmain(int argc, _TCHAR* argv[])
// {
//     SetConsoleTitle( _T("Installing NDIS Intermediate Filter Driver") );
// 
//     if( argc < 2 )
//     {
//  	   return 0;
//     }
// 
//     if( argc > 2 )
//     {
//  	   if( _tcsicmp( argv[2], _T("/v") ) == 0 )
//  	   {
//  		   bVerbose = TRUE;
//  	   }
//     }
// 
//     if( argc > 2 )
//     {
//  	   if( _tcsicmp( argv[2], _T("/hide") ) == 0 )
//  	   {
//  		   bVerbose = FALSE;
//  	   }
//     }
// 
//     if( !bVerbose )
//     {
//  	   ShowWindow( GetConsoleWindow(), SW_HIDE );
//     }
// 
//     // Handle Driver Install
//     if( _tcsicmp( argv[1], _T("/Install") ) == 0 )
//     {
//  	   return InstallDriver();
//     }
// 
//     // Handle Driver Uninstall
//     if( _tcsicmp( argv[1], _T("/Uninstall") ) == 0 )
//     {
//  	   return UninstallDriver();
//     }
// 
//     return 0;
// }

BOOL RenableBindings()
{
	CComPtr<INetCfg> netcfg;
	CComPtr<INetCfgLock> lock;

	HRESULT hr;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"CoInitializeEx 0x%08x\n", hr);
		return 1;
	}

	BOOL ok = ConnectToNetCfg(NDISLWF_SERVICE_PNP_DEVICE_ID);

	CoUninitialize();

	wprintf(ok ? L"Succeeded.\n" : L"Failed.\n");

	return ok;
}