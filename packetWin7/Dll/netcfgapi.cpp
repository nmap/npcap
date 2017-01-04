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
#include "NetCfgAPI.h"
#include "ProtInstall.h"

#include "debug.h"

//+---------------------------------------------------------------------------
//
//  Microsoft Windows
//  Copyright (C) Microsoft Corporation, 2001.
//
//  File:   	N E T C F G A P I . C P P
//
//  Contents:   Functions to illustrate INetCfg API
//
//  Notes:  	
//
//  Author: 	Alok Sinha    15-May-01
//
//  Some revisions by PCAUSA (TFD) 03-Feb-06
//
//----------------------------------------------------------------------------


//
// Function:  HrGetINetCfg
//
// Purpose:   Get a reference to INetCfg.
//
// Arguments:
//    fGetWriteLock  [in]  If TRUE, Write lock.requested.
//    lpszAppName    [in]  Application name requesting the reference.
//    ppnc  		 [out] Reference to INetCfg.
//    lpszLockedBy   [in]  Optional. Application who holds the write lock.
//
// Returns:   S_OK on success, otherwise an error code.
//
// Notes:
//

extern BOOLEAN bWiFiService;

HRESULT HrGetINetCfg(IN BOOL fGetWriteLock, IN LPCTSTR lpszAppName, OUT INetCfg** ppnc, OUT LPTSTR* lpszLockedBy)
{
	TRACE_ENTER();

	INetCfg* pnc = NULL;
	INetCfgLock* pncLock = NULL;
	HRESULT hr = S_OK;
	BOOL selfStartedCom = FALSE;

	//
	// Initialize the output parameters.
	//

	*ppnc = NULL;

	if (lpszLockedBy)
	{
		*lpszLockedBy = NULL;
	}
	//
	// Initialize COM
	//

	hr = CoInitialize(NULL);

	if (hr == S_OK || hr == S_FALSE)
	{
		if (hr == S_OK)
		{
			selfStartedCom = TRUE;
		}
		//
		// Create the object implementing INetCfg.
		//

		hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void**)&pnc);
		if (hr == S_OK)
		{
			if (fGetWriteLock)
			{
				//
				// Get the locking reference
				//

				hr = pnc->QueryInterface(IID_INetCfgLock, (LPVOID *)&pncLock);
				if (hr == S_OK)
				{
					//
					// Attempt to lock the INetCfg for read/write
					//

					hr = pncLock->AcquireWriteLock(LOCK_TIME_OUT, lpszAppName, lpszLockedBy);
					if (hr == S_FALSE)
					{
						hr = NETCFG_E_NO_WRITE_LOCK;
					}
				}
			}

			if (hr == S_OK)
			{
				//
				// Initialize the INetCfg object.
				//

				hr = pnc->Initialize(NULL);

				if (hr == S_OK)
				{
					*ppnc = pnc;
					pnc->AddRef();
				}
				else
				{
					//
					// Initialize failed, if obtained lock, release it
					//

					if (pncLock)
					{
						pncLock->ReleaseWriteLock();
					}
				}
			}

			ReleaseRef(pncLock);
			ReleaseRef(pnc);
		}
		else
		{
			TRACE_PRINT1("CoCreateInstance: error, hr = 0x%08x.", hr);
			//
			// In case of error, uninitialize COM.
			//
			if (selfStartedCom)
			{
				CoUninitialize();
			}
		}
	}

	TRACE_EXIT();
	return hr;
}

//
// Function:  HrReleaseINetCfg
//
// Purpose:   Get a reference to INetCfg.
//
// Arguments:
//    pnc   		[in] Reference to INetCfg to release.
//    fHasWriteLock [in] If TRUE, reference was held with write lock.
//
// Returns:   S_OK on sucess, otherwise an error code.
//
// Notes:
//

HRESULT HrReleaseINetCfg(IN INetCfg* pnc, IN BOOL fHasWriteLock)
{
	TRACE_ENTER();

	INetCfgLock* pncLock = NULL;
	HRESULT hr = S_OK;

	//
	// Uninitialize INetCfg
	//

	hr = pnc->Uninitialize();

	//
	// If write lock is present, unlock it
	//

	if (hr == S_OK && fHasWriteLock)
	{
		//
		// Get the locking reference
		//

		hr = pnc->QueryInterface(IID_INetCfgLock, (LPVOID *)&pncLock);
		if (hr == S_OK)
		{
			hr = pncLock->ReleaseWriteLock();
			ReleaseRef(pncLock);
		}
	}

	ReleaseRef(pnc);

	//
	// Uninitialize COM.
	//

	CoUninitialize();

	TRACE_EXIT();
	return hr;
}

//
// Function:  HrInstallNetComponent
//
// Purpose:   Install a network component(protocols, clients and services)
//  		  given its INF file.
//
// Arguments:
//    pnc   		   [in] Reference to INetCfg.
//    lpszComponentId  [in] PnpID of the network component.
//    pguidClass	   [in] Class GUID of the network component.
//    lpszInfFullPath  [in] INF file to install from.
//
// Returns:   S_OK on sucess, otherwise an error code.
//
// Notes:
//

HRESULT HrInstallNetComponent(IN INetCfg* pnc, IN const GUID* pguidClass, IN LPCTSTR lpszInfFullPath)
{
	TRACE_ENTER();

	DWORD dwError;
	HRESULT hr = S_OK;
	TCHAR szDrive[_MAX_DRIVE];
	TCHAR szDir[_MAX_DIR];
	TCHAR szDirWithDrive[_MAX_DRIVE + _MAX_DIR];

	//
	// If full path to INF has been specified, the INF
	// needs to be copied using Setup API to ensure that any other files
	// that the primary INF copies will be correctly found by Setup API
	//
	if (lpszInfFullPath)
	{
		//
		// Get the path where the INF file is.
		//
		_tsplitpath(lpszInfFullPath, szDrive, szDir, NULL, NULL);

		_tcscpy(szDirWithDrive, szDrive);
		_tcscat(szDirWithDrive, szDir);

		//
		// Copy the Service INF file to the \Windows\Inf Folder
		//
		if (!SetupCopyOEMInfW(lpszInfFullPath, szDirWithDrive, // Other files are in the
			// same dir. as primary INF
			SPOST_PATH,    // First param is path to INF
			0,  		   // Default copy style
			NULL,   	   // Name of the INF after
			// it's copied to %windir%\inf
			0,  		   // Max buf. size for the above
			NULL,   	   // Required size if non-null
			NULL)   	   // Optionally get the filename
			// part of Inf name after it is copied.
		   )
		{
			dwError = GetLastError();
			hr = HRESULT_FROM_WIN32(dwError);
			TRACE_PRINT1("SetupCopyOEMInfW: error, errCode = 0x%08x.", hr);
		}
	}

	if (S_OK == hr)
	{
		//
		// Install the network component.
		//
		TRACE_PRINT1("bWiFiService = %d.", bWiFiService);
		TRACE_PRINT1("HrInstallComponent: executing, szComponentId = %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
		hr = HrInstallComponent(pnc, NDISLWF_SERVICE_PNP_DEVICE_ID, pguidClass);

		if (hr == S_OK)
		{
			if (bWiFiService)
			{
				TRACE_PRINT1("HrInstallComponent: executing, szComponentId = %s.", NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI);
				hr = HrInstallComponent(pnc, NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI, pguidClass);

				if (hr == S_OK)
				{
					//
					// On success, apply the changes
					//
					hr = pnc->Apply();
					if (hr != S_OK)
					{
						TRACE_PRINT1("INetCfg::Apply: error, errCode = 0x%08x.", hr);
					}
				}
				else
				{
					TRACE_PRINT1("HrInstallComponent: error, szComponentId = %s.", NDISLWF_SERVICE_PNP_DEVICE_ID_WIFI);
					// at least install the first service
					hr = pnc->Apply();
					if (hr != S_OK)
					{
						TRACE_PRINT1("INetCfg::Apply: error, errCode = 0x%08x.", hr);
					}
				}
			}
			else
			{
				//
				// On success, apply the changes
				//
				hr = pnc->Apply();
				if (hr != S_OK)
				{
					TRACE_PRINT1("INetCfg::Apply: error, errCode = 0x%08x.", hr);
				}
			}
		}
		else
		{
			TRACE_PRINT1("HrInstallComponent: error, szComponentId = %s.", NDISLWF_SERVICE_PNP_DEVICE_ID);
		}
	}

	TRACE_EXIT();
	return hr;
}

//
// Function:  HrInstallComponent
//
// Purpose:   Install a network component(protocols, clients and services)
//  		  given its INF file.
// Arguments:
//    pnc   		   [in] Reference to INetCfg.
//    lpszComponentId  [in] PnpID of the network component.
//    pguidClass	   [in] Class GUID of the network component.
//
// Returns:   S_OK on sucess, otherwise an error code.
//
// Notes:
//

HRESULT HrInstallComponent(IN INetCfg* pnc, IN LPCTSTR szComponentId, IN const GUID* pguidClass)
{
	TRACE_ENTER();

	INetCfgClassSetup* pncClassSetup = NULL;
	INetCfgComponent* pncc = NULL;
	OBO_TOKEN OboToken;
	HRESULT hr = S_OK;

	//
	// OBO_TOKEN specifies on whose behalf this
	// component is being installed.
	// Set it to OBO_USER so that szComponentId will be installed
	// on behalf of the user.
	//

	ZeroMemory(&OboToken, sizeof(OboToken));
	OboToken.Type = OBO_USER;

	//
	// Get component's setup class reference.
	//
	hr = pnc->QueryNetCfgClass(pguidClass, IID_INetCfgClassSetup, (void**)&pncClassSetup);

	if (hr == S_OK)
	{
		hr = pncClassSetup->Install(szComponentId, &OboToken, 0, 0,  	 // Upgrade from build number.
			NULL,    // Answerfile name
			NULL,    // Answerfile section name
			&pncc); // Reference after the component
		if (S_OK == hr)
		{
			// is installed.

			//
			// we don't need to use pncc (INetCfgComponent), release it
			//

			ReleaseRef(pncc);
		}
		else
		{
			TRACE_PRINT1("INetCfgClassSetup::Install: error, szComponentId = %s.", szComponentId);
		}

		ReleaseRef(pncClassSetup);
	}
	else
	{
		TRACE_PRINT1("INetCfg::QueryNetCfgClass: error, szComponentId = %s.", szComponentId);
	}

	TRACE_EXIT();
	return hr;
}

//
// Function:  HrUninstallNetComponent
//
// Purpose:   Uninstall a network component(protocols, clients and services).
//
// Arguments:
//    pnc   		[in] Reference to INetCfg.
//    szComponentId [in] PnpID of the network component to uninstall.
//
// Returns:   S_OK on sucess, otherwise an error code.
//
// Notes:
//

HRESULT HrUninstallNetComponent(IN INetCfg* pnc, IN LPCTSTR szComponentId)
{
	INetCfgComponent* pncc;
	INetCfgClass* pncClass;
	INetCfgClassSetup* pncClassSetup;
	GUID guidClass;
	OBO_TOKEN obo;
	HRESULT hr;

	TRACE_ENTER();

	//
	// Get a reference to the network component to uninstall.
	//
	hr = pnc->FindComponent(szComponentId, &pncc);

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
							ErrMsg(hr, _T("Couldn't apply the changes after uninstalling %s."), szComponentId);
						}
					}
					else
					{
						ErrMsg(hr, _T("Failed to uninstall %s."), szComponentId);
					}

					ReleaseRef(pncClassSetup);
				}
				else
				{
					ErrMsg(hr, _T("Couldn't get an interface to setup class."));
				}

				ReleaseRef(pncClass);
			}
			else
			{
				ErrMsg(hr, _T("Couldn't get a pointer to class interface of %s."), szComponentId);
			}
		}
		else
		{
			ErrMsg(hr, _T("Couldn't get the class guid of %s."), szComponentId);
		}

		ReleaseRef(pncc);
	}
	else
	{
		ErrMsg(hr, _T("Couldn't get an interface pointer to %s."), szComponentId);
	}

	TRACE_EXIT();
	return hr;
}

//
// Function:  ReleaseRef
//
// Purpose:   Release reference.
//
// Arguments:
//    punk     [in]  IUnknown reference to release.
//
// Returns:   Reference count.
//
// Notes:
//

VOID ReleaseRef(IN IUnknown* punk)
{
	if (punk)
	{
		punk->Release();
	}

	return;
}

BOOL RestartAllBindings(INetCfg *netcfg, PCWSTR szComponentId)
{
	HRESULT hr;
	CComPtr<INetCfgComponent> comp;
	CComPtr<INetCfgComponentBindings> bindings;

	TRACE_ENTER();

	hr = netcfg->FindComponent(szComponentId, &comp);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfg::FindComponent: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	hr = comp.QueryInterface(&bindings);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfgComponent::QueryInterface: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	CComPtr<IEnumNetCfgBindingPath> enumerator;
	hr = bindings->EnumBindingPaths(EBP_BELOW, &enumerator);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfgComponentBindings::EnumBindingPaths: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	// Loop over all bindings that involve this component
	while (true)
	{
		CComPtr<INetCfgBindingPath> path;
		hr = enumerator->Next(1, &path, NULL);
		if (hr == S_FALSE)
		{
			// Reached end of list; quit.
			break;
		}
		if (FAILED(hr))
		{
			TRACE_PRINT1("IEnumNetCfgBindingPath::Next: error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			return FALSE;
		}

		PWSTR token = NULL;
		hr = path->GetPathToken(&token);
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfgBindingPath::GetPathToken: error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			continue;
		}

		TRACE_PRINT1("Found binding %ws.", token);
		CoTaskMemFree(token);

		hr = path->IsEnabled();
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfgBindingPath::IsEnabled: error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			continue;
		}

		if (S_FALSE == hr)
		{
			TRACE_PRINT("Path is already disabled.  Skipping over it.");
			TRACE_EXIT();
			continue;
		}

		// Disable

		hr = path->Enable(FALSE);
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfgBindingPath::Enable(FALSE): error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			continue;
		}

		hr = netcfg->Apply();
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfg::Apply: error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			return FALSE;
		}

		TRACE_PRINT("Path disabled.");

		// Enable

		hr = path->Enable(TRUE);
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfgBindingPath::Enable(TRUE): error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			return FALSE;
		}

		hr = netcfg->Apply();
		if (FAILED(hr))
		{
			TRACE_PRINT1("INetCfg::Apply: error, hr = 0x%08x.", hr);
			TRACE_EXIT();
			return FALSE;
		}

		TRACE_PRINT("Path enabled.");
	}

	TRACE_EXIT();
	return TRUE;
}

BOOL ConnectToNetCfg(PCWSTR lpszPnpID, LPTSTR lpszAppName)
{
	HRESULT hr;
	CComPtr<INetCfg> netcfg;
	CComPtr<INetCfgLock> lock;

	TRACE_ENTER();

	// Before we can get started, we need to do some initialization work.

	hr = netcfg.CoCreateInstance(CLSID_CNetCfg);
	if (FAILED(hr))
	{
		TRACE_PRINT1("CoCreateInstance(CLSID_CNetCfg): error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	hr = netcfg.QueryInterface(&lock);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfg::QueryInterface: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	// Note that this call can block.
	hr = lock->AcquireWriteLock(INFINITE, lpszAppName, NULL);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfgLock::AcquireWriteLock: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	hr = netcfg->Initialize(NULL);
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfg::Initialize: error, hr = 0x%08x.", hr);
		TRACE_EXIT();
		return FALSE;
	}

	BOOL ok = RestartAllBindings(netcfg.p, lpszPnpID);

	hr = netcfg->Uninitialize();
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfg::Uninitialize: error, hr = 0x%08x.", hr);
	}

	hr = lock->ReleaseWriteLock();
	if (FAILED(hr))
	{
		TRACE_PRINT1("INetCfgLock::ReleaseWriteLock: error, hr = 0x%08x.", hr);
	}

	TRACE_EXIT();
	return ok;
}
