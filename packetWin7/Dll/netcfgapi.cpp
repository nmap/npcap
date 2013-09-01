#include "NetCfgAPI.h"
#include "ProtInstall.h"


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
// Returns:   S_OK on sucess, otherwise an error code.
//
// Notes:
//

HRESULT HrGetINetCfg(IN BOOL fGetWriteLock, IN LPCTSTR lpszAppName, OUT INetCfg** ppnc, OUT LPTSTR* lpszLockedBy)
{
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

		//
		// In case of error, uninitialize COM.
		//

		if (hr != S_OK)
		{
			if (selfStartedCom)
			{
				CoUninitialize();
			}
		}
	}

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

HRESULT HrInstallNetComponent(IN INetCfg* pnc, IN LPCTSTR lpszComponentId, IN const GUID* pguidClass, IN LPCTSTR lpszInfFullPath)
{
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
		}
	}

	if (S_OK == hr)
	{
		//
		// Install the network component.
		//
		hr = HrInstallComponent(pnc, lpszComponentId, pguidClass);

		if (hr == S_OK)
		{
			//
			// On success, apply the changes
			//
			hr = pnc->Apply();
		}
	}

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

		ReleaseRef(pncClassSetup);
	}

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
	INetCfgComponent* pncc = NULL;
	INetCfgClass* pncClass = NULL;
	INetCfgClassSetup* pncClassSetup = NULL;
	OBO_TOKEN OboToken;
	GUID guidClass;
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
	// Get the component's reference.
	//

	hr = pnc->FindComponent(szComponentId, &pncc);

	if (S_OK == hr)
	{
		//
		// Get the component's class GUID.
		//

		hr = pncc->GetClassGuid(&guidClass);

		if (hr == S_OK)
		{
			//
			// Get component's class reference.
			//

			hr = pnc->QueryNetCfgClass(&guidClass, IID_INetCfgClass, (void**)&pncClass);
			if (hr == S_OK)
			{
				//
				// Get Setup reference.
				//

				hr = pncClass->QueryInterface(IID_INetCfgClassSetup, (void**)&pncClassSetup);
				if (hr == S_OK)
				{
					hr = pncClassSetup->DeInstall(pncc, &OboToken, NULL);
					if (hr == S_OK)
					{
						//
						// Apply the changes
						//

						hr = pnc->Apply();
					}

					ReleaseRef(pncClassSetup);
				}

				ReleaseRef(pncClass);
			}
		}

		ReleaseRef(pncc);
	}

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

BOOL RestartAllBindings(INetCfg *netcfg, PCWSTR name)
{
	HRESULT hr;
	CComPtr<INetCfgComponent> comp;
	CComPtr<INetCfgComponentBindings> bindings;

	hr = netcfg->FindComponent(name, &comp);
	if (FAILED(hr))
	{
		wprintf(L"INetCfg::FindComponent 0x%08x\n", hr);
		return FALSE;
	}

	hr = comp.QueryInterface(&bindings);
	if (FAILED(hr))
	{
		wprintf(L"QueryInterface(INetCfgComponentBindings) 0x%08x\n", hr);
		return FALSE;
	}

	CComPtr<IEnumNetCfgBindingPath> enumerator;
	hr = bindings->EnumBindingPaths(EBP_BELOW, &enumerator);
	if (FAILED(hr))
	{
		wprintf(L"INetCfgComponentBindings::EnumBindingPaths 0x%08x\n", hr);
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
			wprintf(L"IEnumNetCfgBindingPath::Next 0x%08x\n", hr);
			return FALSE;
		}

		PWSTR token = NULL;
		hr = path->GetPathToken(&token);
		if (FAILED(hr))
		{
			wprintf(L"INetCfgBindingPath::GetPathToken 0x%08x\n", hr);
			continue;
		}

		wprintf(L"Found binding %s\n", token);
		CoTaskMemFree(token);

		hr = path->IsEnabled();
		if (FAILED(hr))
		{
			wprintf(L"INetCfgBindingPath::IsEnabled 0x%08x\n", hr);
			continue;
		}

		if (S_FALSE == hr)
		{
			wprintf(L"\tPath is already disabled.  Skipping over it.\n");
			continue;
		}

		// Diable

		hr = path->Enable(FALSE);
		if (FAILED(hr))
		{
			wprintf(L"INetCfgBindingPath::Enable(FALSE) 0x%8x\n", hr);
			continue;
		}

		hr = netcfg->Apply();
		if (FAILED(hr))
		{
			wprintf(L"INetCfg::Apply 0x%08x\n", hr);
			return FALSE;
		}

		wprintf(L"\tPath disabled\n");

		// Enable

		hr = path->Enable(TRUE);
		if (FAILED(hr))
		{
			wprintf(L"INetCfgBindingPath::Enable(TRUE) 0x%8x\n", hr);
			return FALSE;
		}

		hr = netcfg->Apply();
		if (FAILED(hr))
		{
			wprintf(L"INetCfg::Apply 0x%08x\n", hr);
			return FALSE;
		}

		wprintf(L"\tPath enabled\n");
	}



	return TRUE;
}

BOOL ConnectToNetCfg(PCWSTR name)
{
	HRESULT hr;
	CComPtr<INetCfg> netcfg;
	CComPtr<INetCfgLock> lock;

	// Before we can get started, we need to do some initialization work.

	hr = netcfg.CoCreateInstance(CLSID_CNetCfg);
	if (FAILED(hr))
	{
		wprintf(L"CoCreateInstance(CLSID_CNetCfg 0x%08x\n", hr);
		return FALSE;
	}

	hr = netcfg.QueryInterface(&lock);
	if (FAILED(hr))
	{
		wprintf(L"QueryInterface(INetCfgLock) 0x%08x\n", hr);
		return FALSE;
	}

	// Note that this call can block.
	hr = lock->AcquireWriteLock(INFINITE, APP_NAME, NULL);
	if (FAILED(hr))
	{
		wprintf(L"INetCfgLock::AcquireWriteLock 0x%08x\n", hr);
		return FALSE;
	}

	hr = netcfg->Initialize(NULL);
	if (FAILED(hr))
	{
		wprintf(L"INetCfg::Initialize 0x%08x\n", hr);
		return FALSE;
	}

	BOOL ok = RestartAllBindings(netcfg.p, name);

	hr = netcfg->Uninitialize();
	if (FAILED(hr))
	{
		wprintf(L"INetCfg::Uninitialize 0x%08x\n", hr);
	}

	hr = lock->ReleaseWriteLock();
	if (FAILED(hr))
	{
		wprintf(L"INetCfgLock::ReleaseWriteLock 0x%08x\n", hr);
	}

	return ok;
}