#pragma warning(disable: 4311 4312)

#include <tchar.h>
#include <windows.h>

#include "ProtInstall.h"
#include "LoopbackInstall.h"
#include "CalloutInstall.h"

BOOL PacketInstallDriver60();
BOOL PacketStopDriver60();
BOOL PacketInstallDriver40();
BOOL PacketStopDriver40();

#define STR_COMMAND_USAGE _T("Command Usage: NPFInstall -[i/u/r/ii/uu]: i - install win7 driver, u - uninstall win7 driver, r - restartBindings, ii - install xp driver, uu - uninstall xp driver, il - install Npcap loopback adapter, ul - uninstall Npcap loopback adapter, iw - install WFP callout driver, uw - uninstall WFP callout driver.\n")

BOOL PacketIsServiceStopPending()
{
	BOOL bResult = FALSE;
	SERVICE_STATUS_PROCESS ssp;
	DWORD dwStartTime = GetTickCount();
	DWORD dwBytesNeeded;
	DWORD dwTimeout = 30000; // 30-second time-out
	DWORD dwWaitTime;

	// Get a handle to the SCM database.

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database
		SC_MANAGER_ALL_ACCESS);  // full access rights

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database
		_T(NPF_DRIVER_NAME_SMALL),            // name of service
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Make sure the service is not already stopped.

	if ( !QueryServiceStatusEx(
		schService,
		SC_STATUS_PROCESS_INFO,
		(LPBYTE)&ssp,
		sizeof(SERVICE_STATUS_PROCESS),
		&dwBytesNeeded ) )
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetLastError());
		goto stop_cleanup;
	}

	if ( ssp.dwCurrentState == SERVICE_STOPPED )
	{
		printf("Service is already stopped.\n");
		goto stop_cleanup;
	}

	if (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		bResult = TRUE;
	}

stop_cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return bResult;
}

BOOL PacketInstallDriver60()
{
	BOOL result = FALSE;

	result = (BOOL) InstallDriver();

	return result;
}

BOOL PacketStopDriver60()
{
	BOOL result;

	result = (BOOL) UninstallDriver();

	return result;
}

BOOL PacketInstallDriver40()
{
	PacketStopDriver40();

	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL)
	{
		return FALSE;
	}

	TCHAR szFileFullPath[_MAX_PATH];
	DWORD nResult = GetServiceSysFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		return FALSE;
	}

	SC_HANDLE schService = CreateService(schSCManager, _T(NPF_DRIVER_NAME_SMALL), NPF_SERVICE_DESC_TCHAR,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		szFileFullPath,
		NULL, NULL, NULL, NULL, NULL);
	if (schService == NULL)
	{
		int aaa = GetLastError();
		return FALSE;
	}

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);

	return TRUE;
}

BOOL PacketStopDriver40()
{
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL)
	{
		return FALSE;
	}

	SC_HANDLE schService = OpenService(schSCManager, _T(NPF_DRIVER_NAME_SMALL), SERVICE_ALL_ACCESS | DELETE);
	if (schService == NULL)
	{
		return FALSE;
	}

	DeleteService(schService);

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService); 
	return TRUE;
}

BOOL PacketRenableBindings()
{
	BOOL result;

	result = (BOOL) RenableBindings();

	return result;
}

int _tmain(int argc, _TCHAR* argv[])
{
	BOOL bSuccess = FALSE;
	BOOL bVerbose = FALSE;

	SetConsoleTitle(NPF_SERVICE_DESC_TCHAR _T(" for packet capturing"));

	if (argc >= 2)
	{
		if (_tcscmp(_T("-h"), argv[1]) == 0)
		{
			bVerbose = TRUE;
		}
	}

	if (argc >= 3)
	{
		if (_tcscmp(_T("-v"), argv[2]) == 0)
		{
			bVerbose = TRUE;
		}
		else
		{
			_tprintf(STR_COMMAND_USAGE);
			return -1;
		}
	}

	if (!bVerbose)
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	if (argc < 2)
	{
		_tprintf(STR_COMMAND_USAGE);
		return -1;
	}
	else //argc == 2
	{
		if (_tcscmp(_T("-i"), argv[1]) == 0)
		{
			bSuccess = PacketInstallDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver has failed the installation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-u"), argv[1]) == 0)
		{
			bSuccess = PacketStopDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully uninstalled!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver has failed the uninstallation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-ii"), argv[1]) == 0)
		{
			bSuccess = PacketInstallDriver40();
			if (bSuccess)
			{
				_tprintf(_T("NPF legacy driver has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("NPF legacy driver has failed the installation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-uu"), argv[1]) == 0)
		{
			bSuccess = PacketStopDriver40();
			if (bSuccess)
			{
				_tprintf(_T("NPF legacy driver has been successfully uninstalled!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("NPF legacy driver has failed the uninstallation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-il"), argv[1]) == 0)
		{
			bSuccess = InstallLoopbackAdapter();
			if (bSuccess)
			{
				_tprintf(_T("Npcap Loopback adapter has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap Loopback adapter has failed the installation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-ul"), argv[1]) == 0)
		{
			bSuccess = UninstallLoopbackAdapter();
			if (bSuccess)
			{
				_tprintf(_T("Npcap Loopback adapter has been successfully uninstalled!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap Loopback adapter has failed the uninstallation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-iw"), argv[1]) == 0)
		{
			bSuccess = InstallWFPCallout();
			if (bSuccess)
			{
				_tprintf(_T("Npcap WFP callout driver has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap WFP callout driver has failed the installation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-uw"), argv[1]) == 0)
		{
			bSuccess = UninstallWFPCallout();
			if (bSuccess)
			{
				_tprintf(_T("Npcap WFP callout driver has been successfully uninstalled!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap WFP callout driver has failed the uninstallation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-r"), argv[1]) == 0)
		{
			bSuccess = PacketRenableBindings();
			if (bSuccess)
			{
				_tprintf(_T("Npcap driver's bindings have been successfully restarted!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap driver's bindings have failed to restart."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-d"), argv[1]) == 0)
		{
			bSuccess = PacketIsServiceStopPending();
			if (bSuccess)
			{
				_tprintf(_T("Npcap service is pending to stop!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap service is not pending to stop."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-h"), argv[1]) == 0)
		{
			_tprintf(STR_COMMAND_USAGE);
			return -1;
		}
		else
		{
			_tprintf(_T("Invalid parameter, type in \"NPFInstall -h\" for help.\n"));
			return -1;
		}
	}

	return 0;
}