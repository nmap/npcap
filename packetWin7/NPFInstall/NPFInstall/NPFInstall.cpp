#pragma warning(disable: 4311 4312)

#include <tchar.h>
#include <windows.h>

#include "..\..\..\version.h"

#include "ProtInstall.h"
#include "LoopbackInstall.h"
#include "CalloutInstall.h"
#include "DriverStoreClear.h"
#include "WlanRecord.h"

BOOL PacketInstallDriver60(BOOL bWifiOrNormal);
BOOL PacketStopDriver60();
BOOL PacketInstallDriver40();
BOOL PacketStopDriver40();

#define STR_COMMAND_USAGE \
_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" (http://npcap.org)\n")\
_T("Usage: NPFInstall [Options]\n")\
_T("Options:\n")\
_T("  -i: install win7 driver\n")\
_T("  -u: uninstall win7 driver\n")\
_T("  -r: restartBindings\n")\
_T("  -ii: install xp driver\n")\
_T("  -uu: uninstall xp driver\n")\
_T("  -il: install Npcap loopback adapter\n")\
_T("  -ul: uninstall Npcap loopback adapter\n")\
_T("  -iw: install WFP callout driver\n")\
_T("  -uw: uninstall WFP callout driver\n")\
_T("\n")\
_T("See the MAN Page (https://github.com/nmap/npcap) for more options and examples\n")

BOOL PacketIsServiceStopPending()
{
	BOOL bResult = FALSE;
	SERVICE_STATUS_PROCESS ssp;
	DWORD dwStartTime = GetTickCount();
	DWORD dwBytesNeeded;
	DWORD dwTimeout = 30000; // 30-second time-out
	// DWORD dwWaitTime;

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

BOOL PacketInstallDriver60(BOOL bWifiOrNormal)
{
	BOOL result = FALSE;

	result = (BOOL) InstallDriver(bWifiOrNormal);

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
	vector<tstring> strArgs;
	for (int i = 0; i < argc; i++)
	{
		strArgs.push_back(argv[i]);
	}

	if (argc >= 2)
	{
		if (strArgs[1] == _T("-v"))
		{
			bVerbose = TRUE;
		}
	}

	if (argc >= 3)
	{
		if (strArgs[2] == _T("-v"))
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
		if (strArgs[1] == _T("-i"))
		{
			bSuccess = PacketInstallDriver60(FALSE);
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (standard version) has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver (standard version) has failed the installation."));
				return -1;
			}
		}
		else if (strArgs[1] == _T("-i2"))
		{
			bSuccess = PacketInstallDriver60(TRUE);
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (WiFi version) has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver (WiFi version) has failed the installation."));
				return -1;
			}
		}
		else if (strArgs[1] == _T("-u"))
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
		else if (strArgs[1] == _T("-ii"))
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
		else if (strArgs[1] == _T("-uu"))
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
		else if (strArgs[1] == _T("-il"))
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
		else if (strArgs[1] == _T("-ul"))
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
		else if (strArgs[1] == _T("-iw"))
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
		else if (strArgs[1] == _T("-uw"))
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
		else if (strArgs[1] == _T("-r"))
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
		else if (strArgs[1] == _T("-d"))
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
		else if (strArgs[1] == _T("-c"))
		{
			bSuccess = ClearDriverStore();
			if (bSuccess)
			{
				_tprintf(_T("Npcap driver cache in Driver Store has been successfully cleaned up!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Npcap driver cache in Driver Store has failed the cleanning up."));
				return -1;
			}
		}
		else if (strArgs[1] == _T("-wlan_check"))
		{
			vector<tstring> nstrAdapterGuids;
			nstrAdapterGuids = getWlanAdapterGuids();
			if (nstrAdapterGuids.size() != 0)
			{
				_tprintf(_T("Wlan adapters: %s\n"), printArray(nstrAdapterGuids).c_str());
				return 0;
			}
			else
			{
				_tprintf(_T("Wlan adapters: NULL\n"));
				return -1;
			}
		}
		else if (strArgs[1] == _T("-h"))
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