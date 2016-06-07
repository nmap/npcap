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
_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" ( http://npcap.org )\n")\
_T("Usage: NPFInstall [Options]\n")\
_T("\n")\
_T("OPTIONS:\n")\
_T("  -i\t\t\t: Install the LWF driver (non Wi-Fi version)\n")\
_T("  -i2\t\t\t: Install the LWF driver (Wi-Fi version)\n")\
_T("  -u\t\t\t: Uninstall the LWF driver\n")\
_T("  -iw\t\t\t: Install the WFP callout driver\n")\
_T("  -uw\t\t\t: Uninstall the WFP callout driver\n")\
_T("  -il\t\t\t: Install \"Npcap loopback adapter\"\n")\
_T("  -ul\t\t\t: Uninstall \"Npcap loopback adapter\"\n")\
_T("  -ii\t\t\t: Install the legacy driver (for XP)\n")\
_T("  -uu\t\t\t: Uninstall the legacy driver (for XP)\n")\
_T("  -r\t\t\t: Restart all bindings\n")\
_T("  -d\t\t\t: Detect whether the driver service is pending to stop\n")\
_T("  -c\t\t\t: Clear all the driverstore cache for the driver\n")\
_T("  -wlan_check\t\t: Check whether this machine owns a wireless adapter\n")\
_T("  -wlan_write_reg\t: Write the names of all wireless adapters to registry\n")\
_T("  -n\t\t\t: Hide this window when executing the command\n")\
_T("  -h\t\t\t: Print this help summary page\n")\
_T("\n")\
_T("EXAMPLES:\n")\
_T("  NPFInstall -i\n")\
_T("  NPFInstall -iw\n")\
_T("\n")\
_T("SEE THE MAN PAGE (https://github.com/nmap/npcap) FOR MORE OPTIONS AND EXAMPLES\n")

#define STR_INVALID_PARAMETER _T("Error: invalid parameter, type in \"NPFInstall -h\" for help.\n")

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
	BOOL bNoWindow = FALSE;

	SetConsoleTitle(_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" (http://npcap.org)"));
	vector<tstring> strArgs;
	tstring strTmp;
	for (int i = 0; i < argc; i++)
	{
		strTmp = argv[i];
		if (strTmp == _T("-n"))
		{
			bNoWindow = TRUE;
		}
		else
		{
			strArgs.push_back(strTmp);
		}
	}

	if (bNoWindow)
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	if (strArgs.size() == 1)
	{
		_tprintf(STR_COMMAND_USAGE);
		return -1;
	}
	else if (strArgs.size() >= 3)
	{
		_tprintf(STR_INVALID_PARAMETER);
		return -1;
	}
	else //strArgs.size() == 2
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
				_tprintf(_T("Npcap LWF driver (standard version) has failed to be installed.\n"));
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
				_tprintf(_T("Npcap LWF driver (WiFi version) has failed to be installed.\n"));
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
				_tprintf(_T("Npcap LWF driver has failed to be uninstalled.\n"));
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
				_tprintf(_T("NPF legacy driver has failed to be installed.\n"));
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
				_tprintf(_T("NPF legacy driver has failed to be uninstalled.\n"));
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
				_tprintf(_T("Npcap Loopback adapter has failed to be installed.\n"));
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
				_tprintf(_T("Npcap Loopback adapter has failed to be uninstalled.\n"));
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
				_tprintf(_T("Npcap WFP callout driver has failed to be installed.\n"));
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
				_tprintf(_T("Npcap WFP callout driver has failed to be uninstalled.\n"));
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
				_tprintf(_T("Npcap driver's bindings have failed to be restarted.\n"));
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
				_tprintf(_T("Npcap service is not pending to stop.\n"));
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
				_tprintf(_T("Npcap driver cache in Driver Store has failed to be cleaned up.\n"));
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
		else if (strArgs[1] == _T("-wlan_write_reg"))
		{
			bSuccess = writeWlanAdapterGuidsToRegistry();
			if (bSuccess)
			{
				_tprintf(_T("Wlan adapters have been successfully written to registry!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("Wlan adapters have failed to be written to registry.\n"));
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
			_tprintf(STR_INVALID_PARAMETER);
			return -1;
		}
	}

	return 0;
}