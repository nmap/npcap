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
#pragma warning(disable: 4311 4312)

#include <tchar.h>
#include <windows.h>

#include "..\..\..\version.h"

#include "ProtInstall.h"
#include "LoopbackInstall.h"
#include "CalloutInstall.h"
#include "DriverStoreClear.h"
#include "WlanRecord.h"
#include "RegUtil.h"
#include "ProcessUtil.h"
#include <Netcfgx.h>

#include "debug.h"

extern BOOLEAN bWiFiService;

BOOL PacketInstallDriver60();
BOOL PacketStopDriver60();
BOOL PacketInstallDriver40();
BOOL PacketStopDriver40();

#define STR_COMMAND_USAGE \
_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" ( http://npcap.org )\n")\
_T("Usage: NPFInstall [Options]\n")\
_T("\n")\
_T("OPTIONS:\n")\
_T("  -i\t\t\t: Install the LWF driver\n")\
_T("  -i2\t\t\t: Install the LWF driver (with Wi-Fi support)\n")\
_T("  -u\t\t\t: Uninstall the LWF driver\n")\
_T("  -u2\t\t\t: Uninstall the LWF driver (with Wi-Fi support)\n")\
_T("  -iw\t\t\t: Install the WFP callout driver\n")\
_T("  -uw\t\t\t: Uninstall the WFP callout driver\n")\
_T("  -il\t\t\t: Install \"Npcap loopback adapter\"\n")\
_T("  -ul\t\t\t: Uninstall \"Npcap loopback adapter\"\n")\
_T("  -ii\t\t\t: Install the legacy driver (for XP)\n")\
_T("  -uu\t\t\t: Uninstall the legacy driver (for XP)\n")\
_T("  -r\t\t\t: Restart all bindings\n")\
_T("  -r2\t\t\t: Restart all bindings (with Wi-Fi support)\n")\
_T("  -d\t\t\t: Detect whether the driver service is pending to stop\n")\
_T("  -check_dll\t\t: Detect whether the Npcap DLLs are still used by any processes, will list them if yes\n")\
_T("  -kill_proc\t\t: Terminate all the processes that are still using Npcap DLLs\n")\
_T("  -kill_proc_soft\t: Gracefully terminate all the processes that are still using Npcap DLLs (only for GUI processes, CLI processes will not be terminated)\n")\
_T("  -kill_proc_polite\t: Politely terminate all the processes that are still using Npcap DLLs (wait for 15 seconds for GUI processes to close themselves, CLI processes will still be terminiated immediatelly)\n")\
_T("  -c\t\t\t: Clear all the driverstore cache for the driver\n")\
_T("  -wlan_check\t\t: Check whether this machine owns a wireless adapter\n")\
_T("  -wlan_write_reg\t: Write the names of all wireless adapters to registry\n")\
_T("  -add_path\t\t: Add Npcap folder to the PATH environment variable\n")\
_T("  -remove_path\t\t: Remove Npcap folder from the PATH environment variable\n")\
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
	TRACE_ENTER();

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
		TRACE_PRINT1("OpenSCManager failed (0x%08x)", GetLastError());
		TRACE_EXIT();
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
		TRACE_PRINT1("OpenService failed (0x%08x)", GetLastError());
		CloseServiceHandle(schSCManager);
		TRACE_EXIT();
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
		TRACE_PRINT1("QueryServiceStatusEx failed (0x%08x)", GetLastError());
		goto stop_cleanup;
	}

	if ( ssp.dwCurrentState == SERVICE_STOPPED )
	{
		TRACE_PRINT("Service is already stopped.");
		goto stop_cleanup;
	}

	if (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		bResult = TRUE;
	}

stop_cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	TRACE_EXIT();
	return bResult;
}

BOOL PacketInstallDriver60()
{
	TRACE_ENTER();
	BOOL result = FALSE;

	result = (BOOL) InstallDriver();

	TRACE_EXIT();
	return result;
}

BOOL PacketStopDriver60()
{
	TRACE_ENTER();
	BOOL result;

	result = (BOOL) UninstallDriver();

	TRACE_EXIT();
	return result;
}

BOOL PacketInstallDriver40()
{
	TRACE_ENTER();

	PacketStopDriver40();

	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL)
	{
		TRACE_EXIT();
		return FALSE;
	}

	TCHAR szFileFullPath[_MAX_PATH];
	DWORD nResult = GetServiceSysFilePath(szFileFullPath, MAX_PATH);
	if (nResult == 0)
	{
		TRACE_EXIT();
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
		TRACE_EXIT();
		return FALSE;
	}

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService);

	TRACE_EXIT();
	return TRUE;
}

BOOL PacketStopDriver40()
{
	TRACE_ENTER();

	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager == NULL)
	{
		TRACE_EXIT();
		return FALSE;
	}

	SC_HANDLE schService = OpenService(schSCManager, _T(NPF_DRIVER_NAME_SMALL), SERVICE_ALL_ACCESS | DELETE);
	if (schService == NULL)
	{
		TRACE_EXIT();
		return FALSE;
	}

	DeleteService(schService);

	CloseServiceHandle(schSCManager);
	CloseServiceHandle(schService); 

	TRACE_EXIT();
	return TRUE;
}

BOOL PacketRenableBindings()
{
	BOOL result;

	TRACE_ENTER();

	result = (BOOL) RenableBindings();

	TRACE_EXIT();
	return result;
}

int _tmain(int argc, _TCHAR* argv[])
{
	TRACE_ENTER();

	BOOL bSuccess = FALSE;
	BOOL bNoWindow = FALSE;
	int nStatus = 0;

	SetConsoleTitle(_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" (http://npcap.org)"));
	vector<tstring> strArgs;
	tstring strTmp;
	for (int i = 0; i < argc; i++)
	{
		strTmp = argv[i];
		TRACE_PRINT2("_tmain: executing, argv[%d] = %s.", i, argv[i]);
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
		nStatus = 0;
		goto _EXIT;

	}
	else if (strArgs.size() >= 3)
	{
		_tprintf(STR_INVALID_PARAMETER);
		nStatus = -1;
		goto _EXIT;
	}
	else //strArgs.size() == 2
	{
		if (strArgs[1] == _T("-i"))
		{
			bWiFiService = FALSE;
			bSuccess = PacketInstallDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				if (err == NETCFG_E_MAX_FILTER_LIMIT) {
					_tprintf(_T("Too many filters installed!\n"));
				}
				else {
					_tprintf(_T("Unknown error! %x\n"), err);
				}
				_tprintf(_T("Npcap LWF driver has failed to be installed.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		if (strArgs[1] == _T("-i2"))
		{
			bWiFiService = TRUE;
			bSuccess = PacketInstallDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				if (err == NETCFG_E_MAX_FILTER_LIMIT) {
					_tprintf(_T("Too many filters installed!\n"));
				}
				else {
					_tprintf(_T("Unknown error! %x\n"), err);
				}
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has failed to be installed.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-u"))
		{
			bWiFiService = FALSE;
			bSuccess = PacketStopDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver has failed to be uninstalled.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-u2"))
		{
			bWiFiService = TRUE;
			bSuccess = PacketStopDriver60();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has failed to be uninstalled.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-r"))
		{
			bWiFiService = FALSE;
			bSuccess = PacketRenableBindings();
			if (bSuccess)
			{
				_tprintf(_T("The bindings of Npcap driver have been successfully restarted!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("The bindings of Npcap driver have failed to be restarted.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-r2"))
		{
			bWiFiService = TRUE;
			bSuccess = PacketRenableBindings();
			if (bSuccess)
			{
				_tprintf(_T("The bindings of Npcap driver (with Wi-Fi support) have been successfully restarted!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("The bindings of Npcap driver (with Wi-Fi support) have failed to be restarted.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-ii"))
		{
			bSuccess = PacketInstallDriver40();
			if (bSuccess)
			{
				_tprintf(_T("NPF legacy driver has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("NPF legacy driver has failed to be installed.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-uu"))
		{
			bSuccess = PacketStopDriver40();
			if (bSuccess)
			{
				_tprintf(_T("NPF legacy driver has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("NPF legacy driver has failed to be uninstalled.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-il"))
		{
			bSuccess = InstallLoopbackAdapter();
			if (bSuccess)
			{
				_tprintf(_T("Npcap Loopback adapter has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap Loopback adapter has failed to be installed.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-ul"))
		{
			bSuccess = UninstallLoopbackAdapter();
			if (bSuccess)
			{
				_tprintf(_T("Npcap Loopback adapter has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap Loopback adapter has failed to be uninstalled.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-iw"))
		{
			bSuccess = InstallWFPCallout();
			if (bSuccess)
			{
				_tprintf(_T("Npcap WFP callout driver has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap WFP callout driver has failed to be installed.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-uw"))
		{
			bSuccess = UninstallWFPCallout();
			if (bSuccess)
			{
				_tprintf(_T("Npcap WFP callout driver has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap WFP callout driver has failed to be uninstalled.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-d"))
		{
			bSuccess = PacketIsServiceStopPending();
			if (bSuccess)
			{
				_tprintf(_T("Npcap service is pending to stop!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap service is not pending to stop.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-check_dll"))
		{
			tstring strInUseProcesses = getInUseProcesses();
			if (strInUseProcesses == _T(""))
			{
				_tprintf(_T("<NULL>\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("%s\n"), strInUseProcesses.c_str());
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-kill_proc"))
		{
			bSuccess = killInUseProcesses();
			if (bSuccess)
			{
				_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-kill_proc_soft"))
		{
			bSuccess = killInUseProcesses_Soft();
			if (bSuccess)
			{
				_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated gracefully!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated gracefully.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-kill_proc_polite"))
		{
			bSuccess = killInUseProcesses_Polite();
			if (bSuccess)
			{
				_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated politely!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated politely.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-c"))
		{
			bSuccess = ClearDriverStore();
			if (bSuccess)
			{
				_tprintf(_T("Npcap driver cache in Driver Store has been successfully cleaned up!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap driver cache in Driver Store has failed to be cleaned up.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-wlan_check"))
		{
			vector<tstring> nstrAdapterGuids;
			nstrAdapterGuids = getWlanAdapterGuids();
			if (nstrAdapterGuids.size() != 0)
			{
				_tprintf(_T("Wlan adapters: %s\n"), printArray(nstrAdapterGuids).c_str());
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Wlan adapters: NULL\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-wlan_write_reg"))
		{
			bSuccess = writeWlanAdapterGuidsToRegistry();
			if (bSuccess)
			{
				_tprintf(_T("Wlan adapters have been successfully written to registry!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Wlan adapters have failed to be written to registry.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-add_path"))
		{
			bSuccess = addNpcapFolderToPath();
			if (bSuccess)
			{
				_tprintf(_T("Npcap folder has been successfully added to PATH!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap folder has failed to be added to PATH.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-remove_path"))
		{
			bSuccess = removeNpcapFolderFromPath();
			if (bSuccess)
			{
				_tprintf(_T("Npcap folder has been successfully removed from PATH!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				_tprintf(_T("Npcap folder has failed to be removed from PATH.\n"));
				nStatus = -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-h"))
		{
			_tprintf(STR_COMMAND_USAGE);
			nStatus = 0;
			goto _EXIT;
		}
		else
		{
			_tprintf(STR_INVALID_PARAMETER);
			nStatus = -1;
			goto _EXIT;
		}
	}

_EXIT:
	if (nStatus == 0)
	{
		TRACE_PRINT1("_tmain: succeed, nStatus = %d.", nStatus);
	}
	else
	{
		TRACE_PRINT1("_tmain: error, nStatus = %d.", nStatus);
	}
	TRACE_EXIT();
	return nStatus;
}
