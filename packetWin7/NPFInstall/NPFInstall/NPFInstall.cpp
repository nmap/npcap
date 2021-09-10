/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
#include <tchar.h>
#include <windows.h>

#include "..\..\..\version.h"

#include "ProtInstall.h"
#include "LoopbackInstall.h"
#include "CalloutInstall.h"
#include "DriverStoreClear.h"
#include "RegUtil.h"
#include "ProcessUtil.h"
#include <Netcfgx.h>

#include "debug.h"

extern BOOLEAN bWiFiService;

#define STR_COMMAND_USAGE \
_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" ( http://npcap.org )\n") \
_T("Usage: NPFInstall [Options]\n") \
_T("\n") \
_T("OPTIONS:\n") \
_T("  -i\t\t\t: Install the LWF driver\n") \
_T("  -i2\t\t\t: Install the LWF driver (with Wi-Fi support)\n") \
_T("  -u\t\t\t: Uninstall the LWF driver\n") \
_T("  -u2\t\t\t: Uninstall the LWF driver (with Wi-Fi support)\n") \
_T("  -iw\t\t\t: Install the WFP callout driver\n") \
_T("  -uw\t\t\t: Uninstall the WFP callout driver\n") \
_T("  -il\t\t\t: Install \"Npcap loopback adapter\"\n") \
_T("  -ul\t\t\t: Uninstall \"Npcap loopback adapter\"\n") \
_T("  -r\t\t\t: Restart all bindings\n") \
_T("  -r2\t\t\t: Restart all bindings (with Wi-Fi support)\n") \
_T("  -check_dll\t\t: Detect whether the Npcap DLLs are still used by any processes, will list them if yes\n") \
_T("  -kill_proc\t\t: Terminate all the processes that are still using Npcap DLLs\n") \
_T("  -kill_proc_soft\t: Gracefully terminate all the processes that are still using Npcap DLLs (only for GUI processes, CLI processes will not be terminated)\n") \
_T("  -kill_proc_polite\t: Politely terminate all the processes that are still using Npcap DLLs (wait for 15 seconds for GUI processes to close themselves, CLI processes will still be terminiated immediatelly)\n") \
_T("  -c\t\t\t: Clear all the driverstore cache for the driver\n") \
_T("  -n\t\t\t: Hide this window when executing the command\n") \
_T("  -h\t\t\t: Print this help summary page\n") \
_T("\n") \
_T("EXAMPLES:\n") \
_T("  NPFInstall -i\n") \
_T("  NPFInstall -iw\n") \
_T("\n") \
_T("SEE THE MAN PAGE (https://github.com/nmap/npcap) FOR MORE OPTIONS AND EXAMPLES\n")

#define STR_INVALID_PARAMETER _T("Error: invalid parameter, type in \"NPFInstall -h\" for help.\n")

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
			BOOL first_try = TRUE;
		tryagain_i:
			bWiFiService = FALSE;
			bSuccess = InstallDriver();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				if (err == NETCFG_S_REBOOT) {
					_tprintf(_T("Npcap LWF driver will be installed after reboot.\n"));
					nStatus = err;
					goto _EXIT;
				}
				if (err == NETCFG_E_MAX_FILTER_LIMIT) {
					_tprintf(_T("Too many filters installed!\n"));
					if (first_try && IncrementRegistryDword(_T("SYSTEM\\CurrentControlSet\\Control\\Network"), _T("MaxNumFilters"), 14))
					{
						first_try = FALSE;
						goto tryagain_i;
					}
				}
				else {
					_tprintf(_T("Unknown error! %x\n"), err);
				}
				_tprintf(_T("Npcap LWF driver has failed to be installed.\n"));
				nStatus = err ? err : -1;
				goto _EXIT;
			}
		}
		if (strArgs[1] == _T("-i2"))
		{
			BOOL first_try = TRUE;
		tryagain_i2:
			bWiFiService = TRUE;
			bSuccess = InstallDriver();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has been successfully installed!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				if (err == NETCFG_S_REBOOT) {
					_tprintf(_T("Npcap LWF driver (with Wi-Fi support) will be installed after reboot.\n"));
					nStatus = err;
					goto _EXIT;
				}
				if (err == NETCFG_E_MAX_FILTER_LIMIT) {
					_tprintf(_T("Too many filters installed!\n"));
					if (first_try && IncrementRegistryDword(_T("SYSTEM\\CurrentControlSet\\Control\\Network"), _T("MaxNumFilters"), 14))
					{
						first_try = FALSE;
						goto tryagain_i2;
					}
				}
				else {
					_tprintf(_T("Unknown error! %x\n"), err);
				}
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has failed to be installed.\n"));
				nStatus = err ? err : -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-u"))
		{
			bWiFiService = FALSE;
			bSuccess = UninstallDriver();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				_tprintf(_T("Npcap LWF driver has failed to be uninstalled.\n"));
				nStatus = err ? err : -1;
				goto _EXIT;
			}
		}
		else if (strArgs[1] == _T("-u2"))
		{
			bWiFiService = TRUE;
			bSuccess = UninstallDriver();
			if (bSuccess)
			{
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has been successfully uninstalled!\n"));
				nStatus = 0;
				goto _EXIT;
			}
			else
			{
				DWORD err = GetLastError();
				_tprintf(_T("Npcap LWF driver (with Wi-Fi support) has failed to be uninstalled.\n"));
				nStatus = err ? err : 1;
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("The bindings of Npcap driver have failed to be restarted.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("The bindings of Npcap driver (with Wi-Fi support) have failed to be restarted.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("Npcap Loopback adapter has failed to be installed.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("Npcap Loopback adapter has failed to be uninstalled.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("Npcap WFP callout driver has failed to be installed.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("Npcap WFP callout driver has failed to be uninstalled.\n"));
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
				DWORD err = GetLastError();
				nStatus = err ? err : 1;
				_tprintf(_T("Npcap driver cache in Driver Store has failed to be cleaned up.\n"));
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
