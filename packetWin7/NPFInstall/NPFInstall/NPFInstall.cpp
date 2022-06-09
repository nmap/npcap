/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library
 * and is copyright (c) 2013-2022 by Nmap Software LLC ("The Nmap Project").
 * All rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it
 * is not open source software and may not be redistributed or used in
 * other software without special permission from the Nmap
 * Project. The standard (free) version is usually limited to
 * installation on five systems. For more details, see the LICENSE
 * file included with Npcap and also avaialble at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not
 * a substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap
 * OEM within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may
 * choose between a perpetual unlimited license or a quarterly term license,
 * along with options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to
 * use Npcap OEM internally, without redistribution outside their
 * organization. This allows them to bypass the 5-system usage cap of the
 * Npcap free edition. It includes commercial support and update options, and
 * provides the extra Npcap OEM features such as the silent installer for
 * automated deployment. Prices and details:
 * https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a
 * warranty. Npcap OEM also includes a silent installer for unattended
 * installation. Further details about Npcap OEM are available from
 * https://npcap.com/oem/, and you are also welcome to contact us at
 * sales@nmap.com to ask any questions or set up a license for your
 * organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will
 * be free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial
 * licensing customers) has granted you additional rights to Npcap or
 * Npcap OEM, those additional rights take precedence where they
 * conflict with the terms of the license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features.  By
 * sending these changes to the Nmap Project (including through direct email
 * or our mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap.  If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights and commercial
 * support are available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license
 * header. We have kept those for attribution purposes, but any license terms
 * granted by those notices apply only to their original work, and not to any
 * changes made by the Nmap Project or to this entire file.
 *
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
_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" ( https://npcap.com )\n") \
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

static int trace_exit(_In_ int nStatus)
{
	TRACE_PRINT2("<-- _tmain: %s, nStatus = %d.", nStatus == 0 ? _T("succeed") : _T("error"), nStatus);
	return nStatus;
}

int _tmain(int argc, _TCHAR* argv[])
{
	TRACE_ENTER();

	BOOL bSuccess = FALSE;
	BOOL bNoWindow = FALSE;
	int nStatus = 0;

	SetConsoleTitle(_T("NPFInstall for Npcap ") _T(WINPCAP_VER_STRING) _T(" (https://npcap.com)"));
	bWiFiService = FALSE;
	PTSTR theArg = NULL;

	if (argc <= 1 || argc > 3)
	{
		_tprintf(STR_COMMAND_USAGE);
		return trace_exit(0);
	}

	for (int i = 1; i < argc; i++)
	{
		TRACE_PRINT2("_tmain: executing, argv[%d] = %s.", i, argv[i]);
		if (argv[i][0] == _T('-')) {
			if (argv[i][1] == _T('n') && argv[i][2] == _T('\0')) {
				// -n
				bNoWindow = TRUE;
			}
			else if (argv[i][1] != _T('\0')) {
				if (theArg != NULL) {
					// only one command at a time!
					nStatus = -1;
					break;
				}
				theArg = argv[i];
				if (theArg[2] == _T('2') && theArg[3] == _T('\0')) {
					// -i2, -r2, etc.
					bWiFiService = TRUE;
					theArg[2] = _T('\0');
				}
			}
		}
	}

	if (bNoWindow)
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	if (!theArg || nStatus != 0)
	{
		_tprintf(STR_INVALID_PARAMETER);
		return trace_exit(-1);
	}

	// Guaranteed theArg starts with '-' now
	switch (theArg[1]) {
		case _T('i'):
			if (theArg[2] == _T('\0')) {
				// -i or -i2
				BOOL first_time = TRUE;
				BOOL try_again = FALSE;
				do {
					try_again = FALSE;
					if (InstallDriver())
					{
						_tprintf(_T("%s has been successfully installed!\n"),
								bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
						break;
					}

					const DWORD err = GetLastError();
					if (err == NETCFG_S_REBOOT) {
						_tprintf(_T("%s will be installed after reboot.\n"),
								bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
						nStatus = err;
					}
					else if (first_time && err == NETCFG_E_MAX_FILTER_LIMIT) {
						_tprintf(_T("Too many filters installed!\n"));
						if (IncrementRegistryDword(_T("SYSTEM\\CurrentControlSet\\Control\\Network"), _T("MaxNumFilters"), 14))
						{
							try_again = TRUE;
						}
						else {
							_tprintf(_T("Failed to increment MaxNumFilters: %x\n"), GetLastError());
						}
					}
					else {
						_tprintf(_T("Unknown error! %x\n"), err);
						_tprintf(_T("%s has failed to be installed.\n"),
								bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
						nStatus = err ? err : -1;
					}
					first_time = FALSE;
				} while (try_again);
			}
			else if (theArg[3] == _T('\0')) {
				switch (theArg[2]) {
					case _T('l'):
						if (InstallLoopbackAdapter())
						{
							_tprintf(_T("Npcap Loopback adapter has been successfully installed!\n"));
						}
						else
						{
							const DWORD err = GetLastError();
							_tprintf(_T("Npcap Loopback adapter has failed to be installed.\n"));
							nStatus = err ? err : 1;
						}
						break;
					case _T('w'):
						if (InstallWFPCallout())
						{
							_tprintf(_T("Npcap WFP callout driver has been successfully installed!\n"));
						}
						else
						{
							const DWORD err = GetLastError();
							_tprintf(_T("Npcap WFP callout driver has failed to be installed.\n"));
							nStatus = err ? err : 1;
						}
						break;
					default:
						_tprintf(STR_INVALID_PARAMETER);
						nStatus = -1;
						break;
				}
			}
			else {
				_tprintf(STR_INVALID_PARAMETER);
				nStatus = -1;
			}
			break;
		case _T('u'):
			if (theArg[2] == _T('\0')) {
				bSuccess = UninstallDriver();
				if (bSuccess)
				{
					_tprintf(_T("%s has been successfully uninstalled!\n"),
							bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
				}
				else
				{
					const DWORD err = GetLastError();
					_tprintf(_T("%s failed to be uninstalled.\n"),
							bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
					nStatus = err ? err : -1;
				}
			}
			else if (theArg[3] == _T('\0')) {
				switch (theArg[2]) {
					case _T('l'):
						if (UninstallLoopbackAdapter())
						{
							_tprintf(_T("Npcap Loopback adapter has been successfully uninstalled!\n"));
						}
						else
						{
							const DWORD err = GetLastError();
							_tprintf(_T("Npcap Loopback adapter has failed to be uninstalled.\n"));
							nStatus = err ? err : 1;
						}
						break;
					case _T('w'):
						if (UninstallWFPCallout())
						{
							_tprintf(_T("Npcap WFP callout driver has been successfully uninstalled!\n"));
						}
						else
						{
							const DWORD err = GetLastError();
							_tprintf(_T("Npcap WFP callout driver has failed to be uninstalled.\n"));
							nStatus = err ? err : 1;
						}
						break;
					default:
						_tprintf(STR_INVALID_PARAMETER);
						nStatus = -1;
						break;
				}
			}
			else {
				_tprintf(STR_INVALID_PARAMETER);
				nStatus = -1;
			}
			break;
		case _T('r'):
			if (theArg[2] == _T('\0')) {
				if (RenableBindings())
				{
					_tprintf(_T("The bindings of %s have been successfully restarted!\n"),
							bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
				}
				else
				{
					const DWORD err = GetLastError();
					_tprintf(_T("The bindings of %s have failed to be restarted.\n"),
							bWiFiService ? NPF_SERVICE_DESC_TCHAR_WIFI : NPF_SERVICE_DESC_TCHAR);
					nStatus = err ? err : 1;
				}
			}
			else {
				_tprintf(STR_INVALID_PARAMETER);
				nStatus = -1;
			}
			break;
		case _T('c'):
			if (theArg[2] == _T('\0'))
			{
				if (ClearDriverStore())
				{
					_tprintf(_T("Npcap driver cache in Driver Store has been successfully cleaned up!\n"));
				}
				else
				{
					const DWORD err = GetLastError();
					_tprintf(_T("Npcap driver cache in Driver Store has failed to be cleaned up.\n"));
					nStatus = err ? err : 1;
				}
			}
			else if (0 == _tcscmp(theArg, _T("-check_dll"))) {
				tstring strInUseProcesses = getInUseProcesses();
				if (strInUseProcesses == _T(""))
				{
					_tprintf(_T("<NULL>\n"));
				}
				else
				{
					_tprintf(_T("%s\n"), strInUseProcesses.c_str());
					nStatus = -1;
				}
			}
			else {
				_tprintf(STR_INVALID_PARAMETER);
				nStatus = -1;
			}
			break;
		case _T('k'):
			if (0 == _tcscmp(theArg, _T("-kill_proc")))
			{
				if (killInUseProcesses())
				{
					_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated!\n"));
				}
				else
				{
					_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated.\n"));
					nStatus = -1;
				}
			}
			else if (0 == _tcscmp(theArg, _T("-kill_proc_soft")))
			{
				if (killInUseProcesses_Soft())
				{
					_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated gracefully!\n"));
				}
				else
				{
					_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated gracefully.\n"));
					nStatus = -1;
				}
			}
			else if (0 == _tcscmp(theArg, _T("-kill_proc_polite")))
			{
				if (killInUseProcesses_Polite())
				{
					_tprintf(_T("All the processes that are still using Npcap DLLs have been successfully terminated politely!\n"));
				}
				else
				{
					_tprintf(_T("Some of the processes that are still using Npcap DLLs have failed to be terminated politely.\n"));
					nStatus = -1;
				}
			}
			else {
				_tprintf(STR_INVALID_PARAMETER);
				nStatus = -1;
			}
			break;
		case _T('h'):
			if (theArg[2] == _T('\0'))
			{
				_tprintf(STR_COMMAND_USAGE);
			}
			// else fall through to default invalid parameter
		default:
			_tprintf(STR_INVALID_PARAMETER);
			nStatus = -1;
			break;
	}

	return trace_exit(nStatus);
}
