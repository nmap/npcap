#include <tchar.h>
#include <windows.h>

#include "ProtInstall.h"


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

	SetConsoleTitle( _T("NPF NDIS6.x Driver for WinPcap") );

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
			_tprintf(_T("Command Usage: NPFInstall -[i/u]: i - install, u - uninstall.\n"));
			return -1;
		}
	}

	if (!bVerbose)
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	if (argc < 2)
	{
		_tprintf(_T("Command Usage: NPFInstall -[i/u/r]: i - install, u - uninstall, r - restartBindings.\n"));
		return -1;
	}
	else //argc == 2
	{
		if (_tcscmp(_T("-i"), argv[1]) == 0)
		{
			bSuccess = PacketInstallDriver60();
			if (bSuccess)
			{
				_tprintf(_T("NPF6x driver has been successfully installed!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("NPF6x driver has failed the installation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-u"), argv[1]) == 0)
		{
			bSuccess = PacketStopDriver60();
			if (bSuccess)
			{
				_tprintf(_T("NPF6x driver has been successfully uninstalled!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("NPF6x driver has failed the uninstallation."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-r"), argv[1]) == 0)
		{
			bSuccess = PacketRenableBindings();
			if (bSuccess)
			{
				_tprintf(_T("NPF6x driver's bindings have been successfully restarted!\n"));
				return 0;
			}
			else
			{
				_tprintf(_T("NPF6x driver's bindings have failed to restart."));
				return -1;
			}
		}
		else if (_tcscmp(_T("-h"), argv[1]) == 0)
		{
			_tprintf(_T("Command Usage: NPFInstall -[i/u/r]: i - install, u - uninstall, r - restartBindings.\n"));
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