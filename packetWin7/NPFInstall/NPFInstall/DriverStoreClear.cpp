/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

DriverStoreClear.h

Abstract:

This is used to clear the cache of Npcap driver in the Driver Store.

--*/

#include <windows.h>

#include "DriverStoreClear.h"
#include "LoopbackRename2.h"

#include "debug.h"

// getInfNamesFromPnpUtilOutput() function is used to get INF filenames from string like below:
//
// Microsoft PnP Utility
//
// Published name : oem10.inf
// Driver package provider : Lenovo
// Class : System devices
// Driver date and version : 05 / 15 / 2015 13.52.34.549
// Signer name : Microsoft Windows Hardware Compatibility Publisher
//
// Published name : oem20.inf
// Driver package provider : Disc Soft Ltd
// Class : Storage controllers
// Driver date and version : 03 / 27 / 2015 5.24.0.0
// Signer name : Disc Soft Ltd
//
// Published name : oem44.inf
// Driver package provider : Nmap Project
// Class : Network Service
// Driver date and version : 04 / 13 / 2016 12.3.27.285
// Signer name : Insecure.Com LLC
//
vector<tstring> getInfNamesFromPnpUtilOutput(tstring strOutput)
{
	TRACE_ENTER();

	vector<tstring> nResults;

	size_t iStart = -1;
	size_t iEnd;
	size_t iTime = 0;
	tstring strInfFileName;

	while ((iStart = strOutput.find(_T(':'), iStart + 1)) != tstring::npos)
	{
		iStart ++;
		while (strOutput[iStart] == _T(' ') || strOutput[iStart] == _T('\t'))
		{
			iStart ++;
		}
		iEnd = strOutput.find(_T('\n'), iStart + 1);
		tstring strText = strOutput.substr(iStart, iEnd - iStart);

		if (iTime == 0)
		{
			strInfFileName = strText;
		}
		else if (iTime == 1)
		{
			if (strText == _T("Nmap Project"))
			{
				TRACE_PRINT1("find: executing, strInfFileName = %ws.", strInfFileName.c_str());
				nResults.push_back(strInfFileName);
			}
		}

		iTime ++;
		if (iTime == 5)
		{
			iTime = 0;
		}
	}

	TRACE_EXIT();
	return nResults;
}

BOOLEAN ClearDriverStore()
{
	TRACE_ENTER();

	tstring cmd = executeCommand(_T("pnputil.exe -e"));
	vector<tstring> nInfFileNameList = getInfNamesFromPnpUtilOutput(cmd);

	TCHAR renameCmd[MAX_PATH];
	// "pnputil.exe -d oem1.inf"
	for (size_t i = 0; i < nInfFileNameList.size(); i++)
	{
		_stprintf_s(renameCmd, MAX_PATH, _T("pnputil.exe -d %s"), nInfFileNameList[i].c_str());
		executeCommand(renameCmd);
	}

	TRACE_EXIT();
	return TRUE;
}