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
/*++

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
				TRACE_PRINT1("find: executing, strInfFileName = %s.", strInfFileName.c_str());
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
