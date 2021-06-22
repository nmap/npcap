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
		iStart = strOutput.find_first_not_of(_T(" \t\r\n"), iStart + 1);
		if (iStart == tstring::npos) {
			// No more lines
			break;
		}
		iEnd = strOutput.find_first_of(_T("\r\n"), iStart + 1);
		tstring strText = strOutput.substr(iStart,
				// No EOL found? take the whole thing.
				iEnd != tstring::npos
				? iEnd - iStart
				: tstring::npos);

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

	TCHAR renameCmd[16+MAX_PATH] = _T("pnputil.exe -e");
	// "pnputil.exe -d oem1.inf"
	tstring cmd = executeCommand(renameCmd);
	vector<tstring> nInfFileNameList = getInfNamesFromPnpUtilOutput(cmd);

	// "pnputil.exe -d oem1.inf"
	for (size_t i = 0; i < nInfFileNameList.size(); i++)
	{
		_stprintf_s(renameCmd, MAX_PATH, _T("pnputil.exe -d %s"), nInfFileNameList[i].c_str());
		executeCommand(renameCmd);
	}

	TRACE_EXIT();
	return TRUE;
}
