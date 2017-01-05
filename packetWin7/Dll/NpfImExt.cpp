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
//
// this should be removed in the long term.  GV 20080807
//
#define _CRT_SECURE_NO_WARNINGS

#include "NpfImExt.h"
#include <windows.h>

#include "debug.h"

#ifdef HAVE_NPFIM_API

NPF_IM_HANDLERS	g_NpfImHandlers;
HMODULE			g_hNpfImDll;

BOOL LoadNpfImDll()
{
	TRACE_ENTER("LoadNpfImDll");

	if (g_hNpfImDll != NULL)
	{
		TRACE_EXIT("LoadNpfImDll");
		return TRUE;
	}

	g_hNpfImDll = LoadLibraryA("NpfIm.dll");

	if (g_hNpfImDll == NULL)
	{
		TRACE_EXIT("LoadNpfImDll");
		return FALSE;
	}
	
	g_NpfImHandlers.NpfImFreeDeviceList			= (NpfImFreeDeviceListHandler)			GetProcAddress(g_hNpfImDll,"NpfImFreeDeviceList");
	g_NpfImHandlers.NpfImGetCaptureReadEvent	= (NpfImGetCaptureReadEventHandler)		GetProcAddress(g_hNpfImDll,"NpfImGetCaptureReadEvent");
	g_NpfImHandlers.NpfImGetCaptureStatistics	= (NpfImGetCaptureStatisticsHandler)	GetProcAddress(g_hNpfImDll,"NpfImGetCaptureStatistics");
	g_NpfImHandlers.NpfImGetDeviceList			= (NpfImGetDeviceListHandler)			GetProcAddress(g_hNpfImDll,"NpfImGetDeviceList");
	g_NpfImHandlers.NpfImGetIpAddresses			= (NpfImGetIpAddressesHandler)			GetProcAddress(g_hNpfImDll,"NpfImGetIpAddresses");
	g_NpfImHandlers.NpfImGetLinkSpeed			= (NpfImGetLinkSpeedHandler)			GetProcAddress(g_hNpfImDll,"NpfImGetLinkSpeed");
//	g_NpfImHandlers.NpfImGetMacAddress			= (NpfImGetMacAddressHandler)			GetProcAddress(g_hNpfImDll,"NpfImGetMacAddress");
	g_NpfImHandlers.NpfImGetMedium				= (NpfImGetMediumHandler)				GetProcAddress(g_hNpfImDll,"NpfImGetMedium");
	g_NpfImHandlers.NpfImGetRunningDriverVersion= (NpfImGetRunningDriverVersionHandler)	GetProcAddress(g_hNpfImDll,"NpfImGetRunningDriverVersion");
	g_NpfImHandlers.NpfImIssueQueryOid			= (NpfImIssueQueryOidHandler)			GetProcAddress(g_hNpfImDll,"NpfImIssueQueryOid");
//	g_NpfImHandlers.NpfImIssueSetOid			= (NpfImIssueSetOidHandler)				GetProcAddress(g_hNpfImDll,"NpfImIssueSetOid");
	g_NpfImHandlers.NpfImOpenDevice				= (NpfImOpenDeviceHandler)				GetProcAddress(g_hNpfImDll,"NpfImOpenDevice");
	g_NpfImHandlers.NpfImReceivePackets			= (NpfImReceivePacketsHandler)			GetProcAddress(g_hNpfImDll,"NpfImReceivePackets");
	g_NpfImHandlers.NpfImSetBpfFilter			= (NpfImSetBpfFilterHandler)			GetProcAddress(g_hNpfImDll,"NpfImSetBpfFilter");
	g_NpfImHandlers.NpfImSetCaptureBufferSize	= (NpfImSetCaptureBufferSizeHandler)	GetProcAddress(g_hNpfImDll,"NpfImSetCaptureBufferSize");
	g_NpfImHandlers.NpfImSetMinToCopy			= (NpfImSetMinToCopyHandler)			GetProcAddress(g_hNpfImDll,"NpfImSetMinToCopy");
	g_NpfImHandlers.NpfImSetReadTimeout			= (NpfImSetReadTimeoutHandler)				GetProcAddress(g_hNpfImDll,"NpfImSetReadTimeout");
	g_NpfImHandlers.NpfImCloseDevice			= (NpfImCloseDeviceHandler)				GetProcAddress(g_hNpfImDll, "NpfImCloseDevice");
	
	if (
		   g_NpfImHandlers.NpfImCloseDevice			  == NULL
		|| g_NpfImHandlers.NpfImFreeDeviceList		  == NULL
		|| g_NpfImHandlers.NpfImGetCaptureReadEvent	  == NULL
		|| g_NpfImHandlers.NpfImGetCaptureStatistics  == NULL
		|| g_NpfImHandlers.NpfImGetDeviceList		  == NULL
		|| g_NpfImHandlers.NpfImGetIpAddresses		  == NULL
		|| g_NpfImHandlers.NpfImGetLinkSpeed		  == NULL
//		|| g_NpfImHandlers.NpfImGetMacAddress		  == NULL
		|| g_NpfImHandlers.NpfImGetMedium			  == NULL
		|| g_NpfImHandlers.NpfImGetRunningDriverVersion  == NULL
		|| g_NpfImHandlers.NpfImIssueQueryOid		  == NULL
//		|| g_NpfImHandlers.NpfImIssueSetOid			  == NULL
		|| g_NpfImHandlers.NpfImOpenDevice			  == NULL
		|| g_NpfImHandlers.NpfImReceivePackets		  == NULL
		|| g_NpfImHandlers.NpfImSetBpfFilter		  == NULL
		|| g_NpfImHandlers.NpfImSetCaptureBufferSize  == NULL
		|| g_NpfImHandlers.NpfImSetMinToCopy		  == NULL
		|| g_NpfImHandlers.NpfImSetReadTimeout		  == NULL
		)
	{
		UnloadNpfImDll();
		TRACE_EXIT("LoadNpfImDll");
		return FALSE;
	}

	TRACE_EXIT("LoadNpfImDll");
	return TRUE;
}

BOOL UnloadNpfImDll()
{
	TRACE_ENTER("UnloadNpfImDll");

	if (g_hNpfImDll == NULL)
	{
		TRACE_EXIT("UnloadNpfImDll");
		return FALSE;
	}

	FreeLibrary(g_hNpfImDll);
	g_hNpfImDll = NULL;
	ZeroMemory(&g_NpfImHandlers, sizeof(g_NpfImHandlers));

	TRACE_EXIT("UnloadNpfImDll");
	return TRUE;
}

#endif //HAVE_NPFIM_API
