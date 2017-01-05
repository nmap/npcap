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
#ifndef __NPF_IM_EXT_H___
#define __NPF_IM_EXT_H___

#ifdef HAVE_NPFIM_API

#include <NpfIm.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef BOOL (NPF_IM_CALLCONV *NpfImGetDeviceListHandler)
(
	IN OUT PNPF_IM_DEVICE *ppDevices
);

typedef BOOL (NPF_IM_CALLCONV *NpfImFreeDeviceListHandler)
(
	IN PNPF_IM_DEVICE pDevices
);

typedef BOOL (NPF_IM_CALLCONV *NpfImOpenDeviceHandler)
(
	IN PCHAR name, 
	OUT NPF_IM_DEV_HANDLE *pHandle
);

typedef BOOL (NPF_IM_CALLCONV *NpfImCloseDeviceHandler)
(
	IN NPF_IM_DEV_HANDLE handle
);

typedef BOOL (NPF_IM_CALLCONV *NpfImReceivePacketsHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN OUT PVOID buffer,
	IN DWORD bufferSize,
	OUT PDWORD pReadBytes
);

typedef BOOL (NPF_IM_CALLCONV *NpfImSetBpfFilterHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN PVOID buffer,
	IN DWORD bufferSize
);

typedef BOOL (NPF_IM_CALLCONV *NpfImSetCaptureBufferSizeHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN DWORD bufferSize
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetMediumHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	OUT PNDIS_MEDIUM pMedium
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetMacAddressHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	OUT BYTE macAddress[6]
);

typedef BOOL (NPF_IM_CALLCONV *NpfImSetMinToCopyHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN DWORD minToCopy
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetCaptureReadEventHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	OUT PHANDLE pReadEvent
);

typedef BOOL (NPF_IM_CALLCONV *NpfImSetReadTimeoutHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN DWORD readTimeout
);

typedef BOOL (NPF_IM_CALLCONV *NpfImIssueQueryOidHandler)
(
		IN		NPF_IM_DEV_HANDLE handle,
		IN		ULONG	Oid,
		OUT		PBYTE pBuffer,
		IN OUT	PDWORD pBufferSize
		);

typedef BOOL (NPF_IM_CALLCONV *NpfImIssueSetOidHandler)
(
		IN		NPF_IM_DEV_HANDLE handle,
		IN		ULONG	Oid,
		IN		PBYTE pBuffer,
		IN OUT	PDWORD pBufferSize
		);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetCaptureStatisticsHandler)
(
		IN		NPF_IM_DEV_HANDLE handle,
		OUT		PULONGLONG Statistics,
		IN DWORD bufferSize,
		OUT PDWORD pNeededOrWrittenBytes
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetRunningDriverVersionHandler)
(
		OUT PULONGLONG Version
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetLinkSpeedHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	OUT PULONGLONG pLinkSpeed
);

typedef BOOL (NPF_IM_CALLCONV *NpfImGetIpAddressesHandler)
(
	IN NPF_IM_DEV_HANDLE handle,
	IN OUT PNPF_IM_ADDRESS pAddresses,
	IN DWORD bufferSize,	
	OUT PDWORD pNeededOrWrittenBytes
);

typedef struct _NPF_IM_HANDLERS
{
	NpfImCloseDeviceHandler				NpfImCloseDevice;				
	NpfImFreeDeviceListHandler			NpfImFreeDeviceList;
	NpfImGetCaptureReadEventHandler		NpfImGetCaptureReadEvent;
	NpfImGetCaptureStatisticsHandler	NpfImGetCaptureStatistics;
	NpfImGetDeviceListHandler			NpfImGetDeviceList;
	NpfImGetIpAddressesHandler			NpfImGetIpAddresses;
	NpfImGetLinkSpeedHandler			NpfImGetLinkSpeed;
//	NpfImGetMacAddressHandler			NpfImGetMacAddress;
	NpfImGetMediumHandler				NpfImGetMedium;
	NpfImGetRunningDriverVersionHandler	NpfImGetRunningDriverVersion;
	NpfImIssueQueryOidHandler			NpfImIssueQueryOid;
//	NpfImIssueSetOidHandler				NpfImIssueSetOid;
	NpfImOpenDeviceHandler				NpfImOpenDevice;
	NpfImReceivePacketsHandler			NpfImReceivePackets;
	NpfImSetBpfFilterHandler			NpfImSetBpfFilter;
	NpfImSetCaptureBufferSizeHandler	NpfImSetCaptureBufferSize;
	NpfImSetMinToCopyHandler			NpfImSetMinToCopy;
	NpfImSetReadTimeoutHandler			NpfImSetReadTimeout;
}
	NPF_IM_HANDLERS;

extern NPF_IM_HANDLERS g_NpfImHandlers;
extern HMODULE g_hNpfImDll;

BOOL LoadNpfImDll();
BOOL UnloadNpfImDll();

#ifdef __cplusplus
}
#endif

#endif //#ifdef HAVE_NPFIM_API


#endif //__NPF_IM_EXT_H___
