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