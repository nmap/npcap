
#include "..\..\..\Common\Packet32.h"

#include <windot11.h>
#include <tchar.h>
#include <algorithm>
#include "Tool.h"

vector<tstring> g_strAdapterNames;
vector<tstring> g_strAdapterGUIDs;

tstring OperationMode2String(ULONG OperationMode)
{
	if (OperationMode == DOT11_OPERATION_MODE_EXTENSIBLE_AP)
	{
		return _T("master");
	}
	else if (OperationMode == DOT11_OPERATION_MODE_EXTENSIBLE_STATION)
	{
		return _T("managed");
	}
	else if (OperationMode == DOT11_OPERATION_MODE_NETWORK_MONITOR)
	{
		return _T("monitor");
	}
	else if (OperationMode == DOT11_OPERATION_MODE_WFD_DEVICE)
	{
		return _T("wfd_device");
	}
	else if (OperationMode == DOT11_OPERATION_MODE_WFD_GROUP_OWNER)
	{
		return _T("wfd_owner");
	}
	else if (OperationMode == DOT11_OPERATION_MODE_WFD_CLIENT)
	{
		return _T("wfd_client");
	}
	else
	{
		return _T("unknown");
	}
}

ULONG String2OperationMode(tstring strOperationMode)
{
	if (strOperationMode == _T("master"))
	{
		return DOT11_OPERATION_MODE_EXTENSIBLE_AP;
	}
	else if (strOperationMode == _T("managed"))
	{
		return DOT11_OPERATION_MODE_EXTENSIBLE_STATION;
	}
	else if (strOperationMode == _T("monitor"))
	{
		return DOT11_OPERATION_MODE_NETWORK_MONITOR;
	}
	else if (strOperationMode == _T("wfd_device"))
	{
		return DOT11_OPERATION_MODE_WFD_DEVICE;
	}
	else if (strOperationMode == _T("wfd_owner"))
	{
		return DOT11_OPERATION_MODE_WFD_GROUP_OWNER;
	}
	else if (strOperationMode == _T("wfd_client"))
	{
		return DOT11_OPERATION_MODE_WFD_CLIENT;
	}
	else
	{
		return DOT11_OPERATION_MODE_UNKNOWN;
	}
}

tstring strToLower(const tstring &str)
{
	tstring strTmp = str;
	transform(strTmp.begin(), strTmp.end(), strTmp.begin(), tolower);
	return strTmp;
}

bool compareNoCase(const tstring &strA, const tstring &strB)
{
	tstring str1 = strToLower(strA);
	tstring str2 = strToLower(strB);
	return (str1 == str2);
}

wstring ANSIToUnicode(const string& str)
{
	size_t len = 0;
	len = str.length();
	int unicodeLen = ::MultiByteToWideChar(CP_ACP,
		0,
		str.c_str(),
		-1,
		NULL,
		0);
	wchar_t * pUnicode;
	pUnicode = new wchar_t[unicodeLen + 1];
	memset(pUnicode, 0, (unicodeLen + 1)*sizeof(wchar_t));
	::MultiByteToWideChar(CP_ACP,
		0,
		str.c_str(),
		-1,
		(LPWSTR)pUnicode,
		unicodeLen);
	wstring rt;
	rt = (wchar_t*)pUnicode;
	delete pUnicode;
	return rt;
}

tstring executeCommand(TCHAR* cmd)
{
	TCHAR buffer[128];
	tstring result;

	FILE* pipe = _tpopen(cmd, _T("r"));
	if (!pipe)
	{
		return _T("");
	}

	while (!feof(pipe))
	{
		if (_fgetts(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	_pclose(pipe);

	return result;
}

// There is 1 interface on the system:
// 
//     Name                   : Wi-Fi
//     Description            : Qualcomm Atheros AR9485WB-EG Wireless Network Adapter
//     GUID                   : 42dfd47a-2764-43ac-b58e-3df569c447da
//     Physical address       : a4:db:30:d9:3a:9a
//     State                  : connected
//     SSID                   : LUO-PC_Network
//     BSSID                  : d8:15:0d:72:8c:18
//     Network type           : Infrastructure
//     Radio type             : 802.11n
//     Authentication         : WPA2-Personal
//     Cipher                 : CCMP
//     Connection mode        : Auto Connect
//     Channel                : 1
//     Receive rate (Mbps)    : 150
//     Transmit rate (Mbps)   : 150
//     Signal                 : 100%
//     Profile                : LUO-PC_Network
// 
//     Hosted network status  : Not available

void initAdapterList()
{
	size_t iStart = -1;
	size_t iEnd;
	tstring strAdapterName;
	tstring strGUID;

	tstring strOutput = executeCommand(_T("netsh wlan show interfaces"));
	
	iStart = strOutput.find(_T("\n\n"), iStart + 1);
	if (iStart == tstring::npos) return;
	while ((iStart = strOutput.find(_T(": "), iStart + 1)) != tstring::npos)
	{
		iStart += 2;
		iEnd = strOutput.find(_T('\n'), iStart + 1);
		if (iEnd == tstring::npos) return;
		strAdapterName = strOutput.substr(iStart, iEnd - iStart);
		
		iStart = strOutput.find(_T(": "), iStart + 1);
		if (iStart == tstring::npos) return;
		iStart = strOutput.find(_T(": "), iStart + 1);
		if (iStart == tstring::npos) return;
		iStart += 2;
		iEnd = strOutput.find(_T('\n'), iStart + 1);
		if (iEnd == tstring::npos) return;
		strGUID = strOutput.substr(iStart, iEnd - iStart);

		g_strAdapterNames.push_back(strAdapterName);
		g_strAdapterGUIDs.push_back(strGUID);

		iStart = strOutput.find(_T("\n\n"), iStart + 1);
		if (iStart == tstring::npos) return;
	}
}

tstring getGuidFromAdapterName(tstring strAdapterName)
{
	if (g_strAdapterNames.size() == 0)
	{
		initAdapterList();
	}

	for (size_t i = 0; i < g_strAdapterNames.size(); i++)
	{
		if (compareNoCase(g_strAdapterNames[i], strAdapterName))
		{
			return g_strAdapterGUIDs[i];
		}
	}

	return _T("");
}

BOOL makeOIDRequest_ULONG(tstring strAdapterGUID, ULONG iOid, BOOL bSet, ULONG *pFlag)
{
	TCHAR strAdapterName[256];
	_stprintf_s(strAdapterName, 256, _T("\\Device\\NPF_{%s}"), strAdapterGUID.c_str());

	LPADAPTER pAdapter = PacketOpenAdapter(strAdapterName);
	if (pAdapter == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::PacketOpenAdapter error\n"), -1);
		return FALSE;
	}

	BOOL Status;
	ULONG IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1);
	PPACKET_OID_DATA OidData;
	OidData = (PPACKET_OID_DATA) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, IoCtlBufferLength);
	if (OidData == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::GlobalAllocPtr error\n"), -1);
		return FALSE;
	}

	OidData->Oid = iOid;
	OidData->Length = sizeof(ULONG);

	if (bSet)
	{
		*((ULONG*)OidData->Data) = *pFlag;
	}
	Status = PacketRequest(pAdapter, bSet, OidData);
	if (!bSet)
	{
		*pFlag = *((ULONG*) OidData->Data);
	}

	GlobalFreePtr(OidData);
	PacketCloseAdapter(pAdapter);
	return Status;
}

BOOL makeOIDRequest_DOT11_CURRENT_OPERATION_MODE(tstring strAdapterGUID, ULONG iOid, BOOL bSet, DOT11_CURRENT_OPERATION_MODE *pFlag)
{
	TCHAR strAdapterName[256];
	_stprintf_s(strAdapterName, 256, _T("\\Device\\NPF_{%s}"), strAdapterGUID.c_str());

	LPADAPTER pAdapter = PacketOpenAdapter(strAdapterName);
	if (pAdapter == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::PacketOpenAdapter error\n"), -1);
		return FALSE;
	}

	BOOL Status;
	ULONG IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + sizeof(DOT11_CURRENT_OPERATION_MODE) - 1);
	PPACKET_OID_DATA OidData;
	OidData = (PPACKET_OID_DATA)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, IoCtlBufferLength);
	if (OidData == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::GlobalAllocPtr error\n"), -1);
		return FALSE;
	}

	OidData->Oid = iOid;
	OidData->Length = sizeof(DOT11_CURRENT_OPERATION_MODE);

	if (bSet)
	{
		*((DOT11_CURRENT_OPERATION_MODE*)OidData->Data) = *pFlag;
	}
	Status = PacketRequest(pAdapter, bSet, OidData);
	if (!bSet)
	{
		*pFlag = *((DOT11_CURRENT_OPERATION_MODE*)OidData->Data);
	}

	GlobalFreePtr(OidData);
	PacketCloseAdapter(pAdapter);
	return Status;
}

BOOL GetCurrentOperationMode(tstring strGUID, tstring &strMode)
{
	BOOL bResult;
	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode;

	bResult = makeOIDRequest_DOT11_CURRENT_OPERATION_MODE(strGUID, OID_DOT11_CURRENT_OPERATION_MODE, FALSE, &CurrentOperationMode);
	if (bResult)
	{
		strMode = OperationMode2String(CurrentOperationMode.uCurrentOpMode);
	}
	else
	{
		strMode = _T("unknown (call failed)");
	}

	return bResult;
}

BOOL SetCurrentOperationMode(tstring strGUID, tstring strMode)
{
	BOOL bResult;
	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode;

	CurrentOperationMode.uReserved = 0;
	CurrentOperationMode.uCurrentOpMode = String2OperationMode(strMode);
	if (CurrentOperationMode.uCurrentOpMode == DOT11_OPERATION_MODE_UNKNOWN)
	{
		_tprintf(_T("Error: SetCurrentOperationMode error, unknown mode: %s\n"), strMode);
		return FALSE;
	}

	bResult = makeOIDRequest_DOT11_CURRENT_OPERATION_MODE(strGUID, OID_DOT11_CURRENT_OPERATION_MODE, TRUE, &CurrentOperationMode);
	return bResult;
}

BOOL GetCurrentChannel(tstring strGUID, ULONG &ulChannel)
{
	BOOL bResult;
	ULONG CurrentChannel;

	bResult = makeOIDRequest_ULONG(strGUID, OID_DOT11_CURRENT_CHANNEL, FALSE, &CurrentChannel);
	if (bResult)
	{
		ulChannel = CurrentChannel;
	}
	else
	{
		ulChannel = 0;
	}

	return bResult;
}

BOOL SetCurrentChannel(tstring strGUID, ULONG ulChannel)
{
	BOOL bResult;
	ULONG CurrentChannel;

	CurrentChannel = ulChannel;
	bResult = makeOIDRequest_ULONG(strGUID, OID_DOT11_CURRENT_CHANNEL, TRUE, &CurrentChannel);
	return bResult;
}
