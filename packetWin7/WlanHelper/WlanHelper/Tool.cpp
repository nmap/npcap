
#include "..\..\..\Common\Packet32.h"

#include <windot11.h>
#include <tchar.h>
#include <algorithm>
#include "Tool.h"

#include "../../../Common/WpcapNames.h"
// "\\Device\\NPF_{%s}" or "\\Device\\NPCAP_{%s}"
#define NPF_DRIVER_FORMAT_STR	_T("\\Device\\") _T(NPF_DRIVER_NAME) _T("_{%s}")

vector<tstring> g_strAdapterNames;
vector<tstring> g_strAdapterGUIDs;

vector<tstring> g_nstrPhyTypes;

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

tstring PhyType2String(ULONG PhyType)
{
	if (PhyType == dot11_phy_type_unknown)
	{
		return _T("unknown");
	}
	else if (PhyType == dot11_phy_type_any)
	{
		return _T("any");
	}
	else if (PhyType == dot11_phy_type_fhss)
	{
		return _T("fhss");
	}
	else if (PhyType == dot11_phy_type_dsss)
	{
		return _T("dsss");
	}
	else if (PhyType == dot11_phy_type_irbaseband)
	{
		return _T("irbaseband");
	}
	else if (PhyType == dot11_phy_type_ofdm)
	{
		return _T("ofdm");
	}
	else if (PhyType == dot11_phy_type_hrdsss)
	{
		return _T("hrdsss");
	}
	else if (PhyType == dot11_phy_type_erp)
	{
		return _T("erp");
	}
	else if (PhyType == dot11_phy_type_ht)
	{
		return _T("ht");
	}
	else if (PhyType == dot11_phy_type_vht)
	{
		return _T("vht");
	}
	else if (dot11_phy_type_IHV_start <= PhyType && PhyType <= dot11_phy_type_IHV_end)
	{
		return _T("ihv");
	}
	else
	{
		return _T("undefined");
	}
}

tstring printArray(vector<tstring> nstr)
{
	tstring strResult;
	for (size_t i = 0; i < nstr.size(); i++)
	{
		if (i != 0)
		{
			strResult += _T(", ");
		}
		strResult += nstr[i];
	}
	return strResult;
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

BOOL string2wstring(const std::string &str, std::wstring &wstr)
{
	int nLen = (int)str.length();
	wstr.resize(nLen, L' ');

	int nResult = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)str.c_str(), nLen, (LPWSTR)wstr.c_str(), nLen);

	if (nResult == 0)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL wstring2string(const std::wstring &wstr, std::string &str)
{
	int nLen = (int)wstr.length();
	str.resize(nLen, ' ');

	int nResult = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wstr.c_str(), nLen, (LPSTR)str.c_str(), nLen, NULL, NULL);

	if (nResult == 0)
	{
		return FALSE;
	}

	return TRUE;
}

wstring any2wstring_a(string &str)
{
	wstring wstr;
	string2wstring(str, wstr);
	return wstr;
}

wstring any2wstring_w(wstring &wstr)
{
	return wstr;
}

string any2string_a(string &str)
{
	return str;
}

string any2string_w(wstring &wstr)
{
	string str;
	wstring2string(wstr, str);
	return str;
}

#ifdef UNICODE
#define any2wstring any2wstring_w
#define any2string any2string_w
#else
#define any2wstring any2wstring_a
#define any2string any2string_a
#endif

tstring itos(int i)
{
	TCHAR buf[256];
	_itot_s(i, buf, 10);
	tstring res = buf;
	return res;
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

tstring getAdapterNameFromGuid(tstring strGuid)
{
	if (g_strAdapterGUIDs.size() == 0)
	{
		initAdapterList();
	}

	for (size_t i = 0; i < g_strAdapterGUIDs.size(); i++)
	{
		if (compareNoCase(g_strAdapterGUIDs[i], strGuid))
		{
			return g_strAdapterNames[i];
		}
	}

	return _T("");
}

HINSTANCE hinstLib = NULL;
typedef LPADAPTER (*MY_PACKETOPENADAPTER) (PCHAR AdapterName);
typedef BOOLEAN(*MY_PACKETREQUEST) (LPADAPTER  AdapterObject, BOOLEAN Set, PPACKET_OID_DATA  OidData);
typedef VOID(*MY_PACKETCLOSEADAPTER) (LPADAPTER lpAdapter);
MY_PACKETOPENADAPTER My_PacketOpenAdapter = NULL;
MY_PACKETREQUEST My_PacketRequest = NULL;
MY_PACKETCLOSEADAPTER My_PacketCloseAdapter = NULL;

BOOL initPacketFunctions()
{
	BOOL bRet;
	
	// Get a handle to the packet DLL module.
	hinstLib = LoadLibrary(TEXT("packet.dll"));

	// If the handle is valid, try to get the function address.  
	if (hinstLib != NULL)
	{
		My_PacketOpenAdapter = (MY_PACKETOPENADAPTER)GetProcAddress(hinstLib, "PacketOpenAdapter");
		My_PacketRequest = (MY_PACKETREQUEST)GetProcAddress(hinstLib, "PacketRequest");
		My_PacketCloseAdapter = (MY_PACKETCLOSEADAPTER)GetProcAddress(hinstLib, "PacketCloseAdapter");
		// If the function address is valid, call the function.  

		if (My_PacketOpenAdapter != NULL && My_PacketRequest != NULL && My_PacketCloseAdapter != NULL)
		{
			bRet = TRUE;
		}
		else
		{
			bRet = FALSE;
		}

		
	}
	else
	{
		bRet = FALSE;
	}

	return bRet;
}

void freePacketFunctions()
{
	if (hinstLib)
	{
		// Free the DLL module.  
		FreeLibrary(hinstLib);
		My_PacketOpenAdapter = NULL;
		My_PacketRequest = NULL;
		My_PacketCloseAdapter = NULL;
	}
}

BOOL makeOIDRequest(tstring strAdapterGUID, ULONG iOid, BOOL bSet, PVOID pData, ULONG ulDataSize)
{
	BOOL Status;

	if (!initPacketFunctions())
	{
		_tprintf(_T("Error: makeOIDRequest::initPacketFunctions error\n"));
		Status = FALSE;
		goto makeOIDRequest_Exit3;
	}

	char strAdapterName[256];
	sprintf_s(strAdapterName, 256, NPF_DRIVER_FORMAT_STR, any2string(strAdapterGUID).c_str());

	LPADAPTER pAdapter = My_PacketOpenAdapter(strAdapterName);
	if (pAdapter == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::My_PacketOpenAdapter error\n"));
		Status = FALSE;
		goto makeOIDRequest_Exit2;
	}

	
	ULONG IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + ulDataSize - 1);
	PPACKET_OID_DATA OidData;
	OidData = (PPACKET_OID_DATA)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, IoCtlBufferLength);
	if (OidData == NULL)
	{
		_tprintf(_T("Error: makeOIDRequest::GlobalAllocPtr error\n"));
		Status = FALSE;
		goto makeOIDRequest_Exit1;
	}

	OidData->Oid = iOid;
	OidData->Length = ulDataSize;

	if (bSet)
	{
		CopyMemory(OidData->Data, pData, ulDataSize);
	}
	Status = My_PacketRequest(pAdapter, bSet, OidData);
	if (!Status)
	{
		_tprintf(_T("Error: makeOIDRequest::My_PacketRequest error, error code = %d\n"), GetLastError());
	}
	else
	{
		if (!bSet)
		{
			CopyMemory(pData, OidData->Data, ulDataSize);
		}
	}

	GlobalFreePtr(OidData);
makeOIDRequest_Exit1:
	My_PacketCloseAdapter(pAdapter);
makeOIDRequest_Exit2:
	freePacketFunctions();
makeOIDRequest_Exit3:
	return Status;
}

BOOL GetCurrentOperationMode(tstring strGUID, tstring &strMode)
{
	BOOL bResult;
	DOT11_CURRENT_OPERATION_MODE CurrentOperationMode;

	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_OPERATION_MODE, FALSE, &CurrentOperationMode, sizeof(DOT11_CURRENT_OPERATION_MODE));
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
		_tprintf(_T("Error: SetCurrentOperationMode error, unknown mode: %s\n"), strMode.c_str());
		return FALSE;
	}

	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_OPERATION_MODE, TRUE, &CurrentOperationMode, sizeof(DOT11_CURRENT_OPERATION_MODE));
	return bResult;
}

BOOL GetOperationModeCapability(tstring strGUID, tstring &strModes)
{
	BOOL bResult;
	DOT11_OPERATION_MODE_CAPABILITY OperationModeCapability;

	bResult = makeOIDRequest(strGUID, OID_DOT11_OPERATION_MODE_CAPABILITY, FALSE, &OperationModeCapability, sizeof(DOT11_OPERATION_MODE_CAPABILITY));
	if (bResult)
	{
		strModes = _T("");
		if ((OperationModeCapability.uOpModeCapability & DOT11_OPERATION_MODE_EXTENSIBLE_AP) == DOT11_OPERATION_MODE_EXTENSIBLE_AP)
		{
			if (strModes != _T(""))
			{
				strModes += _T(", ");
			}
			strModes += _T("master");
		}
		if ((OperationModeCapability.uOpModeCapability & DOT11_OPERATION_MODE_EXTENSIBLE_STATION) == DOT11_OPERATION_MODE_EXTENSIBLE_STATION)
		{
			if (strModes != _T(""))
			{
				strModes += _T(", ");
			}
			strModes += _T("managed");
		}
		if ((OperationModeCapability.uOpModeCapability & DOT11_OPERATION_MODE_NETWORK_MONITOR) == DOT11_OPERATION_MODE_NETWORK_MONITOR)
		{
			if (strModes != _T(""))
			{
				strModes += _T(", ");
			}
			strModes += _T("monitor");
		}
	}
	else
	{
		strModes = _T("unknown (call failed)");
	}

	return bResult;
}

BOOL IsMonitorModeSupported(tstring strGUID)
{
	BOOL bResult;
	DOT11_OPERATION_MODE_CAPABILITY OperationModeCapability;

	bResult = makeOIDRequest(strGUID, OID_DOT11_OPERATION_MODE_CAPABILITY, FALSE, &OperationModeCapability, sizeof(DOT11_OPERATION_MODE_CAPABILITY));
	if (bResult)
	{
		if ((OperationModeCapability.uOpModeCapability & DOT11_OPERATION_MODE_NETWORK_MONITOR) == DOT11_OPERATION_MODE_NETWORK_MONITOR)
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
}

BOOL GetCurrentChannel(tstring strGUID, ULONG &ulChannel)
{
	BOOL bResult;
	ULONG CurrentChannel;

	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_CHANNEL, FALSE, &CurrentChannel, sizeof(ULONG));
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
	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_CHANNEL, TRUE, &CurrentChannel, sizeof(ULONG));
	return bResult;
}

BOOL GetCurrentFrequency(tstring strGUID, ULONG &ulFrequency)
{
	BOOL bResult;
	ULONG CurrentFrequency;

	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_FREQUENCY, FALSE, &CurrentFrequency, sizeof(ULONG));
	if (bResult)
	{
		ulFrequency = CurrentFrequency;
	}
	else
	{
		ulFrequency = (ULONG) -1;
	}

	return bResult;
}

BOOL SetCurrentFrequency(tstring strGUID, ULONG ulFrequency)
{
	BOOL bResult;
	ULONG CurrentFrequency;

	CurrentFrequency = ulFrequency;
	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_FREQUENCY, TRUE, &CurrentFrequency, sizeof(ULONG));
	return bResult;
}

BOOL GetSupportedPhyTypes(tstring strGUID, vector<tstring> &nstrPhyTypes)
{
	BOOL bResult;
	DOT11_SUPPORTED_PHY_TYPES SupportedPhyTypes;

	bResult = makeOIDRequest(strGUID, OID_DOT11_SUPPORTED_PHY_TYPES, FALSE, &SupportedPhyTypes, sizeof(DOT11_SUPPORTED_PHY_TYPES));
	if (bResult)
	{
		nstrPhyTypes.clear();
		for (size_t i = 0; i < SupportedPhyTypes.uNumOfEntries; i++)
		{
			nstrPhyTypes.push_back(PhyType2String(SupportedPhyTypes.dot11PHYType[i]));
		}
	}

	g_nstrPhyTypes = nstrPhyTypes;
	return bResult;
}

BOOL GetDesiredPhyList(tstring strGUID, vector<tstring> &nstrPhyList)
{
	BOOL bResult;
	DOT11_PHY_ID_LIST DesiredPhyList;

	if (g_nstrPhyTypes.size() == 0)
	{
		GetSupportedPhyTypes(strGUID, g_nstrPhyTypes);
	}

	bResult = makeOIDRequest(strGUID, OID_DOT11_DESIRED_PHY_LIST, FALSE, &DesiredPhyList, sizeof(DOT11_PHY_ID_LIST));
	if (bResult)
	{
		nstrPhyList.clear();
		for (size_t i = 0; i < DesiredPhyList.uNumOfEntries; i++)
		{
			
			nstrPhyList.push_back(itos(DesiredPhyList.dot11PhyId[i]));
		}
	}

	return bResult;
}

BOOL GetCurrentPhyID(tstring strGUID, ULONG &ulPhyID)
{
	BOOL bResult;
	ULONG CurrentPhyID;

	bResult = makeOIDRequest(strGUID, OID_DOT11_CURRENT_PHY_ID, FALSE, &CurrentPhyID, sizeof(ULONG));
	if (bResult)
	{
		ulPhyID = CurrentPhyID;
	}
	else
	{
		ulPhyID = (ULONG)-1;
	}

	return bResult;
}
