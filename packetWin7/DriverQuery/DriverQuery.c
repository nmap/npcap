#include <stdio.h>
#include <Packet32.h>
#pragma comment(lib, "packet.lib")

#include <ntddndis.h>
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		_ftprintf(stderr, _T("Error in GetSystemDirectory: %x"), GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		_ftprintf(stderr, _T("Error in SetDllDirectory: %x"), GetLastError());
		return FALSE;
	}
	return TRUE;
}

VOID hexDump(PVOID pMem, size_t Len)
{
	PUCHAR data = (PUCHAR) pMem;
	for (size_t i=0; i < Len; i++) {
		if (i % 4 == 0) {
			if (i % 8 == 0) {
				_tprintf(_T("\n%04X "), i);
			}
			else {
				_tprintf(_T(" "));
			}
		}
		_tprintf(_T(" %02x"), data[i]);
	}
	_tprintf(_T("\n"));
}

DWORD doPacketGetInfo(ULONG ulID, PVOID pInfo, size_t infoLen)
{
	PUCHAR IoCtlBuffer = NULL;
	PPACKET_OID_DATA  OidData = NULL;
	DWORD dwResult = ERROR_INVALID_DATA;

	// 0xffff is completely arbitrary, but works as a safeguard
	if (pInfo == NULL || infoLen < sizeof(ULONG) || infoLen > 0xffff) {
		return ERROR_INVALID_DATA;
	}

	IoCtlBuffer = (PUCHAR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
		       	PACKET_OID_DATA_LENGTH(infoLen));
	if (IoCtlBuffer == NULL) {
		return GetLastError();
	}

	OidData = (PPACKET_OID_DATA) IoCtlBuffer;
	OidData->Oid = ulID;
	OidData->Length = infoLen;
	if (!PacketGetInfo(NULL, OidData)) {
		HeapFree(GetProcessHeap(), 0, IoCtlBuffer);
		return GetLastError();
	}
	CopyMemory(pInfo, OidData->Data, infoLen);
	HeapFree(GetProcessHeap(), 0, IoCtlBuffer);
	return ERROR_SUCCESS;
}

VOID printAdapters()
{
	const char *name, *desc;
	char *AdapterNames;
	ULONG NameLength;

	NameLength = 0;
	if (!PacketGetAdapterNames(NULL, &NameLength))
	{
		DWORD last_error = GetLastError();

		if (last_error != ERROR_INSUFFICIENT_BUFFER)
		{
			_tprintf(_T("PacketGetAdapterNames(NULL) error: (%08x)\n"),
					last_error
				);
			return;
		}
	}

	if (NameLength <= 0)
		return;
	AdapterNames = (char*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NameLength);
	if (AdapterNames == NULL)
	{
		_tprintf(_T("HeapAlloc error: (%08x)\n"),
				GetLastError()
			);
		return;
	}

	if (!PacketGetAdapterNames(AdapterNames, &NameLength)) {
		_tprintf(_T("PacketGetAdapterNames(NULL) error: (%08x)\n"),
				GetLastError()
			);
		HeapFree(GetProcessHeap(), 0, AdapterNames);
		return;
	}

	desc = AdapterNames;
	while (*desc != '\0' || *(desc + 1) != '\0')
		desc++;

	desc += 2;

	name = &AdapterNames[0];
	while (*name != '\0') {
		LPADAPTER dev = NULL;
		_tprintf(_T("%hs (%hs)\n"), name, desc);
		if (PacketIsLoopbackAdapter(name)) {
			goto next_name;
		}

		dev = PacketOpenAdapter(name);
		if (dev != NULL) {
			BOOLEAN Status = FALSE;
			size_t data_length = max(sizeof(NDIS_LINK_STATE), sizeof(NDIS_STATISTICS_INFO));
			//data_length = max(data_length, sizeof(IP_OFFLOAD_STATS));
			data_length = max(data_length, sizeof(NDIS_OFFLOAD));
			data_length = max(data_length, sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS));
			PPACKET_OID_DATA OidData = (PPACKET_OID_DATA) HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					PACKET_OID_DATA_LENGTH(data_length)
					);
			if (OidData == NULL) {
				goto next_name;
			}

#define DO_OID_READ(_Oid, _StrOid, _Block, _Length) do { \
	ZeroMemory(OidData->Data, data_length); \
	OidData->Oid = _Oid; \
	OidData->Length = _Length; \
	Status = PacketRequest(dev, FALSE, OidData); \
	if (Status) { \
		_tprintf(_T( _StrOid ": ")); \
		_Block; \
	} \
	else { \
		DWORD err = GetLastError(); \
		switch (err) { \
			case 0xe0010017: \
				_tprintf(_T( _StrOid " error: NDIS_STATUS_INVALID_OID\n")); \
				break; \
			case 0xe00000BB: \
				_tprintf(_T( _StrOid " error: STATUS_NOT_SUPPORTED\n")); \
				break; \
			case 0xe0000001: \
				_tprintf(_T( _StrOid " error: STATUS_INVALID_DEVICE_REQUEST\n")); \
				break; \
			case 0x00000001: \
				_tprintf(_T( _StrOid " error: ERROR_INVALID_FUNCTION\n")); \
				break; \
			default: \
				_tprintf(_T( _StrOid " error: %08x\n"), err); \
				break; \
		} \
	} \
} while (0);

#define DO_OID_READ_ULONG(_Oid) DO_OID_READ(_Oid, #_Oid, \
	       	_tprintf(_T("%08x\n"), *(ULONG *)OidData->Data), \
	       	sizeof(ULONG))

#define DO_OID_READ_HEXDUMP(_Oid, _Length) DO_OID_READ(_Oid, #_Oid, \
		hexDump(OidData->Data, _Length), \
		_Length)

			DO_OID_READ_ULONG(OID_GEN_RCV_OK);
			DO_OID_READ_ULONG(OID_GEN_RCV_NO_BUFFER);
			DO_OID_READ_ULONG(OID_GEN_RECEIVE_BUFFER_SPACE);
			DO_OID_READ_ULONG(OID_GEN_RECEIVE_BLOCK_SIZE);
			DO_OID_READ_ULONG(OID_GEN_XMIT_OK);
			DO_OID_READ_ULONG(OID_GEN_TRANSMIT_BUFFER_SPACE);
			DO_OID_READ_ULONG(OID_GEN_TRANSMIT_QUEUE_LENGTH);
			DO_OID_READ_ULONG(OID_GEN_TRANSMIT_BLOCK_SIZE);

			DO_OID_READ_ULONG(OID_GEN_CURRENT_PACKET_FILTER);
			DO_OID_READ_ULONG(OID_GEN_MAXIMUM_TOTAL_SIZE);
			DO_OID_READ_ULONG(OID_GEN_CURRENT_LOOKAHEAD);

			//DO_OID_READ_HEXDUMP(OID_IP4_OFFLOAD_STATS, sizeof(IP_OFFLOAD_STATS));
			//DO_OID_READ_HEXDUMP(OID_IP6_OFFLOAD_STATS, sizeof(IP_OFFLOAD_STATS));
			DO_OID_READ_HEXDUMP(OID_TCP_OFFLOAD_CURRENT_CONFIG, sizeof(NDIS_OFFLOAD));

			DO_OID_READ_HEXDUMP(OID_GEN_MEDIA_IN_USE, 3 * sizeof(ULONG));

			DO_OID_READ_HEXDUMP(OID_GEN_LINK_STATE,
				       	sizeof(NDIS_LINK_STATE));
			DO_OID_READ_HEXDUMP(OID_GEN_STATISTICS,
				       	sizeof(NDIS_STATISTICS_INFO));
			DO_OID_READ_HEXDUMP(OID_GEN_INTERRUPT_MODERATION,
				       	sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS));

			HeapFree(GetProcessHeap(), 0, OidData);
			PacketCloseAdapter(dev);
		}
		else {
			_tprintf(_T("\tFAILED: %08x\n"), GetLastError());
		}
next_name:
		name += strlen(name) + 1;
		desc += strlen(desc) + 1;
	}

	HeapFree(GetProcessHeap(), 0, AdapterNames);
	return;
}

int main()
{
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		_ftprintf(stderr, _T("Couldn't load Npcap\n"));
		exit(1);
	}

	//
	// Obtain the name of the adapters installed on this machine
	//

	_tprintf(_T("Packet.dll test application.\n"));
       	_tprintf(_T("Library version: %hs\n"), PacketGetVersion());
       	_tprintf(_T("Driver version: %hs\n"), PacketGetDriverVersion());
	
	ULONG ulInfo = 0;
	USHORT usStat[2] = {0};
	DWORD err = ERROR_SUCCESS;

#define GETINFO(_Name) do { \
	err = doPacketGetInfo(_Name, &ulInfo, sizeof(ulInfo)); \
	if (err == ERROR_SUCCESS) { \
		_tprintf(_T( #_Name ": %08x\n"), ulInfo); \
	} \
	else { \
		_tprintf(_T("PacketGetInfo(" #_Name ") error: %08x\n"), \
				GetLastError()); \
	} \
} while (0);

	GETINFO(NPF_GETINFO_VERSION);
	ULONG ulVersion = ulInfo;

	GETINFO(NPF_GETINFO_CONFIG);
	GETINFO(NPF_GETINFO_BPFEXT);
	GETINFO(NPF_GETINFO_MODES);

#define GETSTATS(_Name) do { \
	*((ULONG *)usStat) = _Name; \
	err = doPacketGetInfo(NPF_GETINFO_STATS, &usStat, sizeof(usStat)); \
	if (err == ERROR_SUCCESS) { \
		_tprintf(_T( #_Name ": %hu, %hu\n"), \
			       	usStat[0], usStat[1]); \
	} \
	else if (ulVersion > 0x01540000) { \
		_tprintf(_T("PacketGetInfo(" #_Name ") error: %08x\n"), \
				GetLastError()); \
	} \
} while (0);

	GETSTATS(NPF_STATSINFO_RECVTIMES);
	GETSTATS(NPF_STATSINFO_SENDTIMES);
	GETSTATS(NPF_STATSINFO_DPCTIMES);

	_tprintf(_T("Adapters installed:\n"));
	printAdapters();

	return (0);
}
