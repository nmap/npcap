/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

	LoopbackRecord.h

Abstract:

	This is used for enumerating our "Npcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" or "Local Network Area" to "Npcap Loopback Adapter".
	Also, we need to make a flag in registry to let the Npcap driver know that "this adapter is ours", so send the loopback traffic to it.

--*/

int getIntDevID(TCHAR strDevID[]);
BOOL AddFlagToRegistry(wchar_t strDeviceName[]);
BOOL RecordLoopbackDevice(int iNpcapAdapterID);