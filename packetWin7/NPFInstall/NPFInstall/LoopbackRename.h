/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename.h

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".
    Also, we need to make a flag in registry to let the Npcap driver know that "this adapter is ours", so send the loopback traffic to it.

This code is modified based on example: https://msdn.microsoft.com/en-us/library/windows/desktop/aa364686.aspx
--*/

#include "..\..\Common\WpcapNames.h"

BOOL RenameLoopbackNetwork(wchar_t strDeviceName[]);