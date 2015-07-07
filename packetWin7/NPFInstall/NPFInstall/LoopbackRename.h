/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename.h

Abstract:

    This is used for enumerating our "NPcap Loopback Adapter" using NetCfg API, if found, we changed its name from "Ethernet X" to "NPcap Loopback Adapter".
    Also, we need to make a flag in registry to let the NPcap driver know that "this adapter is ours", so send the loopback traffic to it.

This code is modified based on example: https://msdn.microsoft.com/en-us/library/windows/desktop/aa364686.aspx
--*/

BOOL RenameLoopbackNetwork(wchar_t strDeviceName[]);