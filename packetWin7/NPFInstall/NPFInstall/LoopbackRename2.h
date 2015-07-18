/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

    LoopbackRename2.h

Abstract:

    This is used for enumerating our "Npcap Loopback Adapter" using netsh.exe tool, if found, we changed its name from "Ethernet X" to "Npcap Loopback Adapter".

This code is based on the Windows built-in netsh.exe tool.
--*/

#include "..\..\Common\WpcapNames.h"

void PrepareRenameLoopbackNetwork2();

BOOL DoRenameLoopbackNetwork2();