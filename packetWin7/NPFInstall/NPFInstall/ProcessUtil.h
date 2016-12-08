/*++

Copyright (c) Nmap.org.  All rights reserved.

Module Name:

ProcessUtil.h

Abstract:

Get processes which are using Npcap DLLs.

--*/

#include <vector>
using namespace std;

typedef std::basic_string<TCHAR> tstring;

tstring getInUseProcesses();

BOOL killInUseProcesses();

BOOL killInUseProcesses_Soft();
