NPcap
==========

## Introduction

NPcap is an update of **WinPcap** to **NDIS 6 Light-Weight Filter (LWF)** technique. It is sponsored but not officially supported by the Nmap Project.

## Features

1. NPcap makes use of new LWF driver in Windows 7 and later (the legacy driver is used on XP and Vista), it's faster than the old **NDIS 5 Intermediate** technique, One reason is that packet data stucture has changed (from **NDIS_PACKET** to **NET_BUFFER_LIST**) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. NPcap supports to restrict its use to Administrators for safety purpose. If NPcap is installed with the option **Restrict NPcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the User Account Control (UAC) dialog will prompt asking for Administrator privilege, only when the end user chooses **Yes**, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. NPcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of NPcap **should** be able to use NPcap automatically if WinPcap is unavailable. The applications who knows NPcap's existence can choose to use NPcap or WinPcap first.

## Architecture

NPcap tries to keep the original WinPcap architecture as much as possible. As the table shows, you will find it very similar with WinPcap.
```
File                 Src Directory            Description
wpcap.dll            wpcap                    the same with WinPcap
packet.dll           packetWin7\Dll           changed driver name, add `Admin-only mode` here
npcap.sys            packetWin7\npf           port from NDIS 5 to NDIS 6, the name is changed from npf.sys to npcap.sys
NPFInstall.exe       packetWin7\NPFInstall    a lwf driver installation tool we added to NPcap
NPcapHelper.exe      packetWin7\Helper        the helper program for `Admin-only mode`, will run under Administrator rights
```

## Build

* wpcap.dll, packet.dll and NPcapHelper.exe need to be built using **Visual Studio 2005**.
* NPFInstall.exe needs to be built using **Visual Studio 2008**.
* npcap.sys needs to be built using **Visual Studio 2013** with **Windows Driver Kit 8.1**.

## Packaging

NPcap uses NSIS script to package itself. The script location is: **installer\NPcap-for-nmap.nsi**.

Before compiling the script, make sure you copied the files need packaging into right folders:
```
XP: (the same with WinPcap)
  x86:
    installer\npf.sys
    installer\rpcapd.exe
    installer\wpcap.dll
    installer\nt5\x86\Packet.dll
  x64:
    installer\x64\npf.sys
    installer\x64\wpcap.dll
    installer\nt5\x64\Packet.dll
    
Vista: (the same with WinPcap)
  x86:
    installer\npf.sys
    installer\rpcapd.exe
    installer\wpcap.dll
    installer\vista\x86\Packet.dll
  x64:
    installer\x64\npf.sys
    installer\x64\wpcap.dll
    installer\vista\x64\Packet.dll
    
Win7 and later (with "Admin-only mode" OFF):
  x86:
    installer\win7_above\x86\npcap.cat
    installer\win7_above\x86\npcap.inf
    installer\win7_above\x86\npcap.sys
    installer\win7_above\x86\NPFInstall.exe
    installer\win7_above\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\win7_above\x64\npcap.cat
    installer\win7_above\x64\npcap.inf
    installer\win7_above\x64\npcap.sys
    installer\win7_above\x64\NPFInstall.exe
    installer\win7_above\x64\Packet.dll
    installer\x64\wpcap.dll
    
Win7 and later (with "Admin-only mode" ON):
  x86:
    installer\win7_above\x86\admin_only\npcap.cat
    installer\win7_above\x86\admin_only\npcap.inf
    installer\win7_above\x86\admin_only\npcap.sys
    installer\win7_above\x86\admin_only\NPcapHelper.exe
    installer\win7_above\x86\NPFInstall.exe
    installer\win7_above\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\win7_above\x64\admin_only\npcap.cat
    installer\win7_above\x64\admin_only\npcap.inf
    installer\win7_above\x64\admin_only\npcap.sys
    installer\win7_above\x64\admin_only\NPcapHelper.exe
    installer\win7_above\x64\NPFInstall.exe
    installer\win7_above\x64\Packet.dll
    installer\x64\wpcap.dll
```

## License

The MIT License (MIT)

Copyright (c) 2015 nmap.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## Contact

* dev@nmap.org (Nmap Dev List)
* hsluoyz at gmail.com
