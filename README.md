NPcap
==========
NPcap is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It is sponsored but not officially supported by the [**Nmap Project**](http://nmap.org/) and [**Google Summer of Code (2013 and 2015)**](https://developers.google.com/open-source/gsoc/).

## Features

1. **NDIS 6 Support**: NPcap makes use of new LWF driver in Windows 7 and later (the legacy driver is used on XP and Vista), it's faster than the old [**NDIS 5 Intermediate**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) technique, One reason is that packet data stucture has changed (from **NDIS_PACKET** to **NET_BUFFER_LIST**) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. **"Admin-only Mode" Support**: NPcap supports to restrict its use to Administrators for safety purpose. If NPcap is installed with the option **Restrict NPcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the [**User Account Control (UAC)**](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog will prompt asking for Administrator privilege, only when the end user chooses **Yes**, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. **Coexist With WinPcap**: NPcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of NPcap **SHOULD** be able to use NPcap automatically if WinPcap is unavailable. The applications who knows NPcap's existence can choose to use NPcap or WinPcap first.

## Architecture

NPcap tries to **keep the original WinPcap architecture as much as possible**. As the table shows, you will find it very similar with WinPcap.
```
File                 Src Directory            Description
wpcap.dll            wpcap                    the same with WinPcap
packet.dll           packetWin7\Dll           changed driver name, add `Admin-only mode` here
npcap.sys            packetWin7\npf           port from NDIS 5 to NDIS 6, the name is changed from npf.sys to npcap.sys
NPFInstall.exe       packetWin7\NPFInstall    a lwf driver installation tool we added to NPcap
NPcapHelper.exe      packetWin7\Helper        the helper program for `Admin-only mode`, will run under Administrator rights
```

## Build

* wpcap.dll, packet.dll, NPFInstall.exe and NPcapHelper.exe need to be built using **Visual Studio 2008** with **Windows SDK 8.1**.
* npcap.sys needs to be built using **Visual Studio 2013** with **Windows Driver Kit 8.1**.

## Packaging

NPcap uses NSIS script to package itself. The script location is: **installer\NPcap-for-nmap.nsi**. Compiling this script will generate the installer named **npcap-nmap-%VERSION%.exe**. The prebuilt installer is in [**my SVN repository**](https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/), which can be used to test without building it.

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

## Run

1. Run and install the NPcap installer: **npcap-nmap-%VERSION%.exe**.
2. Use Nmap or Wireshark to test NPcap.

# Known Issues

1. The trunk Nmap doesn't support NPcap yet, we will make it available in the next Nmap release. A prebuilt executable that supports NPcap can be found in: https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/nmap.exe.
2. Wireshark doesn't support NPcap yet, the community is working on it.

## License

NPcap is published under [**The MIT License (MIT)**](http://opensource.org/licenses/MIT).

## Contact

* dev@nmap.org (Nmap Dev List)
* hsluoyz at gmail.com
