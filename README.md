Npcap
==========
Npcap is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It is sponsored but not officially supported by the [**Nmap Project**](http://nmap.org/) and [**Google Summer of Code (2013 and 2015)**](https://developers.google.com/open-source/gsoc/).

## Features

1. **NDIS 6 Support**: Npcap makes use of new LWF driver in Windows 7 and later (the legacy driver is used on XP and Vista), it's faster than the old [**NDIS 5 Intermediate**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) technique, One reason is that packet data stucture has changed (from **NDIS_PACKET** to **NET_BUFFER_LIST**) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. **"Admin-only Mode" Support**: Npcap supports to restrict its use to Administrators for safety purpose. If Npcap is installed with the option **Restrict Npcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the [**User Account Control (UAC)**](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog will prompt asking for Administrator privilege, only when the end user chooses **Yes**, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. **Coexist With WinPcap**: Using "Non-WinPcap Mode", Npcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of Npcap **SHOULD** be able to use Npcap automatically if WinPcap is unavailable. The applications who knows Npcap's existence can choose to use Npcap or WinPcap first. The key about which is loaded first is [**DLL Search Path**](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx). In "Non-WinPcap Mode", Npcap installs its DLLs into **C:\System32\Npcap\** instead of WinPcap's **C:\System32\**, so applications who want to load Npcap first must make **C:\System32\Npcap\** precedent to other paths in ways such as calling [**SetDllDirectory**](https://msdn.microsoft.com/en-us/library/ms686203.aspx), etc. Another point is Npcap uses service name **"npcap"** instead of WinPcap's **"npf"** in "Non-WinPcap Mode", so if applications using **"net start npf"** for starting service must use **"net start npcap"** instead. If you want 100% compatibility with WinPcap, you should install Npcap choosing "WinPcap Mode" (Install Npcap in WinPcap API-compatible Mode). In this mode, Npcap will install its Dlls in WinPcap's **C:\System32\** and use the **"npf"** service name. Remember, before installing in this mode, you must uninstall WinPcap first (the installer wizard will prompt you that).
4. **Loopback Packets Capture Support**: Now Npcap is able to see Windows loopback packets using [**Windows Filtering Platform (WFP)**](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx) technique, after installation, Npcap will create an adapter named **"Npcap Loopback Adapter"** for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like "ping 127.0.0.1" (IPv4) or "ping ::1" (IPv6).

## Architecture

Npcap tries to **keep the original WinPcap architecture as much as possible**. As the table shows, you will find it very similar with WinPcap.
```
File                     Src Directory            Description
wpcap.dll                wpcap                    the same with WinPcap
packet.dll               packetWin7\Dll           changed driver name, add `Admin-only mode` here
npf.sys (or npcap.sys)   packetWin7\npf           port from NDIS 5 to NDIS 6, we support two names: npf or npcap, based on whether Npcap is installed in "WinPcap Mode"
NPFInstall.exe           packetWin7\NPFInstall    a lwf driver installation tool we added to Npcap
NPcapHelper.exe          packetWin7\Helper        the helper program for `Admin-only mode`, will run under Administrator rights
```

## Build

* wpcap.dll, packet.dll, NPFInstall.exe and NPcapHelper.exe need to be built using **Visual Studio 2005**.
* npcap.sys needs to be built using **Visual Studio 2013** with **Windows Driver Kit 8.1**.

## Packaging

Use **installer\Build.bat** to build all Visual Studio projects via MSBuild, make sure you installed Visual Studio 2005 and Visual Studio 2013 Non-Express Editions.

Use **installer\Deploy.bat** to copy and sign the files for "Non-WinPcap Mode", installer will be generated.

Use **installer\Deploy_WinPcap.bat** to copy and sign the files for "WinPcap Mode", installer will be generated.

Npcap uses NSIS script to package itself. The script location is: **installer\NPcap-for-nmap.nsi**. Compiling this script will generate the installer named **npcap-nmap-%VERSION%.exe**. The prebuilt installer is in [**my SVN repository**](https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/), which can be used to test without building it.

**installer\Deploy.bat** will help you copied the files need packaging into right folders (Deploy_WinPcap.bat works similarly):
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

1. Run and install the Npcap installer: **npcap-nmap-%VERSION%.exe**.
2. Use Nmap or Wireshark to test Npcap.

## Try

The latest installers can always be found here: https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/, the latest installer for now is: **npcap-nmap-0.01.exe**.

## License

Npcap is published under [**The MIT License (MIT)**](http://opensource.org/licenses/MIT).

## Contact

* dev@nmap.org (Nmap Dev List)
* hsluoyz at gmail.com
