Npcap
==========
Npcap is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It is sponsored but not officially supported by the [**Nmap Project**](http://nmap.org/) and [**Google Summer of Code (2013 and 2015)**](https://developers.google.com/open-source/gsoc/).

## Features

1. **NDIS 6 Support**: Npcap makes use of new LWF driver in Windows 7 and later (the legacy driver is used on XP and Vista), it's faster than the old [**NDIS 5 Intermediate**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) technique, One reason is that packet data stucture has changed (from **NDIS_PACKET** to **NET_BUFFER_LIST**) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. **"Admin-only Mode" Support**: Npcap supports to restrict its use to Administrators for safety purpose. If Npcap is installed with the option **Restrict Npcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the [**User Account Control (UAC)**](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog will prompt asking for Administrator privilege, only when the end user chooses **Yes**, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. **"WinPcap Compatible Mode" Support**: "WinPcap Compatible Mode" is used to decide whether Npcap should coexist With WinPcap or be compatible with WinPcap. With "WinPcap Compatible Mode" **OFF**, Npcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of Npcap **SHOULD** be able to use Npcap automatically if WinPcap is unavailable. The applications who knows Npcap's existence can choose to use Npcap or WinPcap first. The key about which is loaded first is [**DLL Search Path**](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx). With "WinPcap Compatible Mode" **OFF**, Npcap installs its DLLs into **C:\System32\Npcap\** instead of WinPcap's **C:\System32\**, so applications who want to load Npcap first must make **C:\System32\Npcap\** precedent to other paths in ways such as calling [**SetDllDirectory**](https://msdn.microsoft.com/en-us/library/ms686203.aspx), etc. Another point is Npcap uses service name **"npcap"** instead of WinPcap's **"npf"** with "WinPcap Compatible Mode" **OFF**, so if applications using **"net start npf"** for starting service must use **"net start npcap"** instead. If you want 100% compatibility with WinPcap, you should install Npcap choosing "WinPcap Compatible Mode" (Install Npcap in WinPcap API-compatible Mode). In this mode, Npcap will install its Dlls in WinPcap's **C:\System32\** and use the **"npf"** service name. Remember, before installing in this mode, you must uninstall WinPcap first (the installer wizard will prompt you that).
4. **Loopback Packets Capture Support**: Now Npcap is able to see Windows loopback packets using [**Windows Filtering Platform (WFP)**](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx) technique, after installation, Npcap will create an adapter named **"Npcap Loopback Adapter"** for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like "ping 127.0.0.1" (IPv4) or "ping ::1" (IPv6).
5. **Loopback Packets Send Support**: Besides loopback packets capturing, Npcap can also send out loopback packets based on [**Winsock Kernel (WSK)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff556958(v=vs.85).aspx) technique. A user software (e.g. Nmap) can just send packets out using **"Npcap Loopback Adapter"** like other adapters, **"Npcap Loopback Adapter"** will automatically remove the packet's Ethernet header and inject the payload into Windows TCP/IP stack, so this kind of loopback packet never go out of the machine.

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

* wpcap.dll needs to be built using **Visual Studio 2005**.
* packet.dll, NPFInstall.exe and NPcapHelper.exe need to be built using **Visual Studio 2010**.
* npf.sys (npcap.sys) needs to be built using **Visual Studio 2015** with **Windows Software Development Kit 10** and **Windows Driver Kit 10**.

## Packaging

Use **installer\Build.bat** to build all Visual Studio projects via MSBuild, make sure you installed Visual Studio 2005, Visual Studio 2010 and Visual Studio 2015 Non-Express Editions.

Use **installer\Deploy.bat** to copy and sign the files for "Non-WinPcap Mode", installer will be generated.

Use **installer\Deploy_WinPcap.bat** to copy and sign the files for "WinPcap Mode", installer will be generated.

Npcap uses NSIS script to package itself. The script location is: **installer\NPcap-for-nmap.nsi**. Compiling this script will generate the installer named **npcap-nmap-%VERSION%.exe**. The prebuilt installer is in [**my SVN repository**](https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/), which can be used to test without building it.

**installer\Deploy.bat** and **installer\Deploy_WinPcap.bat** will help you copy the files from build directories into right deployment folders (you need to manually create these folders before deployment):
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

Win7 and later (with "WinPcap Compatible Mode" OFF):
  x86:
    installer\win7_above\x86\npcap.cat
    installer\win7_above\x86\npcap.inf
	installer\win7_above\x86\npcap_wfp.inf
    installer\win7_above\x86\npcap.sys
    installer\win7_above\x86\NPFInstall.exe
	installer\win7_above\x86\NPcapHelper.exe
    installer\win7_above\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\win7_above\x64\npcap.cat
    installer\win7_above\x64\npcap.inf
	installer\win7_above\x64\npcap_wfp.inf
    installer\win7_above\x64\npcap.sys
    installer\win7_above\x64\NPFInstall.exe
	installer\win7_above\x64\NPcapHelper.exe
    installer\win7_above\x64\Packet.dll
    installer\x64\wpcap.dll

Win7 and later (with "WinPcap Compatible Mode" ON, this is the DEFAULT option):
  x86:
    installer\win7_above_winpcap\x86\npf.cat
    installer\win7_above_winpcap\x86\npf.inf
	installer\win7_above_winpcap\x86\npf_wfp.inf
    installer\win7_above_winpcap\x86\npf.sys
    installer\win7_above_winpcap\x86\NPFInstall.exe
	installer\win7_above_winpcap\x86\NPcapHelper.exe
    installer\win7_above_winpcap\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\win7_above_winpcap\x64\npf.cat
    installer\win7_above_winpcap\x64\npf.inf
	installer\win7_above_winpcap\x64\npf_wfp.inf
    installer\win7_above_winpcap\x64\npf.sys
    installer\win7_above_winpcap\x64\NPFInstall.exe
	installer\win7_above_winpcap\x64\NPcapHelper.exe
    installer\win7_above_winpcap\x64\Packet.dll
    installer\x64\wpcap.dll
```

## Run

1. Run and install the Npcap installer: **npcap-nmap-%VERSION%-%REVISION%.exe**.
2. Use Nmap or Wireshark to test Npcap.

## Try

The latest installers can always be found here: https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/.

## License

Npcap is published under [**The MIT License (MIT)**](http://opensource.org/licenses/MIT).

## Contact

* dev@nmap.org (Nmap Dev List)
* hsluoyz at gmail.com
