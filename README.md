Npcap
==========
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Environment](https://img.shields.io/badge/Windows-Vista, 7, 8, 10-yellow.svg)
![Release](https://img.shields.io/github/release/nmap/npcap.svg)
![License](https://img.shields.io/github/license/nmap/npcap.svg)

Npcap is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It supports **Windows Vista, 7, 8 and 10**. It is sponsored but not officially supported by the [**Nmap Project**](http://nmap.org/) and finished by [**Yang Luo**](http://www.veotax.com/) under [**Google Summer of Code 2013**](https://www.google-melange.com/gsoc/homepage/google/gsoc2013) and [**Google Summer of Code 2015**](https://www.google-melange.com/gsoc/homepage/google/gsoc2015). It also received many helpful tests from [**Wireshark**](https://www.wireshark.org/) and [**NetScanTools**](http://www.netscantools.com/).

## Features

1. **NDIS 6 Support**: Npcap makes use of new LWF driver in Windows Vista and later (the legacy driver is used on XP), it's faster than the old [**NDIS 5 Intermediate**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) technique, One reason is that packet data stucture has changed (from **NDIS_PACKET** to **NET_BUFFER_LIST**) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. **"Admin-only Mode" Support**: Npcap supports to restrict its use to Administrators for safety purpose. If Npcap is installed with the option **Restrict Npcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the [**User Account Control (UAC)**](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog will prompt asking for Administrator privilege, only when the end user chooses **Yes**, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. **"WinPcap Compatible Mode" Support**: "WinPcap Compatible Mode" is used to decide whether Npcap should coexist With WinPcap or be compatible with WinPcap. With "WinPcap Compatible Mode" **OFF**, Npcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of Npcap **SHOULD** be able to use Npcap automatically if WinPcap is unavailable. The applications who knows Npcap's existence can choose to use Npcap or WinPcap first. The key about which is loaded first is [**DLL Search Path**](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx). With "WinPcap Compatible Mode" **OFF**, Npcap installs its DLLs into **C:\System32\Npcap\** instead of WinPcap's **C:\System32\**, so applications who want to load Npcap first must make **C:\System32\Npcap\** precedent to other paths in ways such as calling [**SetDllDirectory**](https://msdn.microsoft.com/en-us/library/ms686203.aspx), etc. Another point is Npcap uses service name **"npcap"** instead of WinPcap's **"npf"** with "WinPcap Compatible Mode" **OFF**, so if applications using **"net start npf"** for starting service must use **"net start npcap"** instead. If you want 100% compatibility with WinPcap, you should install Npcap choosing "WinPcap Compatible Mode" (Install Npcap in WinPcap API-compatible Mode). In this mode, Npcap will install its Dlls in WinPcap's **C:\System32\** and use the **"npf"** service name. Remember, before installing in this mode, you must uninstall WinPcap first (the installer wizard will prompt you that).
4. **Loopback Packets Capture Support**: Now Npcap is able to see Windows loopback packets using [**Windows Filtering Platform (WFP)**](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx) technique, after installation, Npcap will create an adapter named **"Npcap Loopback Adapter"** for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like "ping 127.0.0.1" (IPv4) or "ping ::1" (IPv6).
5. **Loopback Packets Send Support**: Besides loopback packets capturing, Npcap can also send out loopback packets based on [**Winsock Kernel (WSK)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff556958(v=vs.85).aspx) technique. A user software (e.g. Nmap) can just send packets out using **"Npcap Loopback Adapter"** like other adapters, **"Npcap Loopback Adapter"** will automatically remove the packet's Ethernet header and inject the payload into Windows TCP/IP stack, so this kind of loopback packet never go out of the machine.

## Architecture

Npcap tries to **keep the original WinPcap architecture as much as possible**. As the table shows, you will find it very similar with WinPcap.
```
File                     Src Directory            Description
wpcap.dll                wpcap                    the same with WinPcap
packet.dll               packetWin7\Dll           changed driver name, add "Admin-only Mode" here
npf.sys (or npcap.sys)   packetWin7\npf           port from NDIS 5 to NDIS 6, we support two names: npf or npcap, based on whether Npcap is installed in "WinPcap Compatible Mode"
NPFInstall.exe           packetWin7\NPFInstall    a lwf driver installation tool we added to Npcap
NPcapHelper.exe          packetWin7\Helper        the helper program for "Admin-only Mode", will run under Administrator rights
```

## For softwares that uses Npcap loopback feature

Npcap's loopback adapter device is based on **Microsoft KM-TEST Loopback Adapter (Microsoft Loopback Adapter)**, it is an Ethernet adapter, and Npcap has changed its behavior and rename it to **"Npcap Loopback Adapter"**, to make it see the real loopback traffic only, the traffic captured by original WinPcap will not appear here. 

The IP address of "Npcap Loopback Adapter" is usually like **169.254.x.x**, however, this is totally meaningless, softwares using Npcap should view this interface's IP address as **127.0.0.1** (IPv4) and **::1** (IPv6). This work can't be done by Npcap because Windows forbids any IP address to be configured as 127.0.0.1, it's reserved.

The MAC address of "Npcap Loopback Adapter" is usually like **02:00:4C:4F:4F:50**, however, this is meaningless too, softwares using Npcap should think this interface doesn't own a MAC address, as the loopback traffic never goes to link layer. For softwares using Npcap to capture loopback traffic, the MAC addresses in captured data will be all zeros. For softwares using Npcap to send loopback traffic, any MAC addresses can be specified as they will be ignored. But notice that ether_type in Ethernet header should be set correctly, only **IPv4** and **IPv6** are accepted, other values like **ARP** will be ignored. (You don't need an ARP request for loopback interface)

The MTU of "Npcap Loopback Adapter" is hard-coded to **65536** by Npcap, softwares using Npcap should get this value automatically and no special handling is needed. This value is determined manually and doesn't mean Windows loopback stack can only support packet size as large as **65536**. So don't feel weird if you have captured packets whose size are larger than it.

Don't try to make OID requests to "Npcap Loopback Adapter" except **OID_GEN_MAXIMUM_TOTAL_SIZE** (MTU), these requests will succeed as other adapters, but they are only meaningful for NDIS adapters and Npcap doesn't even use the NDIS way to handle the loopback traffic. The only handled OID request by Npcap is **OID_GEN_MAXIMUM_TOTAL_SIZE**: If you query its value, you will always get **65550 (65536 + 14)**, if you try to set its value, the operation will always fail.

To conclude, a software that wants to support Npcap loopback feature should do these steps:

* Detect "Npcap Loopback Adapter"'s presence, by reading registry value **Loopback** at key **Computer\HKEY_LOCAL_MACHINE\SOFTWARE(\Wow6432Node)\Npcap**. If "Npcap Loopback Adapter" exsits, then perform the following steps.
* Modify the IP address of "Npcap Loopback Adapter" to **127.0.0.1** (IPv4) and **::1** (IPv6).
* Modify the MAC address of "Npcap Loopback Adapter" to all zeros.
* If you use [**IP Helper API**](https://msdn.microsoft.com/en-us/library/aa366073.aspx) to get adapter list, you will get an interface named like **"Loopback Pseudo-Interface 1"**, this interface is a dummy interface by Microsoft and can't be seen in NDIS layer. It also takes the 127.0.0.1 IP address. A good practise for softwares is that merge the "Npcap Loopback Adapter" and "Loopback Pseudo-Interface 1" into one, like what I have implemented for Nmap.
* Don't make use of OID requests for "Npcap Loopback Adapter" except **OID_GEN_MAXIMUM_TOTAL_SIZE** requests.

## Build

* wpcap.dll needs to be built using **Visual Studio 2005**.
* packet.dll, NPFInstall.exe and NPcapHelper.exe need to be built using **Visual Studio 2010**.
* npf.sys (npcap.sys) needs to be built using **Visual Studio 2015** with **Windows Software Development Kit 10** and **Windows Driver Kit 10**.

## Packaging

Packaging steps:

* Run **installer\Build.bat**: build non-driver projects via MSBuild, make sure you installed Visual Studio 2005, Visual Studio 2010 Non-Express Editions.
* Build **packetWin7\npf**: build driver projects npf.sln and npcap.sln via Visual Studio 2015, I forbid the use of the script build for the driver, because it has signature issue (the compiled binaries are not well signed).
* Run **installer\Deploy.bat**: copy and sign the files for "Non-WinPcap Compatible Mode", installer will be generated.
* Run **installer\Deploy_WinPcap.bat**: copy and sign the files for "WinPcap Compatible Mode", installer will be generated.

Npcap uses NSIS script to package itself. The script location is: **installer\NPcap-for-nmap.nsi**. Compiling this script will generate the installer named **npcap-nmap-%VERSION%.exe**. The prebuilt installer is in [**my SVN repository**](https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/), which can be used to test without building it.

**installer\Deploy.bat** and **installer\Deploy_WinPcap.bat** will help you copy the files from build directories into right deployment folders (you need to manually create these folders before deployment):
```
XP (the same with original WinPcap):
  x86:
    installer\npf.sys
    installer\rpcapd.exe
    installer\wpcap.dll
    installer\nt5\x86\Packet.dll
  x64:
    installer\x64\npf.sys
    installer\x64\wpcap.dll
    installer\nt5\x64\Packet.dll

Vista (with "WinPcap Compatible Mode" OFF):
  x86:
    installer\vista\x86\npcap.cat
    installer\vista\x86\npcap.inf
	installer\vista\x86\npcap_wfp.inf
    installer\vista\x86\npcap.sys
    installer\win7_above\x86\NPFInstall.exe
	installer\win7_above\x86\NPcapHelper.exe
    installer\win7_above\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\vista\x64\npcap.cat
    installer\vista\x64\npcap.inf
	installer\vista\x64\npcap_wfp.inf
    installer\vista\x64\npcap.sys
    installer\win7_above\x64\NPFInstall.exe
	installer\win7_above\x64\NPcapHelper.exe
    installer\win7_above\x64\Packet.dll
    installer\x64\wpcap.dll

Vista (with "WinPcap Compatible Mode" ON, this is the DEFAULT option):
  x86:
    installer\vista_winpcap\x86\npf.cat
    installer\vista_winpcap\x86\npf.inf
	installer\vista_winpcap\x86\npf_wfp.inf
    installer\vista_winpcap\x86\npf.sys
    installer\win7_above_winpcap\x86\NPFInstall.exe
	installer\win7_above_winpcap\x86\NPcapHelper.exe
    installer\win7_above_winpcap\x86\Packet.dll
    installer\wpcap.dll
  x64:
    installer\vista_winpcap\x64\npf.cat
    installer\vista_winpcap\x64\npf.inf
	installer\vista_winpcap\x64\npf_wfp.inf
    installer\vista_winpcap\x64\npf.sys
    installer\win7_above_winpcap\x64\NPFInstall.exe
	installer\win7_above_winpcap\x64\NPcapHelper.exe
    installer\win7_above_winpcap\x64\Packet.dll
    installer\x64\wpcap.dll

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

* The latest installer can always be found here:
https://github.com/nmap/npcap/releases

* Previous installers before Npcap 0.05 can be found here:
https://svn.nmap.org/nmap-exp/yang/NPcap-LWF/npcap_history_versions/

* The changes of Nmap to use Npcap's loopback feature can be found here:
https://svn.nmap.org/nmap-exp/yang/nmap-npcap/

* The compiled Nmap binaries after above changes can be found here:
https://svn.nmap.org/nmap-exp/yang/nmap-npcap_compiled_binaries/

## License

Npcap is published under [**The MIT License (MIT)**](http://opensource.org/licenses/MIT).

## Contact

* dev@nmap.org (Nmap development list, this is **preferred**)
* hsluoyz@gmail.com (Yang Luo's email, if your issue needs to be kept private, please contact me via this mail)
