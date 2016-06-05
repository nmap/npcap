Npcap
==========

[![Build status](https://ci.appveyor.com/api/projects/status/01yoks5rn14wgny2?svg=true)](https://ci.appveyor.com/project/hsluoyz/npcap)
![Environment](https://img.shields.io/badge/Windows-Vista, 7, 8, 10-brightgreen.svg)
![Release](https://img.shields.io/github/release/nmap/npcap.svg)
![License](https://img.shields.io/github/license/nmap/npcap.svg)
![Downloads](https://img.shields.io/github/downloads/nmap/npcap/latest/total.svg)
![TotalDownloads](https://img.shields.io/github/downloads/nmap/npcap/total.svg)

[**Npcap**](http://www.npcap.org) is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It supports **Windows Vista, 7, 8 and 10**. It is sponsored by the [**Nmap Project**](http://nmap.org/) and developed by [**Yang Luo**](http://www.veotax.com/) under [**Google Summer of Code 2013**](https://www.google-melange.com/gsoc/project/details/google/gsoc2013/hsluoyz/5727390428823552) and [**2015**](https://www.google-melange.com/gsoc/project/details/google/gsoc2015/hsluoyz/5723971634855936). It also received many helpful tests from [**Wireshark**](https://www.wireshark.org/) and [**NetScanTools**](http://www.netscantools.com/).

![Npcap Logo](installer/npcap-logo.png)

## Features

1. **NDIS 6 Support**: Npcap makes use of new [NDIS 6 Light-Weight Filter (LWF)](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) API in Windows Vista and later (the legacy driver is used on XP). It's faster than the deprecated [NDIS 5](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) API, which Microsoft could remove at any time.
2. **Extra Security**: Npcap can be restricted so that only Administrators can sniff packets. If a non-Admin user tries to utilize Npcap through software such as Nmap or Wireshark, the user will have to pass a [User Account Control (UAC)](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog to utilize the driver. This is conceptually similar to UNIX, where root access is generally required to capture packets.
3. **WinPcap Compatibility**: If you choose ``WinPcap Compatible Mode`` at install-time, Npcap will use the WinPcap-style DLL directories ``c:\Windows\System32`` and servcie name ``npf``, allowing software built with WinPcap in mind to transparently use Npcap instead. If compatability mode is not selected, Npcap is installed in a different location ``C:\Windows\System32\Npcap`` with a different service name ``npcap`` so that both drivers can coexist on the same system. In this case, applications which only know about WinPcap will continue using that, while other applications can choose to use the newer and faster Npcap driver instead.
4. **Loopback Packet Capture**: Npcap is able to sniff loopback packets (transmissions between services on the same machine) by using the [Windows Filtering Platform (WFP)](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx). After installation, Npcap will create an adapter named ``Npcap Loopback Adapter`` for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like ``ping 127.0.0.1`` (IPv4) or ``ping ::1`` (IPv6).
5. **Loopback Packet Injection**: Npcap is also able to send loopback packets using the [Winsock Kernel (WSK)](https://msdn.microsoft.com/en-us/library/windows/hardware/ff556958(v=vs.85).aspx) technique. User-level software such as [Nping](https://nmap.org/nping/) can just send the packets out using ``Npcap Loopback Adapter`` just like any other adapter. Npcap then does the magic of removing the packet's Ethernet header and injecting the payload into the Windows TCP/IP stack.
6. **Raw 802.11 Packet Capture**: Npcap is able to see **802.11** packets instead of **fake Ethernet** packets on ordinary wireless adapters. You need to select the ``Support raw 802.11 traffic (and monitor mode) for wireless adapters`` option in the installation wizard to enable this feature. When your adapter is in ``Monitor Mode``, Npcap will supply all ``802.11 data + control + management`` packets with ``radiotap`` headers. When your adapter is in ``Managed Mode``, Npcap will only supply ``802.11 data`` packets with ``radiotap`` headers. Moreover, Npcap provides the ``WlanHelper.exe`` tool to help you switch to ``Monitor Mode`` on Windows. See more details about this feature in section ``For software that use Npcap raw 802.11 feature``. See more details about ``radiotap`` here: http://www.radiotap.org/

## Documentation

[Npcap Users' Guide](https://htmlpreview.github.io/?https://github.com/nmap/npcap/blob/master/docs/npcap-guide-wrapper.html)

## Build

Run ``installer\Build.bat``: build all DLLs and the driver. The DLLs need to be built using **Visual Studio 2013**. And the driver needs to be built using **Visual Studio 2015** with **Windows SDK 10 10586** & **Windows Driver Kit 10 10586**.

## Packaging

Run ``installer\Deploy.bat``: copy the files from build directories to deployment directories and sign the files. Generate an installer named ``npcap-%VERSION%.exe`` using [NSIS large strings build](http://nsis.sourceforge.net/Special_Builds) with the [SysRestore plug-in (special build for Npcap)](https://github.com/hsluoyz/SysRestore) and sign the installer.

## Build SDK (optional)

Run ``build_sdk.bat``: copy the headers, libraries, examples and docs from build directories to ``npcap-sdk`` directory and package them into a zip file named ``npcap-sdk-<VERSION>.zip`` in the ``installer`` folder using [7-Zip](http://www.7-zip.org/).

## Generating debug symbols (optional)

Run ``installer\Deploy_Symbols.bat``: copy the debug symbol files (.PDB) from build directories to deployment directories and package them into a zip file named ``npcap-<VERSION>-DebugSymbols.zip`` using [7-Zip](http://www.7-zip.org/).

## Downloads

1. Download and install the latest Npcap installer: https://github.com/nmap/npcap/releases
2. Use [Nmap](https://nmap.org/) or [Wireshark](https://www.wireshark.org/) to test Npcap.

## Development kit

Npcap has its own SDK for ``Non-WinPcap Compatible Mode``. By using it, your software will run under ``Non-WinPcap Compatible Mode``. We don't update the SDK as frequently as the binaries. The latest SDK is [Npcap SDK 0.07 r9](https://github.com/nmap/npcap/releases/tag/v0.07-r9).

If you only want to build your software under ``WinPcap Compatible Mode`` (which is **NOT** recommended), please use the legacy [WinPcap 4.1.2 Developer's Pack](http://www.winpcap.org/devel.htm) instead.

## Our users

Npcap has been used in many software. They are:

* [Nmap](https://nmap.org/) (``Non-WinPcap Compatible Mode``, installer integrated, in beta test)
* [Wireshark](https://www.wireshark.org/) (``WinPcap Compatible Mode``, installer detected)
* [GNS3](https://www.gns3.com/) (``Non-WinPcap Compatible Mode``, installer integrated, in beta test)
* [Aircrack-ng](http://www.aircrack-ng.org/) (in development)
* [VividCortex](https://www.vividcortex.com/) (``WinPcap Compatible Mode``, recommended in docs)
* [Elastic Beats](https://www.elastic.co/products/beats) (``WinPcap Compatible Mode``, recommended in FAQ)
* [ApacheBeat](https://github.com/radoondas/apachebeat) (``WinPcap Compatible Mode``, recommended in FAQ)

Any other user software who want to be listed here can contact: [Yang Luo](mailto:hsluoyz@gmail.com).

## Bug report

Please report any bugs or issues about Npcap at: https://github.com/nmap/nmap/issues

## License

See: [LICENSE](https://github.com/nmap/npcap/blob/master/LICENSE)

## Contact

* ``dev@nmap.org`` (Nmap development list, this is **preferred**)
* ``hsluoyz@gmail.com`` (Yang Luo's email, if your issue needs to be kept private, please contact me via this mail)
