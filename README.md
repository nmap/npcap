Npcap
==========

[![Build status](https://ci.appveyor.com/api/projects/status/01yoks5rn14wgny2?svg=true)](https://ci.appveyor.com/project/hsluoyz/npcap)
![Environment](https://img.shields.io/badge/Windows-Vista,%207,%208,%2010-brightgreen.svg)
[![Release](https://img.shields.io/github/release/nmap/npcap.svg)](https://github.com/nmap/npcap/releases)
![License](https://img.shields.io/github/license/nmap/npcap.svg)
![Downloads](https://img.shields.io/github/downloads/nmap/npcap/latest/total.svg)
![TotalDownloads](https://img.shields.io/github/downloads/nmap/npcap/total.svg)

[**Npcap**](http://www.npcap.org) is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It supports **Windows Vista, 7, 8 and 10**. It is sponsored by the [**Nmap Project**](http://nmap.org/) and developed by [**Yang Luo**](http://www.veotax.com/) under [**Google Summer of Code 2013**](https://www.google-melange.com/gsoc/project/details/google/gsoc2013/hsluoyz/5727390428823552) and [**2015**](https://www.google-melange.com/gsoc/project/details/google/gsoc2015/hsluoyz/5723971634855936). It also received many helpful tests from [**Wireshark**](https://www.wireshark.org/), [**libpcap**](https://github.com/the-tcpdump-group/libpcap) and [**NetScanTools**](http://www.netscantools.com/).

## Features

1. **NDIS 6 Support**: Npcap makes use of new [NDIS 6 Light-Weight Filter (LWF)](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) API in Windows Vista and later (the legacy driver is used on XP). It's faster than the deprecated [NDIS 5](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) API, which Microsoft could remove at any time.
2. **Latest libpcap API Support**: Npcap provides support for the latest [libpcap API](https://github.com/the-tcpdump-group/libpcap) by accepting libpcap as a [Git submodule](https://git-scm.com/docs/git-submodule). The latest libpcap 1.8.0 has integrated more fascinating features and functions than the [deprecated libpcap 1.0.0 shipped by WinPcap](https://www.winpcap.org/misc/changelog.htm). Moreover, since Linux already has a good support for latest libpcap API, using Npcap on Windows facilitates your software to base on the same API on both Windows and Linux.
3. **Extra Security**: Npcap can be restricted so that only Administrators can sniff packets. If a non-Admin user tries to utilize Npcap through software such as Nmap or Wireshark, the user will have to pass a [User Account Control (UAC)](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog to utilize the driver. This is conceptually similar to UNIX, where root access is generally required to capture packets.
4. **WinPcap Compatibility**: If you choose ``WinPcap Compatible Mode`` at install-time, Npcap will use the WinPcap-style DLL directories ``c:\Windows\System32`` and servcie name ``npf``, allowing software built with WinPcap in mind to transparently use Npcap instead. If compatability mode is not selected, Npcap is installed in a different location ``C:\Windows\System32\Npcap`` with a different service name ``npcap`` so that both drivers can coexist on the same system. In this case, applications which only know about WinPcap will continue using that, while other applications can choose to use the newer and faster Npcap driver instead.
5. **Loopback Packet Capture**: Npcap is able to sniff loopback packets (transmissions between services on the same machine) by using the [Windows Filtering Platform (WFP)](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx). After installation, Npcap will create an adapter named ``Npcap Loopback Adapter`` for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like ``ping 127.0.0.1`` (IPv4) or ``ping ::1`` (IPv6).
6. **Loopback Packet Injection**: Npcap is also able to send loopback packets using the [Winsock Kernel (WSK)](https://msdn.microsoft.com/en-us/library/windows/hardware/ff556958(v=vs.85).aspx) technique. User-level software such as [Nping](https://nmap.org/nping/) can just send the packets out using ``Npcap Loopback Adapter`` just like any other adapter. Npcap then does the magic of removing the packet's Ethernet header and injecting the payload into the Windows TCP/IP stack.
7. **Raw 802.11 Packet Capture**: Npcap is able to see **802.11** packets instead of **fake Ethernet** packets on ordinary wireless adapters. You need to select the ``Support raw 802.11 traffic (and monitor mode) for wireless adapters`` option in the installation wizard to enable this feature. When your adapter is in ``Monitor Mode``, Npcap will supply all ``802.11 data + control + management`` packets with ``radiotap`` headers. When your adapter is in ``Managed Mode``, Npcap will only supply ``Ethernet`` packets. Npcap directly supports to use Wireshark to capture in ``Monitor Mode``. Meantime, Npcap also provides the ``WlanHelper.exe`` tool to help you switch to ``Monitor Mode`` on your own. See more details about this feature in section ``For software that use Npcap raw 802.11 feature``. See more details about ``radiotap`` here: http://www.radiotap.org/

## Documentation

[Npcap Users' Guide](https://rawgit.com/nmap/npcap/master/docs/npcap-guide-wrapper.html)

## Get the code

Run ``git clone https://github.com/nmap/npcap``: pull this repo. This repo contains [libpcap](https://github.com/the-tcpdump-group/libpcap) as a submodule, so make sure that you have also pulled all the submodules.

## Build

Run ``installer\Build.bat``: build all DLLs and the driver. The DLLs need to be built using **Visual Studio 2013**. And the driver needs to be built using **Visual Studio 2015** with **Windows SDK 10 10586** & **Windows Driver Kit 10 10586**. The build of ``wpcap.dll`` also requires to install [Win flex-bison](https://sourceforge.net/projects/winflexbison/). Please unzip the downloaded package and add the directory to the ``PATH`` environment variable.

## Packaging

Run ``installer\Deploy.bat``: copy the files from build directories to deployment directories and sign the files. Generate an installer named ``npcap-%VERSION%.exe`` using [NSIS 2.51](http://nsis.sourceforge.net/Main_Page) with the [advanced logging special build](http://nsis.sourceforge.net/Special_Builds#Advanced_logging) and [SysRestore plug-in (special build for Npcap)](https://github.com/hsluoyz/SysRestore) and sign the installer.

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

## Bug report

Please report any bugs or issues about Npcap at: [Nmap issues on GitHub](https://github.com/nmap/nmap/issues). In your report, please provide your **DiagReport** output, user software version (e.g. Nmap, Wireshark), reproduce steps and other information you think necessary. If your issue occurs only on a special OS version (e.g. Win10 1511, 1607), please mention it in the report.

### Diagnostic report ###

Npcap has provided a diagnostic utility called ``DiagReport``. It provides a lot of information including OS metadata, Npcap related files, install options, registry values, services, etc. You can simply click the ``C:\Program Files\Npcap\DiagReport.bat`` file to run ``DiagReport``. It will pop up a text report via Notepad (it's stored in: ``C:\Program Files\Npcap\DiagReport.txt``). Please always submit it to us if you encounter any issues.

For Vista users: ``DiagReport`` is a script written by [Windows PowerShell](https://msdn.microsoft.com/en-us/powershell/mt173057.aspx), and Vista doesn't have it installed by default. So if you are using Vista, you need to install ``PowerShell 2.0 (KB968930)`` on your system. Please download it [here for x86](https://www.microsoft.com/en-hk/download/details.aspx?id=9864) and [here for x64](https://www.microsoft.com/en-us/download/details.aspx?id=9239). Win7 and later systems have built-in PowerShell support and don't need to do anything about it.

### General installation log

Npcap keeps track of the installation in a log file: ``C:\Program Files\Npcap\install.log``, please submit it together in your report if you encounter issues about the installation (e.g. the installer halts).

### Driver installation log

Npcap keeps track of the driver installation (aka commands run by ``NPFInstall.exe``) in a log file: ``C:\Program Files\Npcap\NPFInstall.log``, please submit it together in your report if you encounter issues about the driver installation and ``Npcap Loopback Adapter``.

There's another system-provided driver installation log in: ``C:\Windows\INF\setupapi.dev.log``. If you encounter errors about the driver/service installation, please copy the Npcap-related lines out and send them together in your report.

### Driver log

If you think the driver doesn't function well, you can open an ``Administrator`` command prompt, enter ``sc query npcap`` to query the driver status and ``net start npcap`` to start the driver (replace ``npcap`` with ``npf`` if you installed Npcap in ``WinPcap Compatible Mode``). The command output will inform you whether there's an error. If the driver is running well, but the issue still exists, then you need to check the driver's log. Normal Npcap releases don't switch on the driver log function for performance. So you have to install a debug version Npcap. We don't build a debug version for every release. Currently, the latest debug version is [Npcap 0.07 r16](https://github.com/nmap/npcap/releases/tag/v0.07-r16). If the currently available debug version Npcap doesn't have your issue, you can ask me to build a debug version Npcap for a specific version in mail. I'll be happy to do that. When you have got an appropriate debug version Npcap, you need to use [DbgView](https://technet.microsoft.com/en-us/sysinternals/debugview.aspx) to read the Windows kernel log (which contains our driver log). You may need to turn on DbgView before installing Npcap, if the error occurs when the driver loads. When done, save the DbgView output to a file and submit it in your report.

### Blue screen of death (BSoD) dump

If you encountered BSoD when using Npcap, please attach the minidump file (in ``C:\Windows\Minidump``) to your report together with the Npcap version. We may ask you to provide the full dump (``C:\Windows\MEMORY.DMP``) for further troubleshooting.

## License

See: [LICENSE](https://github.com/nmap/npcap/blob/master/LICENSE)

## Contact

* ``dev@nmap.org`` (Nmap development list, for technical issues and discussion)
* ``sales@nmap.com`` (Sales address for commercial/licensing issues)
* [Npcap Issues Tracker](https://github.com/nmap/nmap/issues/) (Bugs can be filed on this shared Nmap/Npcap tracker)
