Npcap
==========
http://www.npcap.org

[![Build status](https://ci.appveyor.com/api/projects/status/01yoks5rn14wgny2?svg=true)](https://ci.appveyor.com/project/hsluoyz/npcap)
![Environment](https://img.shields.io/badge/Windows-Vista, 7, 8, 10-yellow.svg)
![Release](https://img.shields.io/github/release/nmap/npcap.svg)
![License](https://img.shields.io/github/license/nmap/npcap.svg)
![Downloads](https://img.shields.io/github/downloads/nmap/npcap/latest/total.svg)
![TotalDownloads](https://img.shields.io/github/downloads/nmap/npcap/total.svg)

Npcap is an update of [**WinPcap**](http://www.winpcap.org/) to [**NDIS 6 Light-Weight Filter (LWF)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff565492(v=vs.85).aspx) technique. It supports **Windows Vista, 7, 8 and 10**. It is sponsored by the [**Nmap Project**](http://nmap.org/) and developed by [**Yang Luo**](http://www.veotax.com/) under [**Google Summer of Code 2013**](https://www.google-melange.com/gsoc/project/details/google/gsoc2013/hsluoyz/5727390428823552) and [**2015**](https://www.google-melange.com/gsoc/project/details/google/gsoc2015/hsluoyz/5723971634855936). It also received many helpful tests from [**Wireshark**](https://www.wireshark.org/) and [**NetScanTools**](http://www.netscantools.com/).

## Features

1. **NDIS 6 Support**: Npcap makes use of new LWF driver in Windows Vista and later (the legacy driver is used on XP). It's faster than the legacy [**NDIS 5 Intermediate**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff557012(v=vs.85).aspx) technique. One reason is that packet data stucture has changed (from ``NDIS_PACKET`` to ``NET_BUFFER_LIST``) since Vista and NDIS 5 needs to handle extra packet structure conversion.
2. **"Admin-only Mode" Support**: Npcap supports to restrict its use to Administrators for safety purpose. If Npcap is installed with the option **Restrict Npcap driver's access to Administrators only** checked, when a non-Admin user tries to start a user software (Nmap, Wireshark, etc), the [**User Account Control (UAC)**](http://windows.microsoft.com/en-us/windows/what-is-user-account-control#1TC=windows-7) dialog will prompt asking for Administrator privilege. Only when the end user chooses ``Yes``, the driver can be accessed. This is similar to UNIX where you need root access to capture packets.
3. **"WinPcap Compatible Mode" Support**: "WinPcap Compatible Mode" is used to decide whether Npcap should coexist With WinPcap or be compatible with WinPcap. With "WinPcap Compatible Mode" ``OFF``, Npcap can coexist with WinPcap and share the DLL binary interface with WinPcap. So the applications unaware of Npcap **SHOULD** be able to use Npcap automatically if WinPcap is unavailable. The applications who knows Npcap's existence can choose to use Npcap or WinPcap first. The key about which is loaded first is [**DLL Search Path**](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx). With "WinPcap Compatible Mode" ``OFF``, Npcap installs its DLLs into ``C:\Windows\System32\Npcap\`` instead of WinPcap's ``C:\Windows\System32\``. So applications who want to load Npcap first must make ``C:\Windows\System32\Npcap\`` precedent to other paths in ways such as calling [**SetDllDirectory**](https://msdn.microsoft.com/en-us/library/ms686203.aspx), etc. Another point is Npcap uses service name ``npcap`` instead of WinPcap's ``npf`` with "WinPcap Compatible Mode" ``OFF``. So applications using ``net start npf`` for starting service must use ``net start npcap`` instead. If you want 100% compatibility with WinPcap, you should install Npcap choosing "WinPcap Compatible Mode" (Install Npcap in WinPcap API-compatible Mode). In this mode, Npcap will install its Dlls in WinPcap's ``C:\Windows\System32\`` and use the ``npf`` service name. It's notable that before installing in this mode, you must uninstall WinPcap first (the installer wizard will prompt you that).
4. **Loopback Packets Capture Support**: Now Npcap is able to see Windows loopback packets using [**Windows Filtering Platform (WFP)**](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366510(v=vs.85).aspx) technique. After installation, Npcap will create an adapter named ``Npcap Loopback Adapter`` for you. If you are a Wireshark user, choose this adapter to capture, you will see all loopback traffic the same way as other non-loopback adapters. Try it by typing in commands like ``ping 127.0.0.1`` (IPv4) or ``ping ::1`` (IPv6).
5. **Loopback Packets Send Support**: Besides loopback packets capturing, Npcap can also send out loopback packets based on [**Winsock Kernel (WSK)**](https://msdn.microsoft.com/en-us/library/windows/hardware/ff556958(v=vs.85).aspx) technique. A user software (e.g. Nmap) can just send packets out using ``Npcap Loopback Adapter`` like other adapters. ``Npcap Loopback Adapter`` will automatically remove the packet's Ethernet header and inject the payload into Windows TCP/IP stack, so this kind of loopback packet never go out of the machine.
6. **Raw 802.11 Packets Capture Support**: Npcap is able to see **802.11** packets instead of **fake Ethernet** packets on ordinary wireless adapters. You need to select the ``Support raw 802.11 traffic (and monitor mode) for wireless adapters`` option in the installation wizard to enable this feature. When your adapter is in ``Monitor Mode``, Npcap will supply all ``802.11 data + control + management`` packets with ``radiotap`` headers. When your adapter is in ``Managed Mode``, Npcap will only supply ``802.11 data`` packets with ``radiotap`` headers. Moreover, Npcap provides the ``WlanHelper.exe`` tool to help you switch to ``Monitor Mode`` on Windows. See more details about this feature in section ``For softwares that use Npcap raw 802.11 feature``. See more details about ``radiotap`` here: http://www.radiotap.org/

## Documents

[Npcap Users' Guide](https://htmlpreview.github.io/?https://github.com/nmap/npcap/blob/master/docs/npcap-guide-wrapper.html)

## Downloads

1. Download and install the latest Npcap installer: https://github.com/nmap/npcap/releases
2. Use ``Nmap`` or ``Wireshark`` to test Npcap.

## Bug report

Please report any bugs or issues about Npcap at: https://github.com/nmap/nmap/issues

## License

See: [LICENSE](https://github.com/nmap/npcap/blob/master/LICENSE)

## Contact

* ``dev@nmap.org`` (Nmap development list, this is **preferred**)
* ``hsluoyz@gmail.com`` (Yang Luo's email, if your issue needs to be kept private, please contact me via this mail)
