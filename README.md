Npcap
==========

[![Build status](https://ci.appveyor.com/api/projects/status/woero8l6qhgy4syx?svg=true)](https://ci.appveyor.com/project/dmiller-nmap/npcap)
![Environment](https://img.shields.io/badge/Windows-7,%208,%208.1,%2010,%2011-brightgreen.svg)
[![Release](https://img.shields.io/github/release/nmap/npcap.svg)](https://npcap.com/#download)
[![Issues](https://img.shields.io/github/issues/nmap/npcap.svg)](https://github.com/nmap/npcap/issues)

[**Npcap**](https://npcap.com) is a packet capture and injection library for
Windows by the [**Nmap Project**](https://nmap.org). It is a complete update to
the unmaintained [**WinPcap**](http://www.winpcap.org/) project with improved
speed, reliability, and security.

## Documentation

The complete documentation for Npcap is available in the [Npcap
Guide](https://npcap.com/guide/) on [npcap.com](https://npcap.com/). There you
will find information about
[installation](https://npcap.com/guide/npcap-users-guide.html#npcap-installation),
[reporting
bugs](https://npcap.com/guide/npcap-users-guide.html#npcap-issues),
[developing software with
Npcap](https://npcap.com/guide/npcap-devguide.html), and [Npcap
internals](https://npcap.com/guide/npcap-internals.html).

## Downloads

The latest installer, Software Development Kit (SDK), source, and debug symbols
can be downloaded from https://npcap.com/#download

## Bug report

Please report any bugs or issues about Npcap at: [Npcap issues on
GitHub](https://github.com/nmap/npcap/issues). In your report, please provide
your
[**DiagReport**](https://npcap.com/guide/npcap-users-guide.html#npcap-issues-diagreport)
output, user software version (e.g. Nmap, Wireshark), reproduce steps and other
information you think necessary. Refer to [the Npcap Guide section on reporting
bugs](https://npcap.com/guide/npcap-users-guide.html#npcap-issues) for more
complete directions.

## Contribution

If you want to contribute to the development of this project, first you need to setup the development environment.

### Development Environment

Install a Windows. For example, use Windows 11, version 21H2. 

When you install Visual Studio 2022, select the Desktop development with C++ workload, then under Individual Components add:

- MSVC v143 - VS 2022 C++ ARM64/ARM64EC Spectre-mitigated libs (Latest)
- MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (Latest)
- C++ ATL for latest v143 build tools with Spectre Mitigations (ARM64/ARM64EC)
- C++ ATL for latest v143 build tools with Spectre Mitigations (x86 & x64)
- C++ MFC for latest v143 build tools with Spectre Mitigations (ARM64/ARM64EC)
- C++ MFC for latest v143 build tools with Spectre Mitigations (x86 & x64)
- Windows Driver Kit

Install Windows SDK from https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/ if you get the error "The Windows SDK version 10.0.26100.0 was not found.".

You also need WDK for Windows 11, version 21H2. Download and install it from https://go.microsoft.com/fwlink/?linkid=2166289

For addition tasks, like building the documentation, you need roffit. Clone it from 
```
cd C:\Users\Measurement\
git clone https://github.com/bagder/roffit.git
```

Also, download 7z from https://www.7-zip.org/a/7z2409-x64.exe

As this version of Visual Studio does not support the compilation for Win32 drivers out of the box, please follow the instructions given in 
https://stackoverflow.com/questions/75509242/compiling-32-bits-driver-using-msvc-2022
In addition, you might need additional files (TODO).

Next, download AirPCAP Devpack from https://support.riverbed.com/bin/support/download?sid=l3vk3eu649usgu3rj60uncjqqu
and unpack it to, for example to %USERPROFILE%\Airpcap_Devpack

Then, download https://npcap.com/dist/ npcap-sdk and install it under, e.g. %USERPROFILE%\npcap-sdk-1.14

We need Winflex, which can be download at https://github.com/lexxmark/winflexbison/releases . Be sure that it is in environment variable 'Path'. 
Test it by entering 'win_flex -V' into a command shell.

You might also need pkg-config from https://download.gnome.org/binaries/win32/dependencies/pkg-config_0.26-1_win32.zip

#### Cloing the reposiory

On https://github.com, fork both the repositories npcap https://github.com/nmap/npcap and libpcap https://github.com/the-tcpdump-group/libpcap.
Then, enter the following commands.

```
cd %USERPROFILE%
git clone https://github.com/YOURUSER/npcap
git submodule update --init --recursive
cd wpcap
wpcap-cmake.bat
cd ..
cd installer
build.bat
```

## License

The [Npcap License](https://github.com/nmap/npcap/blob/master/LICENSE) allows
end users to download, install, and use Npcap from our site for free on up to 5
systems (including commercial usage). Software providers (open source or
otherwise) which want to use Npcap functionality are welcome to point their
users to [npcap.com](https://npcap.com/) for those users to download and install.

We fund the Npcap project by selling [Npcap OEM](https://npcap.com/oem/). This
special version of Npcap includes enterprise features such as the silent
installer and commercial support as well as special license rights.


## Contact

* ``dev@nmap.org`` (Nmap development list, for technical issues and discussion)
* ``sales@nmap.com`` (Sales address for commercial/licensing issues)
* [Npcap Issues Tracker](https://github.com/nmap/npcap/issues/)
