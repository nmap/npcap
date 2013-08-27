The WinPcap 4.1.3 for Nmap (NPcap 1.2) mainly has three parts: wpcap.dll, packet.dll and npf.sys.

The compiling instructions for the three parts are as belows:


1) npf.sys (packetWin7\npf\npf.sln)
i. Install VS2012 (No EXPRESS version, you need a key to register your VS2012) and update 3.

VS2012 download link:
http://www.microsoft.com/visualstudio/eng/downloads

VS2012 update 3 download link:
http://www.microsoft.com/en-us/download/details.aspx?id=39305

ii. Install WDK8.0.

WDK8.0 download link:
http://msdn.microsoft.com/en-us/library/windows/hardware/hh852365.aspx

iii. Open the npf.sln file in VS2012 and compile the debug version.
If you want to compile the release version, first go to the properties
page of both "npf" and "npf Package", navigate to "Driver Signing", "General",
then switch the "Sign Mode" to "Off". This option is used for code signing,
so you will want a "off" if you don't own a certificate.


2) packet.dll (packetWin7\Dll\Project\Packet.sln)

i. Install VS2005 and SP1 (maybe VS2008, VS2010 and VS2012 are OK here too,
I just remained the original WinPcap VS version).

VS2005 download link:
http://msdn.microsoft.com/zh-cn/express/aa975050.aspx

VS2005 SP1 download link:
http://www.microsoft.com/en-us/download/details.aspx?id=5553


ii. Install WDK7.1.0 (maybe WDK8.0 is OK here too, I tried this and
encountered some compiling problems which are difficult to settle,
so an old version like 7.1.0 is recommended).

WDK7.1.0 download link:
http://www.microsoft.com/en-hk/download/details.aspx?id=11800


iii. Open the Packet.sln file in VS2005.


iv. Open the "VC++ Directories" tab in Tools, Options dialog, make sure
    to add the WDK7.1.0 include and lib path to your VS. Mine is like
    this (substitute "D:\WinDDK\" to your own):

Include files:
D:\WinDDK\7600.16385.1\inc\api
D:\WinDDK\7600.16385.1\inc\ddk
$(VCInstallDir)include
$(VCInstallDir)atlmfc\include
$(VCInstallDir)PlatformSDK\include
$(VCInstallDir)PlatformSDK\common\include

Library files:
$(VCInstallDir)lib
$(VCInstallDir)atlmfc\lib
$(VCInstallDir)atlmfc\lib\i386
$(VCInstallDir)PlatformSDK\lib
$(VCInstallDir)PlatformSDK\common\lib
$(VSInstallDir)
$(VSInstallDir)lib
D:\WinDDK\7600.16385.1\lib\win7\i386


v. Compile.


3) NPFInstall.exe (packetWin7\NPFInstall\NPFInstall.sln)

The compiling environment for NPFInstall.exe is the same with that of 2),
just click "Compile" if you have finished step 2).
