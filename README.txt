The original WinPcap mainly has three parts: wpcap.dll, packet.dll and
npf.sys.

The compiling instructions for the three parts are as belows:


1) npf6x.sys (packetWin7\npf6x\npf6x.sln)
i. Install VS2012 and update 3.

VS2012 download link:
http://www.microsoft.com/visualstudio/eng/downloads

VS2012 update 3 download link:
http://www.microsoft.com/en-us/download/details.aspx?id=39305

ii. Install WDK8.0.

WDK8.0 download link:
http://msdn.microsoft.com/en-us/library/windows/hardware/hh852365.aspx

iii. Open the npf6x.sln file in VS2012 and compile.


2) packet.dll (packetWin7\Dll\Project\Packet.sln)
i. Install VS2005 and sp1 (maybe VS2008, VS2010 and VS2012 are OK here
   too, I just remained the original WinPcap VS version).

VS2005 download link:
http://msdn.microsoft.com/zh-cn/express/aa975050.aspx

VS2005 sp1 download link:
http://www.microsoft.com/en-us/download/details.aspx?id=5553


ii. Install WDK7.1.0.

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


3) NPF6xInstall.exe (packetWin7\NPF6xInstall\NPF6xInstall.sln) (The same
   with 2.)
