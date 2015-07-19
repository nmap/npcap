
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Use VS2005's MSBuild to build wpcap.dll, Packet.dll, NPFInstall.exe and NPcapHelper.exe
call "C:\Program Files (x86)\Microsoft Visual Studio 8\VC\vcvarsall.bat"

msbuild "..\wpcap\PRJ\wpcap.sln" /t:Build /p:Configuration="Release - No AirPcap" /p:Platform="Win32"
msbuild "..\wpcap\PRJ\wpcap.sln" /t:Build /p:Configuration="Release - No AirPcap" /p:Platform="x64"

msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Release No NetMon and AirPcap" /p:Platform="Win32"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Release No NetMon and AirPcap" /p:Platform="x64"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Release No NetMon and AirPcap(WinPcap Mode)" /p:Platform="Win32"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Release No NetMon and AirPcap(WinPcap Mode)" /p:Platform="x64"

msbuild "..\packetWin7\NPFInstall\NPFInstall.sln" /t:Build /p:Configuration="Release" /p:Platform="Win32"
msbuild "..\packetWin7\NPFInstall\NPFInstall.sln" /t:Build /p:Configuration="Release" /p:Platform="x64"
msbuild "..\packetWin7\NPFInstall\NPFInstall.sln" /t:Build /p:Configuration="Release(WinPcap Mode)" /p:Platform="Win32"
msbuild "..\packetWin7\NPFInstall\NPFInstall.sln" /t:Build /p:Configuration="Release(WinPcap Mode)" /p:Platform="x64"

msbuild "..\packetWin7\Helper\NPcapHelper.sln" /t:Build /p:Configuration="Release" /p:Platform="Win32"
msbuild "..\packetWin7\Helper\NPcapHelper.sln" /t:Build /p:Configuration="Release" /p:Platform="x64"

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Use VS2013's MSBuild to build npcap.sys
::call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"

::msbuild "..\packetWin7\npf\npcap.sln" /t:Build /p:Configuration="Win7 Release" /p:Platform="Win32"
::msbuild "..\packetWin7\npf\npcap.sln" /t:Build /p:Configuration="Win7 Release" /p:Platform="x64"
::msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Release" /p:Platform="Win32"
::msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Release" /p:Platform="x64"

pause


