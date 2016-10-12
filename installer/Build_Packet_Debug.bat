::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Use VS2013's MSBuild to build wpcap.dll, Packet.dll, NPFInstall.exe, NpcapHelper.exe and WlanHelper.exe
call "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"

msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Debug No NetMon and AirPcap" /p:Platform="Win32"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Debug No NetMon and AirPcap" /p:Platform="x64"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Debug No NetMon and AirPcap(WinPcap Mode)" /p:Platform="Win32"
msbuild "..\packetWin7\Dll\Project\Packet.sln" /t:Build /p:Configuration="Debug No NetMon and AirPcap(WinPcap Mode)" /p:Platform="x64"