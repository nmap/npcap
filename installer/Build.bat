SET NPCAPDIR=".."
SET MODE="Release"
rem SET MODE="Debug"

::::::::::
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% No NetMon and AirPcap" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% No NetMon and AirPcap" /p:Platform="x64"
:: "%28" is the escape for "(", "%29" is the escape for ")", and "%%" is the escape for "%" itself. Not using escape will cause target error of MSBuild.
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% No NetMon and AirPcap%%28WinPcap Mode%%29" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% No NetMon and AirPcap%%28WinPcap Mode%%29" /p:Platform="x64"

pause

