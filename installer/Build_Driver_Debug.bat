
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Use VS2015's MSBuild to build npf.sys (and npcap.sys)
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

:: "%28" is the escape for "(", "%29" is the escape for ")", and "%%" is the escape for "%" itself. Not using escape will cause target error of MSBuild.
msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Debug%%28WinPcap Mode%%29" /p:Platform="Win32"
msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Debug%%28WinPcap Mode%%29" /p:Platform="x64"
msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Debug" /p:Platform="Win32"
msbuild "..\packetWin7\npf\npf.sln" /t:Build /p:Configuration="Win7 Debug" /p:Platform="x64"

pause


