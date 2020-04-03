SET NPCAPDIR=".."
SET MODE="Release"
rem SET MODE="Debug"

::::::::::
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"

msbuild "%NPCAPDIR%\wpcap\build-win32\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="Win32"
msbuild "%NPCAPDIR%\wpcap\build-x64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"

pause

