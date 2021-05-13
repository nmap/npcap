SET NPCAPDIR=".."
SET MODE="Release"
rem SET MODE="Debug"

::::::::::
for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x86

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win8 driver" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x86"
msbuild "%NPCAPDIR%\wpcap\build-win32\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="Win32"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x64

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win8 driver" /p:Platform="x64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x64"
msbuild "%NPCAPDIR%\wpcap\build-x64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" ARM64

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="ARM64"
rem msbuild "%NPCAPDIR%\wpcap\build-ARM64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"

pause

