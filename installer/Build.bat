SET NPCAPDIR=".."
SET MODE="Release"
rem SET MODE="Debug"

::::::::::
for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x86
if %ERRORLEVEL% NEQ 0 goto :badenv

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win8 driver" /p:Platform="x86"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x86"
msbuild "%NPCAPDIR%\wpcap\build-win32\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="Win32"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x64
if %ERRORLEVEL% NEQ 0 goto :badenv

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win8 driver" /p:Platform="x64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x64"
msbuild "%NPCAPDIR%\wpcap\build-x64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
if %ERRORLEVEL% NEQ 0 goto :badenv

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"
rem ARM64 is only supported for Win10, so we do not have separate Win8/Win10 driver configurations for this platform
msbuild "%NPCAPDIR%\wpcap\build-ARM64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"

exit /b

:bad_env
echo Failed to set environment
exit /b 1
