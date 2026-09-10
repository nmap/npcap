SET NPCAPDIR=".."
SET MODE="Release"
rem SET MODE="Debug"
SET VSVER=17

::::::::::
for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version %VSVER% -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x86 & goto :break1
:break1
if %ERRORLEVEL% NEQ 0 goto :badenv

REM msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x86"
REM msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x86"
REM msbuild "%NPCAPDIR%\wpcap\build-win32\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="Win32"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version %VSVER% -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" x64 & goto :break2
:break2
if %ERRORLEVEL% NEQ 0 goto :badenv

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="x64"
msbuild "%NPCAPDIR%\wpcap\build-x64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="x64"

for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version %VSVER% -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64 & goto :break3
:break3
if %ERRORLEVEL% NEQ 0 goto :badenv

msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"
msbuild "%NPCAPDIR%\packetWin7\vs14\npcap.sln" /m /t:Build /p:Configuration="%MODE% Win10 driver" /p:Platform="ARM64"
msbuild "%NPCAPDIR%\wpcap\build-ARM64\wpcap.vcxproj" /m /t:Build /p:Configuration="%MODE%" /p:Platform="ARM64"

exit /b

:bad_env
echo Failed to set environment
exit /b 1
