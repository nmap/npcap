SET MODE="Release"
SET TOPSRCDIR=%cd%
SET VERB=Build
if NOT "%1" == "" SET VERB="%1"

rem call build_sdk.bat || goto :error
cd %TOPSRCDIR%

Call :BUILD_TEST x86 || goto :error
Call :BUILD_TEST x64 || goto :error
Call :BUILD_TEST ARM64 || goto :error
exit /b

:BUILD_TEST
set TOOLSET=%1
if "%1" == "ARM64" set TOOLSET=amd64_arm64
for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 16 -property installationPath`) do call "%%a\VC\Auxiliary\Build\vcvarsall.bat" %TOOLSET%
if %ERRORLEVEL% NEQ 0 goto :error

msbuild /p:ForceImportBeforeCppTargets="%CD%\test\static.props" ".\npcap-sdk\Examples-pcap\MakeAll.sln" /m /t:%VERB% /p:Configuration=%MODE% /p:Platform="%1" || goto :error
msbuild /p:ForceImportBeforeCppTargets="%CD%\test\static.props" ".\npcap-sdk\Examples-remote\sendcap\sendcap.vcxproj" /m /t:%VERB% /p:Configuration=%MODE% /p:Platform="%1" || goto :error
if NOT "%VERB%" == "Build" goto :EOF

set BINDIR=%1\
if "%1" == "x86" set BINDIR=""

mkdir test\%1\
copy /b ".\npcap-sdk\Examples-pcap\%BINDIR%%MODE%\iflist.exe" test\%1\
copy /b ".\npcap-sdk\Examples-pcap\%BINDIR%%MODE%\pcap_filter.exe" test\%1\
copy /b ".\npcap-sdk\Examples-pcap\%BINDIR%%MODE%\sendpack.exe" test\%1\
copy /b ".\npcap-sdk\Examples-pcap\%BINDIR%%MODE%\readfile.exe" test\%1\

copy /b ".\npcap-sdk\Examples-remote\sendcap\%BINDIR%%MODE%\sendcap.exe" test\%1\

goto :EOF

:error
echo Something failed: %ERRORLEVEL%
exit /b 1
