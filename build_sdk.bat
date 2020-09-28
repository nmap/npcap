@echo off
for /F tokens^=3^,4^ delims^=^"^	^  %%A in (version.h) do if "%%A" == "NPCAP_SDK_VERSION" set SDK_VER=%%B
if "%SDK_VER%" == "" goto :fail
set SDKFILENAME=npcap-sdk-%SDK_VER%.zip

if "%2"== "" ( rd /s/q ./npcap-sdk 2>nul >nul) else ( rd /s /q "%2" 2>nul >nul)

SET TOPSRCDIR=%cd%

rem Must build Npcap in order to have the lib files available (and to ensure it builds correctly!)
cd installer
call Build.bat
cd %TOPSRCDIR%

rem Requires Cygwin to provide make.exe
call create_include.bat %1 %2

call create_lib.bat %1 %2 || goto :fail

call create_examples.bat %1 %2

rem Requires xsltproc and Docbook XSL stylesheets
call create_docs.bat %1 %2

del %SDKFILENAME%
cd .\npcap-sdk
"C:\Program Files\7-Zip\7z.exe" a ..\%SDKFILENAME% .
PAUSE

exit /b
:fail
echo Failed!
pause
exit /b 1
