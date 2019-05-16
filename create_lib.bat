@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Checking for wpcap build dirs
set WPCAPBUILDDIR32=%WINPCAPSOURCEDIR%\wpcap\build-win32
if not exist "%WPCAPBUILDDIR32%" goto :fail
set WPCAPBUILDDIR64=%WINPCAPSOURCEDIR%\wpcap\build-x64
if not exist "%WPCAPBUILDDIR64%" goto :fail

echo Checking for Packet build dir
set PACKETBUILDDIR=%WINPCAPSOURCEDIR%\packetWin7\vs14
if not exist "%PACKETBUILDDIR%" goto :fail

echo Creating \Lib folder
mkdir %WPDPACKDESTDIR% 		>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib 	>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib\x64	>nul 2>nul

xcopy /v /Y "%WPCAPBUILDDIR32%\Release\wpcap.lib" %WPDPACKDESTDIR%\Lib\ || goto :fail
xcopy /v /Y "%WPCAPBUILDDIR64%\Release\wpcap.lib" %WPDPACKDESTDIR%\Lib\x64 || goto :fail
xcopy /v /Y "%PACKETBUILDDIR%\Release No NetMon and AirPcap\packet.lib" %WPDPACKDESTDIR%\Lib\ || goto :fail
xcopy /v /Y "%PACKETBUILDDIR%\x64\Release No NetMon and AirPcap\packet.lib" %WPDPACKDESTDIR%\Lib\x64 || goto :fail

echo Folder \Lib created successfully

set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=

exit /b

:fail
echo Failed.
pause
exit /b 1

