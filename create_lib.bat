@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Lib folder
mkdir %WPDPACKDESTDIR% 		>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib 	>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib\x64	>nul 2>nul

xcopy /v /Y "%WINPCAPSOURCEDIR%\wpcap\PRJ\Release No AirPcap\x86\wpcap.lib"				%WPDPACKDESTDIR%\Lib\ >nul
xcopy /v /Y "%WINPCAPSOURCEDIR%\wpcap\PRJ\Release No AirPcap\x64\wpcap.lib"				%WPDPACKDESTDIR%\Lib\x64 >nul
xcopy /v /Y "%WINPCAPSOURCEDIR%\packetWin7\Dll\Project\Release No NetMon and AirPcap\packet.lib"	 	%WPDPACKDESTDIR%\Lib\ >nul
xcopy /v /Y "%WINPCAPSOURCEDIR%\packetWin7\Dll\Project\x64\Release No NetMon and AirPcap\packet.lib"	 	%WPDPACKDESTDIR%\Lib\x64 >nul

echo Folder \Lib created successfully

set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=

