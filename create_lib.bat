@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\WpdPack\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Lib folder
mkdir %WPDPACKDESTDIR% 		>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib 	>nul 2>nul
mkdir %WPDPACKDESTDIR%\Lib\x64	>nul 2>nul

xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\PRJ\Release\x86\wpcap.lib				%WPDPACKDESTDIR%\Lib\ >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\PRJ\Release\x64\wpcap.lib				%WPDPACKDESTDIR%\Lib\x64 >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\Dll\Project\Release\x86\packet.lib	 	%WPDPACKDESTDIR%\Lib\ >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\Dll\Project\Release\x64\packet.lib	 	%WPDPACKDESTDIR%\Lib\x64 >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\Dll\Project\libpacket.a			%WPDPACKDESTDIR%\Lib\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\LIB\libwpcap.a					%WPDPACKDESTDIR%\Lib\ >nul

echo Folder \Lib created successfully

set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=

