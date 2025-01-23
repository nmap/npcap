@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Include folder
mkdir %WPDPACKDESTDIR%  		2>nul >nul
mkdir %WPDPACKDESTDIR%\Include  	2>nul >nul
mkdir %WPDPACKDESTDIR%\Include\pcap  	2>nul >nul


SETLOCAL ENABLEEXTENSIONS

xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap\  %WPDPACKDESTDIR%\Include\pcap\ >nul
for /F "usebackq skip=1 tokens=3 delims=/ " %%i in (`findstr "CMAKE_INSTALL_INCLUDEDIR" "%WINPCAPSOURCEDIR%\wpcap\libpcap\CMakeLists.txt"`) do (
	copy /v /Y "%WINPCAPSOURCEDIR%\wpcap\libpcap\%%i"  "%WPDPACKDESTDIR%\Include\%%i"
)

xcopy /v /Y %WINPCAPSOURCEDIR%\Common\Packet32.h   %WPDPACKDESTDIR%\Include\ >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\Common\npcap-bpf.h  %WPDPACKDESTDIR%\Include\ >nul
xcopy /v /Y %WINPCAPSOURCEDIR%\Common\npcap-defs.h %WPDPACKDESTDIR%\Include\ >nul

echo Folder \Include created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
