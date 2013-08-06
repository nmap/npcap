@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\WpdPack\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Examples folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
mkdir %WPDPACKDESTDIR%\Examples-pcap >nul 2>nul
mkdir %WPDPACKDESTDIR%\Examples-remote >nul 2>nul

xcopy /s/e/v /Y %WINPCAPSOURCEDIR%\Examples		%WPDPACKDESTDIR%\Examples-remote >nul
 
rem *** Delete Netmeter since it's no more part of the Developer's pack *** 
rd /S /Q %WPDPACKDESTDIR%\Examples-remote\NetMeter\

rem *** Delete kdump since the feature is not available at the moment *** 
rd /S /Q %WPDPACKDESTDIR%\Examples-remote\kdump\

xcopy /s/e/v /Y %WINPCAPSOURCEDIR%\Examples-pcap		%WPDPACKDESTDIR%\Examples-pcap >nul

rem *** Delete WinPcapStress, since it's not a real example ***
rd /S /Q %WPDPACKDESTDIR%\Examples-pcap\winpcap_stress

rem *** Delete stats, since it's not a real example ***
rd /S /Q %WPDPACKDESTDIR%\Examples-pcap\stats


echo Folder \Examples created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=

echo ********************************************************************
echo *                                                                  *
echo * Now you can build the examples from the developers' pack folder! *
echo *                                                                  *
echo ********************************************************************
