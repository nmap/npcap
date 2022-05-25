@echo off

IF "%2"=="" (set WPDPACKDESTDIR=npcap-sdk) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Examples folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
rd /S /Q %WPDPACKDESTDIR%\Examples-pcap >nul 2>nul
mkdir %WPDPACKDESTDIR%\Examples-pcap >nul 2>nul
rd /S /Q %WPDPACKDESTDIR%\Examples-remote >nul 2>nul
mkdir %WPDPACKDESTDIR%\Examples-remote >nul 2>nul

rem Can't pipe stdout to stdin of tar; claims "Damaged archive"
git archive --prefix="%WPDPACKDESTDIR%/Examples-remote/" HEAD:Examples -o Examples-remote.tar
tar xf Examples-remote.tar
del Examples-remote.tar

git archive --prefix="%WPDPACKDESTDIR%/Examples-pcap/" HEAD:Examples-pcap -o Examples-pcap.tar
tar xf Examples-pcap.tar
del Examples-pcap.tar

rem *** Delete Netmeter since it's no more part of the Developer's pack *** 
rd /S /Q %WPDPACKDESTDIR%\Examples-remote\NetMeter\

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
