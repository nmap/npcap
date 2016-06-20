@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \Include folder
mkdir %WPDPACKDESTDIR%  		2>nul >nul
mkdir %WPDPACKDESTDIR%\Include  	2>nul >nul
mkdir %WPDPACKDESTDIR%\Include\pcap  	2>nul >nul


xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap\*.h		 		%WPDPACKDESTDIR%\Include\pcap\	>nul

xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap.h			 	%WPDPACKDESTDIR%\Include\	>nul
rem xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap-int.h			%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap-bpf.h		 		%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap-namedb.h	 		%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\remote-ext.h		 	%WPDPACKDESTDIR%\Include\	>nul

xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\pcap-stdinc.h		 	%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\Win32-Extensions\Win32-Extensions.h 	%WPDPACKDESTDIR%\Include\	>nul

xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\Win32\Include\bittypes.h 		%WPDPACKDESTDIR%\Include\	>nul	 
xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\Win32\Include\ip6_misc.h		%WPDPACKDESTDIR%\Include\	>nul

rem xcopy /v /Y %WINPCAPSOURCEDIR%\wpcap\libpcap\Win32\Include\Gnuc.h 		%WPDPACKDESTDIR%\Include\	>nul


IF "%HAVE_BUGGY_TME_SUPPORT%"=="" ( goto skip_tme )

rem TME stuff
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\bucket_lookup.h	 		%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\count_packets.h	 		%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\memory_t.h		 	%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\normal_lookup.h	 		%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\tcp_session.h		 	%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\time_calls.h		 	%WPDPACKDESTDIR%\Include\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\packetNtx\driver\tme.h			 	%WPDPACKDESTDIR%\Include\	>nul

:skip_tme

xcopy /v /Y %WINPCAPSOURCEDIR%\Common\Packet32.h			 	%WPDPACKDESTDIR%\Include\	>nul

echo Folder \Include created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
