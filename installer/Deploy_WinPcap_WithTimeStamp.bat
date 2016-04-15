
set DRIVER_NAME=npf
set DEPLOY_FOLDER_NAME=win8_above_winpcap
set WIN7_DEPLOY_FOLDER_NAME=win7_winpcap
set VISTA_DEPLOY_FOLDER_NAME=vista_winpcap
set VS_CONFIG_MODE=(WinPcap Mode)

set CERT_SIGN_TOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set CERT_MS_CROSS_CERT="C:\DigiCert High Assurance EV Root CA.crt"
set CERT_HASH_VISTA="67cdca7703a01b25e6e0426072ec08b0046eb5f8"
set CERT_HASH_WIN7_ABOVE="928101b5d0631c8e1ada651478e41afaac798b4c"
set CERT_TIMESTAMP_SERVER=http://timestamp.digicert.com
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Copy Npcap driver files
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"					.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"					.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"					.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"				.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"					.\%DEPLOY_FOLDER_NAME%\x64\

xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"						.\%WIN7_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"						.\%WIN7_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"					.\%WIN7_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"						.\%WIN7_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"					.\%WIN7_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"					.\%WIN7_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"				.\%WIN7_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"					.\%WIN7_DEPLOY_FOLDER_NAME%\x64\

xcopy /Y	"..\packetWin7\npf\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"					.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.cat"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"				.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Release%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\

:: Copy Packet.dll
xcopy /Y	"..\packetWin7\Dll\Project\Release No NetMon and AirPcap%VS_CONFIG_MODE%\Packet.dll"		.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\Dll\Project\x64\Release No NetMon and AirPcap%VS_CONFIG_MODE%\Packet.dll"	.\%DEPLOY_FOLDER_NAME%\x64\

:: Copy NPFInstall.exe
xcopy /Y	"..\packetWin7\NPFInstall\Release%VS_CONFIG_MODE%\NPFInstall.exe"							.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\NPFInstall\x64\Release%VS_CONFIG_MODE%\NPFInstall.exe"						.\%DEPLOY_FOLDER_NAME%\x64\

:: Copy NPcapHelper.exe
xcopy /Y	"..\packetWin7\Helper\release\NPcapHelper.exe"								.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\Helper\x64\release\NPcapHelper.exe"							.\%DEPLOY_FOLDER_NAME%\x64\

:: Npcap uses the original WinPcap wpcap.dll with exactly the same code, we just changed the version number.
:: Copy wpcap.dll
xcopy /Y	"..\wpcap\PRJ\Release No AirPcap\x86\wpcap.dll"								.\
xcopy /Y	"..\wpcap\PRJ\Release No AirPcap\x64\wpcap.dll"								.\x64\

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: 1. Add "signtool.exe" to PATH
:: 2. Put the MS CVR cert of DigiCert to "C:\DigiCert High Assurance EV Root CA.crt"
:: 3. Get the hash of your cert, make it the value of option "/sha1" below

:: Sign Npcap driver for Vista
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%VISTA_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%VISTA_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.cat
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%VISTA_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%VISTA_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.cat

:: Sign Npcap driver for Win7
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%WIN7_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%WIN7_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.cat
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%WIN7_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%WIN7_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.cat

:: Sign Npcap driver for Win8 and later
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.cat
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.cat

:: Sign Packet.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x86\Packet.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x86\Packet.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x64\Packet.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x64\Packet.dll

:: Sign NPFInstall.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x86\NPFInstall.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x86\NPFInstall.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x64\NPFInstall.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x64\NPFInstall.exe

:: Sign NPcapHelper.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x86\NPcapHelper.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x86\NPcapHelper.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%DEPLOY_FOLDER_NAME%\x64\NPcapHelper.exe
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%DEPLOY_FOLDER_NAME%\x64\NPcapHelper.exe

:: Sign wpcap.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\wpcap.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\wpcap.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\x64\wpcap.dll
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\x64\wpcap.dll

pause
