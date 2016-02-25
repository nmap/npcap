
set DRIVER_NAME=npf
set DEPLOY_FOLDER_NAME=win7_above_winpcap
set VISTA_DEPLOY_FOLDER_NAME=vista_winpcap
set VS_CONFIG_MODE=(WinPcap Mode)

set CERT_SIGN_TOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set CERT_SIGNING_CERT="C:\insecurecom-digicert-codesigning-cert.p12"
:: set CERT_SIGNING_PK=THE_SIGNING_CERT_PRIVATE_KEY
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Copy Npcap driver files
xcopy /Y	"..\packetWin7\npf\Win7 Debug%VS_CONFIG_MODE%\npf\%DRIVER_NAME%.cat"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"					.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"						.\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Debug%VS_CONFIG_MODE%\%DRIVER_NAME%\%DRIVER_NAME%.cat"					.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"					.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"				.\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"					.\%DEPLOY_FOLDER_NAME%\x64\

xcopy /Y	"..\packetWin7\npf\Vista Debug%VS_CONFIG_MODE%\npf\%DRIVER_NAME%.cat"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"					.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"						.\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Vista Debug%VS_CONFIG_MODE%\%DRIVER_NAME%\%DRIVER_NAME%.cat"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.inf"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%_wfp.inf"				.\%VISTA_DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\x64\Vista Debug%VS_CONFIG_MODE%\npf Package\%DRIVER_NAME%.sys"					.\%VISTA_DEPLOY_FOLDER_NAME%\x64\

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
:: First need to add "signtool.exe" to PATH, then put the cert file (e.g. C:\xxx.pfx) to environment variable %NPF_CERT_PATH%,
:: put the private key string (e.g. 123456) to environment variable %NPF_SIGN_PK%

:: Sign Npcap driver for Vista
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%VISTA_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%VISTA_DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.cat
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%VISTA_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%VISTA_DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.cat

:: Sign Npcap driver for Win7 and later
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x86\%DRIVER_NAME%.cat
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.sys
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x64\%DRIVER_NAME%.cat

:: Sign Packet.dll
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x86\Packet.dll
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x64\Packet.dll

:: Sign NPFInstall.exe
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x86\NPFInstall.exe
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x64\NPFInstall.exe

:: Sign NPcapHelper.exe
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x86\NPcapHelper.exe
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\%DEPLOY_FOLDER_NAME%\x64\NPcapHelper.exe

:: Sign wpcap.dll
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\wpcap.dll
%CERT_SIGN_TOOL% sign /f %CERT_SIGNING_CERT% /p %CERT_SIGNING_PK% .\x64\wpcap.dll

pause
