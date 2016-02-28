
set PDB_FOLDER_NAME=npcap-DebugSymbols
set PDB_ZIP_NAME=npcap-nmap-0.05-DebugSymbols.zip
set ARCHIVE_7ZIP_TOOL="C:\Program Files\7-Zip\7z.exe"

set DRIVER_NAME=npcap
set DEPLOY_FOLDER_NAME=win7_above
set VISTA_DEPLOY_FOLDER_NAME=vista
set VS_CONFIG_MODE=
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Copy PDB files for Npcap driver
xcopy /Y	"..\packetWin7\npf\Win7 Release%VS_CONFIG_MODE%\%DRIVER_NAME%.pdb"						.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Win7 Release%VS_CONFIG_MODE%\%DRIVER_NAME%.pdb"					.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x64\
xcopy /Y	"..\packetWin7\npf\Vista Release%VS_CONFIG_MODE%\%DRIVER_NAME%.pdb"						.\%PDB_FOLDER_NAME%\%VISTA_DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\npf\x64\Vista Release%VS_CONFIG_MODE%\%DRIVER_NAME%.pdb"					.\%PDB_FOLDER_NAME%\%VISTA_DEPLOY_FOLDER_NAME%\x64\

:: Copy PDB files for Packet.dll
xcopy /Y	"..\packetWin7\Dll\Project\Release No NetMon and AirPcap%VS_CONFIG_MODE%\Packet.pdb"		.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\Dll\Project\x64\Release No NetMon and AirPcap%VS_CONFIG_MODE%\Packet.pdb"	.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x64\

:: Copy PDB files for NPFInstall.exe
xcopy /Y	"..\packetWin7\NPFInstall\Release%VS_CONFIG_MODE%\NPFInstall.pdb"							.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\NPFInstall\x64\Release%VS_CONFIG_MODE%\NPFInstall.pdb"						.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x64\

:: Copy PDB files for NPcapHelper.exe
xcopy /Y	"..\packetWin7\Helper\release\NPcapHelper.pdb"								.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x86\
xcopy /Y	"..\packetWin7\Helper\x64\release\NPcapHelper.pdb"							.\%PDB_FOLDER_NAME%\%DEPLOY_FOLDER_NAME%\x64\

:: Npcap uses the original WinPcap wpcap.dll with exactly the same code, we just changed the version number.
:: Copy PDB files for wpcap.dll
xcopy /Y	"..\wpcap\PRJ\Release No AirPcap\x86\wpcap.pdb"								.\%PDB_FOLDER_NAME%\
xcopy /Y	"..\wpcap\PRJ\Release No AirPcap\x64\wpcap.pdb"								.\%PDB_FOLDER_NAME%\x64\

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Generate the zip package for the PDB files using 7-Zip, make sure you installed 7-Zip first.
%ARCHIVE_7ZIP_TOOL% a %PDB_ZIP_NAME% .\%PDB_FOLDER_NAME%\*

pause
