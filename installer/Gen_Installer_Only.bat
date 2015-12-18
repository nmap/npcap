::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: First need to add "makensis.exe" to PATH
:: Generate installer
"C:\Program Files (x86)\NSIS\makensis.exe" .\NPcap-for-nmap.nsi

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Sign the installer
signtool sign /f %NPF_CERT_PATH% /p %NPF_SIGN_PK% .\npcap-nmap-0.05.exe

pause
