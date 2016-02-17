
set INSTALLER_NAME=npcap-nmap-0.05.exe
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: First need to add "makensis.exe" to PATH
:: Generate installer
"C:\Program Files (x86)\NSIS\makensis.exe" .\NPcap-for-nmap.nsi

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Sign the installer
signtool sign /ac "C:\DigiCert High Assurance EV Root CA.crt" /sha1 "684d2e7df5b275515e703e6f42d962712b512da7" /fd sha1 /t http://timestamp.digicert.com .\%INSTALLER_NAME%
signtool sign /ac "C:\DigiCert High Assurance EV Root CA.crt" /sha1 "684d2e7df5b275515e703e6f42d962712b512da7" /as /fd sha256 /tr http://timestamp.digicert.com /td sha256 .\%INSTALLER_NAME%

pause
