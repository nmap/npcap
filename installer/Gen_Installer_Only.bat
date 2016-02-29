
set INSTALLER_NAME=npcap-nmap-0.06.exe

set CERT_SIGN_TOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set CERT_MS_CROSS_CERT="C:\DigiCert High Assurance EV Root CA.crt"
set CERT_HASH_VISTA="7e9978b1828447b97fbeba7c085dd1a217b07399"
set CERT_HASH_WIN7_ABOVE="684d2e7df5b275515e703e6f42d962712b512da7"
set CERT_TIMESTAMP_SERVER=http://timestamp.digicert.com
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: First need to add "makensis.exe" to PATH
:: Generate installer
"C:\Program Files (x86)\NSIS\makensis.exe" .\NPcap-for-nmap.nsi

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Sign the installer
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_VISTA% /fd sha1 /t %CERT_TIMESTAMP_SERVER% .\%INSTALLER_NAME%
%CERT_SIGN_TOOL% sign /ac %CERT_MS_CROSS_CERT% /sha1 %CERT_HASH_WIN7_ABOVE% /as /fd sha256 /tr %CERT_TIMESTAMP_SERVER% /td sha256 .\%INSTALLER_NAME%

pause
