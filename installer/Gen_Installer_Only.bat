
set INSTALLER_NAME=npcap-nmap-0.06.exe

set CERT_SIGN_TOOL="C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
set CERT_MS_CROSS_CERT="C:\DigiCert High Assurance EV Root CA.crt"
set CERT_HASH_VISTA="67cdca7703a01b25e6e0426072ec08b0046eb5f8"
set CERT_HASH_WIN7_ABOVE="928101b5d0631c8e1ada651478e41afaac798b4c"
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
