SET MODE="Release"
SET TOPSRCDIR=%cd%

call build_sdk.bat || goto :error

call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

cd %TOPSRCDIR%
msbuild ".\npcap-sdk\Examples-pcap\MakeAll.sln" /m /t:Build /p:Configuration=%MODE% /p:Platform="x86" || goto :error
msbuild ".\npcap-sdk\Examples-pcap\MakeAll.sln" /m /t:Build /p:Configuration=%MODE% /p:Platform="x64" || goto :error
msbuild ".\npcap-sdk\Examples-remote\MakeAll.sln" /m /t:Build /p:Configuration=%MODE% /p:Platform="x86" || goto :error
msbuild ".\npcap-sdk\Examples-remote\MakeAll.sln" /m /t:Build /p:Configuration=%MODE% /p:Platform="x64" || goto :error

copy /b ".\npcap-sdk\Examples-pcap\x64\%MODE%\iflist.exe" test\
copy /b ".\npcap-sdk\Examples-pcap\x64\%MODE%\pcap_filter.exe" test\
copy /b ".\npcap-sdk\Examples-pcap\x64\%MODE%\sendpack.exe" test\
copy /b ".\npcap-sdk\Examples-pcap\x64\%MODE%\readfile.exe" test\

copy /b ".\npcap-sdk\Examples-remote\x64\%MODE%\sendcap.exe" test\
