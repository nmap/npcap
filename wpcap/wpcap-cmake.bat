set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set GENERATOR=Visual Studio 16 2019
set NPCAP_SDK=..\npcap-sdk
set AIRPCAP_SDK=..\..\Airpcap_Devpack

mkdir build-win32
cd build-win32
%CMAKE% -A Win32 -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -DAirPcap_ROOT=..\%AIRPCAP_SDK% -G "%GENERATOR%" ..\libpcap\
cd ..

mkdir build-x64
cd build-x64
%CMAKE% -A x64 -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -DAirPcap_ROOT=..\%AIRPCAP_SDK% -G "%GENERATOR%" ..\libpcap\
cd ..

rem AirPcap does not have ARM64 libs
mkdir build-ARM64
cd build-ARM64
%CMAKE% -A ARM64 -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR%" ..\libpcap\
cd ..
