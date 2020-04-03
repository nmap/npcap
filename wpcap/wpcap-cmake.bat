set CMAKE="C:\Program Files\CMake\bin\cmake.exe"
set GENERATOR=Visual Studio 14 2015
set NPCAP_SDK=..\..\npcap-sdk-1.05\

mkdir build-win32
cd build-win32
%CMAKE% -DPACKET_DLL_DIR=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR%" ..\libpcap\
cd ..

mkdir build-x64
cd build-x64
%CMAKE% -DPACKET_DLL_DIR=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR% Win64" ..\libpcap\
cd ..
