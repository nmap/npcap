set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set GENERATOR=Visual Studio 16 2019
set NPCAP_SDK=..\..\npcap-sdk-1.05\

mkdir build-win32
cd build-win32
%CMAKE% -A Win32 -DPACKET_DLL_DIR=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR%" ..\libpcap\
cd ..

mkdir build-x64
cd build-x64
%CMAKE% -A x64 -DPACKET_DLL_DIR=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR%" ..\libpcap\
cd ..
