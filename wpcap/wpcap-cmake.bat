for /f "usebackq delims=#" %%a in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -version 17 -property installationPath`) do set CMAKE="%%a\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set GENERATOR=Visual Studio 17 2022
set NPCAP_SDK=..\..\npcap-sdk-1.16
set AIRPCAP_SDK=..\..\Airpcap_Devpack
set CFG_FLAGS=/guard:cf

mkdir build-win32
cd build-win32
%CMAKE% -A Win32 -DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE -DOpenSSL_FOUND=FALSE -DCMAKE_C_FLAGS_INIT=%CFG_FLAGS% -DCMAKE_SHARED_LINKER_FLAGS_INIT=%CFG_FLAGS% -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -DAirPcap_ROOT=..\%AIRPCAP_SDK% -G "%GENERATOR%" ..\libpcap\
cd ..

mkdir build-x64
cd build-x64
%CMAKE% -A x64 -DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE -DOpenSSL_FOUND=FALSE -DCMAKE_C_FLAGS_INIT=%CFG_FLAGS% -DCMAKE_SHARED_LINKER_FLAGS_INIT=%CFG_FLAGS% -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -DAirPcap_ROOT=..\%AIRPCAP_SDK% -G "%GENERATOR%" ..\libpcap\
cd ..

rem AirPcap does not have ARM64 libs
mkdir build-ARM64
cd build-ARM64
%CMAKE% -A ARM64 -DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE -DOpenSSL_FOUND=FALSE -DCMAKE_C_FLAGS_INIT=%CFG_FLAGS% -DCMAKE_SHARED_LINKER_FLAGS_INIT=%CFG_FLAGS% -DPacket_ROOT=..\%NPCAP_SDK% -DLIBRARY_NAME=wpcap -G "%GENERATOR%" ..\libpcap\
cd ..
