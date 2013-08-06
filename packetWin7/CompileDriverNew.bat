@echo off

if  "%2" == "checked" (
	set __BUILD_TYPE=checked
) else (
	set __BUILD_TYPE=free
)

if "%1"=="x86" goto x86_build
if "%1"=="AMD64" goto amd64_build

echo ******************************************************
echo   ERROR: unknown or unspecified build architecture (%1)
echo ******************************************************

goto end

:x86_build

echo ******************************************************
echo *  Compiling the driver for Windows NT5.x 32 bit     *
echo ******************************************************

mkdir driver\bin 2> nul

set NPF_C_DEFINES=-DNDIS50

rem ** enable the following line to enable the TME extensions **
rem set NPF_TME_FILES=tme.c count_packets.c tcp_session.c functions.c bucket_lookup.c normal_lookup.c win_bpf_filter_init.c
rem set NPF_C_DEFINES=%NPF_C_DEFINES% -DHAVE_BUGGY_TME_SUPPORT

ddkbuild -WLHXP -prefast %__BUILD_TYPE% .\driver -cefw

rem ** enable the following line to enable the TME extensions **
rem set NPF_TME_FILES=
rem set NPF_JIT_FILES=
set NPF_C_DEFINES=

goto end

:amd64_build

echo *******************************************************
echo *  Compiling the driver for Windows NT5.x x64 (AMD64) *
echo *******************************************************

mkdir driver\bin 2> nul
mkdir driver\bin\xp 2> nul

set NPF_C_DEFINES=-DNDIS50

rem
rem The TME extensions and the JIT is not supported on x64, at the moment
rem
rem set NPF_TME_FILES=
rem set NPF_JIT_FILES=

ddkbuild -WLHA64 -prefast %__BUILD_TYPE% .\driver -cefw

set NPF_C_DEFINES=
rem set NPF_TME_FILES=
rem set NPF_JIT_FILES=

goto end

:end

set __BUILD_TYPE=
