@echo off

rem Make sure we can find where Npcap is installed
set KEY_NAME=HKLM\Software\WOW6432Node\Npcap
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /ve 2^>nul ^| find "REG_SZ"`) do (
	set NPCAP_DIR=%%C
)
if defined NPCAP_DIR (goto DO_CHECK)
set KEY_NAME=HKLM\Software\Npcap
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /ve 2^>nul ^| find "REG_SZ"`) do (
	set NPCAP_DIR=%%C
)
if defined NPCAP_DIR (goto DO_CHECK) else (goto ABORT)

:DO_CHECK

rem If start type is not SYSTEM_START, we need to fix that.
for /F "usebackq tokens=1,4" %%A in (`sc.exe qc npcap`) do (
	if %%A == START_TYPE (
	    if NOT %%B == SYSTEM_START (
		goto FIXINSTALL
	    )
	)
)

goto ABORT

:FIXINSTALL
"%NPCAP_DIR%\FixInstall.bat"
exit /b %ERRORLEVEL%

:ABORT
exit /b 0
