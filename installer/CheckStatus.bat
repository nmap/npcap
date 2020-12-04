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
if exist "%NPCAP_DIR%\loopback.ini" (
	rem NetConnectionID may be different, see nmap/nmap#1416
	rem but Name will always be Npcap Loopback Adapter
	%SYSTEMROOT%\wbem\wmic.exe nic GET Name,NetConnectionID | find "Npcap Loopback Adapter"
	if ERRORLEVEL 1 (
		rem loopback.ini is present, but the adapter is gone. Run FixInstall.bat
		goto FIXINSTALL
	)
)

goto ABORT

:FIXINSTALL
"%NPCAP_DIR%\FixInstall.bat"

:ABORT
