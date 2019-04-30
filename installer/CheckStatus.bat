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
if exist "%NPCAP_DIR%\loopback.ini" (
	rem NetConnectionID may be different, see nmap/nmap#1416
	rem but Name will always be Npcap Loopback Adapter
	wmic.exe nic GET Name,NetConnectionID | find "Npcap Loopback Adapter"
	if ERRORLEVEL 1 (
		rem loopback.ini is present, but the adapter is gone. Run FixInstall.bat
		"%NPCAP_DIR%\FixInstall.bat"
	)
)

:ABORT
