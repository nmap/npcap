@echo off
rem Start type auto will start the Npcap service at boot. Set this to "demand" for demand start instead.
set START_TYPE=system

setlocal ENABLEEXTENSIONS

rem Get the installed configuration
set KEY_NAME=HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /v "Dot11Support" 2^>nul ^| find "Dot11Support"`) do (
	set Dot11Support=%%C
)
echo Dot11Support = %Dot11Support%
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /v "LoopbackAdapter" 2^>nul ^| find "LoopbackAdapter"`) do (
	set LoopbackAdapter=%%C
)
echo LoopbackAdapter = %LoopbackAdapter%

rem Make sure we can find where Npcap is installed
set KEY_NAME=HKLM\Software\WOW6432Node\Npcap
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /ve 2^>nul ^| find "REG_SZ"`) do (
	set NPCAP_DIR=%%C
)
if defined NPCAP_DIR (goto DO_FIX)
set KEY_NAME=HKLM\Software\Npcap
for /F "usebackq tokens=1,2*" %%A IN (`reg query "%KEY_NAME%" /ve 2^>nul ^| find "REG_SZ"`) do (
	set NPCAP_DIR=%%C
)
if defined NPCAP_DIR (goto DO_FIX) else (goto ABORT)

:DO_FIX
echo NPCAP_DIR = "%NPCAP_DIR%"
rem Stop the services and set their start types properly
net stop npcap
sc.exe config npcap start= %START_TYPE%
if %Dot11Support% == 0x1 (
	net stop npcap_wifi
	rem *_wifi service is disabled at install
	sc.exe config npcap_wifi start= disabled
)

rem Remove and reinstall loopback adapters
if not %LoopbackAdapter% == "" (
"%NPCAP_DIR%\NPFInstall.exe" -ul
rem )
rem TODO Remove any leftover adapters in any case
rem netsh interface show interface | find "Npcap Loopback Adapter"
rem if NOT ERRORLEVEL 1 (
rem 	echo Some Npcap Loopback Adapter was not removed. Remove it manually:
rem 	echo 1. In the Device Manager, open 'Network adapters'
rem 	echo 2. Right-click any 'Npcap Loopback Adapter' and choose 'Uninstall device'
rem 	echo 3. Repeat until all Npcap Loopback Adapters are removed
rem 	start devmgmt.msc
rem 	pause
rem )
rem
rem if not %LoopbackAdapter% == "" (
"%NPCAP_DIR%\NPFInstall.exe" -il
)

rem Start the Base Filtering Engine in case it was disabled
sc.exe config bfe start= auto
net start bfe

rem Restart the services
net start npcap

rem Rebind the filters to all adapters
if %Dot11Support% == 0x1 (
	"%NPCAP_DIR%\NPFInstall.exe" -r2
) else (
	"%NPCAP_DIR%\NPFInstall.exe" -r
)

rem Done!
goto EOF

:ABORT
echo "Unable to find or fix your installation"
exit /b 1

:EOF
exit /b 0
