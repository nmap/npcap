SET SAVEPID=0

set ARCH=x86
rem All platforms support x86 emulation
Call :DO_TEST x86 || goto :error

rem If we're running in native arch,
if "%PROCESSOR_ARCHITEW6432%" == "" (
	rem and it's x86, we're done.
	if "%PROCESSOR_ARCHITECTURE%" == "x86" goto :quit

	rem Otherwise, test the native arch
	set ARCH=%PROCESSOR_ARCHITECTURE%
) else (
	rem Otherwise, we're running in WOW64, so test the native arch
	set ARCH=%PROCESSOR_ARCHITEW6432%
)

if "%ARCH%" == "AMD64" (
	set ARCH=x64
) else (
	if NOT "%ARCH%" == "ARM64" goto :error
)

Call :DO_TEST %ARCH% || goto :error

:quit
pause
exit /b %ERR%

:error
set ERR=%ERRORLEVEL%
if "%ERR%" == "" set ERR=1
echo %ARCH% Failed: %ERR%
if %SAVEPID% NEQ 0 taskkill /PID %SAVEPID%
goto :quit

:DO_TEST

echo Testing iflist...
for /f "TOKENS=1,2" %%a in ('nmap --iflist') do @if %%a==lo0 set devname=%%b
if not "%devname%"=="\Device\NPF_Loopback" goto :error
.\%1\iflist.exe || goto :error

echo Testing Loopback operations...
echo Testing pcap_filter...
del loopback.pcap
start .\%1\pcap_filter.exe -o loopback.pcap -s %devname% -f tcp
for /F "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq pcap_filter.exe"') do set SAVEPID=%%b
if "%SAVEPID%" == "" goto :error

echo Running nmap...
nmap -F -O -d -n localhost || goto :error
nmap -F -O -d -n -6 localhost || goto :error

echo Testing sendpack...
.\%1\sendpack.exe %devname% || goto :error

echo Killing pcap_filter...
taskkill /PID %SAVEPID% || goto :error
SET SAVEPID=0

echo Reading dump file...
.\%1\readfile.exe loopback.pcap || goto :error

echo Replaying dump file...
.\%1\sendcap.exe loopback.pcap %devname% || goto :error


echo Checking for Internet...
for /f "TOKENS=1,3" %%a in ('nmap --route-dst scanme.nmap.org') do @if %%b==srcaddr set ifname=%%a
if %ifname%=="" goto :error
for /f "TOKENS=1,2" %%a in ('nmap --iflist') do @if %%a==%ifname% set devname=%%b
if not %devname:~0,12%==\Device\NPF_ goto :error

echo Testing pcap_filter...
del scanme.pcap
start .\%1\pcap_filter.exe -o scanme.pcap -s %devname% -f tcp
for /F "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq pcap_filter.exe"') do set SAVEPID=%%b

echo Running nmap...
nmap -F -O -d -n scanme.nmap.org || goto :error
rem Need IPv6 connectivity to test this:
rem nmap -F -O -d -n -6 scanme.nmap.org || goto :error

echo Testing sendpack...
.\%1\sendpack.exe %devname% || goto :error

echo Killing pcap_filter...
taskkill /PID %SAVEPID% || goto :error
SET SAVEPID=0

echo Reading dump file...
.\%1\readfile.exe scanme.pcap || goto :error

echo Replaying dump file...
.\%1\sendcap.exe scanme.pcap %devname% || goto :error

goto :EOF
