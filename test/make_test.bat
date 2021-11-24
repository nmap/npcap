SET SAVEPID=0

echo Testing iflist...
for /f "TOKENS=1,2" %%a in ('nmap --iflist') do @if %%a==lo0 set devname=%%b
if not %devname:~0,12%==\Device\NPF_ goto :error
.\iflist.exe

echo Testing Loopback operations...
echo Testing pcap_filter...
del loopback.pcap
start .\pcap_filter.exe -o loopback.pcap -s %devname% -f tcp
for /F "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq pcap_filter.exe"') do set SAVEPID=%%b

echo Running nmap...
nmap -F -O -d -n localhost || goto :error
nmap -F -O -d -n -6 localhost || goto :error

echo Testing sendpack...
.\sendpack.exe %devname% || goto :error

echo Killing pcap_filter...
taskkill /PID %SAVEPID% || goto :error
SET SAVEPID=0

echo Reading dump file...
.\readfile.exe loopback.pcap || goto :error

echo Replaying dump file...
.\sendcap.exe loopback.pcap %devname% || goto :error


echo Checking for Internet...
for /f "TOKENS=1,3" %%a in ('nmap --route-dst scanme.nmap.org') do @if %%b==srcaddr set ifname=%%a
if %ifname%=="" goto :error
for /f "TOKENS=1,2" %%a in ('nmap --iflist') do @if %%a==%ifname% set devname=%%b
if not %devname:~0,12%==\Device\NPF_ goto :error

echo Testing pcap_filter...
del scanme.pcap
start .\pcap_filter.exe -o scanme.pcap -s %devname% -f tcp
for /F "TOKENS=1,2,*" %%a in ('tasklist /FI "IMAGENAME eq pcap_filter.exe"') do set SAVEPID=%%b

echo Running nmap...
nmap -F -O -d -n scanme.nmap.org || goto :error
rem Need IPv6 connectivity to test this:
rem nmap -F -O -d -n -6 scanme.nmap.org || goto :error

echo Testing sendpack...
.\sendpack.exe %devname% || goto :error

echo Killing pcap_filter...
taskkill /PID %SAVEPID% || goto :error
SET SAVEPID=0

echo Reading dump file...
.\readfile.exe scanme.pcap || goto :error

echo Replaying dump file...
.\sendcap.exe scanme.pcap %devname% || goto :error

pause
exit /b

:error
echo Failed: %errorlevel%
if %SAVEPID% NEQ 0 taskkill /PID %SAVEPID%
pause
exit /b %errorlevel%
