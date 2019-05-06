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

echo Reading dump file...
.\readfile.exe loopback.pcap || goto :error

echo Replaying dump file...
.\sendcap.exe loopback.pcap %devname% || goto :error


echo Running nmap...
nmap -F -O -d -n scanme.nmap.org || goto :error

pause
exit

:error
echo Failed: %errorlevel%
pause
exit /b %errorlevel%
