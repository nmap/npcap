@echo off
set dir=.
set scriptPath=%dir%\Deploy.ps1
for /f "tokens=*" %%a in ('powershell Get-ExecutionPolicy') do (
set originPolicy=%%a
)
powershell Set-ExecutionPolicy -scope currentuser 0
powershell %scriptPath%
powershell Set-ExecutionPolicy -scope currentuser %originPolicy%

pause