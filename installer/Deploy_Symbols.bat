@echo off
set dir=.
set scriptPath=%dir%\Deploy.ps1
for /f "tokens=*" %%a in ('powershell Get-ExecutionPolicy') do (
set originPolicy=%%a
)
powershell Set-ExecutionPolicy 0
powershell %scriptPath% deploy-symbols
powershell Set-ExecutionPolicy %originPolicy%

pause