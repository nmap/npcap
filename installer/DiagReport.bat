@echo off

whoami /Groups | find "S-1-16-12288" >NUL
if ERRORLEVEL 1 (
  rem This tools must run with administrator permissions
  rem It will popup the UAC dialog, please click [Yes] to continue.
  echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
  echo UAC.ShellExecute "%~s0", "%*", "", "runas", 1 >> "%temp%\getadmin.vbs"
  "%temp%\getadmin.vbs"
  exit /b 2
)

set dir=%~dp0
set scriptPath=%dir%DiagReport.ps1
for /f "tokens=*" %%a in ('powershell Get-ExecutionPolicy') do (
set originPolicy=%%a
)
powershell Set-ExecutionPolicy 0

rem this call only works for Administrator
rem powershell %scriptPath%

rem This call works also for normal users
rem "No Exit" version:
rem powershell -NoExit -noprofile -command "&{start-process powershell -ArgumentList '-NoExit -noprofile -file \"%scriptPath%\"' -verb RunAs}"
rem "Exit" version:
powershell -noprofile -command "&{start-process powershell -ArgumentList '-noprofile -file \"%scriptPath%\"' -verb RunAs}"

powershell Set-ExecutionPolicy %originPolicy%

rem pause
