@echo off

if "%1"=="" (
	echo You must specify the version string as parameter
	goto end
)

echo Creating \web folder
mkdir .\web									>nul 2>nul
mkdir .\web\install							>nul 2>nul
mkdir .\web\install\bin						>nul 2>nul
mkdir .\web\install\bin\debug 				>nul 2>nul
mkdir .\web\install\bin\debug\nt4_%1  		>nul 2>nul
mkdir .\web\install\bin\debug\nt4_%1\x86 	>nul 2>nul
mkdir .\web\install\bin\debug\nt5x_%1		>nul 2>nul
mkdir .\web\install\bin\debug\nt5x_%1\x86	>nul 2>nul
mkdir .\web\install\bin\debug\nt5x_%1\x64	>nul 2>nul
mkdir .\web\install\bin\debug\nt6_%1		>nul 2>nul
mkdir .\web\install\bin\debug\nt6_%1\x86	>nul 2>nul
mkdir .\web\install\bin\debug\nt6_%1\x64	>nul 2>nul
mkdir .\web\docs							>nul 2>nul
mkdir .\web\docs\docs_%1					>nul 2>nul


rem 
rem debug DLLs
rem
xcopy /v /y ".\packetntx\dll\project\release LOG_TO_FILE\x86\packet.dll"			.\web\install\bin\debug\nt5x_%1\x86 >nul
xcopy /v /y ".\packetntx\dll\project\release LOG_TO_FILE\x64\packet.dll"			.\web\install\bin\debug\nt5x_%1\x64 >nul
xcopy /v /y ".\packetntx\dll\project\release No NetMon LOG_TO_FILE\x86\packet.dll"	.\web\install\bin\debug\nt6_%1\x86 >nul
xcopy /v /y ".\packetntx\dll\project\release No NetMon LOG_TO_FILE\x64\packet.dll"	.\web\install\bin\debug\nt6_%1\x64 >nul
xcopy /v /y ".\packetNtx\Dll\Project\Release NT4 LOG_TO_FILE\x86\packet.dll"		.\web\install\bin\debug\nt4_%1\x86 >nul

rem
rem docs
rem
xcopy /s /e /v /y ".\wpdpack\docs\*.*"  .\web\docs\docs_%1\ >nul

:end