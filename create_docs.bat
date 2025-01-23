@echo off

rem Ensure trailing slash
IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk\) ELSE (set WPDPACKDESTDIR=%~dp2)
rem Remove last character (trailing slash)
set WPDPACKDESTDIR=%WPDPACKDESTDIR:~0,-1%

rem Ensure trailing slash
IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%~dp1) 
rem Remove last character (trailing slash)
set WINPCAPSOURCEDIR=%WINPCAPSOURCEDIR:~0,-1%

set DOCBOOKXSL_VER=1.79.2

if exist "C:\msys64\usr\bin\env.exe" (
	set RUNBASH=C:\msys64\usr\bin\env.exe MSYSTEM=MINGW64 CHERE_INVOKING=1 /usr/bin/bash --login
) else (
	set RUNBASH=C:\cygwin\bin\bash.exe --login
)

set DOCBOOKXSL=C:\xslt\docbook-xsl-%DOCBOOKXSL_VER%
set XSLTPROC=C:\xslt\bin\xsltproc.exe
if not exist %XSLTPROC% (
	set XSLTPROC=%RUNBASH% -c "xsltproc ""$@"";" --
	set DOCBOOKXSL=/mingw64/share/xml/docbook/xsl-stylesheets-%DOCBOOKXSL_VER%
) else (
	if not exist %DOCBOOKXSL% (
		set MISSING=%DOCBOOKXSL%
		goto :missing
	)
)
set ROFFIT=%WINPCAPSOURCEDIR%\..\roffit\roffit
if not exist %ROFFIT% (
	set MISSING=%ROFFIT%
	goto :missing
)

echo Creating \docs folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
mkdir %WPDPACKDESTDIR%\docs >nul 2>nul

echo - Deleting existing WinPcap documentation
del /q /S %WPDPACKDESTDIR%\docs\*.* 2> nul > nul
echo - Creating new documentation
xcopy /v /Y "%WINPCAPSOURCEDIR%\Npcap_Guide.html" %WPDPACKDESTDIR%\
mkdir %WPDPACKDESTDIR%\docs\wpcap >nul 2>nul
%XSLTPROC% --path %DOCBOOKXSL% --nonet --stringparam media.type html --stringparam base.dir %WPDPACKDESTDIR%/docs/ --stringparam use.id.as.filename 1 %DOCBOOKXSL%/html/chunk.xsl %WINPCAPSOURCEDIR%/docs/npcap-guide-wrapper.xml

for %%i in (%WINPCAPSOURCEDIR%) do set FULLPATHSOURCE=%%~fi
for %%i in (%WPDPACKDESTDIR%) do set FULLPATHDEST=%%~fi
%RUNBASH% -c "cd $(cygpath '%FULLPATHSOURCE%'); make -f create_docs.make LIBPCAPDIR=$(cygpath '%FULLPATHSOURCE%/wpcap/libpcap') DOCDIR=$(cygpath '%FULLPATHDEST%/docs') ROFFIT=perl\ $(cygpath '%ROFFIT%');"

echo Folder \docs created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
exit /b

:missing
echo "Failed to generate docs: %MISSING% is missing"
exit /b 1
