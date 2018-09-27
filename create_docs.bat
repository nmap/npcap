@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

set DOCBOOKXSL=C:\xslt\docbook-xsl-1.79.2
set XSLTPROC=C:\xslt\bin\xsltproc.exe
set ROFFIT=%WINPCAPSOURCEDIR%\..\roffit\roffit

echo Creating \docs folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
mkdir %WPDPACKDESTDIR%\docs >nul 2>nul

echo - Deleting existing WinPcap documentation
del /q %WPDPACKDESTDIR%\docs\*.* 2> nul > nul
echo - Creating new documentation
mkdir %WPDPACKDESTDIR%\docs\wpcap >nul 2>nul
%XSLTPROC% --path %DOCBOOKXSL% --nonet --stringparam media.type html --stringparam base.dir %WPDPACKDESTDIR%/docs/ --stringparam use.id.as.filename 1 %DOCBOOKXSL%\html\chunk.xsl %WINPCAPSOURCEDIR%\docs\npcap-guide-wrapper.xml

for %%i in (%WINPCAPSOURCEDIR%) do set FULLPATHSOURCE=%%~fi
for %%i in (%WPDPACKDESTDIR%) do set FULLPATHDEST=%%~fi
C:\cygwin\bin\bash.exe --login -c "cd $(cygpath '%FULLPATHSOURCE%'); make -f create_docs.make LIBPCAPDIR=$(cygpath '%FULLPATHSOURCE%/wpcap/libpcap') DOCDIR=$(cygpath '%FULLPATHDEST%/docs') ROFFIT=perl\ $(cygpath '%ROFFIT%')"

echo Folder \docs created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
