@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\npcap-sdk) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

set DOCBOOKXSL=C:\xslt\docbook-xsl-1.79.2
set XSLTPROC=C:\xslt\bin\xsltproc.exe

echo Creating \docs folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
mkdir %WPDPACKDESTDIR%\docs >nul 2>nul

echo - Deleting existing WinPcap documentation
del /q %WPDPACKDESTDIR%\docs\*.* 2> nul > nul
echo - Creating new documentation
%XSLTPROC% --path %DOCBOOKXSL% --nonet --stringparam media.type html --stringparam base.dir %WPDPACKDESTDIR%/docs/ --stringparam use.id.as.filename 1 %DOCBOOKXSL%\html\chunk.xsl %WINPCAPSOURCEDIR%\docs\npcap-guide-wrapper.xml

echo Folder \docs created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
