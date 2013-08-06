@echo off

IF "%2"=="" (set WPDPACKDESTDIR=.\WpdPack\) ELSE (set WPDPACKDESTDIR=%2)

IF ""=="%1" (set WINPCAPSOURCEDIR=.\) ELSE (set WINPCAPSOURCEDIR=%1) 

echo Creating \docs folder
mkdir %WPDPACKDESTDIR% >nul 2>nul
mkdir %WPDPACKDESTDIR%\docs >nul 2>nul
mkdir %WPDPACKDESTDIR%\docs\html >nul 2>nul

pushd %WINPCAPSOURCEDIR%\dox\prj

echo - Deleting existing WinPcap documentation
del /q docs\*.* 2> nul > nul
echo - Creating new documentation
doxygen winpcap_noc.dox >nul
echo - Copying all gif files
xcopy ..\pics\*.gif docs\. /v /y /q >nul
xcopy ..\*.gif docs\. /v /y /q >nul

popd

xcopy /v /Y %WINPCAPSOURCEDIR%\dox\WinPcap_docs.html	%WPDPACKDESTDIR%\docs\ 		>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\dox\prj\docs\*.*		%WPDPACKDESTDIR%\docs\html\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\dox\*.gif		%WPDPACKDESTDIR%\docs\html\	>nul
xcopy /v /Y %WINPCAPSOURCEDIR%\dox\pics\*.gif		%WPDPACKDESTDIR%\docs\html\	>nul
echo Folder \docs created successfully
set WPDPACKDESTDIR=
set WINPCAPSOURCEDIR=
