@echo off
set SDKFILENAME=npcap-sdk-1.01.zip

if "%2"== "" ( rd /s/q ./npcap-sdk 2>nul >nul) else ( rd /s /q "%2" 2>nul >nul)

rem Requires Cygwin to provide make.exe
call create_include.bat %1 %2

call create_lib.bat %1 %2

call create_examples.bat %1 %2

rem Requires xsltproc and Docbook XSL stylesheets
call create_docs.bat %1 %2

del %SDKFILENAME%
cd .\npcap-sdk
"C:\Program Files\7-Zip\7z.exe" a ..\%SDKFILENAME% .
PAUSE

