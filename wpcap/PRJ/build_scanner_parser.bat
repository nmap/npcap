@echo off

echo Building the libpcap parser and scanner...
del /Q /F  ..\libpcap\grammar.c > nul 2> nul
del /Q /F  ..\libpcap\tokdefs.h > nul 2> nul

bison -y -p pcap_ -d ../libpcap/GRAMMAR.Y > nul
if not %ERRORLEVEL% == 0 (
	echo failure in generating the grammar.
	goto end
	)

move y.tab.c ..\libpcap\grammar.c
move y.tab.h ..\libpcap\tokdefs.h

del /Q /F ..\libpcap\scanner.c >/nul 2>/nul
flex -Ppcap_ -t  ../libpcap/scanner.l > ../libpcap/scanner.c

if not %ERRORLEVEL% == 0 (
	echo failure in generating the scanner.
	goto end
	)

echo  --- Done!

:end