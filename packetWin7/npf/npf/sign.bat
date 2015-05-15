mkdir bin\

copy npf.inf bin\

copy objchk_win7_amd64\amd64\npf.sys bin\

SignTool sign /v /s TestCertStoreName /n darkjames.pl /t http://timestamp.verisign.com/scripts/timstamp.dll bin\npf.sys

Inf2cat.exe /driver:bin\ /os:7_X86

SignTool sign /v /s TestCertStoreName /n darkjames.pl /t http://timestamp.verisign.com/scripts/timstamp.dll bin\npf.cat