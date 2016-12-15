del .\disk1\Npcap.cab
makecab /f npcap.ddf
"\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe" sign /v /sha1 ec2ae51775f3252541b266c40528daa77baa072f /t http://timestamp.verisign.com/scripts/timstamp.dll .\disk1\Npcap.cab
pause