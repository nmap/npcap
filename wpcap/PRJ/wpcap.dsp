# Microsoft Developer Studio Project File - Name="wpcap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=wpcap - Win32 Debug REMOTE NO AIRPCAP
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "wpcap.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "wpcap.mak" CFG="wpcap - Win32 Debug REMOTE NO AIRPCAP"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "wpcap - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Debug REMOTE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Debug REMOTE DAG" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Release REMOTE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Release REMOTE DAG" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Release REMOTE NO AIRPCAP" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "wpcap - Win32 Debug REMOTE NO AIRPCAP" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBPCAP_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D HAVE_ADDRINFO=1 /D "NDEBUG" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/release/libpcap.lib /nologo /dll /debug /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap_no_extensions.def" /FORCE:MULTIPLE /WARN:0 /opt:ref
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBPCAP_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D "HAVE_ADDRINFO" /D "_DEBUG" /D "HAVE_DAG_API" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug/libpcap.lib /nologo /dll /debug /machine:I386 /def:".\Wpcap_no_extensions.def" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_REMOTE"
# PROP BASE Intermediate_Dir "Debug_REMOTE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_REMOTE"
# PROP Intermediate_Dir "Debug_REMOTE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /D "HAVE_ADDRINFO" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "_DEBUG" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_REMOTE" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D "HAVE_ADDRINFO" /D "_DEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug/libpcap.lib /nologo /dll /debug /machine:I386 /implib:"../lib/wpcap.lib" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug_REMOTE/libpcap.lib /nologo /dll /debug /machine:I386 /def:".\wpcap.def" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Debug_REMOTE
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_REMOTE_DAG"
# PROP BASE Intermediate_Dir "Debug_REMOTE_DAG"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_REMOTE_DAG"
# PROP Intermediate_Dir "Debug_REMOTE_DAG"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /D "HAVE_ADDRINFO" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "_DEBUG" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_REMOTE" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D "HAVE_ADDRINFO" /D "_DEBUG" /D "HAVE_REMOTE" /D "HAVE_DAG_API" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/Debug_REMOTE_DAG/libpcap.lib /nologo /dll /debug /machine:I386 /implib:"../lib/wpcap.lib" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug_REMOTE_DAG/libpcap.lib /nologo /dll /debug /machine:I386 /def:".\wpcap.def" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Debug_REMOTE_DAG
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_REMOTE"
# PROP BASE Intermediate_Dir "Release_REMOTE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_REMOTE"
# PROP Intermediate_Dir "Release_REMOTE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /D HAVE_ADDRINFO=1 /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "NDEBUG" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_REMOTE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D HAVE_ADDRINFO=1 /D "NDEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/Release_REMOTE/libpcap.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /implib:"../lib/wpcap.lib" /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/release_REMOTE/libpcap.lib /nologo /dll /debug /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /FORCE:MULTIPLE /WARN:0 /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_REMOTE
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_REMOTE_DAG"
# PROP BASE Intermediate_Dir "Release_REMOTE_DAG"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_REMOTE_DAG"
# PROP Intermediate_Dir "Release_REMOTE_DAG"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /D HAVE_ADDRINFO=1 /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "NDEBUG" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_REMOTE" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D HAVE_ADDRINFO=1 /D "NDEBUG" /D "HAVE_REMOTE" /D "HAVE_DAG_API" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /D "HAVE_AIRPCAP_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/Release_REMOTE_DAG/libpcap.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /implib:"../lib/wpcap.lib" /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/release_REMOTE_DAG/libpcap.lib /nologo /dll /debug /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /FORCE:MULTIPLE /WARN:0 /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_REMOTE_DAG
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "wpcap___Win32_Release_REMOTE_NO_AIRPCAP"
# PROP BASE Intermediate_Dir "wpcap___Win32_Release_REMOTE_NO_AIRPCAP"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_REMOTE_NO_AIRPCAP"
# PROP Intermediate_Dir "Release_REMOTE_NO_AIRPCAP"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D HAVE_ADDRINFO=1 /D "NDEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D HAVE_ADDRINFO=1 /D "NDEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/release_REMOTE/libpcap.lib /nologo /dll /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/release_REMOTE/libpcap.lib /nologo /dll /debug /machine:I386 /nodefaultlib:"libcmtd.lib" /def:".\wpcap.def" /FORCE:MULTIPLE /WARN:0 /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_REMOTE_NO_AIRPCAP
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "wpcap___Win32_Debug_REMOTE_NO_AIRPCAP"
# PROP BASE Intermediate_Dir "wpcap___Win32_Debug_REMOTE_NO_AIRPCAP"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_REMOTE_NO_AIRPCAP"
# PROP Intermediate_Dir "Debug_REMOTE_NO_AIRPCAP"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D "HAVE_ADDRINFO" /D "_DEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../libpcap/" /I "../libpcap/bpf" /I "../libpcap/lbl" /I "../libpcap/Win32/Include" /I "../../common" /I "../Win32-Extensions" /I "../../../Airpcap_Devpack/include" /D "HAVE_ADDRINFO" /D "_DEBUG" /D "HAVE_REMOTE" /D "YY_NEVER_INTERACTIVE" /D yylval=pcap_lval /D "_USRDLL" /D "LIBPCAP_EXPORTS" /D "HAVE_STRERROR" /D "__STDC__" /D "INET6" /D "_WINDOWS" /D SIZEOF_CHAR=1 /D SIZEOF_SHORT=2 /D SIZEOF_INT=4 /D "WPCAP" /D "HAVE_SNPRINTF" /D "HAVE_VSNPRINTF" /D "WIN32" /D "_MBCS" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug_REMOTE/libpcap.lib /nologo /dll /debug /machine:I386 /def:".\wpcap.def" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib ../libpcap/win32/prj/debug_REMOTE/libpcap.lib /nologo /dll /debug /machine:I386 /def:".\wpcap.def" /pdbtype:sept /FORCE:MULTIPLE /WARN:0
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Debug_REMOTE_NO_AIRPCAP
SOURCE="$(InputPath)"
PostBuild_Desc=copy wpcap.lib file
PostBuild_Cmds=mkdir       $(OutDir)\..\..\LIB       >       nul      	copy              $(OutDir)\wpcap.lib              $(OutDir)\..\..\LIB\ 
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "wpcap - Win32 Release"
# Name "wpcap - Win32 Debug"
# Name "wpcap - Win32 Debug REMOTE"
# Name "wpcap - Win32 Debug REMOTE DAG"
# Name "wpcap - Win32 Release REMOTE"
# Name "wpcap - Win32 Release REMOTE DAG"
# Name "wpcap - Win32 Release REMOTE NO AIRPCAP"
# Name "wpcap - Win32 Debug REMOTE NO AIRPCAP"
# Begin Group "Extensions"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\Win32-Extensions\Win32-Extensions.c"
# End Source File
# End Group
# Begin Group "Libraries"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\common\Packet.lib
# End Source File
# End Group
# Begin Source File

SOURCE="..\libpcap\pcap-new.c"

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\libpcap\pcap-remote.c"

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\libpcap\sockutils.c

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

!ENDIF 

# End Source File
# Begin Source File

SOURCE="..\Win32-Extensions\version.rc"
# End Source File
# Begin Source File

SOURCE=.\wpcap.def

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\Wpcap_no_extensions.def

!IF  "$(CFG)" == "wpcap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE DAG"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE DAG"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Release REMOTE NO AIRPCAP"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "wpcap - Win32 Debug REMOTE NO AIRPCAP"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# End Target
# End Project
