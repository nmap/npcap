# Microsoft Developer Studio Project File - Name="PacketNT" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=PacketNT - Win32 Debug Vista
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Packet.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Packet.mak" CFG="PacketNT - Win32 Debug Vista"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "PacketNT - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 NT4 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 NT4 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Debug LOG_TO_FILE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Release LOG_TO_FILE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 NT4 Debug LOG_TO_FILE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 NT4 Release LOG_TO_FILE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Debug No AirPcap" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Release No AirPcap" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Debug NpfIm" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Release NpfIm" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Debug Vista" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Release Vista" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "PacketNT - Win32 Release Vista LOG_TO_FILE" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "PacketNT - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /D "HAVE_WANPACKET_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /D "HAVE_WANPACKET_API" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\Debug
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 NT4 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "NT4_Debug"
# PROP BASE Intermediate_Dir "NT4_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "NT4_Debug"
# PROP Intermediate_Dir "NT4_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../common" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /D "_WINNT4" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG" /d "_WINNT4"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\NT4_Debug
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 NT4 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "NT4_Release"
# PROP BASE Intermediate_Dir "NT4_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "NT4_Release"
# PROP Intermediate_Dir "NT4_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../../../common" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /D "_WINNT4" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG" /d "_WINNT4"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib Ws2_32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib Ws2_32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\NT4_Release
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Debug LOG_TO_FILE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_LOG_TO_FILE"
# PROP BASE Intermediate_Dir "Debug_LOG_TO_FILE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_LOG_TO_FILE"
# PROP Intermediate_Dir "Debug_LOG_TO_FILE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../common" /I "../../../dag/include" /I "../../../dag/drv/windows" /D "WIN32" /D "_WINDOWS" /D "HAVE_DAG_API" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "HAVE_AIRPCAP_API" /D "_DEBUG_TO_FILE" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /FR /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\Debug_LOG_TO_FILE
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Release LOG_TO_FILE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_LOG_TO_FILE"
# PROP BASE Intermediate_Dir "Release_LOG_TO_FILE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_LOG_TO_FILE"
# PROP Intermediate_Dir "Release_LOG_TO_FILE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../../../common" /I "../../../dag/include" /I "../../../dag/drv/windows" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "HAVE_DAG_API" /YX /FD /c
# ADD CPP /nologo /MT /W4 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "_DEBUG_TO_FILE" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /FR /YX /FD /c
# SUBTRACT CPP /u
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_LOG_TO_FILE
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 NT4 Debug LOG_TO_FILE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "NT4_Debug_LOG_TO_FILE"
# PROP BASE Intermediate_Dir "NT4_Debug_LOG_TO_FILE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "NT4_Debug_LOG_TO_FILE"
# PROP Intermediate_Dir "NT4_Debug_LOG_TO_FILE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../common" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /D "_DEBUG_TO_FILE" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /D "_WINNT4" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG" /d "_WINNT4"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\NT4_Debug_LOG_TO_FILE
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 NT4 Release LOG_TO_FILE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "NT4_Release_LOG_TO_FILE"
# PROP BASE Intermediate_Dir "NT4_Release_LOG_TO_FILE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "NT4_Release_LOG_TO_FILE"
# PROP Intermediate_Dir "NT4_Release_LOG_TO_FILE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../../../common" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_WINNT4" /D "_DEBUG_TO_FILE" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /D "_WINNT4" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG" /d "_WINNT4"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib Ws2_32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib Ws2_32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\NT4_Release_LOG_TO_FILE
SOURCE="$(InputPath)"
PostBuild_Desc=Copy packet.lib into Common
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Debug No AirPcap"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_No_AirPcap"
# PROP BASE Intermediate_Dir "Debug_No_AirPcap"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_No_AirPcap"
# PROP Intermediate_Dir "Debug_No_AirPcap"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../z1211u/airpcap/" /D "WIN32" /D "_WINDOWS" /D "HAVE_AIRPCAP_API" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\Debug_No_AirPcap
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Release No AirPcap"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_No_AirPcap"
# PROP BASE Intermediate_Dir "Release_No_AirPcap"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_No_AirPcap"
# PROP Intermediate_Dir "Release_No_AirPcap"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../z1211u/airpcap/" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "HAVE_AIRPCAP_API" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_No_AirPcap
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Debug NpfIm"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_No_NpfIm"
# PROP BASE Intermediate_Dir "Debug_No_NpfIm"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_No_NpfIm"
# PROP Intermediate_Dir "Debug_No_NpfIm"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /D "_DBG" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /I "../../../../NpfIm_DevPack" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib NpfIm.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/ ../../../../NpfIm_DevPack"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\Debug_No_NpfIm
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Release NpfIm"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_No_NpfIm"
# PROP BASE Intermediate_Dir "Release_No_NpfIm"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_No_NpfIm"
# PROP Intermediate_Dir "Release_No_NpfIm"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /I "../../../../NpfIm_DevPack" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/"
# ADD LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib NpfIm.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/ ../../../../NpfIm_DevPack" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_No_NpfIm
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Debug Vista"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug_Vista"
# PROP BASE Intermediate_Dir "Debug_Vista"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug_Vista"
# PROP Intermediate_Dir "Debug_Vista"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG" /d "_WINVISTA"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wsock32.lib ..\wanpacket\debug\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT BASE LINK32 /pdb:none /incremental:no
# ADD LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"../../../../Airpcap_Devpack/lib/"
# SUBTRACT LINK32 /pdb:none /incremental:no
# Begin Special Build Tool
OutDir=.\Debug_Vista
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Release Vista"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_Vista"
# PROP BASE Intermediate_Dir "Release_Vista"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_Vista"
# PROP Intermediate_Dir "Release_Vista"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG" /d "_WINVISTA"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 Ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_Vista
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ELSEIF  "$(CFG)" == "PacketNT - Win32 Release Vista LOG_TO_FILE"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release_Vista_LOG_TO_FILE"
# PROP BASE Intermediate_Dir "Release_Vista_LOG_TO_FILE"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release_Vista_LOG_TO_FILE"
# PROP Intermediate_Dir "Release_Vista_LOG_TO_FILE"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W4 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "_DEBUG_TO_FILE" /D "WIN32" /D "_WINDOWS" /D "HAVE_WANPACKET_API" /D "HAVE_IPHELPER_API" /D "HAVE_NPFIM_API" /FR /YX /FD /c
# SUBTRACT BASE CPP /u
# ADD CPP /nologo /MT /W4 /GX /Zi /O2 /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../common" /I "../../../../Airpcap_Devpack/include/" /D "NDEBUG" /D "HAVE_AIRPCAP_API" /D "_DEBUG_TO_FILE" /D "WIN32" /D "_WINDOWS" /D "HAVE_IPHELPER_API" /FR /YX /FD /c
# SUBTRACT CPP /u
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG" /d "_WINVISTA"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 Ws2_32.lib ..\wanpacket\release\wanpacket.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 Ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib Iphlpapi.lib version.lib /nologo /subsystem:windows /dll /debug /machine:I386 /libpath:"../../../../Airpcap_Devpack/lib/" /opt:ref
# SUBTRACT LINK32 /pdb:none
# Begin Special Build Tool
OutDir=.\Release_Vista_LOG_TO_FILE
SOURCE="$(InputPath)"
PostBuild_Cmds=copy                    $(OutDir)\packet.lib                    ..\..\..\Common\ 
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "PacketNT - Win32 Release"
# Name "PacketNT - Win32 Debug"
# Name "PacketNT - Win32 NT4 Debug"
# Name "PacketNT - Win32 NT4 Release"
# Name "PacketNT - Win32 Debug LOG_TO_FILE"
# Name "PacketNT - Win32 Release LOG_TO_FILE"
# Name "PacketNT - Win32 NT4 Debug LOG_TO_FILE"
# Name "PacketNT - Win32 NT4 Release LOG_TO_FILE"
# Name "PacketNT - Win32 Debug No AirPcap"
# Name "PacketNT - Win32 Release No AirPcap"
# Name "PacketNT - Win32 Debug NpfIm"
# Name "PacketNT - Win32 Release NpfIm"
# Name "PacketNT - Win32 Debug Vista"
# Name "PacketNT - Win32 Release Vista"
# Name "PacketNT - Win32 Release Vista LOG_TO_FILE"
# Begin Group "Source files"

# PROP Default_Filter "*.c *.cpp"
# Begin Source File

SOURCE=..\AdInfo.c
# End Source File
# Begin Source File

SOURCE=..\NpfImExt.c
# End Source File
# Begin Source File

SOURCE=..\PACKET32.C
# End Source File
# End Group
# Begin Group "Header files"

# PROP Default_Filter "*.h"
# Begin Source File

SOURCE=..\debug.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\ioctls.h
# End Source File
# Begin Source File

SOURCE="..\Packet32-Int.h"
# End Source File
# Begin Source File

SOURCE=..\..\..\Common\Packet32.h
# End Source File
# Begin Source File

SOURCE=..\..\..\Common\WpcapNames.h
# End Source File
# End Group
# Begin Group "Resources"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\version.rc
# End Source File
# End Group
# Begin Source File

SOURCE=..\Packet.def
# End Source File
# End Target
# End Project
