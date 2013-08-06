# Microsoft Developer Studio Project File - Name="WanPacket" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=WANPACKET - WIN32 DEBUG
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "WanPacket.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "WanPacket.mak" CFG="WANPACKET - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "WanPacket - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "WanPacket - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "WanPacket - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "WANPACKET_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /I "..\..\..\Common" /I "..\..\driver" /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../../z1211u/airpcap/" /D "NDEBUG" /D "_MBCS" /D "_USRDLL" /D "WANPACKET_EXPORTS" /D "WIN32" /D "_WINDOWS" /D "HAVE_DAG_API" /D "__NPF_x86__" /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "NDEBUG"
# ADD RSC /l 0x410 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 npptools.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /libpath:"..\..\WanPacket\Release\\" /opt:ref
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "WanPacket - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "WANPACKET_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "..\..\..\Common" /I "..\..\driver" /I "../../../dag/include" /I "../../../dag/drv/windows" /I "../../../../z1211u/airpcap/" /D "_DEBUG" /D "_MBCS" /D "_USRDLL" /D "WANPACKET_EXPORTS" /D "WIN32" /D "_WINDOWS" /D "HAVE_DAG_API" /D "__NPF_x86__" /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x410 /d "_DEBUG"
# ADD RSC /l 0x410 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib npptools.lib /nologo /dll /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "WanPacket - Win32 Release"
# Name "WanPacket - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Group "TME"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\driver\bucket_lookup.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\count_packets.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\functions.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\normal_lookup.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\tcp_session.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\tme.c
# End Source File
# Begin Source File

SOURCE=..\..\driver\win_bpf_filter_init.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\version.rc
# End Source File
# Begin Source File

SOURCE=.\WanPacket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\driver\win_bpf_filter.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Group "TME No. 1"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\driver\bucket_lookup.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\count_packets.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\functions.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\memory_t.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\normal_lookup.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\tcp_session.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\tme.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\valid_insns.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\win_bpf_filter_init.h
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\driver\DEBUG.H
# End Source File
# Begin Source File

SOURCE=..\..\driver\time_calls.h
# End Source File
# Begin Source File

SOURCE=..\..\driver\win_bpf.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=.\WanPacket.def
# End Source File
# End Target
# End Project
