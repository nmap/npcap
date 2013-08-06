##################################################################
#
#       Microsoft Confidential
#       Copyright (C) Microsoft Corporation 1993-95
#       All Rights Reserved.
#
#       Master Makefile for packet driver
#
#       This document is provided for informational purposes only and Microsoft 
#       Corporation makes no warranties, either expressed or implied, in this document.
#       Information in this document may be substantially changed without notice in
#       subsequent versions of windows and does not represent a commitment on the 
#       part of Microsoft Corporation. This information is for internal use only for 
#       development purposes.
#
#       INPUT:
#               BIN: Where to put the stuff
#               DEB: Flags to control debug level
#
##################################################################

NDIS_STDCALL=1

!IFNDEF DEBLEVEL
DEBLEVEL=1
!ENDIF

DDEB            =       -DDEBUG -DDBG=1 -DDEBLEVEL=$(DEBLEVEL) -DCHICAGO -Zi
RDEB            =       -DDEBLEVEL=0 -DCHICAGO

!IFNDEF BIN
BIN             =       retail
DEB             =       $(RDEB)
LDEB            =       NONE
!ELSE
DEB             =       $(DDEB)
LDEB            =       FULL
!ENDIF


WIN32           =       $(DDKROOT)
NETROOT         =       $(DDKROOT)\net
NDISROOT        =       $(NETROOT)\ndis3
LIBDIR          =       $(NDISROOT)\lib
INCLUDE         =       ..\..\common;$(INCLUDE);.

DDKTOOLS        =       $(WIN32)\bin

i386                             =                      TRUE
VXD                              =                      TRUE
ASM             =       ml.exe
CL              =       cl.exe -bzalign
CHGNAM          =       chgnam.exe
CHGNAMSRC       =       $(DDKTOOLS)\chgnam.vxd
INCLUDES        =       $(NETROOT)\bin\includes.exe
MAPSYM          =       mapsym

LIBNDIS         =       $(LIBDIR)\$(BIN)\libndis.clb
LINK            =       link.exe /DEBUG /DEBUGTYPE:CV
LIBWRAPS        =       $(DDKROOT)\lib\vxdwraps.clb


LFLAGS  =   /m /NOD /MA /LI /NOLOGO /NOI

CFLAGS  = -Zp -Gs -c -DIS_32 -Zl -DWIN32 -DW95
AFLAGS  = -DIS_32 -W2 -Cx -DMASM6 -DVMMSYS -Zm -DSEGNUM=3

#AFLAGS  = $(AFLAGS) -DNDIS_WIN -c -coff -DBLD_COFF
AFLAGS  = $(AFLAGS) -c -coff -DBLD_COFF -DDEVICE=$(DEVICE)

!ifdef NDIS_STDCALL
CFLAGS = $(CFLAGS) -Gz -DNDIS_STDCALL
AFLAGS = $(AFLAGS) -DNDIS_STDCALL
!endif

.asm{$(BIN)}.obj:
		set INCLUDE=$(INCLUDE)
		set ML= $(AFLAGS) $(DEB)
		$(ASM) -Fo$*.obj $<

.asm{$(BIN)}.lst:
		set INCLUDE=$(INCLUDE)
		set ML= $(AFLAGS) $(DEB)
		$(ASM) -Fl$*.obj $<

.c{$(BIN)}.obj:
		set INCLUDE=$(INCLUDE)
		set CL= $(CFLAGS) $(DEB)
		$(CL) -Fo$*.obj $<

target: $(BIN) $(BIN)\$(DEVICE).VXD $(BIN)\$(DEVICE).RES

$(BIN):
	if not exist $(BIN)\nul md $(BIN)

dbg:    depend
		$(MAKE) BIN=debug DEB="$(DDEB)"

rtl:    depend
		$(MAKE) BIN=retail DEB="$(RDEB)"

all: rtl dbg

!if EXIST (depend.mk)
!include depend.mk
!endif

VERSION =   4.0

!ifdef OMB

$(BIN)\$(DEVICE).VXD: $(OBJS) $(DEVICE).def $(LIBNDIS)
				$(LINK) @<<
$(OBJS: =+^
)
$(BIN)\$(DEVICE).VXD $(LFLAGS)
$(BIN)\$(DEVICE).map
$(LIBNDIS)
$(DEVICE).def
<<

!else

$(BIN)\$(DEVICE).VXD: $(OBJS) $(DEVICE).def $(LIBNDIS) $(LIBWRAPS)
		$(LINK) @<<
-MACHINE:i386
-DEBUG:$(LDEB)
-DEBUGTYPE:CV
-PDB:NONE
-DEF:$(DEVICE).def
-OUT:$(BIN)\$(DEVICE).VXD
-MAP:$(BIN)\$(DEVICE).map
-VXD
$(LIBNDIS)
$(LIBWRAPS)
$(OBJS: =^
)


<<
!endif
		cd      $(BIN)
		$(MAPSYM) $(DEVICE)

		cd      ..


$(BIN)\$(DEVICE).RES:
      $(SDKROOT)\bin\rc -r -i$(DDKROOT)\inc32 $(DEVICE).RC

		move     $(DEVICE).RES $(BIN)
		cd      $(BIN)
     
      adrc2vxd $(DEVICE).vxd $(DEVICE).res

		cd      ..
		


depend:
#        -mkdir debug
#        -mkdir retail
		set INCLUDE=$(INCLUDE)
#		$(INCLUDES) -i -L$$(BIN) -S$$(BIN) *.asm *.c > depend.mk
#		$(INCLUDES) -i -L$$(BIN) -S$$(BIN) $(NDISSRC)\ndisdev.asm >> depend.mk


clean :
		- del debug\*.obj
		- del debug\*.sym
      - del debug\*.VXD
		- del debug\*.map
		- del debug\*.lst
		- del retail\*.obj
		- del retail\*.sym
      - del retail\*.VXD
		- del retail\*.map
		- del retail\*.lst
		- del depend.mk


