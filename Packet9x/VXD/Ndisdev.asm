.LALL
;*****************************************************************************
;
;       (C) Copyright MICROSOFT Corp, 1995
;
;       Title:      NDISDEV.ASM sourced from:
;       Title:      NDISLNK.ASM - Assembly linkage to NDIS Wrapper for MACs
;                                  and Protocols
;
;	This document is provided for informational purposes only and Microsoft 
;	Corporation makes no warranties, either expressed or implied, in this document.
;	Information in this document may be substantially changed without notice in
;	subsequent versions of windows and does not represent a commitment on the 
;	part of Microsoft Corporation. This information is for internal use only for 
;	development purposes.
;
;       Version:    3.00
;
;       Date:       05-Nov-1991
;
;=============================================================================
    TITLE $PACKET
    .386P
INCLUDE VMM.INC
INCLUDE NDIS.INC
INCLUDE NETVXD.INC          ; Net VxD initialization oredr
include vtd.inc


; the following equate makes the VXD dynamically loadable.
%DEVICE_DYNAMIC EQU 1
DECLARE_VIRTUAL_DEVICE %DEVICE, 3, 10, <%DEVICE>_Control, Undefined_Device_Id, PROTOCOL_Init_Order
VxD_LOCKED_DATA_SEG
Public bInitAlready	
	bInitAlready	 DB 0
	
VxD_LOCKED_DATA_ENDS
VxD_LOCKED_CODE_SEG
BeginProc C_Device_Init
IFDEF NDIS_STDCALL
	extern _DriverEntry@8:NEAR
ELSE
	extern _DriverEntry:NEAR
ENDIF
	mov  		al, bInitAlready
	cmp  		al, 0					; Make sure we' haven't been called already.
	jnz  		Succeed_Init_Phase
	inc  		bInitAlready			; Set the "Called Already" Flag
; Make sure the wrapper (Ndis.386) is loaded
   VxDcall	NdisGetVersion
   jc   		Fail_Init_Phase
   push 		0
   push 		0
IFDEF NDIS_STDCALL
   call 		_DriverEntry@8
ELSE
   call 		_DriverEntry
   add  		esp,8
ENDIF
   cmp  		eax, NDIS_STATUS_SUCCESS
   jne  		Fail_Init_Phase
Succeed_Init_Phase:
   clc
   ret
Fail_Init_Phase:
   stc
   ret
EndProc C_Device_Init


Begin_Control_Dispatch %DEVICE
    Control_Dispatch Sys_Dynamic_Device_Init,	C_Device_Init
    Control_Dispatch W32_DEVICEIOCONTROL,    	PacketIOControl, sCall, <ecx, ebx, edx, esi>
IFDEF DEBUG
    Control_Dispatch DEBUG_QUERY,					PacketDebugQuery, sCall
ENDIF
End_Control_Dispatch %DEVICE
VxD_LOCKED_CODE_ENDS
	END
