.LALL

;
;  Copyright (c) 1999, 2000
;	Politecnico di Torino.  All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that: (1) source code distributions
; retain the above copyright notice and this paragraph in its entirety, (2)
; distributions including binary code include the above copyright notice and
; this paragraph in its entirety in the documentation or other materials
; provided with the distribution, and (3) all advertising materials mentioning
; features or use of this software display the following acknowledgement:
; ``This product includes software developed by the netgroup of Politecnico 
; di Torino, and its contributors.'' Neither the name of
; the University nor the names of its contributors may be used to endorse
; or promote products derived from this software without specific prior
; written permission.
; THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
; WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
; MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
;

    TITLE $PACKET
    .386P
INCLUDE VMM.INC
INCLUDE NDIS.INC
INCLUDE NETVXD.INC          ; Net VxD initialization oredr
include vtd.inc

; the following equate makes the VXD dynamically loadable.
%DEVICE_DYNAMIC EQU 1

VxD_LOCKED_DATA_SEG

VxD_LOCKED_DATA_ENDS


VxD_LOCKED_CODE_SEG


BeginProc _SetReadTimeOut@12, PUBLIC

push	esi

mov     eax, [esp+12]	;number of ms
mov     edx, [esp+16]	;data returned to the procedure
mov     esi, [esp+8]
VMMcall	Set_Global_Time_Out
mov		eax, esi

pop		esi
ret 3*4

_SetReadTimeOut@12 EndP


BeginProc _CancelReadTimeOut@0, PUBLIC

	VMMcall Cancel_Time_Out

ret

_CancelReadTimeOut@0 EndP


BeginProc _QuerySystemTime@0, PUBLIC

	VxdCall VTD_Get_Real_Time
	ret

_QuerySystemTime@0 EndP


BeginProc _GetDate@0, PUBLIC

	VxdCall VTD_Get_Date_And_Time
	ret

_GetDate@0 EndP

VxD_LOCKED_CODE_ENDS

END
