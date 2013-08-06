/*
 * Copyright (c) 1999 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#if DEBUG
#define IF_PACKETDEBUG(f) if ( PacketTraceImpt & (f) )
extern ULONG PacketTraceImpt;
#define PACKET_TRACE_IMPT				0x00000001  
#define PACKET_DEBUG_VERY_LOUD			0x00000002  
#define PACKET_DEBUG_INIT				0x00000100  
#define PACKET_DEBUG_BREAK				0x00000200

#define IF_BREAK_SET 		IF_PACKETDEBUG( PACKET_DEBUG_BREAK ) DbgBreakPoint();
#define IF_INIT_TRACE(A)	IF_PACKETDEBUG( PACKET_DEBUG_INIT ) { DbgPrint("Packet: %s\r\n", A); DbgBreakPoint(); }
#define IF_TRACE(A) 			IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("Packet: %s\r\n", A); IF_BREAK_SET }
#define IF_VERY_LOUD(A) 	IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) { DbgPrint("Packet: %s\r\n", A); IF_BREAK_SET }
#define IF_TRACE_MSG(A,B)	IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("Packet: "); DbgPrint(A,B); DbgPrint("\r\n"); IF_BREAK_SET }
#define IF_TRACE_MSG2(A,B,C)	IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("Packet: "); DbgPrint(A,B,C); DbgPrint("\r\n"); IF_BREAK_SET }
#define IF_TRACE_MSG3(A,B,C,D)	IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("Packet: "); DbgPrint(A,B,C,D); DbgPrint("\r\n"); IF_BREAK_SET }
#define IF_TRACE_MSG4(A,B,C,D,E)	IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("Packet: "); DbgPrint(A,B,C,D,E); DbgPrint("\r\n"); IF_BREAK_SET }
#define INIT_ENTER(A)		IF_PACKETDEBUG( PACKET_DEBUG_INIT ) { DbgPrint("==> Packet: %s\r\n", A); DbgBreakPoint();}
#define INIT_LEAVE(A)		IF_PACKETDEBUG( PACKET_DEBUG_INIT ) { DbgPrint("<== Packet: %s\r\n", A); IF_BREAK_SET}
#define TRACE_ENTER(A)		IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("==> Packet: %s\r\n", A); IF_BREAK_SET}
#define TRACE_LEAVE(A)		IF_PACKETDEBUG( PACKET_TRACE_IMPT ) { DbgPrint("<== Packet: %s\r\n", A); IF_BREAK_SET}
#else
#define IF_PACKETDEBUG(f) 
#define IF_BREAK_SET
#define IF_INIT_TRACE(A)
#define IF_TRACE(A)
#define IF_VERY_LOUD(A)
#define IF_TRACE_MSG(A,B)
#define IF_TRACE_MSG2(A,B)
#define IF_TRACE_MSG3(A,B)
#define IF_TRACE_MSG4(A,B)
#define INIT_ENTER(A)
#define INIT_LEAVE(A)
#define TRACE_ENTER(A)
#define TRACE_LEAVE(A)
#endif
