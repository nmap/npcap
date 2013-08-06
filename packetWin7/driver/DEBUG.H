/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
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

#ifndef __DEBUG_INCLUDE
#define __DEBUG_INCLUDE


#if DBG

#define IF_PACKETDEBUG(f) if (PacketDebugFlag & (f))
extern ULONG PacketDebugFlag;

#define PACKET_DEBUG_LOUD               0x00000001  // debugging info
#define PACKET_DEBUG_VERY_LOUD          0x00000002  // excessive debugging info

#define PACKET_DEBUG_INIT               0x00000100  // init debugging info

//
// unfortunately, NT4 does not have the __FUNCTION__ macro, so we define it as null
//
#ifndef __FUNCTION__
#define __FUNCTION__ 
#endif

//
// Macro for deciding whether to dump lots of debugging information.
//

#define IF_LOUD(A) IF_PACKETDEBUG( PACKET_DEBUG_LOUD ) { A }
#define IF_VERY_LOUD(A) IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD ) { A }
#define IF_INIT_LOUD(A) IF_PACKETDEBUG( PACKET_DEBUG_INIT ) { A }

#define TRACE_ENTER() DbgPrint("--> " __FUNCTION__)
#define TRACE_EXIT() DbgPrint("<-- " __FUNCTION__)
#define TRACE_MESSAGE(__level__, __message__) do{ if (PacketDebugFlag & (__level__)) DbgPrint("    " __FUNCTION__ ": " __message__);} while(FALSE)

#define TRACE_MESSAGE1(__level__, __message__, __p1__) do			\
	{																\
		if (PacketDebugFlag & (__level__))							\
			DbgPrint("    " __FUNCTION__ ": " __message__, __p1__);	\
	} while(FALSE)

#define TRACE_MESSAGE2(__level__, __message__, __p1__, __p2__) do			\
	{																		\
		if (PacketDebugFlag & (__level__))									\
			DbgPrint("    " __FUNCTION__ ": " __message__, __p1__, __p2__);	\
	} while(FALSE)

#define TRACE_MESSAGE3(__level__, __message__, __p1__, __p2__, __p3__) do	\
	{																		\
		if (PacketDebugFlag & (__level__))									\
			DbgPrint("    " __FUNCTION__ ": " __message__, __p1__, __p2__, __p3__);	\
	} while(FALSE)

#define TRACE_MESSAGE4(__level__, __message__, __p1__, __p2__, __p3__, __p4__) do	\
	{																		\
		if (PacketDebugFlag & (__level__))									\
			DbgPrint("    " __FUNCTION__ ": " __message__, __p1__, __p2__, __p3__, __p4__ );	\
	} while(FALSE)


#else //DBG

#define IF_LOUD(A)
#define IF_VERY_LOUD(A)
#define IF_INIT_LOUD(A)

#define TRACE_ENTER()
#define TRACE_EXIT()
#define TRACE_MESSAGE(__level__, __message__)
#define TRACE_MESSAGE1(__level__, __message__, __p1__)
#define TRACE_MESSAGE2(__level__, __message__, __p1__, __p2__)
#define TRACE_MESSAGE3(__level__, __message__, __p1__, __p2__, __p3__)
#define TRACE_MESSAGE4(__level__, __message__, __p1__, __p2__, __p3__, __p4__)

#endif

#endif /*#define __DEBUG_INCLUDE*/
