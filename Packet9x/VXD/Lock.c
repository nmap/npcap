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

#define WANTVXDWRAPS
#include <basedef.h>
#include <vmm.h>
#include <debug.h>
#include <vxdwraps.h>
#include <vwin32.h>
#include <winerror.h>
#include "debug.h"
#pragma VxD_LOCKED_CODE_SEG
#pragma VxD_LOCKED_DATA_SEG
DWORD _stdcall PacketPageLock(DWORD, DWORD);
void  _stdcall PacketPageUnlock(DWORD, DWORD);
DWORD VXDINLINE
_PageCheckLinRange( DWORD Page, DWORD nPages, DWORD Flags )
{
	DWORD dw;
	
	_asm push [Flags]	
	_asm push [nPages]
	_asm push [Page]
	VMMCall( _PageCheckLinRange )
	_asm add esp, 0Ch
	_asm mov [dw], eax
	return (dw);
}

DWORD _stdcall PacketPageLock(DWORD lpMem, DWORD cbSize)
{
	
	DWORD LinOffset, nCommittedPages, nPages;
	if ( lpMem && cbSize )
	{
		LinOffset = lpMem & PAGEMASK;		
		nPages = ((lpMem + cbSize) >> PAGESHIFT) - PAGE(lpMem) + 1;

		nCommittedPages = _PageCheckLinRange( PAGE( lpMem ), nPages, 0 );
		if ( nCommittedPages >= nPages )
		{
			lpMem  = _LinPageLock( PAGE( lpMem ), nPages, PAGEMAPGLOBAL );
			lpMem += (( lpMem ) ? LinOffset : 0);
			return lpMem;
		}
	}
	return NULL;
}

void _stdcall PacketPageUnlock( DWORD lpMem, DWORD cbSize )
{
	DWORD nPages;

	if ( lpMem && cbSize )
	{
		nPages = ((lpMem + cbSize) >> PAGESHIFT) - PAGE(lpMem) + 1;

#ifdef W95
		//The damn name of this function changes from Win95 to Win98
		_LinPageUnlock( PAGE(lpMem) , nPages, PAGEMAPGLOBAL );
#else
		_LinPageUnLock( PAGE(lpMem) , nPages, PAGEMAPGLOBAL );
#endif
	}
}


#if DEBUG
#include <ndis.h>
#include "packet.h"
ULONG PacketTraceImpt = PACKET_TRACE_IMPT;
VOID DumpReceiveEntries( PLIST_ENTRY pListHead )
{
	PLIST_ENTRY			pListEntry;
	PPACKET_RESERVED	pReserved;
	if ( !IsListEmpty( pListHead ) )
	{
		pListEntry = pListHead->Flink;
		while ( pListEntry != pListHead )
		{
			pReserved = CONTAINING_RECORD( pListEntry, PACKET_RESERVED, ListElement );
			DbgPrint( "          Entry %lx\n\r", pListEntry );
			DbgPrint( "               lpBuffer          %lx\n\r", pReserved->lpBuffer );
			DbgPrint( "               cbBuffer          %ld\n\r", pReserved->cbBuffer );
			DbgPrint( "               lpcbBytesReturned %lx\n\r", pReserved->lpcbBytesReturned );
			DbgPrint( "               lpoOverlapped     %lx\n\r", pReserved->lpoOverlapped );
			pListEntry = pListEntry->Flink;
		}
	}
}
VOID DumpRequestEntries( PLIST_ENTRY pList )
{
	PLIST_ENTRY			pEntry;
	PPACKET_RESERVED	pReserved;
	PINTERNAL_REQUEST	pRequest;
	if ( !IsListEmpty( pList ) )
	{
		pEntry = pList->Flink;
		while ( pEntry != pList )
		{
			pReserved = CONTAINING_RECORD( pEntry, PACKET_RESERVED, ListElement );
			pRequest  = CONTAINING_RECORD( pReserved, INTERNAL_REQUEST, Reserved );
			DbgPrint( "          Entry %lx  Request %lx\n\r", pEntry, pRequest );
			pEntry = pEntry->Flink;
		}
	}
}
VOID DumpList( char n )
{
	PLIST_ENTRY		pEntry, pList;
	POPEN_INSTANCE pOpen;
	
	
	if ( GlobalDeviceExtension )
	{
		pList  = &GlobalDeviceExtension->OpenList;
		if ( !IsListEmpty( pList ) )
		{
			pEntry = pList->Flink;
	
			while ( pEntry != pList )
			{
				pOpen = CONTAINING_RECORD( pEntry, OPEN_INSTANCE, ListElement );
				
				DbgPrint( "     Adapter %lx\n\r", pOpen );
				switch ( n )
				{
				case '1':
					DumpReceiveEntries( &pOpen->RcvList );
					break;
				case '2':
					DumpRequestEntries( &pOpen->RequestList );
					break;
				case '3':
					DumpRequestEntries( &pOpen->ResetIrpList );
					break;
				}
				pEntry = pEntry->Flink;
			}
		}
	}
	return;
}
DWORD _stdcall PacketDebugQuery( void ) 
{
	char outList = 1;
	Out_Debug_String( "Packet Debug Services:\n\r" );
	while ( 1 )
	{
		char c;
		Out_Debug_String( "\n\r" );
		
		if ( outList )
		{
			outList = 0;
			Out_Debug_String( "[0] Adapter List\n\r" );
			Out_Debug_String( "[1] Receive List\n\r" );
			Out_Debug_String( "[2] Request List\n\r" );
			Out_Debug_String( "[3] Reset   List\n\r\n\r" );
			Out_Debug_String( "[4] Turn OFF Trace Information\n\r" );
			IF_PACKETDEBUG( PACKET_TRACE_IMPT )
				Out_Debug_String( "[5] TOGGLE Normal Trace OFF\n\r" );
			else
				Out_Debug_String( "[5] TOGGLE Normal Trace ON\n\r" );
			IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )
				Out_Debug_String( "[6] TOGGLE Trace ALL OFF\n\r" );
			else
				Out_Debug_String( "[6] TOGGLE Trace ALL ON\n\r" );
			
			IF_PACKETDEBUG( PACKET_DEBUG_INIT )
				Out_Debug_String( "[7] TOGGLE Trace Init OFF\n\r" );
			else
				Out_Debug_String( "[7] TOGGLE Trace Init ON\n\r" );
			
			IF_PACKETDEBUG( PACKET_DEBUG_BREAK )
				Out_Debug_String( "[8] TOGGLE Break on Trace OFF\n\r" );
			else
				Out_Debug_String( "[8] TOGGLE Break on Trace ON\n\r" );
			Out_Debug_String( "\r\n[h] Reprint Commands\r\n" );
		}
		Out_Debug_String( "Enter selection or Press ESC to Exit: " );
		
		VxDCall( In_Debug_Chr );
		_asm	jz		Debug_Exit
		_asm	mov		c, al
		Out_Debug_String( "\n\r" );
		switch ( c )
		{
		case '0':
			Out_Debug_String( "\n\rAdapter List:\n\r" );
			DumpList( c );
			break;
		case '1':
			Out_Debug_String( "\n\rRecieve List:\n\r" );
			DumpList( c );
			break;
		case '2':
			Out_Debug_String( "\n\rRequest List:\n\r" );
			DumpList( c );
			break;
		case '3':
			Out_Debug_String( "\n\rReset List:\n\r" );
			DumpList( c );
			break;
		case '4':
			PacketTraceImpt = 0;
			break;
		case '5':
			IF_PACKETDEBUG( PACKET_TRACE_IMPT )
			{
				PacketTraceImpt &= ~(PACKET_TRACE_IMPT | PACKET_DEBUG_VERY_LOUD);
			}
			else
			{
				PacketTraceImpt |= PACKET_TRACE_IMPT;
				PacketTraceImpt &= ~PACKET_DEBUG_VERY_LOUD;
			}
			break;
		case '6':
			IF_PACKETDEBUG( PACKET_DEBUG_VERY_LOUD )
				PacketTraceImpt &= ~PACKET_DEBUG_VERY_LOUD;
			else
				PacketTraceImpt |= PACKET_DEBUG_VERY_LOUD | PACKET_TRACE_IMPT;
			break;
		case '7':
			IF_PACKETDEBUG( PACKET_DEBUG_INIT )
				PacketTraceImpt &= ~PACKET_DEBUG_INIT;
			else
				PacketTraceImpt |= PACKET_DEBUG_INIT;
			break;
		case '8':
			IF_PACKETDEBUG( PACKET_DEBUG_BREAK )
				PacketTraceImpt &= ~PACKET_DEBUG_BREAK;
			else
				PacketTraceImpt |= PACKET_DEBUG_BREAK;
			break;
		default:
			outList = 1;
			break;
		}
	}
Debug_Exit:
	return( VXD_SUCCESS );
}
#endif
