/*
 * Copyright (c) 2003 - 2005 NetGroup, Politecnico di Torino (Italy)
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

#if !defined(AFX_WANPACKET_H__C87BC2BD_187D_4A72_A5FF_537A9F4B588F__INCLUDED_)
#define AFX_WANPACKET_H__C87BC2BD_187D_4A72_A5FF_537A9F4B588F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif


//BOOLEAN LoadNdisNpp(DWORD Reason);
BOOLEAN WanPacketSetBpfFilter(PWAN_ADAPTER pWanAdapter, PUCHAR FilterCode, DWORD Length);
PWAN_ADAPTER WanPacketOpenAdapter();
BOOLEAN WanPacketCloseAdapter(PWAN_ADAPTER pWanAdapter);
BOOLEAN WanPacketSetBufferSize(PWAN_ADAPTER pWanAdapter, DWORD BufferSize);
DWORD WanPacketReceivePacket(PWAN_ADAPTER pWanAdapter, PUCHAR Buffer, DWORD BufferSize);
BOOLEAN WanPacketSetMinToCopy(PWAN_ADAPTER pWanAdapter, DWORD MinToCopy);
BOOLEAN WanPacketGetStats(PWAN_ADAPTER pWanAdapter, struct bpf_stat *s);
BOOLEAN WanPacketSetReadTimeout(PWAN_ADAPTER pWanAdapter, DWORD ReadTimeout);
BOOLEAN WanPacketSetMode(PWAN_ADAPTER pWanAdapter, DWORD Mode);
HANDLE WanPacketGetReadEvent(PWAN_ADAPTER pWanAdapter);
BOOLEAN WanPacketTestAdapter();

#ifdef __cplusplus
}
#endif


#endif // !defined(AFX_WANPACKET_H__C87BC2BD_187D_4A72_A5FF_537A9F4B588F__INCLUDED_)


