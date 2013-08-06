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
#define _WIN32_DCOM 

#include <tchar.h>
#include <winsock2.h>
#include <windows.h>
#include <crtdbg.h>
#include <eh.h>

HMODULE g_hModule = NULL;

#include <netmon.h>

#include "win_bpf.h"

#ifdef HAVE_BUGGY_TME_SUPPORT
#include "win_bpf_filter_init.h"
#endif HAVE_BUGGY_TME_SUPPORT

#include <tchar.h>
#include <packet32.h>
#include "../Packet32-Int.h"
#include "wanpacket.h"

/*!
  \brief Describes an opened wan (dialup, VPN...) network adapter using the NetMon API

  This structure is the most important for the functioning of WanPacket.dll.
  This structure should be considered opaque by users.
*/
struct WAN_ADAPTER_INT
{
	HBLOB			hCaptureBlob;		///< Handle to the BLOB (the network adapter in the NetMon world) used to capture
	CRITICAL_SECTION CriticalSection;	///< Used to synchronize access to this structure.
	PUCHAR			Buffer;				///< Pointer to the ring buffer used to capture packets.
	DWORD			C;					///< Zero-based index of the consumer in the ring buffer. It indicates the first free byte to be read.
	DWORD			P;					///< Zero-based index of the producer in the ring buffer. It indicates the first free byte to be written.
	DWORD			Free;				///< Number of the free bytes in the ring buffer.
	DWORD			Size;				///< Size of the ring buffer used to capture packets.
	DWORD			Dropped;			///< Number of packets that the current instance had to drop, from its opening. A packet is dropped if there is no more space to store it in the ring buffer.
	DWORD			Accepted;			///< Number of packets that the current capture instance has accepted, from its opening. A packet is accepted if it passes the bpf filter and fits in the ring buffer. Accepted packets are the ones that reach the application. 
	DWORD			Received;			///< Number of packets received by current instance from its opening. 
	DWORD			MinToCopy;			///< Minimum amount of data in the ring buffer that unlocks a read.
	DWORD			ReadTimeout;		///< Timeout after which a read is released, also if the amount of data in the ring buffer is less than MinToCopy.
	HANDLE			hReadEvent;			///< Pointer to the event on which the read calls on this instance must wait.
	bpf_insn		*FilterCode;		///< Pointer to the filtering pseudo-code associated with current instance of capture.
	DWORD			Mode;				///< Working mode of the driver. See PacketSetMode() for details.
	LARGE_INTEGER	Nbytes;				///< Amount of bytes accepted by the filter when this instance is in statistical mode.
	LARGE_INTEGER	Npackets;			///< Number of packets accepted by the filter when this instance is in statistical mode.
#ifdef HAVE_BUGGY_TME_SUPPORT
	MEM_TYPE		MemEx;				///< Memory used by the TME virtual co-processor
	TME_CORE		Tme;				///< Data structure containing the virtualization of the TME co-processor
#endif //HAVE_BUGGY_TME_SUPPORT
	IRTC			*pIRTC;				///< Pointer to the NetMon IRTC COM interface used to capture packets.
};

#define ALIGN_TO_WORD(x) (((x) + 3)&~(3))

BOOLEAN WanPacketAddPacketToRingBuffer(PWAN_ADAPTER pWanAdapter, LPFRAME_DESCRIPTOR lpFrameDesc, DWORD SnapToCopy, struct timeval PacketTime);
DWORD WanPacketRemovePacketsFromRingBuffer(PWAN_ADAPTER pWanAdapter, PUCHAR Buffer, DWORD BuffSize);
BOOLEAN IsWindows2000();

#if 0
/*! 
  \brief The main dll function.
*/
#ifdef WPCAP_OEM
BOOLEAN LoadNdisNpp(DWORD Reason)
#else
BOOLEAN APIENTRY DllMain( HANDLE hModule, DWORD  Reason, LPVOID lpReserved)
#endif // WPCAP_OEM
{
    switch(Reason)
    {
	case DLL_PROCESS_ATTACH:
		g_hModule = LoadLibrarySafe(_T("npp\\ndisnpp.dll"));
		break;

	case DLL_PROCESS_DETACH:
		if (g_hModule != NULL)
			FreeLibrary(g_hModule);
		break;
	}

	return TRUE;
}

#endif

/*! 
  \brief It returns the current time formatted as a timeval structure.
  \return The current time formatted as a timeval structure.
*/
struct timeval WanPacketGetCurrentTime()
{
	struct timeval tvReturn;
	FILETIME FileTime;
	GetSystemTimeAsFileTime(&FileTime);
	tvReturn.tv_sec = (LONG)(((LARGE_INTEGER*)&FileTime)->QuadPart / 10000000);
	tvReturn.tv_usec = (LONG)(((LARGE_INTEGER*)&FileTime)->QuadPart % 10000000 / 10);

	return tvReturn;
}

/*! 
  \brief This is the callback used by the NetMon IRTC interface to pass the packets to the user.
  \param Event. An UPDATE_EVENT structure containing the packets.
  \return Not clearly defined by the NetMon IRTC MSDN documentation.
*/
DWORD WINAPI WanPacketReceiverCallback(UPDATE_EVENT Event)
{
    DWORD i;
    LPFRAMETABLE lpFrameTable;
	LPFRAME_DESCRIPTOR lpFrameDesc;
	PWAN_ADAPTER pWanAdapter;
	u_int FilterResult;
	struct time_conv TimeConv;
	struct timeval PacketTime;

	pWanAdapter = (PWAN_ADAPTER)Event.lpUserContext;
	lpFrameTable = Event.lpFrameTable;

	// the frame table can wrap the indices
    for (i = lpFrameTable->StartIndex; i != lpFrameTable->EndIndex; (i == lpFrameTable->FrameTableLength) ? i=0: i ++ )
	{
	    lpFrameDesc = &lpFrameTable->Frames[i];

		PacketTime.tv_sec = (ULONG) (lpFrameDesc->TimeStamp / (__int64)1000000 - 11644473600);
		PacketTime.tv_usec= (ULONG) (lpFrameDesc->TimeStamp % (__int64)1000000);

		FORCE_TIME(&PacketTime, &TimeConv);

		EnterCriticalSection( &pWanAdapter->CriticalSection );
		pWanAdapter->Received ++;

#ifdef HAVE_BUGGY_TME_SUPPORT
		FilterResult = bpf_filter(pWanAdapter->FilterCode, 
			lpFrameDesc->FramePointer, 
			lpFrameDesc->FrameLength, 
			lpFrameDesc->nBytesAvail,
			&pWanAdapter->MemEx,
			&pWanAdapter->Tme,
			&TimeConv);
#else 
		FilterResult = bpf_filter(pWanAdapter->FilterCode, 
			lpFrameDesc->FramePointer, 
			lpFrameDesc->FrameLength, 
			lpFrameDesc->nBytesAvail);
#endif //HAVE_BUGGY_TME_SUPPORT

		if ( pWanAdapter->Mode == PACKET_MODE_MON && FilterResult == 1 )
			SetEvent( pWanAdapter->hReadEvent );

		if (FilterResult == (u_int) -1 || FilterResult > lpFrameDesc->nBytesAvail )
			FilterResult = lpFrameDesc->nBytesAvail;
		
		if ( pWanAdapter->Mode == PACKET_MODE_STAT )
		{
			pWanAdapter->Npackets.QuadPart ++;
			if ( lpFrameDesc->FrameLength < 60 )
				pWanAdapter->Nbytes.QuadPart += 60;
			else
				pWanAdapter->Nbytes.QuadPart += lpFrameDesc->FrameLength;
			// add preamble+SFD+FCS to the packet
			// these values must be considered because are not part of the packet received from NDIS
			pWanAdapter->Nbytes.QuadPart += 12;
		}

			if ( pWanAdapter->Mode == PACKET_MODE_CAPT && FilterResult > 0 )
		{
			if ( WanPacketAddPacketToRingBuffer(pWanAdapter, lpFrameDesc,  FilterResult, PacketTime ) )
				pWanAdapter->Accepted++;
			else	
				pWanAdapter->Dropped++;
		}

		LeaveCriticalSection( &pWanAdapter->CriticalSection );
	}
	
	return NOERROR;
}

/*! 
  \brief Tries to open the wan (dialup, vpn...) adapter, and immediately closes it.
  \return TRUE on success.
*/
BOOLEAN WanPacketTestAdapter()
{
	PBLOB_TABLE pBlobTable = NULL;
	HBLOB hFilterBlob = NULL;
	BOOLEAN retVal;
	DWORD i;
	HRESULT hResult;

	if ( g_hModule == NULL)
	{
		g_hModule = LoadLibrarySafe(_T("npp\\ndisnpp.dll"));
	}

	if ( g_hModule == NULL)
	{
		return FALSE;
	}

	hResult = CoInitialize(NULL);

	//
 	// if  the calling thread has already initialized COM with a 
 	// different threading model, we have this error
 	// however, we are able to support another threading model,
 	// so we try to initialize COM with another threading model.
 	// This new call should succeed with S_FALSE.
 	//
 	if (hResult == RPC_E_CHANGED_MODE)
	{
		hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	
		//MULTITHREADED threading is only supported on Windows 2000
		if (hResult == RPC_E_CHANGED_MODE && IsWindows2000())
		{
			hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		}
	}

	if (hResult != S_OK && hResult != S_FALSE)
		return FALSE;

	if ( CreateBlob(&hFilterBlob) != NMERR_SUCCESS )
	{
		CoUninitialize();
		return FALSE;
	}
	
	if ( SetBoolInBlob(hFilterBlob, OWNER_NPP, CATEGORY_CONFIG, TAG_INTERFACE_REALTIME_CAPTURE, TRUE) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		CoUninitialize();
		return FALSE;
	}

	if ( SetBoolInBlob(hFilterBlob, OWNER_NPP, CATEGORY_LOCATION, TAG_RAS, TRUE) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		CoUninitialize();
		return FALSE;
	}

	if ( GetNPPBlobTable(hFilterBlob, &pBlobTable) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		CoUninitialize();
		return FALSE;
	}

	DestroyBlob (hFilterBlob);

	if (pBlobTable->dwNumBlobs == 1)
		retVal = TRUE;
	else
		retVal = FALSE;

	for ( i = 0 ; i < pBlobTable->dwNumBlobs ; i++ )
		DestroyBlob(pBlobTable->hBlobs[i]);
		
	GlobalFree(pBlobTable);	
	CoUninitialize();
			
	return retVal;
}

/*!
	\brief Returns true if the system is running windows 2000
	\return TRUE if the system is running windows 2000. FALSE otherwise.
*/
BOOLEAN IsWindows2000()
{
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	// Try calling GetVersionEx using the OSVERSIONINFOEX structure.
	// If that fails, try using the OSVERSIONINFO structure.

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi);
	if( !bOsVersionInfoEx )
	{
		osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
		if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) 
			return FALSE;
	}

	if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT && osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
		//windows 2000
		return TRUE;
	return FALSE;

}

/*! 
  \brief Opens the wan (dialup, vpn...) adapter.
  \return If the function succeeds, the return value is the pointer to a properly initialized WAN_ADAPTER structure,
   otherwise the return value is NULL.
*/
PWAN_ADAPTER WanPacketOpenAdapter()
{
	PWAN_ADAPTER pWanAdapter = NULL;
	PBLOB_TABLE pBlobTable = NULL;
	HBLOB hFilterBlob = NULL;
	HRESULT hResult;
	DWORD i;

	if ( g_hModule == NULL)
	{
		g_hModule = LoadLibrarySafe(_T("npp\\ndisnpp.dll"));
	}

	if ( g_hModule == NULL)
	{
		return NULL;
	}

	hResult = CoInitialize(NULL);

	//
 	// if  the calling thread has already initialized COM with a 
 	// different threading model, we have this error
 	// however, we are able to support another threading model,
 	// so we try to initialize COM with another threading model.
 	// This new call should succeed with S_FALSE.
 	//
 	if (hResult == RPC_E_CHANGED_MODE)
	{
		hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	
		//MULTITHREADED threading is only supported on Windows 2000
		if (hResult == RPC_E_CHANGED_MODE && IsWindows2000())
		{
			hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		}
	}

	if (hResult != S_OK && hResult != S_FALSE)
		return NULL;

	pWanAdapter = (PWAN_ADAPTER)GlobalAlloc(GPTR, sizeof (WAN_ADAPTER));

	if ( pWanAdapter == NULL )
		goto error;
	
	memset(pWanAdapter, 0, sizeof(WAN_ADAPTER));
	
	if ( CreateBlob(&hFilterBlob) != NMERR_SUCCESS )
	{
		goto error;
	}
	
	if ( SetBoolInBlob(hFilterBlob, OWNER_NPP, CATEGORY_CONFIG, TAG_INTERFACE_REALTIME_CAPTURE, TRUE) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		goto error;
	}

	if ( SetBoolInBlob(hFilterBlob, OWNER_NPP, CATEGORY_LOCATION, TAG_RAS, TRUE) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		goto error;
	}

	if ( GetNPPBlobTable(hFilterBlob, &pBlobTable) != NMERR_SUCCESS )
	{
		DestroyBlob( hFilterBlob);
		goto error;
	}

	DestroyBlob (hFilterBlob);

	if ( pBlobTable->dwNumBlobs == 0 || pBlobTable->dwNumBlobs > 1)
	{
		///fixme.....
		for ( i = 0 ; i < pBlobTable->dwNumBlobs ; i++ )
			DestroyBlob(pBlobTable->hBlobs[i]);
		
		GlobalFree(pBlobTable);
		goto error;
	}

	pWanAdapter->hCaptureBlob = pBlobTable->hBlobs[0];

	GlobalFree(pBlobTable);

	InitializeCriticalSection(&pWanAdapter->CriticalSection);

	pWanAdapter->hReadEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if ( pWanAdapter->hReadEvent == NULL )
		goto error;

#ifdef HAVE_BUGGY_TME_SUPPORT
	pWanAdapter->MemEx.buffer = (PUCHAR)GlobalAlloc(GPTR, DEFAULT_MEM_EX_SIZE);
	if (pWanAdapter->MemEx.buffer == NULL)
		goto error;
	
	pWanAdapter->MemEx.size = DEFAULT_MEM_EX_SIZE;
	pWanAdapter->Tme.active = TME_NONE_ACTIVE;
#endif //HAVE_BUGGY_TME_SUPPORT

	if (CreateNPPInterface(pWanAdapter->hCaptureBlob, IID_IRTC, (void**) &pWanAdapter->pIRTC) == NMERR_SUCCESS && pWanAdapter->pIRTC != NULL) 
	{
		//create OK
		if (pWanAdapter->pIRTC->Connect(pWanAdapter->hCaptureBlob, NULL, WanPacketReceiverCallback, (LPVOID)pWanAdapter , NULL) == NMERR_SUCCESS)
		{
			//connect OK
			if (pWanAdapter->pIRTC->Start() == NMERR_SUCCESS)
			{
				return pWanAdapter;
			}
			else
			{
				pWanAdapter->pIRTC->Disconnect();
				pWanAdapter->pIRTC->Release();
				goto error;
			}
		}
		else
		{
			pWanAdapter->pIRTC->Release();
			goto error;
		}
	}
	else
	{
		goto error;
	}

	//awfully never reached
//	return NULL;

error:

	if (pWanAdapter != NULL)
	{
		if (pWanAdapter->hReadEvent != NULL)
			CloseHandle(pWanAdapter->hReadEvent);

		DeleteCriticalSection(&pWanAdapter->CriticalSection);
		if (pWanAdapter->hCaptureBlob)
			DestroyBlob(pWanAdapter->hCaptureBlob);

		GlobalFree(pWanAdapter);
	}

	CoUninitialize();
	
	return NULL;
}

/*! 
  \brief Closes a wan (dialup, vpn...) adapter.
  \param lpWanAdapter the pointer to the wan adapter to close. 

  WanPacketCloseAdapter closes the given adapter and frees the associated WAN_ADAPTER structure
*/
BOOLEAN WanPacketCloseAdapter(PWAN_ADAPTER pWanAdapter)
{
	if (pWanAdapter->pIRTC->Stop() != NMERR_SUCCESS)
		OutputDebugStringA("WanPacketCloseAdapter: Severe error, IRTC::Stop failed\n");
	if (pWanAdapter->pIRTC->Disconnect() != NMERR_SUCCESS)
		OutputDebugStringA("WanPacketCloseAdapter: Severe error, IRTC::Disconnect failed\n");
	if (pWanAdapter->pIRTC->Release() != NMERR_SUCCESS)
		OutputDebugStringA("WanPacketCloseAdapter: Severe error, IRTC::Release failed\n");
	Sleep(0); //Just a stupid hack to make all the stuff work. I don't why it's necessary.


	//setting a NULL filter will actually deallocate the in-use filter
	WanPacketSetBpfFilter(pWanAdapter, NULL, 0);
	//setting a zero-sized buffer will deallocate any in-use ring buffer
	WanPacketSetBufferSize(pWanAdapter, 0);

	CloseHandle(pWanAdapter->hReadEvent);

	//destroy the BLOB used to capture
	DestroyBlob(pWanAdapter->hCaptureBlob);

	DeleteCriticalSection(&pWanAdapter->CriticalSection);

#ifdef HAVE_BUGGY_TME_SUPPORT
	//deallocate the extended memory, if any.
	if (pWanAdapter->MemEx.size > 0)
		GlobalFree(pWanAdapter->MemEx.buffer);
#endif //HAVE_BUGGY_TME_SUPPORT

	GlobalFree(pWanAdapter);
	//uninitialize COM
	CoUninitialize();

	return TRUE;
}

/*!
  \brief Sets the working mode of a wan (dialup, vpn...) adapter.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param mode The new working mode of the adapter.
  \return If the function succeeds, the return value is true.

  For more information, see the documentation of PacketSetMode
*/


BOOLEAN WanPacketSetMode(PWAN_ADAPTER pWanAdapter, DWORD Mode)
{
	if (Mode != PACKET_MODE_CAPT && Mode != PACKET_MODE_STAT && Mode != PACKET_MODE_MON)
		return FALSE;
	pWanAdapter->Mode = Mode;
	return TRUE;
}

/*!
  \brief Sets the bpf packet filter.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param FilterCode Pointer to the BPF filtering code that will be associated with this capture or monitoring 
  instance and that will be executed on every incoming packet.
  \param Length Length, in bytes, of the BPF filter code.
  \return This function returns TRUE if the filter is set successfully, FALSE if an error occurs 
   or if the filter program is not accepted after a safeness check.  This API
   performs the check in order to avoid unexpected behavior due to buggy or malicious filters, and it rejects non
   conformant filters.

  For more information, see the documentation of PacketSetBpf
*/
BOOLEAN WanPacketSetBpfFilter(PWAN_ADAPTER pWanAdapter, PUCHAR FilterCode, DWORD Length)
{
	PUCHAR	NewFilterCode = NULL;
	DWORD NumberOfInstructions;	
	DWORD Counter;
	struct bpf_insn *InitializationCode;
	struct time_conv TimeConv;
	if ( Length < 0)
		return FALSE;

	EnterCriticalSection(&pWanAdapter->CriticalSection);
	if (Length > 0)
	{
		NumberOfInstructions = Length/sizeof(struct bpf_insn);
		for(Counter = 0; 
			Counter < NumberOfInstructions && ((struct bpf_insn*)FilterCode)[Counter].code != BPF_SEPARATION ;
			Counter++);

		if ( Counter != NumberOfInstructions &&
			NumberOfInstructions != Counter + 1 &&
			((struct bpf_insn*)FilterCode)[Counter].code == BPF_SEPARATION )
		{
			//we need to initialize the TME
			InitializationCode = &((struct bpf_insn*)FilterCode)[Counter+1];
			
			//FIXME, just an hack, this structure is never used here.		
			TimeConv.start[0].tv_sec = 0;
			TimeConv.start[0].tv_usec = 0;
			
#ifdef HAVE_BUGGY_TME_SUPPORT
			if ( bpf_filter_init(InitializationCode,
				&pWanAdapter->MemEx,
				&pWanAdapter->Tme,
				&TimeConv) != INIT_OK )
			{
				LeaveCriticalSection(&pWanAdapter->CriticalSection);
				return FALSE;
			}
#endif //HAVE_BUGGY_TME_SUPPORT
		}

		NumberOfInstructions = Counter;

#ifdef HAVE_BUGGY_TME_SUPPORT
		if ( bpf_validate((struct bpf_insn*)FilterCode, Counter, pWanAdapter->MemEx.size) == 0)
#else
		if ( bpf_validate((struct bpf_insn*)FilterCode, Counter) == 0)
#endif //HAVE_BUGGY_TME_SUPPORT
		{
			//filter not validated
			//FIXME: the machine has been initialized(?), but the operative code is wrong. 
			//we have to reset the machine!
			//something like: reallocate the mem_ex, and reset the tme_core
			LeaveCriticalSection(&pWanAdapter->CriticalSection);
			return FALSE;
		}


		NewFilterCode = (PUCHAR)GlobalAlloc( GMEM_FIXED, Counter * sizeof(struct bpf_insn) );
		if (NewFilterCode == NULL)
		{
			LeaveCriticalSection(&pWanAdapter->CriticalSection);
			return FALSE;
		}
	
		RtlCopyMemory(NewFilterCode, FilterCode, Counter * sizeof(struct bpf_insn));
	}

	if ( pWanAdapter->FilterCode != NULL )
		GlobalFree(pWanAdapter->FilterCode);

	pWanAdapter->FilterCode = (struct bpf_insn*)NewFilterCode;
	//we reset all the ring buffer related counters.
	pWanAdapter->C = 0;
	pWanAdapter->P = 0;
	pWanAdapter->Free = pWanAdapter->Size;
	pWanAdapter->Accepted = 0;
	pWanAdapter->Dropped = 0;
	pWanAdapter->Received = 0;
	pWanAdapter->Nbytes.QuadPart = 0;
	pWanAdapter->Npackets.QuadPart = 0;

	LeaveCriticalSection(&pWanAdapter->CriticalSection);

	return TRUE;
}

/*!
  \brief Sets the size of the ring buffer associated with this instance.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param BufferSize New size of the buffer, in \b kilobytes.
  \return The function returns TRUE if successfully completed, FALSE if there is not enough memory to 
   allocate the new buffer.

  For more information, see the documentation of PacketSetBuff

*/
BOOLEAN WanPacketSetBufferSize(PWAN_ADAPTER pWanAdapter, DWORD BufferSize)
{
	PUCHAR	NewBuffer = NULL;
	
	if ( BufferSize < 0 || ( BufferSize > 0 && BufferSize < sizeof (struct bpf_hdr) ) )
		return FALSE;

	if ( BufferSize > 0 )
	{
		NewBuffer = (PUCHAR)GlobalAlloc( GMEM_FIXED, BufferSize );
		if (NewBuffer == NULL)
			return FALSE;
	}

	EnterCriticalSection(&pWanAdapter->CriticalSection);

	if ( pWanAdapter->Buffer != NULL )
		GlobalFree(pWanAdapter->Buffer);
    
	pWanAdapter->Buffer = NewBuffer;
	pWanAdapter->Size = BufferSize;
	pWanAdapter->C = 0;
	pWanAdapter->P = 0;
	pWanAdapter->Free = BufferSize;

	LeaveCriticalSection(&pWanAdapter->CriticalSection);

	return TRUE;
}

/*! 
  \brief Read data (packets or statistics) from this wan (dialup, vpn...) instance.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param Buffer Buffer that will receive the data.
  \param BufferSize Size of receiving buffer.
  \return It returns the number of written bytes in the buffer.

	For more information, see the documentation of PacketReceivePacket
  */
DWORD WanPacketReceivePacket(PWAN_ADAPTER pWanAdapter, PUCHAR Buffer, DWORD BufferSize)
{
	DWORD ReadBytes = 0;
	//first of all, we wait for either the ReadTimeout to expire, or enough data
	//in the buffer (i.e. hReadEvent gets set).
	WaitForSingleObject(pWanAdapter->hReadEvent, pWanAdapter->ReadTimeout);

	//we have to prevent other entities from modifying the pWanAdapter structure
	EnterCriticalSection(&pWanAdapter->CriticalSection);

	if ( pWanAdapter->Mode == PACKET_MODE_CAPT )
	{	//capture mode, we have an ad-hoc fcn
		ReadBytes = WanPacketRemovePacketsFromRingBuffer(pWanAdapter, Buffer, BufferSize);
	}
	
	if ( pWanAdapter->Mode == PACKET_MODE_STAT )
	{
		if ( BufferSize < sizeof(LONGLONG) * 2 + sizeof(struct bpf_hdr))
			ReadBytes = 0;	//not enough space in the dest buffer
		else
		{
			//insert tthe bpf header
			((struct bpf_hdr*)Buffer)->bh_caplen = 2*sizeof(LONGLONG);
			((struct bpf_hdr*)Buffer)->bh_datalen = 2*sizeof(LONGLONG);
			((struct bpf_hdr*)Buffer)->bh_hdrlen = sizeof(struct bpf_hdr);
			((struct bpf_hdr*)Buffer)->bh_tstamp = WanPacketGetCurrentTime();
			//copy the counters
			((LONGLONG*)(Buffer + sizeof(struct bpf_hdr)))[0] = pWanAdapter->Npackets.QuadPart;
			((LONGLONG*)(Buffer + sizeof(struct bpf_hdr)))[1] = pWanAdapter->Nbytes.QuadPart;
			ReadBytes = sizeof(struct bpf_hdr) + 2 + sizeof(LONGLONG);
			//reset the counters 
			pWanAdapter->Nbytes.QuadPart = 0;
			pWanAdapter->Npackets.QuadPart = 0;
		}
	}


#ifdef HAVE_BUGGY_TME_SUPPORT
	if ( pWanAdapter->Mode == PACKET_MODE_MON )
	{
		PTME_DATA pTmeData;
		DWORD ByteCopy;
		struct bpf_hdr *pHeader;
		
		if (
			!IS_VALIDATED(pWanAdapter->Tme.validated_blocks, pWanAdapter->Tme.active_read)
			|| BufferSize < sizeof(struct bpf_hdr) 
			)
		{	//the TME is either not active, or no tme block has been set to be used for passing data to the user
			ReadBytes = 0;
		}
		else
		{
			//insert the bpf header
			pHeader = (struct bpf_hdr*)Buffer;
			pHeader->bh_tstamp = WanPacketGetCurrentTime();
			pHeader->bh_hdrlen = sizeof(struct bpf_hdr);
			
			pTmeData = &pWanAdapter->Tme.block_data[pWanAdapter->Tme.active_read];

			if ( pTmeData->last_read.tv_sec != 0 )
				pTmeData->last_read = pHeader->bh_tstamp;
			
			//check the amount of data that must be copied
			ByteCopy = pTmeData->block_size * pTmeData->filled_blocks;
			
			if ( BufferSize - sizeof(struct bpf_hdr) < ByteCopy )
				ByteCopy = BufferSize - sizeof(struct bpf_hdr); //we copy only the data that fit in the buffer
			else 
				ByteCopy = pTmeData->filled_blocks * pTmeData->block_size; //we copy all the data

			//actual copy of data
			RtlCopyMemory(Buffer + sizeof(struct bpf_hdr), pTmeData->shared_memory_base_address, ByteCopy);
						
			//fix the bpf header
			pHeader->bh_caplen = ByteCopy;
			pHeader->bh_datalen = pHeader->bh_caplen;

			ReadBytes = ByteCopy + sizeof(struct bpf_hdr);
		}
	}
#endif //HAVE_BUGGY_TME_SUPPORT

	//done with the pWanAdapter data
	LeaveCriticalSection(&pWanAdapter->CriticalSection);

	return ReadBytes;
}

/*! 
  \brief Defines the minimum amount of data that will be received in a read.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure
  \param MinToCopy The minimum amount of data in the ring buffer that will cause the instance to release a read on this adapter.
  \return If the function succeeds, the return value is TRUE.

  For more information, see the documentation of PacketSetMinToCopy
*/
BOOLEAN WanPacketSetMinToCopy(PWAN_ADAPTER pWanAdapter, DWORD MinToCopy)
{
	EnterCriticalSection( &pWanAdapter->CriticalSection );

	pWanAdapter->MinToCopy = MinToCopy;

	LeaveCriticalSection( &pWanAdapter->CriticalSection );

	return TRUE;
}

/*!
  \brief Returns statistic values about the current capture session.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param s Pointer to a user provided bpf_stat structure that will be filled by the function.
  \return If the function succeeds, the return value is TRUE.

  For more information, see the documentation of PacketGetStats and PacketGetStatsEx
*/
BOOLEAN WanPacketGetStats(PWAN_ADAPTER pWanAdapter, struct bpf_stat *s)
{
	EnterCriticalSection (&pWanAdapter->CriticalSection);

	s->bs_drop = pWanAdapter->Dropped;
	s->bs_recv = pWanAdapter->Received;
	s->bs_capt = pWanAdapter->Accepted;
	s->ps_ifdrop = 0;

	LeaveCriticalSection (&pWanAdapter->CriticalSection);

	return TRUE;
}

/*!
  \brief Sets the timeout after which a read on an wan adapter returns.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \param ReadTimeout indicates the timeout, in milliseconds, after which a call to WanPacketReceivePacket() on 
  the adapter pointed by pWanAdapter will be released, even if no packets have been captured by NetMon IRTC. 
  Setting timeout to 0 means no timeout, i.e. PacketReceivePacket() never returns if no packet arrives.  
  A timeout of -1 causes PacketReceivePacket() to always return immediately.
  \return If the function succeeds, the return value is TRUE.

  \note This function works also if the adapter is working in statistics mode, and can be used to set the 
  time interval between two statistic reports.
*/
BOOLEAN WanPacketSetReadTimeout(PWAN_ADAPTER pWanAdapter, DWORD ReadTimeout)
{

	if (ReadTimeout == 0)
		ReadTimeout = INFINITE;
	else
		if (ReadTimeout == -1)
			ReadTimeout = 0;

	EnterCriticalSection( &pWanAdapter->CriticalSection );

	pWanAdapter->ReadTimeout = ReadTimeout;
	
	LeaveCriticalSection( &pWanAdapter->CriticalSection );

	return TRUE;
}


/*!
  \brief Returns the notification event associated with the read calls on the wan adapter.
  \param pWanAdapter Pointer to a WAN_ADAPTER structure.
  \return The handle of the event that the the IRTC receive callback signals when some data is available in the ring buffer.

  For more information, see the documentation of PacketGetReadEvent
*/
HANDLE WanPacketGetReadEvent(PWAN_ADAPTER pWanAdapter)
{
	return pWanAdapter->hReadEvent;
}

/*! 
  \brief Moves the packets from the ring buffer to a given buffer.
  \param pWanAdapter Pointer to WAN_ADAPTER structure associated with this instance.
  \param Buffer Pointer to the destination, user allocated, buffer.
  \param BuffSize Size of the buffer.
  \return It returns the number of bytes correctly written to the destination buffer
*/
DWORD WanPacketRemovePacketsFromRingBuffer(PWAN_ADAPTER pWanAdapter, PUCHAR Buffer, DWORD BuffSize)
{
	DWORD Copied;
	struct bpf_hdr *Header;
	Copied = 0;
	DWORD ToCopy;
	DWORD Increment;

	ResetEvent(pWanAdapter->hReadEvent);
	
	while (BuffSize > Copied)
	{
		if ( pWanAdapter->Free < pWanAdapter->Size )  
		{  //there are some packets in the selected (aka LocalData) buffer
			Header = (struct bpf_hdr*)(pWanAdapter->Buffer + pWanAdapter->C);

			if (Header->bh_caplen + sizeof (struct bpf_hdr) > BuffSize - Copied)  
			{  //if the packet does not fit into the user buffer, we've ended copying packets
				return Copied;
			}
				
			*((struct bpf_hdr*)(Buffer + Copied)) = *Header;
			
			Copied += sizeof(struct bpf_hdr);
			pWanAdapter->C += sizeof(struct bpf_hdr);

			if ( pWanAdapter->C == pWanAdapter->Size )
				pWanAdapter->C = 0;

			if ( pWanAdapter->Size - pWanAdapter->C < (DWORD)Header->bh_caplen )
			{
				//the packet is fragmented in the buffer (i.e. it skips the buffer boundary)
				ToCopy = pWanAdapter->Size - pWanAdapter->C;
				CopyMemory(Buffer + Copied,pWanAdapter->Buffer + pWanAdapter->C, ToCopy);
				CopyMemory(Buffer + Copied + ToCopy, pWanAdapter->Buffer + 0, Header->bh_caplen - ToCopy);
				pWanAdapter->C = Header->bh_caplen - ToCopy;
			}
			else
			{
				//the packet is not fragmented
				CopyMemory(Buffer + Copied ,pWanAdapter->Buffer + pWanAdapter->C ,Header->bh_caplen);
				pWanAdapter->C += Header->bh_caplen;
		//		if (c==size)  inutile, contemplato nell "header atomico"
		//			c=0;
			}

			Copied += ALIGN_TO_WORD(Header->bh_caplen);

			Increment = Header->bh_caplen + sizeof(struct bpf_hdr);
			if ( pWanAdapter->Size - pWanAdapter->C < sizeof(struct bpf_hdr) )
			{   //the next packet would be saved at the end of the buffer, but the NewHeader struct would be fragmented
				//so the producer (--> the consumer) skips to the beginning of the buffer
				Increment += pWanAdapter->Size - pWanAdapter->C;
				pWanAdapter->C = 0;
			}
			pWanAdapter->Free += Increment;
		}
		else
			return Copied;
	}
	return Copied;
}

/*! 
  \brief Adds a packet to the ring buffer.
  \param pWanAdapter Pointer to WAN_ADAPTER structure associated with this instance.
  \param lpFrameDesc Pointer to a packet as received by the IRTC receiver callback.
  \param SnapToCopy Number of bytes to be copied from the packet to the ring buffer.
  \param PacketTime Timestamp of the packet.
  \return It returns TRUE if the copy was successful, FALSE if the packet did not fit in the ring buffer.
*/
BOOLEAN WanPacketAddPacketToRingBuffer(PWAN_ADAPTER pWanAdapter, LPFRAME_DESCRIPTOR lpFrameDesc, DWORD SnapToCopy, struct timeval PacketTime)
{
	struct bpf_hdr *Header;
	DWORD ToCopy;
	DWORD increment;
	
	if (SnapToCopy + sizeof(struct bpf_hdr) > pWanAdapter->Free)
		return FALSE;

	Header = (struct bpf_hdr*)(pWanAdapter->Buffer + pWanAdapter->P);

	// We need to change reference from January, 1st 1601 to January, 1st 1970 = 11644473600 seconds if I'm right!!
	Header->bh_tstamp = PacketTime;

 	if (SnapToCopy > lpFrameDesc->FrameLength)
 		SnapToCopy = lpFrameDesc->FrameLength;

	Header->bh_caplen = SnapToCopy;
	Header->bh_datalen = lpFrameDesc->FrameLength;
	Header->bh_hdrlen = sizeof(struct bpf_hdr);

	pWanAdapter->P += sizeof(struct bpf_hdr);
	if ( pWanAdapter->P == pWanAdapter->Size )
		pWanAdapter->P = 0;

	if ( pWanAdapter->Size - pWanAdapter->P < SnapToCopy )
	{
		//the packet will be fragmented in the buffer (aka, it will skip the buffer boundary)
		//two copies!!
		ToCopy = pWanAdapter->Size - pWanAdapter->P;
		CopyMemory(pWanAdapter->Buffer + pWanAdapter->P, lpFrameDesc->FramePointer, ToCopy);
		CopyMemory(pWanAdapter->Buffer + 0 , (PUCHAR)lpFrameDesc->FramePointer + ToCopy, SnapToCopy - ToCopy);
		pWanAdapter->P = SnapToCopy - ToCopy;
	}
	else
	{
		//the packet does not need to be fragmented in the buffer (aka, it doesn't skip the buffer boundary)
		// ;-)))))) only ONE copy
		CopyMemory(pWanAdapter->Buffer + pWanAdapter->P, lpFrameDesc->FramePointer, SnapToCopy);
		pWanAdapter->P += SnapToCopy;
	}
	increment = SnapToCopy + sizeof(struct bpf_hdr);
	if ( pWanAdapter->Size - pWanAdapter->P < sizeof(struct bpf_hdr) )  //we check that the available, AND contiguous, space in the buffer will fit
	{																	//the bpf_hdr structure, at least, otherwise we skip the producer
		increment += pWanAdapter->Size - pWanAdapter->P;				//at the beginning of the buffer (p = 0), and decrement the free bytes appropriately
		pWanAdapter->P = 0;
	}

	pWanAdapter->Free -= increment;

	if( pWanAdapter-> Size - pWanAdapter->Free >= pWanAdapter->MinToCopy )
	{
		SetEvent(pWanAdapter->hReadEvent);	
	}

	return TRUE;
}
