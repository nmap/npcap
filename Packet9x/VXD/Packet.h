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



struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};

// OID definitions
#define OID_GEN_CURRENT_LOOKAHEAD		   		0x0001010F
// IOCTLs
#define	 BIOCSETBUFFERSIZE 9592
#define	 BIOCSETF 9030
#define  BIOCGSTATS 9031
#define	 BIOCSRTIMEOUT 7416
#define	 BIOCSMODE 7412
#define	 BIOCSWRITEREP 7413
#define	 BIOATTACHPROCESS 7117
#define	 BIODETACHPROCESS 7118
#define  BIOCEVNAME 7415
#define	 BIOCSETOID 2147483648
#define	 BIOCQUERYOID 2147483652

#define  BIOCSTIMEZONE 7471

// working modes
#define MODE_CAPT 0
#define MODE_STAT 1

//
// Alignment macros.  Packet_WORDALIGN rounds up to the next 
// even multiple of Packet_ALIGNMENT. 
//
#define Packet_ALIGNMENT sizeof(int)
#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))

// from BPF
struct bpf_program {
	UINT bf_len;
	struct bpf_insn *bf_insns;
};

// from BPF
struct bpf_insn {
	USHORT	code;
	UCHAR 	jt;
	UCHAR 	jf;
	int k;
};

// from BPF
struct bpf_hdr {
	struct timeval		bh_tstamp;	/* time stamp */
	UINT				bh_caplen;	/* length of captured portion */
	UINT				bh_datalen;	/* original length of packet */
	USHORT				bh_hdrlen;	/* length of bpf header (this struct plus alignment padding) */
};

#define MAX_BUFFER_SPACE MAX_PACKET_LENGTH+sizeof(struct bpf_hdr)



#define  MAX_REQUESTS   4
#ifdef DEBUG
#define	PACKETASSERT(a)		if( !(a) ) { DbgPrint( "Packet: ASSERTION FAILED!\r\n" ); DbgBreakPoint(); }
#else
#define PACKETASSERT(a)
#endif
struct _PACKET_RESERVED 
{
	LIST_ENTRY	ListElement;
	char*		lpBuffer;
	DWORD		cbBuffer;
	DWORD*		lpcbBytesReturned;
	OVERLAPPED*	lpoOverlapped;
};
typedef struct _PACKET_RESERVED PACKET_RESERVED, *PPACKET_RESERVED;

struct _INTERNAL_REQUEST 
{
	PACKET_RESERVED Reserved;
   NDIS_REQUEST	 Request;
}; 
typedef struct _INTERNAL_REQUEST INTERNAL_REQUEST, *PINTERNAL_REQUEST;


struct _OPEN_ADAPTER 
{
	LIST_ENTRY			ListElement;
	NDIS_STATUS			Status;
	NDIS_HANDLE			AdapterHandle;
	NDIS_HANDLE			BindAdapterContext;
}; 

typedef struct _OPEN_ADAPTER OPEN_ADAPTER, *POPEN_ADAPTER;


typedef struct _OPEN_INSTANCE
{
	LIST_ENTRY			ListElement;
	NDIS_STATUS			Status;
	NDIS_HANDLE			AdapterHandle;
	NDIS_HANDLE			BindAdapterContext;

	NDIS_HANDLE			BufferPool;
	NDIS_SPIN_LOCK		RcvQSpinLock;
	LIST_ENTRY			RcvList;
	NDIS_SPIN_LOCK	    RequestSpinLock;
	LIST_ENTRY			RequestList;
	NDIS_SPIN_LOCK		ResetSpinLock;
	LIST_ENTRY			ResetIrpList;
	INTERNAL_REQUEST	Requests[MAX_REQUESTS];
	DWORD				hDevice;
	DWORD				tagProcess;

	NDIS_HANDLE			PacketPool;
	PUCHAR				Buffer;
    NDIS_SPIN_LOCK      BufferLock;
	UINT				Dropped;			
	UINT				Received;
	PUCHAR				bpfprogram; 
	UINT				bpfprogramlen;
	__int64				StartTime;  
	UINT				Bhead;
	UINT				Btail;
	UINT				BufSize;
	UINT				BLastByte;
	UINT				TimeOut;
	UINT				ReadTimeoutTimer;
	int					mode;
	__int64				Nbytes;
	__int64				Npackets;
	NDIS_SPIN_LOCK		CountersLock;
	UINT				Nwrites;
	UINT				Multiple_Write_Counter;
	DWORD				ReadEvent;

} OPEN_INSTANCE, *POPEN_INSTANCE;

typedef struct ADAPTER_NAME
{
LIST_ENTRY			ListElement;
char				realname[32];
char				devicename[32];
NDIS_STRING			realnamestr;
}ADAPTER_NAME, *PADAPTER_NAME;

struct _DEVICE_EXTENSION 
{
	PDRIVER_OBJECT		DriverObject;
	NDIS_HANDLE			NdisProtocolHandle;
	LIST_ENTRY			OpenList;
	NDIS_SPIN_LOCK		OpenSpinLock;
	LIST_ENTRY			AdapterNames;
}; 

typedef struct _DEVICE_EXTENSION DEVICE_EXTENSION, *PDEVICE_EXTENSION;
extern PDEVICE_EXTENSION GlobalDeviceExtension;
#define  ETHERNET_HEADER_LENGTH   14
#define RESERVED(_p) ((PPACKET_RESERVED)((_p)->ProtocolReserved))
#define  TRANSMIT_PACKETS    32
extern void YieldExecution( void );


DWORD Bind_Names(void);

VOID _cdecl ReadTimeout(void);

__int64 QuerySystemTime(void);

LARGE_INTEGER GetDate(void);

void EchoStr(void);


int bpf_validate(struct bpf_insn *f,int len);
UINT bpf_filter(register struct bpf_insn *pc,
				register UCHAR *p,
				UINT wirelen,
				register UINT buflen);

UINT bpf_filter_with_2_buffers(register struct bpf_insn *pc,
							   register UCHAR *p,
							   register UCHAR *pd,
							   register int headersize,
							   UINT wirelen,
							   register UINT buflen);

PLIST_ENTRY
PacketRemoveHeadList(
    IN PLIST_ENTRY pListHead
    );
VOID NDIS_API

PacketOpenAdapterComplete(
    IN NDIS_HANDLE  ProtocolBindingContext,
    IN NDIS_STATUS  Status,
    IN NDIS_STATUS  OpenErrorStatus
    );
VOID NDIS_API
PacketUnbindAdapterComplete(
    IN NDIS_HANDLE  ProtocolBindingContext,
    IN NDIS_STATUS  Status
    );
NDIS_STATUS NDIS_API
Packet_tap(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_HANDLE MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
    );
VOID NDIS_API
PacketReceiveComplete(
    IN NDIS_HANDLE  ProtocolBindingContext
    );
DWORD
PacketRequest( POPEN_INSTANCE		pOpen,
					DWORD  				FunctionCode,
					DWORD  				dwDDB,
               DWORD					hDevice,
               PDIOCPARAMETERS 	pDiocParms
	);
VOID NDIS_API
PacketRequestComplete(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN PNDIS_REQUEST pRequest,
    IN NDIS_STATUS   Status
    );
VOID NDIS_API
PacketSendComplete(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN PNDIS_PACKET  pPacket,
    IN NDIS_STATUS   Status
    );
VOID
PacketReset( PNDIS_STATUS		pStatus,
				 POPEN_INSTANCE	pOpen );
VOID NDIS_API
PacketResetComplete(
    IN NDIS_HANDLE  ProtocolBindingContext,
    IN NDIS_STATUS  Status
    );
VOID NDIS_API
PacketStatus(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN NDIS_STATUS   Status,
    IN PVOID         StatusBuffer,
    IN UINT          StatusBufferSize
    );
VOID NDIS_API
PacketStatusComplete(
    IN NDIS_HANDLE 	ProtocolBindingContext
    );
VOID
PacketAllocatePacketBuffer( PNDIS_STATUS	pStatus,
						 POPEN_INSTANCE		pOpen,
						 PNDIS_PACKET		*lplpPacket,
						 PDIOCPARAMETERS 	pDiocParms,
						 DWORD				FunctionCode );
VOID NDIS_API
PacketTransferDataComplete(
    IN NDIS_HANDLE	ProtocolBindingContext,
    IN PNDIS_PACKET	Packet,
    IN NDIS_STATUS	Status,
    IN UINT 			BytesTransferred
    );
VOID
PacketRemoveReference(
    IN PDEVICE_EXTENSION DeviceExtension
    );
VOID 
PacketFreeResources( POPEN_INSTANCE Open );
VOID
PacketCleanUp( PNDIS_STATUS	Status,
					POPEN_INSTANCE Open );
NTSTATUS NDIS_API
PacketShutdown(
    IN PDEVICE_OBJECT DeviceObject
    );

VOID NDIS_API PacketUnload();


VOID NDIS_API
PacketBindAdapter( OUT PNDIS_STATUS Status,
				IN  NDIS_HANDLE  BindAdapterContext,
				IN  PNDIS_STRING AdapterName,
				IN  PVOID        SystemSpecific1,
				IN  PVOID        SystemSpecific2 
				);
VOID NDIS_API
PacketUnbindAdapter( OUT PNDIS_STATUS	Status,
				 IN NDIS_HANDLE	ProtocolBindingContext,
				 IN NDIS_HANDLE	UnbindContext
				 );
DWORD
PacketWrite( POPEN_INSTANCE	Open,
				 DWORD  				dwDDB,
             DWORD  				hDevice,
			  	 PDIOCPARAMETERS	pDiocParms
	);

DWORD PacketOpen(PNDIS_STRING AdapterName,DWORD dwDDB,DWORD hDevice,PDIOCPARAMETERS pDiocParms/*, int CloseMode*/);

DWORD
PacketClose( POPEN_INSTANCE		Open,
				DWORD  				dwDDB,
            DWORD  				hDevice,
			  	PDIOCPARAMETERS   pDiocParms
	);


DWORD
PacketRead( POPEN_INSTANCE		Open,
				DWORD  				dwDDB,
            DWORD  				hDevice,
			  	PDIOCPARAMETERS   pDiocParms
	);
DWORD _stdcall PacketIOControl( DWORD  			dwService,
                                DWORD  			dwDDB,
                                DWORD  			hDevice,
                                PDIOCPARAMETERS lpDIOCParms );
void VXDINLINE
VWIN32_DIOCCompletionRoutine( DWORD hEvent )
{
	_asm mov ebx, hEvent
	VxDCall( VWIN32_DIOCCompletionRoutine );
}

ULONG strlen( BYTE *s );
BYTE compare(BYTE *, BYTE *);
#define strcat( d, s )	NdisMoveMemory( d+strlen(d), s, strlen(s) )
#define memset( _S, _C, _N )\
{\
	UCHAR* _pS = _S;\
	ULONG  _I  = _N;\
	while ( _I-- )\
	{\
		*_pS++ = _C;\
	}\
}
