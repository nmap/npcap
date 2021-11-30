/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
 * Copyright (c) 2010 - 2013 Riverbed Technology, San Francisco (California), Yang Luo (China)
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

/** @addtogroup NPF
 *  @{
 */

/** @defgroup NPF_include NPF structures and definitions
 *  @{
 */
#include "stdafx.h"

#ifndef __PACKET_INCLUDE______
#define __PACKET_INCLUDE______

#include "win_bpf.h"
#include <wdm.h>

/* If DISPATCH_LEVEL can be determined, use that in the FILTER_*_LOCK macros
 * Otherwise, use NPF_IRQL_UNKNOWN so we can find and update them as we add more tracking
 */
#define NPF_IRQL_UNKNOWN FALSE
#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel) if (DispatchLevel) { \
	NdisDprAcquireSpinLock(_pLock); \
} else { \
	NdisAcquireSpinLock(_pLock); \
}
#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel) if (DispatchLevel) { \
	NdisDprReleaseSpinLock(_pLock); \
} else { \
	NdisReleaseSpinLock(_pLock); \
}

typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT,**PFILTER_REQUEST_CONTEXT;

//
// Global variables
//
extern NDIS_HANDLE         FilterDriverObject;

#define Packet_ALIGNMENT sizeof(int) ///< Alignment macro. Defines the alignment size.
#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))	///< Alignment macro. Rounds up to the next
///< even multiple of Packet_ALIGNMENT.


// Working modes
#define MODE_CAPT							0x0		///< Capture working mode
#define MODE_STAT							0x1		///< Statistical working mode
#define MODE_MON							0x2		///< Kernel monitoring mode
#define MODE_DUMP							0x10		///< Kernel dump working mode


#define IMMEDIATE 1			///< Immediate timeout. Forces a read call to return immediately.

// Loopback behaviour definitions
#define NPF_DISABLE_LOOPBACK				1	///< Tells the driver to drop the packets sent by itself. This is usefult when building applications like bridges.
#define NPF_ENABLE_LOOPBACK					2	///< Tells the driver to capture the packets sent by itself.

// Admin only mode definition
//#define NPF_ADMIN_ONLY_MODE			///< Tells the driver to restrict its access only to Administrators. This is used to support "Admin-only Mode" for Npcap.

// Loopback interface MTU definition
#define NPF_LOOPBACK_INTERFACR_MTU			65536	///< The MTU of the "Npcap Loopback Adapter", this value adopts Linux's "lo" MTU and can't be modified.

// Custom link type, originally defined in Packet32.h, NDIS doesn't provide an equivalent for some of values
#define NdisMediumNull						-1		///< The link type of the "Npcap Loopback Adapter", this value will be recognized by packet.dll code.
#define NdisMediumCHDLC						-2		///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumPPPSerial					-3		///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumBare80211					-4		///< The link type of the Native WiFi adapters, Npcap versions with Native WiFi feature enabled will support this value.
#define NdisMediumRadio80211				-5		///< Custom linktype: NDIS doesn't provide an equivalent
#define NdisMediumPpi						-6		///< Custom linktype: NDIS doesn't provide an equivalent

#define CCH2BYTES(_cch) ((_cch) * sizeof(WCHAR))
#define BYTES2CCH(_bytes) ((_bytes) / sizeof(WCHAR))
/* Length of a string literal minus the terminating null */
#define CONST_WCHAR_BYTES(_A) (sizeof(_A) - sizeof(WCHAR))
#define CONST_WCHAR_CCH(_A) BYTES2CCH(CONST_WCHAR_BYTES(_A))
// The GUID for the filters
#define				FILTER_UNIQUE_NAME			L"{7daf2ac8-e9f6-4765-a842-f1f5d2501341}"
#define				FILTER_UNIQUE_NAME_WIFI		L"{7daf2ac8-e9f6-4765-a842-f1f5d2501351}"

#define DEVICE_PATH_PREFIX L"\\Device\\"
#define DEVICE_PATH_BYTES CONST_WCHAR_BYTES(DEVICE_PATH_PREFIX)
#define DEVICE_PATH_CCH CONST_WCHAR_CCH(DEVICE_PATH_PREFIX)

// format: {ADAPTER_GUID}-{FILTER_GUID}
// guid * 2 + 1 ("-") - 3 ("XX}")
#define SECOND_LAST_HEX_INDEX_OF_FILTER_UNIQUE_NAME (2*CONST_WCHAR_CCH(FILTER_UNIQUE_NAME) + 1 - 3)

// Maximum pool size allowed in bytes (defence against bad BIOCSETBUFFERSIZE calls)
#define NPF_MAX_BUFFER_SIZE 0x40000000L

#ifdef HAVE_DOT11_SUPPORT
#include "ieee80211_radiotap.h"
/* These are the fields we support, hence the max size
 * of radiotap header buffer */
#define SIZEOF_RADIOTAP_BUFFER sizeof(IEEE80211_RADIOTAP_HEADER) \
			+ 8 /* TSFT */ \
			+ 1 /* Flags */ \
			+ 1 /* Rate */ \
			+ 2 + 2 /* Channel */ \
			+ 1 /* Antenna signal */ \
			+ 3 /* MCS */ \
			+ 12 /* VHT */
#endif

/*!
  \brief Structure containing an OID request.

  It is used by the PacketRequest() function to send an OID to the interface card driver.
  It can be used, for example, to retrieve the status of the error counters on the adapter, its MAC address,
  the list of the multicast groups defined on it, and so on.
*/
typedef struct _PACKET_OID_DATA
{
	ULONG Oid;					///< OID code. See the Microsoft DDK documentation or the file ntddndis.h
								///< for a complete list of valid codes.
	ULONG Length;				///< Length of the data field
	UCHAR Data[1];				///< variable-lenght field that contains the information passed to or received
								///< from the adapter.
}
PACKET_OID_DATA, * PPACKET_OID_DATA;

C_ASSERT(sizeof(PACKET_OID_DATA) == 12);

/*!
  \brief Stores an OID request.

  This structure is used by the driver to perform OID query or set operations on the underlying NIC driver.
  The OID operations be performed usually only by network drivers, but NPF exports this mechanism to user-level
  applications through an IOCTL interface. The driver uses this structure to wrap a NDIS_REQUEST structure.
  This allows to handle correctly the callback structure of NdisRequest(), handling multiple requests and
  maintaining information about the IRPs to complete.
*/
typedef struct _INTERNAL_REQUEST
{
	NDIS_EVENT			InternalRequestCompletedEvent;
	NDIS_OID_REQUEST	Request;			///< The structure with the actual request, that will be passed to NdisRequest().
	NDIS_STATUS			RequestStatus;
} INTERNAL_REQUEST, *PINTERNAL_REQUEST;

/*!
  \brief Port device extension.

  Structure containing some data relative to every device NPF exposes
*/
typedef struct _DEVICE_EXTENSION
{
	PWSTR		ExportString;			///< Name of the exported device, i.e. name that the applications will use
										///< to open this adapter through Packet.dll.
	LIST_ENTRY AllOpens;
	PNDIS_RW_LOCK_EX AllOpensLock;
	NDIS_HANDLE FilterDriverHandle;

	LOOKASIDE_LIST_EX BufferPool; // Pool of BUFCHAIN_ELEM to hold capture data temporarily.
	LOOKASIDE_LIST_EX NBLCopyPool; // Pool of NPF_NBL_COPY, NPF_NB_COPIES, NPF_SRC_NB objects
	LOOKASIDE_LIST_EX NBCopiesPool; // Pool of NPF_NB_COPIES objects
	LOOKASIDE_LIST_EX SrcNBPool; // Pool of NPF_SRC_NB objects
	LOOKASIDE_LIST_EX InternalRequestPool; // Pool of INTERNAL_REQUEST structures that wrap every single OID request.
	LOOKASIDE_LIST_EX CapturePool; // Pool of NPF_CAP_DATA objects
#ifdef HAVE_DOT11_SUPPORT
	LOOKASIDE_LIST_EX Dot11HeaderPool; // Pool of Radiotap header buffers
#endif
	UCHAR bBufferPoolInit:1;
	UCHAR bNBLCopyPoolInit:1;
	UCHAR bNBCopiesPoolInit:1;
	UCHAR bSrcNBPoolInit:1;
	UCHAR bInternalRequestPoolInit:1;
	UCHAR bCapturePoolInit:1;
	UCHAR bDot11HeaderPoolInit:1;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef enum _FILTER_STATE
{
    FilterStateUnspecified,
    FilterInitialized,
    FilterAttaching,
    FilterPausing,
    FilterPaused,
    FilterRunning,
    FilterRestarting,
    FilterDetaching,
    FilterDetached
} FILTER_STATE;

typedef enum _OPEN_STATE
{
	OpenRunning, // All features available
	OpenAttached, // Some features need to be initialized.
	OpenDetached, // No NDIS adapter associated, most features unavailable
	OpenClosed, // No features available, about to shut down. New IRPs rejected.
	OpenInvalidStateMax // all valid states are less than this
} OPEN_STATE;

typedef enum _FILTER_OPS_STATE
{
	OpsDisabled,
	OpsDisabling,
	OpsEnabling,
	OpsFailed,
	OpsEnabled
} FILTER_OPS_STATE;

#define OPEN_SIGNATURE 'NPFO'

/* Filter module (per-adapter) */
typedef struct _NPCAP_FILTER_MODULE
{
	SINGLE_LIST_ENTRY FilterModulesEntry;
	// List of open instances needs to be write-locked only when inserting/removing.
	// Ordinary traversal can use faster and concurrent read-lock.
	SINGLE_LIST_ENTRY OpenInstances; //GroupHead
	PNDIS_RW_LOCK_EX OpenInstancesLock; // GroupLock

	NDIS_STRING				AdapterName;
	NET_LUID AdapterID;

	/* Config booleans as a bitfield */
#ifdef HAVE_WFP_LOOPBACK_SUPPORT
	UINT Loopback:1;
#endif
#ifdef HAVE_RX_SUPPORT
	UINT SendToRxPath:1;
	UINT BlockRxPath:1;
#endif
#ifdef HAVE_DOT11_SUPPORT
	UINT Dot11:1;
	UINT HasDataRateMappingTable:1;
#endif

	ULONG					MyPacketFilter;
	ULONG					HigherPacketFilter;
	ULONG					PhysicalMedium;
#ifdef HAVE_DOT11_SUPPORT
	ULONG					Dot11PacketFilter;
	DOT11_DATA_RATE_MAPPING_TABLE	DataRateMappingTable;
#endif

	NDIS_SPIN_LOCK			OIDLock;		///< Lock for protection of state and outstanding sends and recvs
	PNDIS_OID_REQUEST		PendingOidRequest;

	NDIS_HANDLE				AdapterHandle;	///< NDIS idetifier of the adapter used by this instance.
	NDIS_HANDLE				PacketPool;		///< Pool of NDIS_PACKET structures used to transfer the packets from and to the NIC driver.
	UINT					MaxFrameSize;	///< Maximum frame size that the underlying MAC acceptes. Used to perform a check on the
											///< size of the frames sent with NPF_Write() or NPF_BufferedWrite().
	ULONG					AdapterHandleUsageCounter;
	NDIS_SPIN_LOCK			AdapterHandleLock;
	FILTER_STATE					AdapterBindingStatus;	///< Specifies if NPF is still bound to the adapter used by this instance, it's unbinding or it's not bound.
	FILTER_OPS_STATE OpsState; // Whether all operations are enabled

} 
NPCAP_FILTER_MODULE, *PNPCAP_FILTER_MODULE;

/* Open instance
 * Represents an open device handle by a process
 */
typedef struct _OPEN_INSTANCE
{
	ULONG OpenSignature;
    SINGLE_LIST_ENTRY OpenInstancesEntry; //GroupNext
    LIST_ENTRY AllOpensEntry;
    PNPCAP_FILTER_MODULE pFiltMod;
	NET_LUID AdapterID;

	PDEVICE_EXTENSION DeviceExtension;
	ULONG					MyPacketFilter;
	PKEVENT					ReadEvent;		///< Pointer to the event on which the read calls on this instance must wait.
	PUCHAR					bpfprogram;		///< Pointer to the filtering pseudo-code associated with current instance of the driver.
											///< This code is used only in particular situations (for example when the packet received
											///< from the NIC driver is stored in two non-consecutive buffers. In normal situations
											///< the filtering routine created by the JIT compiler and pointed by the next field
											///< is used. See \ref NPF for details on the filtering process.
	UINT					MinToCopy;		///< Minimum amount of data in the circular buffer that unlocks a read. Set with the
											///< BIOCSMINTOCOPY IOCTL.
	LARGE_INTEGER			Nbytes;			///< Amount of bytes accepted by the filter when this instance is in statistical mode.
	LARGE_INTEGER			Npackets;		///< Number of packets accepted by the filter when this instance is in statistical mode.
	NDIS_SPIN_LOCK			CountersLock;	///< SpinLock that protects the statistical mode counters.
	UINT					Nwrites;		///< Number of times a single write must be physically repeated. See \ref NPF for an
											///< explanation
	ULONG					Multiple_Write_Counter;	///< Counts the number of times a single write has already physically repeated.
	NDIS_EVENT				WriteEvent;		///< Event used to synchronize the multiple write process.
	LONG WriteInProgress; ///< 1 if a write is currently in progress. NPF currently allows a single write on
											///< the same open instance.

	/* Config booleans as a bitfield */
	// working modes, see PacketSetMode():
	UINT bModeCapt:1; // MODE_CAPT (1) vs MODE_STAT (0)
	// UINT bModeMon:1; // MODE_MON not supported
	// Loopback Behavior:
	UINT SkipSentPackets:1; ///< True if this instance should not capture back the packets that it transmits.
	// Info used to match a FilterModule when reattaching:
	UINT bDot11:1; // pFiltMod->Dot11
	UINT bLoopback:1; // pFiltMod->Loopback

	PNDIS_RW_LOCK_EX MachineLock; ///< Lock that protects the BPF filter while in use.

	/* Buffer */
	PNDIS_RW_LOCK_EX BufferLock; // Lock for modifying the buffer size/configuration
	LIST_ENTRY PacketQueue; // Head of packet buffer queue
	KSPIN_LOCK PacketQueueLock; // Lock controlling buffer queue
	LONG Free; // Bytes of buffer free for writing
	LONG Size; ///< Size of the kernel buffer

	/* Stats */
	ULONG Accepted; /// A packet is accepted if it passes the filter and
			//  fits in the buffer. Accepted packets are the
			//  ones that reach the application.
	ULONG Received; /// number of packet received by the network adapter
                        //  since the beginning of the capture session.
	ULONG Dropped; /// A packet is dropped if there is no more space to
		       //  store it in the circular buffer.
	ULONG ResourceDropped; /// A packet is resource-dropped if there is
		       //  insufficient memory to allocate a copy.

	NDIS_EVENT				NdisWriteCompleteEvent;	///< Event that is signalled when all the packets have been successfully sent by NdisSend (and corresponfing sendComplete has been called)
	ULONG					TransmitPendingPackets;	///< Specifies the number of packets that are pending to be transmitted, i.e. have been submitted to NdisSendXXX but the SendComplete has not been called yet.
	ULONG PendingIrps[OpenClosed]; //Counters for pending IRPs at each state. No IRPs are accepted at OpenClosed and greater.

	OPEN_STATE OpenStatus;
	NDIS_SPIN_LOCK			OpenInUseLock;
	ULONG TimestampMode;
	struct timeval start; // Time synchronization of QPC with last boot
	ULONG UserPID; // A PID associated with this handle
}
OPEN_INSTANCE, *POPEN_INSTANCE;

/* This value should be sized to hold most packets processed by the driver. If
 * a packet (snaplen) exceeds this size, it will cost an additional BUFCHAIN_ELEM
 * allocation/free. On the other hand, every captured packet will use up at
 * least this much space in memory, so keep it small. Nmap uses 256 snaplen, so
 * we'll try that.
 */
#define NPF_BUFCHAIN_SIZE 256

typedef struct _NPF_NBL_COPY
{
	SINGLE_LIST_ENTRY NBCopiesHead;
	SINGLE_LIST_ENTRY NBLCopyEntry;
	struct timeval tstamp;
#ifdef HAVE_DOT11_SUPPORT
	PUCHAR Dot11RadiotapHeader;
#endif
	ULONG refcount;
} NPF_NBL_COPY, *PNPF_NBL_COPY;

/* Fixed-size buffers for holding packet data. Fixed size makes math easier and
 * lets us use lookaside lists */
typedef struct _BUFCHAIN_ELEM *PBUFCHAIN_ELEM;
typedef struct _BUFCHAIN_ELEM
{
	PBUFCHAIN_ELEM Next;
	UCHAR Buffer [NPF_BUFCHAIN_SIZE];
} BUFCHAIN_ELEM;

/* This is like a lower-overhead version of NET_BUFFER based on BUFCHAIN_ELEM instead of MDL */
typedef struct _NPF_NB_COPIES
{
	PNPF_NBL_COPY pNBLCopy;
	ULONG ulSize; //Size of all used space in the bufchain.
	ULONG ulPacketSize; // Size of the original packet
	ULONG refcount;
	BUFCHAIN_ELEM FirstElem; // Bufchain of packet data
} NPF_NB_COPIES, *PNPF_NB_COPIES;

typedef struct _NPF_SRC_NB
{
	SINGLE_LIST_ENTRY CopiesEntry;
	PNPF_NB_COPIES pNBCopy;
	PBUFCHAIN_ELEM pLastElem; // Last elem in the chain
	PMDL pSrcCurrMdl; // MDL where we left off copying from the source NET_BUFFER
	ULONG ulCurrMdlOffset; // Position in that MDL.
} NPF_SRC_NB, *PNPF_SRC_NB;

// so we can use the same lookaside list for all these things
typedef union _NPF_NB_STORAGE
{
	NPF_NBL_COPY NBLCopy;
	NPF_SRC_NB SrcNB;
	NPF_NB_COPIES NBCopy;
} NPF_NB_STORAGE, *PNPF_NB_STORAGE;

/* Structure of a captured packet data description */
typedef struct _NPF_CAP_DATA
{
	LIST_ENTRY PacketQueueEntry;
	PNPF_NB_COPIES pNBCopy;
	ULONG ulCaplen;
}
NPF_CAP_DATA, *PNPF_CAP_DATA;

#define NPF_CAP_SIZE(_CapLen) (sizeof(struct bpf_hdr) + _CapLen)

#ifdef HAVE_DOT11_SUPPORT
#define NPF_CAP_OBJ_SIZE(_P, _R) NPF_CAP_SIZE( \
		(_P)->ulCaplen \
		+ (_R != NULL ? _R->it_len : 0))
#else
#define NPF_CAP_OBJ_SIZE(_P, _N) NPF_CAP_SIZE((_P)->ulCaplen)
#endif

_When_(AcquireLock == FALSE, _Requires_lock_held_(Open->BufferLock))
VOID
NPF_ResetBufferContents(
	_Inout_ POPEN_INSTANCE Open,
	_In_ BOOLEAN AcquireLock
);

VOID NPF_ReturnNBCopies(
	_In_ PNPF_NB_COPIES pNBCopy,
	_In_ PDEVICE_EXTENSION pDevExt);

VOID NPF_ReturnNBLCopy(
	_In_ PNPF_NBL_COPY pNBLCopy,
	_In_ PDEVICE_EXTENSION pDevExt);

VOID NPF_ReturnCapData(
	_In_ PNPF_CAP_DATA pCapData,
	_In_ PDEVICE_EXTENSION pDevExt);

/*!
  \brief Function to free the Net Buffer Lists initiated by ourself.
*/
VOID
NPF_FreePackets(
	_In_ __drv_freesMem(mem) PNET_BUFFER_LIST    NetBufferLists
	);

// This function exists only to suppress C6014 regarding memory leak.
// Be very suspicious of any use of it!
// MUST be accompanied by a well-researched justification.
inline VOID
#pragma warning(suppress: 28194) // We aren't really aliasing it here, but we know that it's aliased for some other reason.
NPF_AnalysisAssumeAliased(_In_ __drv_aliasesMem PVOID p)
{
	UNREFERENCED_PARAMETER(p);
	return;
}

/*!
\brief Context information for originated sent packets
*/
typedef struct _PACKET_RESERVED
{
	BOOLEAN		FreeBufAfterWrite;	///< True if the memory buffer associated with the packet must be freed.
	POPEN_INSTANCE		ChildOpen;			///< The child open pointer that binded the group head open.
}  PACKET_RESERVED, *PPACKET_RESERVED;

#define RESERVED(_p) ((PPACKET_RESERVED)((_p)->Context->ContextData + (_p)->Context->Offset)) ///< Macro to obtain a NDIS_PACKET from a PACKET_RESERVED

#define TRANSMIT_PACKETS 256	///< Maximum number of packets in the transmit packet pool. This value is an upper bound to the number
///< of packets that can be transmitted at the same time or with a single call to NdisSendPackets.


/// Macro used in the I/O routines to return the control to user-mode with a success status.
#define EXIT_SUCCESS(quantity) Irp->IoStatus.Information=quantity;\
	Irp->IoStatus.Status = STATUS_SUCCESS;\
	IoCompleteRequest(Irp, IO_NO_INCREMENT);\
	return STATUS_SUCCESS;\

/// Macro used in the I/O routines to return the control to user-mode with a failure status.
#define EXIT_FAILURE(quantity) Irp->IoStatus.Information=quantity;\
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;\
	IoCompleteRequest(Irp, IO_NO_INCREMENT);\
	return STATUS_UNSUCCESSFUL;\

/**
 *  @}
 */


/***************************/
/*  	 Prototypes 	   */
/***************************/

/** @defgroup NPF_code NPF functions
 *  @{
 */

FILTER_SET_OPTIONS NPF_RegisterOptions;


/*!
  \brief Callback for NDIS AttachHandler. Not used by NPF.
  \param NdisFilterHandle Specify a handle identifying this instance of the filter. FilterAttach
   should save this handle. It is a required  parameter in subsequent calls to NdisFxxx functions.
  \param FilterDriverContext Filter driver context passed to NdisFRegisterFilterDriver.
  \param AttachParameters attach parameters.
  \return NDIS_STATUS_SUCCESS: FilterAttach successfully allocated and initialize data structures for this filter instance.
		  NDIS_STATUS_RESOURCES: FilterAttach failed due to insufficient resources.
		  NDIS_STATUS_FAILURE: FilterAttach could not set up this instance of this filter and it has called

  Function called by NDIS when a new adapter is installed on the machine With Plug and Play.
*/
FILTER_ATTACH NPF_AttachAdapter;
// NDIS_STATUS
// NPF_AttachAdapter(
// 	NDIS_HANDLE                     NdisFilterHandle,
// 	NDIS_HANDLE                     FilterDriverContext,
// 	PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
// 	);


/*!
  \brief Callback for NDIS DetachHandler.
  \param FilterModuleContext Pointer to the filter context area.

  Function called by NDIS when a new adapter is removed from the machine without shutting it down.
  NPF_DetachAdapter closes the adapter calling NdisCloseAdapter() and frees the memory and the structures
  associated with it.
*/
FILTER_DETACH NPF_DetachAdapter;
// VOID
// NPF_DetachAdapter(
// 	NDIS_HANDLE     FilterModuleContext
// 	);


/*!
  \brief Function called by the OS when NPF is unloaded.
  \param DriverObject The driver object of NPF created by the system.

  This is the last function executed when the driver is unloaded from the system. It frees global resources,
  delete the devices and deregisters the filter. The driver can be unloaded by the user stopping the NPF
  service (from control panel or with a console 'net stop npf').
*/
DRIVER_UNLOAD NPF_Unload;
// VOID
// NPF_Unload(
// 	IN PDRIVER_OBJECT DriverObject
// 	);


/*!
  \brief Filter restart routine, callback for NDIS RestartHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param RestartParameters Additional information about the restart operation.
  \return NDIS_STATUS_SUCCESS: if filter restarts successfully
		  NDIS_STATUS_XXX: Otherwise.

  Start the datapath - begin sending and receiving NBLs.
*/
FILTER_RESTART NPF_Restart;
// NDIS_STATUS
// NPF_Restart(
// 	NDIS_HANDLE                     FilterModuleContext,
// 	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
// 	);

/*!
  \brief Filter pause routine, Callback for NDIS PauseHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param PauseParameters Additional information about the pause operation.
  \return NDIS_STATUS_SUCCESS if filter pauses successfully, NDIS_STATUS_PENDING if not.
   No other return value is allowed (pause must succeed, eventually).

   Complete all the outstanding sends and queued sends,
   wait for all the outstanding recvs to be returned
   and return all the queued receives.
   N.B.: When the filter is in Pausing state, it can still process OID requests,
   complete sending, and returning packets to NDIS, and also indicate status.
   After this function completes, the filter must not attempt to send or
   receive packets, but it may still process OID requests and status
   indications.
*/
FILTER_PAUSE NPF_Pause;
// NDIS_STATUS
// NPF_Pause(
// 	NDIS_HANDLE                     FilterModuleContext,
// 	PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
// 	);


FILTER_OID_REQUEST NPF_OidRequest;

FILTER_CANCEL_OID_REQUEST NPF_CancelOidRequest;

FILTER_OID_REQUEST_COMPLETE NPF_OidRequestComplete;

/*!
  \brief Callback for NDIS StatusHandler. Not used by NPF
*/
FILTER_STATUS NPF_Status;
// VOID
// NPF_Status(
// 	NDIS_HANDLE             FilterModuleContext,
// 	PNDIS_STATUS_INDICATION StatusIndication
// 	);


/*!
  \brief Device PNP event handler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetDevicePnPEvent A Device PnP event.

  Callback for NDIS DevicePnPEventNotifyHandler. Not used by NPF
*/
FILTER_DEVICE_PNP_EVENT_NOTIFY NPF_DevicePnPEventNotify;
// VOID
// NPF_DevicePnPEventNotify(
// 	NDIS_HANDLE             FilterModuleContext,
// 	PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
// 	);


/*!
  \brief Net PNP event handler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetPnPEventNotification A Net PnP event.
  \return NDIS_STATUS_XXX

  Callback for NDIS NetPnPEventHandler. Not used by NPF
*/
FILTER_NET_PNP_EVENT NPF_NetPnPEvent;
// NDIS_STATUS
// NPF_NetPnPEvent(
// 	NDIS_HANDLE					FilterModuleContext,
// 	PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification
// 	);


/*!
  \brief Callback for NDIS SendNetBufferListsHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetBufferLists A List of NetBufferLists to send.
  \param PortNumber Port Number to which this send is targeted.
  \param SendFlags Specifies if the call is at DISPATCH_LEVEL.

  This function is an optional function for filter drivers. If provided, NDIS
  will call this function to transmit a linked list of NetBuffers, described by a
  NetBufferList, over the network. If this handler is NULL, NDIS will skip calling
  this filter when sending a NetBufferList and will call the next lower
  driver in the stack.  A filter that doesn't provide a FilerSendNetBufferList
  handler can not originate a send on its own.
*/
FILTER_SEND_NET_BUFFER_LISTS NPF_SendEx;
// VOID
// NPF_SendEx(
// 	NDIS_HANDLE         FilterModuleContext,
// 	PNET_BUFFER_LIST    NetBufferLists,
// 	NDIS_PORT_NUMBER    PortNumber,
// 	ULONG               SendFlags
// 	);


/*!
  \brief Callback for NDIS ReturnNetBufferListsHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetBufferLists A linked list of NetBufferLists that this
						filter driver indicated in a previous call to
						NdisFIndicateReceiveNetBufferLists.
  \param ReturnFlags Flags specifying if the caller is at DISPATCH_LEVEL.

  FilterReturnNetBufferLists is an optional function. If provided, NDIS calls
  FilterReturnNetBufferLists to return the ownership of one or more NetBufferLists
  and their embedded NetBuffers to the filter driver. If this handler is NULL, NDIS
  will skip calling this filter when returning NetBufferLists to the underlying
  miniport and will call the next lower driver in the stack. A filter that doesn't
  provide a FilterReturnNetBufferLists handler cannot originate a receive indication
  on its own.
*/
FILTER_RETURN_NET_BUFFER_LISTS NPF_ReturnEx;
// VOID
// NPF_ReturnEx(
// 	NDIS_HANDLE         FilterModuleContext,
// 	PNET_BUFFER_LIST    NetBufferLists,
// 	ULONG               ReturnFlags
// 	);

/*!
  \brief Callback for NDIS SendNetBufferListsCompleteHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetBufferLists A chain of NBLs that are being returned to you.
  \param SendCompleteFlags Flags (see documentation).

  This routine is invoked whenever the lower layer is finished processing
  sent NET_BUFFER_LISTs.  If the filter does not need to be involved in the
  send path, you should remove this routine and the FilterSendNetBufferLists
  routine.  NDIS will pass along send packets on behalf of your filter more
  efficiently than the filter can.
*/
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE NPF_SendCompleteEx;
// VOID
// NPF_SendCompleteEx(
// 	NDIS_HANDLE         FilterModuleContext,
// 	PNET_BUFFER_LIST    NetBufferLists,
// 	ULONG               SendCompleteFlags
// 	);


/*!
  \brief Callback for NDIS ReceiveNetBufferListsHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param NetBufferLists A linked list of NetBufferLists.
  \param PortNumber Port on which the receive is indicated.
  \param NumberOfNetBufferLists Number of NetBufferLists.
  \param ReceiveFlags Flags (see documentation).

  FilerReceiveNetBufferLists is an optional function for filter drivers.
  If provided, this function processes receive indications made by underlying
  NIC or lower level filter drivers. This function  can also be called as a
  result of loopback. If this handler is NULL, NDIS will skip calling this
  filter when processing a receive indication and will call the next higher
  driver in the stack. A filter that doesn't provide a
  FilterReceiveNetBufferLists handler cannot provide a
  FilterReturnNetBufferLists handler and cannot a initiate an original receive
  indication on its own.
  N.B.: It is important to check the ReceiveFlags in NDIS_TEST_RECEIVE_CANNOT_PEND.
  This controls whether the receive indication is an synchronous or
  asynchronous function call.
*/
FILTER_RECEIVE_NET_BUFFER_LISTS NPF_TapEx;
// VOID
// NPF_TapEx(
// 	NDIS_HANDLE         FilterModuleContext,
// 	PNET_BUFFER_LIST    NetBufferLists,
// 	NDIS_PORT_NUMBER    PortNumber,
// 	ULONG               NumberOfNetBufferLists,
// 	ULONG               ReceiveFlags
// 	);


/*!
  \brief Callback for NDIS CancelSendNetBufferListsHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \param CancelId An identifier for all NBLs that should be dequeued.

  This function cancels any NET_BUFFER_LISTs pended in the filter and then
  calls the NdisFCancelSendNetBufferLists to propagate the cancel operation.
  If your driver does not queue any send NBLs, you may omit this routine.
  NDIS will propagate the cancelation on your behalf more efficiently.
*/
FILTER_CANCEL_SEND_NET_BUFFER_LISTS NPF_CancelSendNetBufferLists;
// VOID
// NPF_CancelSendNetBufferLists(
// 	NDIS_HANDLE             FilterModuleContext,
// 	PVOID                   CancelId
// 	);


/*!
  \brief Callback for NDIS SetFilterModuleOptionsHandler.
  \param FilterModuleContext Pointer to the filter context structure.
  \return NDIS_STATUS_SUCCESS
		  NDIS_STATUS_RESOURCES
		  NDIS_STATUS_FAILURE

  This function set the optional handlers for the filter. Not used by NPF
*/
FILTER_SET_MODULE_OPTIONS NPF_SetModuleOptions;
// NDIS_STATUS
// 	NPF_SetModuleOptions(
// 	NDIS_HANDLE             FilterModuleContext
// 	);

/* Validate I/O IRP parameters and do boilerplate init.
 * Suitable for IRP_MJ_READ and IRP_MJ_WRITE with DO_DIRECT_IO
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS NPF_ValidateIoIrp(
	_In_ PIRP pIrp,
	_Outptr_result_nullonfailure_ POPEN_INSTANCE* ppOpen
);

/*!
  \brief The initialization routine of the driver.
  \param DriverObject The driver object of NPF created by the system.
  \param RegistryPath The registry path containing the keys related to the driver.
  \return STATUS_SUCCESS
		  STATUS_UNSUCCESSFUL.

  DriverEntry is a mandatory function in a device driver. Like the main() of a user level program, it is called
  by the system when the driver is loaded in memory and started. Its purpose is to initialize the driver,
  performing all the allocations and the setup. In particular, DriverEntry registers all the driver's I/O
  callbacks, creates the devices, defines NPF as a protocol inside NDIS.
*/
DRIVER_INITIALIZE DriverEntry;
// NTSTATUS
// DriverEntry(
// 	IN PDRIVER_OBJECT DriverObject,
// 	IN PUNICODE_STRING RegistryPath
// 	);

/*!
  \brief Opens a new instance of the driver.
  \param DeviceObject Pointer to the device object utilized by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called by the OS when a new instance of the driver is opened, i.e. when a user application
  performs a CreateFile on a device created by NPF. NPF_Open allocates and initializes variables, objects
  and buffers needed by the new instance, fills the OPEN_INSTANCE structure associated with it and opens the
  adapter with a call to NdisOpenAdapter.
*/
_Dispatch_type_(IRP_MJ_CREATE)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_OpenAdapter;
// NTSTATUS
// NPF_OpenAdapter(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// 	);


/*!
  \brief Closes an instance of the driver.
  \param DeviceObject Pointer to the device object utilized by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called when a running instance of the driver is closed by the user with a CloseHandle().
  Used together with NPF_CloseAdapter().
  It stops the capture process, deallocates the memory and the objects associated with the
  instance and closing the files.
*/
_Dispatch_type_(IRP_MJ_CLEANUP)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_Cleanup;
// NTSTATUS
// NPF_Cleanup(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// 	);


/*!
  \brief Closes an instance of the driver.
  \param DeviceObject Pointer to the device object utilized by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called when a running instance of the driver is closed by the user with a CloseHandle().
  Used together with NPF_Cleanup().
  It stops the capture process, deallocates the memory and the objects associated with the
  instance and closing the files. The network adapter is then closed with a call to NdisCloseAdapter.
*/
_Dispatch_type_(IRP_MJ_CLOSE)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_CloseAdapter;
// NTSTATUS
// NPF_CloseAdapter(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// 	);


/*!
  \brief Capture a NBL for all OpenInstances on an adapter.
  \param pFiltMod Pointer to a filter module where the packets should be captured
  \param pNetBufferLists A List of NetBufferLists to receive.
  \param pOpenOriginating A pointer to the OpenInstance that originated/injected these packets so SkipSentPackets can be honored. NULL if not applicable.
  \param AtDispatchLevel Set to TRUE if the caller knows they are at DISPATCH_LEVEL.

  NPF_DoTap() is called for every incoming and outgoing packet. It is the most important and one of
  the most complex functions of NPF: it executes the filter, runs the statistical engine (if the instance is in
  statistical mode), gathers the timestamp, moves the packet in the buffer. NPF_DoTap() is the only function,
  along with the filtering ones, that is executed for every incoming packet, therefore it is carefully
  optimized.
*/
VOID
_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
NPF_DoTap(
	_In_ PNPCAP_FILTER_MODULE pFiltMod,
	_In_ const PNET_BUFFER_LIST NetBufferLists,
	_In_opt_ POPEN_INSTANCE pOpenOriginating,
	_In_ BOOLEAN AtDispatchLevel
	);

/*!
  \brief Handles the IOCTL calls.
  \param DeviceObject Pointer to the device object utilized by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  Once the packet capture driver is opened it can be configured from user-level applications with IOCTL commands
  using the DeviceIoControl() system call. NPF_IoControl receives and serves all the IOCTL calls directed to NPF.
  The following commands are recognized:
  - #BIOCSETBUFFERSIZE
  - #BIOCSETF
  - #BIOCGSTATS
  - #BIOCSRTIMEOUT
  - #BIOCSMODE
  - #BIOCSWRITEREP
  - #BIOCSMINTOCOPY
  - #BIOCSETOID
  - #BIOCQUERYOID
  - #BIOCGEVNAME
  -	#BIOCSENDPACKETSSYNC
  -	#BIOCSENDPACKETSNOSYNC
*/
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_IoControl;
// NTSTATUS
// NPF_IoControl(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// );


/*!
  \brief Writes a raw packet to the network.
  \param DeviceObject Pointer to the device object on which the user wrote the packet.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called by the OS in consequence of user WriteFile() call, with the data of the packet that must
  be sent on the net. The data is contained in the buffer associated with Irp, NPF_Write takes it and
  delivers it to the NIC driver via the NdisSend() function. The Nwrites field of the OPEN_INSTANCE structure
  associated with Irp indicates the number of copies of the packet that will be sent: more than one copy of the
  packet can be sent for performance reasons.
*/
_Dispatch_type_(IRP_MJ_WRITE)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_Write;
// NTSTATUS
// NPF_Write(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// 	);


/*!
  \brief Writes a buffer of raw packets to the network.
  \param Open Pointer to the open instance performing this write
  \param UserBuff Pointer to the buffer containing the packets to send.
  \param UserBuffSize Size of the buffer with the packets.
  \param sync If set to TRUE, the packets are transmitted respecting their timestamps.
  \param Written The amount of bytes actually sent.
  \return NTSTATUS value indicating success or error.

  This function is called by the OS in consequence of a BIOCSENDPACKETSNOSYNC or a BIOCSENDPACKETSSYNC IOCTL.
  The buffer received as input parameter contains an arbitrary number of packets, each of which preceded by a
  dump_bpf_hdr structure. NPF_BufferedWrite() scans the buffer and sends every packet via the NdisSend() function.
  When Sync is set to TRUE, the packets are synchronized with the KeQueryPerformanceCounter() function.
  This requires a remarkable amount of CPU, but allows to respect the timestamps associated with packets with a precision
  of some microseconds (depending on the precision of the performance counter of the machine).
  If Sync is false, the timestamps are ignored and the packets are sent as fat as possible.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NPF_BufferedWrite(
	_In_ POPEN_INSTANCE Open,
	_In_reads_bytes_(UserBuffSize) PUCHAR UserBuff,
	_In_ ULONG UserBuffSize,
	_In_ BOOLEAN Sync,
	_Out_ PULONG_PTR Written
	);

/*!
  \brief Function that serves the user's reads.
  \param DeviceObject Pointer to the device used by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called by the OS in consequence of user ReadFile() call. It moves the data present in the
  kernel buffer to the user buffer associated with Irp.
  Any available packets are transferred regardless of MinToCopy. Statistics are
  delivered regardless of PacketSetReadTimeout. These values are handled in
  user-mode by Packet.dll. The Read call will return as quickly as possible
  without waiting on the ReadEvent.
*/
_Dispatch_type_(IRP_MJ_READ)
_IRQL_requires_max_(PASSIVE_LEVEL)
DRIVER_DISPATCH NPF_Read;
// NTSTATUS
// NPF_Read(
// 	IN PDEVICE_OBJECT DeviceObject,
// 	IN PIRP Irp
// 	);


/*!
  \brief Add the filter module context to the global filter module array.
  \param pFiltMod Pointer to filter module context structure.

  This function is used by NPF_AttachAdapter() and NPF_OpenAdapter() to add a new open context to
  the global open array, this array is designed to help find and clean the specific adapter context.
*/
void
NPF_AddToFilterModuleArray(
	_In_ PNPCAP_FILTER_MODULE pFiltMod
	);

/*!
  \brief Get the filter module for the loopback adapter
  \return Pointer to the loopback filter module.
 */
_Ret_maybenull_
PNPCAP_FILTER_MODULE
NPF_GetLoopbackFilterModule();


/*!
  \brief Create a filter module.
  \param AdapterName The adapter name of the target filter module.
  \param SelectedIndex The medium of the filter module.
  \return Pointer to the new filter module.

  This function is used to create a filter module context object
*/
_Ret_maybenull_
PNPCAP_FILTER_MODULE
NPF_CreateFilterModule(
	_In_ NDIS_HANDLE NdisFilterHandle,
	_In_ PNDIS_STRING AdapterName,
	_In_ UINT SelectedIndex
	);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NPF_ReleaseOpenInstanceResources(_Inout_ POPEN_INSTANCE pOpen);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NPF_ReleaseFilterModuleResources(_Inout_ PNPCAP_FILTER_MODULE pFiltMod);

BOOLEAN NPF_IsOpenInstance(_In_ POPEN_INSTANCE pOpen);

_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
BOOLEAN NPF_StartUsingBinding(_Inout_ PNPCAP_FILTER_MODULE pFiltMod, _In_ BOOLEAN AtDispatchLevel);

_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
VOID NPF_StopUsingBinding(_Inout_ PNPCAP_FILTER_MODULE pFiltMod, _In_ BOOLEAN AtDispatchLevel);

_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
_When_(pOpen->OpenStatus > OpenRunning, _IRQL_requires_(PASSIVE_LEVEL))
BOOLEAN NPF_StartUsingOpenInstance(_Inout_ POPEN_INSTANCE pOpen, _In_range_(OpenRunning,OpenDetached) OPEN_STATE MaxOpen, _In_ BOOLEAN AtDispatchLevel);

_When_(AtDispatchLevel != FALSE, _IRQL_requires_(DISPATCH_LEVEL))
VOID NPF_StopUsingOpenInstance(_Inout_ POPEN_INSTANCE pOpen, _In_range_(OpenRunning,OpenDetached) OPEN_STATE MaxOpen, _In_ BOOLEAN AtDispatchLevel);

_IRQL_requires_(PASSIVE_LEVEL)
VOID NPF_CloseOpenInstance(_Inout_ POPEN_INSTANCE pOpen);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NPF_GetDeviceMTU(_In_ PNPCAP_FILTER_MODULE pFiltMod, _Out_ PUINT  pMtu);

#ifdef HAVE_DOT11_SUPPORT
USHORT NPF_LookUpDataRateMappingTable(
	       _In_ PNPCAP_FILTER_MODULE pFiltMod,
	       _In_ UCHAR ucDataRate
	       );
#endif

/**
 *  @}
 */

#endif  /*main ifndef/define*/
