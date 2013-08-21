/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
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

// #if !defined(NDIS620)
// #error NDIS620 should be defined
// #endif

#ifdef _X86_
#define NTKERNEL	///< Forces the compilation of the jitter with kernel calls 
#include "jitter.h"
#endif

#ifdef HAVE_BUGGY_TME_SUPPORT
#ifndef _X86_
#error TME support is available only on x86 architectures
#endif // _X86_
#endif //HAVE_BUGGY_TME_SUPPORT


//
// Needed to disable a warning due to the #pragma prefast directives,
// that are ignored by the normal DDK compiler
//
#ifndef _PREFAST_
#pragma warning(disable:4068)
#endif

#include "win_bpf.h"


// #define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
// 	{                                                           \
// 	if (DispatchLevel)                                      \
// 		{                                                       \
// 		NdisDprAcquireSpinLock(_pLock);                     \
// 		}                                                       \
// 		else                                                    \
// 		{                                                       \
// 		NdisAcquireSpinLock(_pLock);                        \
// 		}                                                       \
// 	}
// 
// #define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
// 	{                                                           \
// 	if (DispatchLevel)                                      \
// 		{                                                       \
// 		NdisDprReleaseSpinLock(_pLock);                     \
// 		}                                                       \
// 		else                                                    \
// 		{                                                       \
// 		NdisReleaseSpinLock(_pLock);                        \
// 		}                                                       \
// 	}

#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel) NdisAcquireSpinLock(_pLock)
#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel) NdisReleaseSpinLock(_pLock)


extern NDIS_SPIN_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;

#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
	NdisAllocateMemoryWithTagPriority(_NdisHandle, _Size, NPF6X_ALLOC_TAG, LowPoolPriority)
#define FILTER_FREE_MEM(_pMem)    NdisFreeMemory(_pMem, 0, 0)

//
// Define the filter struct
//
// typedef struct _MS_FILTER
//  {
// 	 LIST_ENTRY                     FilterModuleLink;
// 	 //Reference to this filter
// 	 ULONG                           RefCount;
// 
// 	 NDIS_HANDLE                     FilterHandle;
// 
// 	 NDIS_STATUS                     Status;
// 	 NDIS_EVENT                      Event;
// 	 ULONG                           BackFillSize;
// 	 FILTER_LOCK                     Lock;    // Lock for protection of state and outstanding sends and recvs
// 
// 	 FILTER_STATE                    State;   // Which state the filter is in
// 	 ULONG                           OutstandingSends;
// 	 ULONG                           OutstandingRequest;
// 	 ULONG                           OutstandingRcvs;
// 	 FILTER_LOCK                     SendLock;
// 	 FILTER_LOCK                     RcvLock;
// 	 QUEUE_HEADER                    SendNBLQueue;
// 	 QUEUE_HEADER                    RcvNBLQueue;
// 
// 
// 	 NDIS_STRING                     FilterName;
// 	 ULONG                           CallsRestart;
// 	 BOOLEAN                         TrackReceives;
// 	 BOOLEAN                         TrackSends;
// 
// 	 PNDIS_OID_REQUEST               PendingOidRequest;
// 
//  }MS_FILTER, * PMS_FILTER;

typedef struct _FILTER_DEVICE_EXTENSION
{
	ULONG            Signature;
	NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT,**PFILTER_REQUEST_CONTEXT;

//
// Global variables
//
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      DeviceObject;

extern NDIS_SPIN_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;

//
// function prototypes
//
DRIVER_INITIALIZE DriverEntry;

FILTER_SET_OPTIONS NPF_RegisterOptions;

FILTER_ATTACH NPF_Attach;

FILTER_DETACH NPF_Detach;

DRIVER_UNLOAD NPF_Unload;

FILTER_RESTART NPF_Restart;

FILTER_PAUSE NPF_Pause;

FILTER_OID_REQUEST NPF_OidRequest;

FILTER_CANCEL_OID_REQUEST NPF_CancelOidRequest;

FILTER_OID_REQUEST_COMPLETE NPF_OidRequestComplete;

FILTER_STATUS NPF_Status;

FILTER_DEVICE_PNP_EVENT_NOTIFY NPF_DevicePnPEventNotify;

FILTER_NET_PNP_EVENT NPF_NetPnPEvent;

FILTER_SEND_NET_BUFFER_LISTS NPF_SendEx;

FILTER_RETURN_NET_BUFFER_LISTS NPF_ReturnEx;

FILTER_SEND_NET_BUFFER_LISTS_COMPLETE NPF_SendCompleteEx;

FILTER_RECEIVE_NET_BUFFER_LISTS NPF_TapEx;

FILTER_CANCEL_SEND_NET_BUFFER_LISTS NPF_CancelSendNetBufferLists;

FILTER_SET_MODULE_OPTIONS NPF_SetModuleOptions;

DRIVER_DISPATCH FilterDispatch;

DRIVER_DISPATCH FilterDeviceIoControl;

VOID
	NPF_InternalRequestComplete(
	_In_ NDIS_HANDLE                  FilterModuleContext,
	_In_ PNDIS_OID_REQUEST            NdisRequest,
	_In_ NDIS_STATUS                  Status
	);

#define  MAX_REQUESTS   32 ///< Maximum number of simultaneous IOCTL requests.

#define Packet_ALIGNMENT sizeof(int) ///< Alignment macro. Defines the alignment size.
#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))	///< Alignment macro. Rounds up to the next 
///< even multiple of Packet_ALIGNMENT. 


// Working modes
#define MODE_CAPT 0x0		///< Capture working mode
#define MODE_STAT 0x1		///< Statistical working mode
#define MODE_MON  0x2		///< Kernel monitoring mode
#define MODE_DUMP 0x10		///< Kernel dump working mode


#define IMMEDIATE 1			///< Immediate timeout. Forces a read call to return immediately.

#define NDIS_FLAGS_SKIP_LOOPBACK_W2K	0x400 ///< This is an undocumented flag for NdisSetPacketFlags() that allows to disable loopback reception.

// The following definitions are used to provide compatibility 
// of the dump files with the ones of libpcap
#define TCPDUMP_MAGIC 0xa1b2c3d4	///< Libpcap magic number. Used by programs like tcpdump to recognize a driver's generated dump file.
#define PCAP_VERSION_MAJOR 2		///< Major libpcap version of the dump file. Used by programs like tcpdump to recognize a driver's generated dump file.
#define PCAP_VERSION_MINOR 4		///< Minor libpcap version of the dump file. Used by programs like tcpdump to recognize a driver's generated dump file.

// Loopback behaviour definitions
#define NPF_DISABLE_LOOPBACK	1	///< Tells the driver to drop the packets sent by itself. This is usefult when building applications like bridges.
#define NPF_ENABLE_LOOPBACK		2	///< Tells the driver to capture the packets sent by itself.

/*!
  \brief Header of a libpcap dump file.

  Used when a driver instance is set in dump mode to create a libpcap-compatible file.
*/
struct packet_file_header
{
	UINT magic;				///< Libpcap magic number
	USHORT version_major;	///< Libpcap major version
	USHORT version_minor;	///< Libpcap minor version
	UINT thiszone;			///< Gmt to local correction
	UINT sigfigs;			///< Accuracy of timestamps
	UINT snaplen;			///< Length of the max saved portion of each packet
	UINT linktype;			///< Data link type (DLT_*). See win_bpf.h for details.
};

/*!
  \brief Header associated to a packet in the driver's buffer when the driver is in dump mode.
  Similar to the bpf_hdr structure, but simpler.
*/
struct sf_pkthdr
{
	struct timeval ts;			///< time stamp
	UINT caplen;		///< Length of captured portion. The captured portion can be different from 
	///< the original packet, because it is possible (with a proper filter) to 
	///< instruct the driver to capture only a portion of the packets. 
	UINT len;		///< Length of the original packet (off wire).
};

//
// NT4 DDK doesn't have C_ASSERT
//
#ifndef C_ASSERT
#define C_ASSERT(a)
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
	LIST_ENTRY ListElement;		///< Used to handle lists of requests.
	//    PIRP			Irp;				///< Irp that performed the request
	//	BOOLEAN			Internal;			///< True if the request is for internal use of npf.sys. False if the request is performed by the user through an IOCTL.
	NDIS_EVENT InternalRequestCompletedEvent;
	NDIS_OID_REQUEST Request;			///< The structure with the actual request, that will be passed to NdisRequest().
	NDIS_STATUS RequestStatus;
} INTERNAL_REQUEST, * PINTERNAL_REQUEST;

/*!
  \brief Contains a NDIS packet.
  
  The driver uses this structure to wrap a NDIS_PACKET  structure.
  This allows to handle correctly the callback structure of NdisTransferData(), handling multiple requests and
  maintaining information about the IRPs to complete.
*/

typedef struct _PACKET_RESERVED
{
	LIST_ENTRY ListElement;		///< Used to handle lists of packets. ((NO USE!!)
	BOOLEAN FreeBufAfterWrite;	///< True if the memory buffer associated with the packet must be freed.
	PVOID ChildOpen;	///< The child open pointer that binded the group head open.
	PIRP Irp;					///< Irp that performed the request.
	//PMDL pMdl;				///< MDL mapping the buffer of the packet. (NO USE!! also no space for this variable)
	///< after a call to NdisSend().
	//ULONG Cpu;				///< The CPU on which the packet was pulled out of the linked list of free packets (NO USE!! also no space for this variable)
}  PACKET_RESERVED, * PPACKET_RESERVED;

#define RESERVED(_p) ((PPACKET_RESERVED)((_p)->ProtocolReserved)) ///< Macro to obtain a NDIS_PACKET from a PACKET_RESERVED

/*!
  \brief Port device extension.
  
  Structure containing some data relative to every adapter on which NPF is bound.
*/
typedef struct _DEVICE_EXTENSION
{
	NDIS_STRING AdapterName;			///< Name of the adapter.
	PWSTR ExportString;		///< Name of the exported device, i.e. name that the applications will use 
	///< to open this adapter through WinPcap.
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

/*!
  \brief Kernel buffer of each CPU.

  Structure containing the kernel buffer (and other CPU related fields) used to capture packets.
*/
typedef struct __CPU_Private_Data
{
	ULONG P;					///< Zero-based index of the producer in the buffer. It indicates the first free byte to be written.
	ULONG C;					///< Zero-based index of the consumer in the buffer. It indicates the first free byte to be read.
	ULONG Free;				///< Number of the free bytes in the buffer
	PUCHAR Buffer;				///< Pointer to the kernel buffer used to capture packets.
	ULONG Accepted;			///< Number of packet that current capture instance acepted, from its opening. A packet 
	///< is accepted if it passes the filter and fits in the buffer. Accepted packets are the
	///< ones that reach the application. 
	///< This number is related to the particular CPU this structure is referring to.
	ULONG Received;			///< Number of packets received by current instance from its opening, i.e. number of 
	///< packet received by the network adapter since the beginning of the 
	///< capture/monitoring/dump session. 
	///< This number is related to the particular CPU this structure is referring to.
	ULONG Dropped;			///< Number of packet that current instance had to drop, from its opening. A packet 
	///< is dropped if there is no more space to store it in the circular buffer that the 
	///< driver associates to current instance. 
	///< This number is related to the particular CPU this structure is referring to.
	NDIS_SPIN_LOCK BufferLock;	///< It protects the buffer associated with this CPU.
	PMDL TransferMdl1;		///< MDL used to map the portion of the buffer that will contain an incoming packet. 
	PMDL TransferMdl2;		///< Second MDL used to map the portion of the buffer that will contain an incoming packet. 
	ULONG NewP;				///< Used by NdisTransferData() (when we call NdisTransferData, p index must be updated only in the TransferDataComplete.
}
CpuPrivateData;


/*!
  \brief Contains the state of a running instance of the NPF driver.
  
  This is the most important structure of NPF: it is used by almost all the functions of the driver. An
  _OPEN_INSTANCE structure is associated with every user-level session, allowing concurrent access
  to the driver.
*/
typedef struct _OPEN_INSTANCE
{
	NDIS_STRING AdapterName;
	BOOLEAN DirectBinded;
	struct _OPEN_INSTANCE *Next;
	struct _OPEN_INSTANCE *GroupNext;
	struct _OPEN_INSTANCE *GroupHead;

	ULONG MyPacketFilter;
	ULONG HigherPacketFilter;

	//LIST_ENTRY FilterModuleLink;
	NDIS_SPIN_LOCK OIDLock;    // Lock for protection of state and outstanding sends and recvs
	PNDIS_OID_REQUEST PendingOidRequest;

	PDEVICE_EXTENSION DeviceExtension;	///< Pointer to the _DEVICE_EXTENSION structure of the device on which
	///< the instance is bound.
	NDIS_HANDLE AdapterHandle;		///< NDIS idetifier of the adapter used by this instance.
	//NDIS_HANDLE BindContext;
	UINT Medium;				///< Type of physical medium the underlying NDIS driver uses. See the
	///< documentation of NdisOpenAdapter in the MS DDK for details.
	NDIS_HANDLE PacketPool;			///< Pool of NDIS_PACKET structures used to transfer the packets from and to the NIC driver.
	KSPIN_LOCK RequestSpinLock;	///< SpinLock used to synchronize the OID requests.
	LIST_ENTRY RequestList;		///< List of pending OID requests.
	LIST_ENTRY ResetIrpList;		///< List of pending adapter reset requests.
	INTERNAL_REQUEST Requests[MAX_REQUESTS]; ///< Array of structures that wrap every single OID request.
	PMDL BufferMdl;			///< Pointer to a Memory descriptor list (MDL) that maps the circular buffer's memory.
	PKEVENT ReadEvent;			///< Pointer to the event on which the read calls on this instance must wait.
	PUCHAR bpfprogram;			///< Pointer to the filtering pseudo-code associated with current instance of the driver.
	///< This code is used only in particular situations (for example when the packet received
	///< from the NIC driver is stored in two non-consecutive buffers. In normal situations
	///< the filtering routine created by the JIT compiler and pointed by the next field 
	///< is used. See \ref NPF for details on the filtering process.
#ifdef _X86_
	JIT_BPF_Filter* Filter;			///< Pointer to the native filtering function created by the jitter. 
	///< See BPF_jitter() for details.
#endif //_X86_
	UINT MinToCopy;			///< Minimum amount of data in the circular buffer that unlocks a read. Set with the
	///< BIOCSMINTOCOPY IOCTL. 
	LARGE_INTEGER TimeOut;			///< Timeout after which a read is released, also if the amount of data in the buffer is 
	///< less than MinToCopy. Set with the BIOCSRTIMEOUT IOCTL.

	int mode;				///< Working mode of the driver. See PacketSetMode() for details.
	LARGE_INTEGER Nbytes;				///< Amount of bytes accepted by the filter when this instance is in statistical mode.
	LARGE_INTEGER Npackets;			///< Number of packets accepted by the filter when this instance is in statistical mode.
	NDIS_SPIN_LOCK CountersLock;		///< SpinLock that protects the statistical mode counters.
	UINT Nwrites;			///< Number of times a single write must be physically repeated. See \ref NPF for an 
	///< explanation
	ULONG Multiple_Write_Counter;	///< Counts the number of times a single write has already physically repeated.
	NDIS_EVENT WriteEvent;			///< Event used to synchronize the multiple write process.
	BOOLEAN WriteInProgress;	///< True if a write is currently in progress. NPF currently allows a single wite on 
	///< the same open instance.
	NDIS_SPIN_LOCK WriteLock;			///< SpinLock that protects the WriteInProgress variable.
	NDIS_EVENT NdisRequestEvent;	///< Event used to synchronize I/O requests with the callback structure of NDIS.
	BOOLEAN SkipSentPackets;	///< True if this instance should not capture back the packets that it transmits.
	NDIS_STATUS IOStatus;			///< Maintains the status of and OID request call, that will be passed to the application.
	HANDLE DumpFileHandle;		///< Handle of the file used in dump mode.
	PFILE_OBJECT DumpFileObject;		///< Pointer to the object of the file used in dump mode.
	PKTHREAD DumpThreadObject;	///< Pointer to the object of the thread used in dump mode.
	HANDLE DumpThreadHandle;	///< Handle of the thread created by dump mode to asynchronously move the buffer to disk.
	NDIS_EVENT DumpEvent;			///< Event used to synchronize the dump thread with the tap when the instance is in dump mode.
	LARGE_INTEGER DumpOffset;			///< Current offset in the dump file.
	UNICODE_STRING DumpFileName;		///< String containing the name of the dump file.
	UINT MaxDumpBytes;		///< Maximum dimension in bytes of the dump file. If the dump file reaches this size it 
	///< will be closed. A value of 0 means unlimited size.
	UINT MaxDumpPacks;		///< Maximum number of packets that will be saved in the dump file. If this number of 
	///< packets is reached the dump will be closed. A value of 0 means unlimited number of 
	///< packets.
	BOOLEAN DumpLimitReached;	///< TRUE if the maximum dimension of the dump file (MaxDumpBytes or MaxDumpPacks) is 
	///< reached.
#ifdef HAVE_BUGGY_TME_SUPPORT
	MEM_TYPE mem_ex;				///< Memory used by the TME virtual co-processor
	TME_CORE tme;				///< Data structure containing the virtualization of the TME co-processor
#endif //HAVE_BUGGY_TME_SUPPORT

	NDIS_SPIN_LOCK MachineLock;		///< SpinLock that protects the BPF filter and the TME engine, if in use.
	UINT MaxFrameSize;		///< Maximum frame size that the underlying MAC acceptes. Used to perform a check on the 
	///< size of the frames sent with NPF_Write() or NPF_BufferedWrite().
	//
	// KAFFINITY is used as a bit mask for the affinity in the system. So on every supported OS is big enough for all the CPUs on the system (32 bits on x86, 64 on x64?).
	// We use its size to compute the max number of CPUs.
	//
	CpuPrivateData CpuData[sizeof(KAFFINITY) * 8];		///< Pool of kernel buffer structures, one for each CPU.
	ULONG ReaderSN;			///< Sequence number of the next packet to be read from the pool of kernel buffers.
	ULONG WriterSN;			///< Sequence number of the next packet to be written in the pool of kernel buffers.
	///< These two sequence numbers are unique for each capture instance.
	ULONG Size;				///< Size of each kernel buffer contained in the CpuData field.
	ULONG AdapterHandleUsageCounter;
	NDIS_SPIN_LOCK AdapterHandleLock;
	ULONG AdapterBindingStatus;	///< Specifies if NPF is still bound to the adapter used by this instance, it's unbinding or it's not bound.	

	NDIS_EVENT NdisOpenCloseCompleteEvent;
	NDIS_EVENT NdisWriteCompleteEvent;	///< Event that is signalled when all the packets have been successfully sent by NdisSend (and corresponfing sendComplete has been called)
	NTSTATUS OpenCloseStatus;
	ULONG TransmitPendingPackets;	///< Specifies the number of packets that are pending to be transmitted, i.e. have been submitted to NdisSendXXX but the SendComplete has not been called yet.
	ULONG NumPendingIrps;
	BOOLEAN ClosePending; 
	NDIS_SPIN_LOCK OpenInUseLock;
}
OPEN_INSTANCE, * POPEN_INSTANCE;

enum ADAPTER_BINDING_STATUS
{
	ADAPTER_UNBOUND,
	ADAPTER_BOUND,
	ADAPTER_UNBINDING,
};

/*!
  \brief Structure prepended to each packet in the kernel buffer pool.
  
  Each packet in one of the kernel buffers is prepended by this header. It encapsulates the bpf_header, 
  which will be passed to user level programs, as well as the sequence number of the packet, set by the producer (the tap function),
  and used by the consumer (the read function) to "reorder" the packets contained in the various kernel buffers.
*/
struct PacketHeader
{
	ULONG SN;								///< Sequence number of the packet.
	struct bpf_hdr header;					///< bpf header, created by the tap, and copied unmodified to user level programs.
};

extern ULONG g_NCpu;
extern struct time_conv G_Start_Time; // from openclos.c
extern UINT g_SendPacketFlags;

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


/*!
  \brief The initialization routine of the driver.
  \param DriverObject The driver object of NPF created by the system.
  \param RegistryPath The registry path containing the keys related to the driver.
  \return A string containing a list of network adapters.

  DriverEntry is a mandatory function in a device driver. Like the main() of a user level program, it is called
  by the system when the driver is loaded in memory and started. Its purpose is to initialize the driver, 
  performing all the allocations and the setup. In particular, DriverEntry registers all the driver's I/O
  callbacks, creates the devices, defines NPF as a protocol inside NDIS.
*/ 
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);

/*!
  \brief Returns the list of the MACs available on the system.
  \return A string containing a list of network adapters.

  The list of adapters is retrieved from the 
  SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318} registry key. 
  NPF tries to create its bindings from this list. In this way it is possible to be loaded
  and unloaded dynamically without passing from the control panel.
*/
PWCHAR getAdaptersList(VOID);

/*!
  \brief Returns the MACs that bind to TCP/IP.
  \return Pointer to the registry key containing the list of adapters on which TCP/IP is bound.

  If getAdaptersList() fails, NPF tries to obtain the TCP/IP bindings through this function.
*/
PKEY_VALUE_PARTIAL_INFORMATION getTcpBindings(VOID);

/*!
  \brief Creates a device for a given MAC.
  \param adriverObjectP The driver object that will be associated with the device, i.e. the one of NPF.
  \param amacNameP The name of the network interface that the device will point.
  \return If the function succeeds, the return value is nonzero.

  NPF creates a device for every valid network adapter. The new device points to the NPF driver, but contains
  information about the original device. In this way, when the user opens the new device, NPF will be able to
  determine the correct adapter to use.
*/
BOOLEAN NPF_CreateDevice(IN OUT PDRIVER_OBJECT adriverObjectP, IN PUNICODE_STRING amacNameP);
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
NTSTATUS NPF_OpenAdapter(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

/*!
  \brief Closes an instance of the driver.
  \param DeviceObject Pointer to the device object utilized by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called when a running instance of the driver is closed by the user with a CloseHandle(). 
  It stops the capture/monitoring/dump process, deallocates the memory and the objects associated with the 
  instance and closing the files. The network adapter is then closed with a call to NdisCloseAdapter. 
*/
NTSTATUS NPF_Cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS NPF_CleanupForUnclosed(POPEN_INSTANCE Open);

NTSTATUS NPF_CloseAdapter(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS NPF_CloseAdapterForUnclosed(POPEN_INSTANCE pOpen);


/*!
  \brief Callback invoked by NDIS when a packet arrives from the network.
  \param ProtocolBindingContext Context of the function. Points to a OPEN_INSTANCE structure that identifies 
   the NPF instance to which the packets are destined.
  \param MacReceiveContext Handle that identifies the underlying NIC driver that generated the request. 
   This value must be used when the packet is transferred from the NIC driver with NdisTransferData().
  \param HeaderBuffer Pointer to the buffer in the NIC driver memory that contains the header of the packet.
  \param HeaderBufferSize Size in bytes of the header.
  \param LookAheadBuffer Pointer to the buffer in the NIC driver's memory that contains the incoming packet's 
   data <b>available to NPF</b>. This value does not necessarily coincide with the actual size of the packet,
   since only a portion can be available at this time. The remaining portion can be obtained with the
   NdisTransferData() NDIS function.
  \param LookaheadBufferSize Size in bytes of the lookahead buffer.
  \param PacketSize Total size of the incoming packet, excluded the header.
  \return The status of the operation. See ntstatus.h in the DDK.

  NPF_tap() is called by the underlying NIC for every incoming packet. It is the most important and one of 
  the most complex functions of NPF: it executes the filter, runs the statistical engine (if the instance is in 
  statistical mode), gathers the timestamp, moves the packet in the buffer. NPF_tap() is the only function,
  along with the filtering ones, that is executed for every incoming packet, therefore it is carefully 
  optimized.
*/

VOID NPF_tapExForEachOpen(IN POPEN_INSTANCE Open, IN PNET_BUFFER_LIST pNetBufferLists);

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
  - #BIOCSETDUMPFILENAME
  - #BIOCGEVNAME
  -	#BIOCSENDPACKETSSYNC
  -	#BIOCSENDPACKETSNOSYNC
*/
NTSTATUS NPF_IoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


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
NTSTATUS NPF_Write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


/*!
  \brief Writes a buffer of raw packets to the network.
  \param Irp Pointer to the IRP containing the user request.
  \param UserBuff Pointer to the buffer containing the packets to send.
  \param UserBuffSize Size of the buffer with the packets.
  \param sync If set to TRUE, the packets are transmitted respecting their timestamps.
  \return The amount of bytes actually sent. If the return value is smaller than the Size parameter, an
		  error occurred during the send. The error can be caused by an adapter problem or by an
		  inconsistent/bogus user buffer.

  This function is called by the OS in consequence of a BIOCSENDPACKETSNOSYNC or a BIOCSENDPACKETSSYNC IOCTL.
  The buffer received as input parameter contains an arbitrary number of packets, each of which preceded by a
  sf_pkthdr structure. NPF_BufferedWrite() scans the buffer and sends every packet via the NdisSend() function.
  When Sync is set to TRUE, the packets are synchronized with the KeQueryPerformanceCounter() function.
  This requires a remarkable amount of CPU, but allows to respect the timestamps associated with packets with a precision 
  of some microseconds (depending on the precision of the performance counter of the machine).
  If Sync is false, the timestamps are ignored and the packets are sent as fat as possible.
*/

INT NPF_BufferedWrite(IN PIRP Irp, IN PCHAR UserBuff, IN ULONG UserBuffSize, BOOLEAN sync);

/*!
  \brief Waits the completion of all the sends performed by NPF_BufferedWrite.

  \param Open Pointer to open context structure

  Used by NPF_BufferedWrite to wait the completion of all the sends before returning the control to the user.
*/
VOID NPF_WaitEndOfBufferedWrite(POPEN_INSTANCE Open);

/*!
*/

VOID NPF_SendCompleteExForEachOpen(IN POPEN_INSTANCE Open, BOOLEAN FreeBufAfterWrite);

/*!
  \brief Callback for NDIS StatusHandler. Not used by NPF
*/
VOID NPF_StatusEx(IN NDIS_HANDLE				ProtocolBindingContext, IN PNDIS_STATUS_INDICATION	StatusIndication);


/*!
  \brief Callback for NDIS StatusCompleteHandler. Not used by NPF
*/
VOID NPF_StatusComplete(IN NDIS_HANDLE  ProtocolBindingContext);


/*!
  \brief Function that serves the user's reads.
  \param DeviceObject Pointer to the device used by the user.
  \param Irp Pointer to the IRP containing the user request.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function is called by the OS in consequence of user ReadFile() call. It moves the data present in the
  kernel buffer to the user buffer associated with Irp.
  First of all, NPF_Read checks the amount of data in kernel buffer associated with current NPF instance. 
  - If the instance is in capture mode and the buffer contains more than OPEN_INSTANCE::MinToCopy bytes,
  NPF_Read moves the data in the user buffer and returns immediatly. In this way, the read performed by the
  user is not blocking.
  - If the buffer contains less than MinToCopy bytes, the application's request isn't 
  satisfied immediately, but it's blocked until at least MinToCopy bytes arrive from the net 
  or the timeout on this read expires. The timeout is kept in the OPEN_INSTANCE::TimeOut field.
  - If the instance is in statistical mode or in dump mode, the application's request is blocked until the 
  timeout kept in OPEN_INSTANCE::TimeOut expires.
*/
NTSTATUS NPF_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


void NPF_AddToOpenArray(POPEN_INSTANCE Open);

/*!

*/
void NPF_AddToGroupOpenArray(POPEN_INSTANCE Open);

/*!

*/
void NPF_RemoveFromOpenArray(POPEN_INSTANCE Open);

/*!

*/
void NPF_RemoveFromGroupOpenArray(POPEN_INSTANCE Open);

/*!

*/
int NPF_CompareAdapterName(PNDIS_STRING s1, PNDIS_STRING s2);

/*!

*/
POPEN_INSTANCE NPF_GetCopyFromOpenArray(PNDIS_STRING pAdapterName, PDEVICE_EXTENSION DeviceExtension);

void NPF_RemoveUnclosedAdapters();

POPEN_INSTANCE NPF_DuplicateOpenObject(POPEN_INSTANCE OriginalOpen, PDEVICE_EXTENSION DeviceExtension);

POPEN_INSTANCE NPF_CreateOpenObject(PNDIS_STRING AdapterName, UINT SelectedIndex, PDEVICE_EXTENSION DeviceExtension);

/*!
  \brief Creates the file that will receive the packets when the driver is in dump mode.
  \param Open The NPF instance that opens the file.
  \param fileName Pointer to a UNICODE string containing the name of the file.
  \param append Boolean value that specifies if the data must be appended to the file.
  \return The status of the operation. See ntstatus.h in the DDK.
*/
NTSTATUS NPF_OpenDumpFile(POPEN_INSTANCE Open, PUNICODE_STRING fileName, BOOLEAN append);

/*!
  \brief Starts dump to file.
  \param Open The NPF instance that opens the file.
  \return The status of the operation. See ntstatus.h in the DDK.

  This function performs two operations. First, it writes the libpcap header at the beginning of the file.
  Second, it starts the thread that asynchronously dumps the network data to the file.
*/
NTSTATUS NPF_StartDump(POPEN_INSTANCE Open);

/*!
  \brief The dump thread.
  \param Open The NPF instance that creates the thread.

  This function moves the content of the NPF kernel buffer to file. It runs in the user context, so at lower 
  priority than the TAP.
*/
VOID NPF_DumpThread(PVOID Open);

/*!
  \brief Saves the content of the packet buffer to the file associated with current instance.
  \param Open The NPF instance that creates the thread.

  Used by NPF_DumpThread() and NPF_CloseDumpFile().
*/
NTSTATUS NPF_SaveCurrentBuffer(POPEN_INSTANCE Open);

/*!
  \brief Writes a block of packets on the dump file.
  \param FileObject The file object that will receive the packets.
  \param Offset The offset in the file where the packets will be put.
  \param Length The amount of bytes to write.
  \param Mdl MDL mapping the memory buffer that will be written to disk.
  \param IoStatusBlock Used by the function to return the status of the operation.
  \return The status of the operation. See ntstatus.h in the DDK.

  NPF_WriteDumpFile addresses directly the file system, creating a custom IRP and using it to send a portion
  of the NPF circular buffer to disk. This function is used by NPF_DumpThread().
*/
VOID NPF_WriteDumpFile(PFILE_OBJECT FileObject, PLARGE_INTEGER Offset, ULONG Length, PMDL Mdl, PIO_STATUS_BLOCK IoStatusBlock);



/*!
  \brief Closes the dump file associated with an instance of the driver.
  \param Open The NPF instance that closes the file.
  \return The status of the operation. See ntstatus.h in the DDK.
*/
NTSTATUS NPF_CloseDumpFile(POPEN_INSTANCE Open);

BOOLEAN NPF_StartUsingBinding(IN POPEN_INSTANCE pOpen);

VOID NPF_StopUsingBinding(IN POPEN_INSTANCE pOpen);

VOID NPF_CloseBinding(IN POPEN_INSTANCE pOpen);

VOID NPF_CloseBindingAndAdapter(IN POPEN_INSTANCE pOpen);

BOOLEAN NPF_StartUsingOpenInstance(IN POPEN_INSTANCE pOpen);

VOID NPF_StopUsingOpenInstance(IN POPEN_INSTANCE pOpen);

VOID NPF_CloseOpenInstance(IN POPEN_INSTANCE pOpen);

NTSTATUS NPF_GetDeviceMTU(IN POPEN_INSTANCE pOpen, IN PIRP	pIrp, OUT PUINT  pMtu);

/*!
  \brief Returns the amount of bytes present in the packet buffer.
  \param Open The NPF instance that closes the file.
*/
UINT GetBuffOccupation(POPEN_INSTANCE Open);

//  
//	Old registry based WinPcap names
//
///*!
//  \brief Helper function to query a value from the global WinPcap registry key
//*/
//VOID NPF_QueryWinpcapRegistryString(PWSTR SubKeyName,
//								 WCHAR *Value,
//  							 UINT ValueLen, 
//								 WCHAR *DefaultValue);
//

VOID NPF_ResetBufferContents(POPEN_INSTANCE Open);

/**
 *  @}
 */

/**
 *  @}
 */

#endif  /*main ifndef/define*/