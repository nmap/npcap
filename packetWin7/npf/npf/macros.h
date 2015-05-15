#ifndef __MACRO
#define __MACRO

#define NPF_CANCEL_ID_LOW_MASK	 (((ULONG_PTR)-1) >> 8)

#define NPF_GET_NEXT_CANCEL_ID()  												 \
	(PVOID)(Globals.PartialCancelId |   										\
	((NdisInterlockedIncrement((PLONG)&Globals.LocalCancelId)) & NPROT_CANCEL_ID_LOW_MASK))

// #define NPFSetNBLFlags(_NBL, _Flags)     (DWORD) ((_NBL)->ProtocolReserved[0]) |= (_Flags)
// #define NPFClearNBLFlags(_NBL, _Flags)   (DWORD) ((_NBL)->ProtocolReserved[0]) &= ~(_Flags)

// #define NPFSetNBLTag(_NBL, _Flags)		 ((_NBL)->ProtocolReserved[2]) = (_Flags)
// #define NPFGetNBLTag(_NBL)				 ((_NBL)->ProtocolReserved[2])

//////////////////////////////////////////////////////////////////////////////////////////////////
// NPF_Write is waiting for NdisWriteCompleteEvent event, which should be
// signaled by NPF_SendCompleteExForEachOpen() function but it was not called
// on some NIC cards / drivers(virtio, Intel(R) PRO / 1000 MT Desktop Adapter)
// 
// It seems that some drivers are using NET_BUFFER_LIST->Scratch pointer for their own
// data, which overwrite NPF information about file handle which is waiting for completion.
// 
// Workaround the issue by not using NET_BUFFER_LIST->Scratch, but ProtocolReserved.
// I'm not 100% if ProtocolReserved information might not be overwriten on some setup,
// so in the future I would recomend rewriting it to use NET_BUFFER_LIST->Context,
// or some other structure for keeping that information.
// 
// For now it seems that workaround is working good.
// #define NPFSetNBLChildOpen(_NBL, _Flags)		 ((_NBL)->Scratch) = (_Flags)
// #define NPFGetNBLChildOpen(_NBL)				 ((_NBL)->Scratch)
#define NPFSetNBLChildOpen(_NBL, _Flags)		 (RESERVED(_NBL)->ChildOpen) = (_Flags)
#define NPFGetNBLChildOpen(_NBL)				 (RESERVED(_NBL)->ChildOpen)
//////////////////////////////////////////////////////////////////////////////////////////////////

#define NPROT_MAC_ADDR_LEN            6

typedef struct _NDISPROT_ETH_HEADER
{
	UCHAR       DstAddr[NPROT_MAC_ADDR_LEN];
	UCHAR       SrcAddr[NPROT_MAC_ADDR_LEN];
	USHORT      EthType;

} NDISPROT_ETH_HEADER;

typedef struct _NDISPROT_ETH_HEADER UNALIGNED * PNDISPROT_ETH_HEADER;

#define NPROT_ETH_TYPE               0x8e88
#define NPROT_8021P_TAG_TYPE         0x0081

#endif