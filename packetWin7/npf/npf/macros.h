#ifndef __MACRO
#define __MACRO

#define NPF6X_CANCEL_ID_LOW_MASK	 (((ULONG_PTR)-1) >> 8)

#define NPF6X_GET_NEXT_CANCEL_ID()  												 \
	(PVOID)(Globals.PartialCancelId |   										\
	((NdisInterlockedIncrement((PLONG)&Globals.LocalCancelId)) & NPROT_CANCEL_ID_LOW_MASK))

// #define NPF6XSetNBLFlags(_NBL, _Flags)     (DWORD) ((_NBL)->ProtocolReserved[0]) |= (_Flags)
// #define NPF6XClearNBLFlags(_NBL, _Flags)   (DWORD) ((_NBL)->ProtocolReserved[0]) &= ~(_Flags)

// #define NPF6XSetNBLTag(_NBL, _Flags)		 ((_NBL)->ProtocolReserved[2]) = (_Flags)
// #define NPF6XGetNBLTag(_NBL)				 ((_NBL)->ProtocolReserved[2])

#define NPF6XSetNBLChildOpen(_NBL, _Flags)		 ((_NBL)->Scratch) = (_Flags)
#define NPF6XGetNBLChildOpen(_NBL)				 ((_NBL)->Scratch)

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