/*
* Copyright (c) 1997 - 2015
* Nmap.org (U.S.)
* All rights reserved.
*
* Loopback.h
*
* Abstract:
* This file declares common data types and function prototypes used
* throughout loopback packets capturing.
*
* This code is based on Microsoft WFP Network Inspect sample.
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

#ifndef __LOOPBACK
#define __LOOPBACK

#ifdef HAVE_WFP_LOOPBACK_SUPPORT

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>

#define IPPROTO_NPCAP_LOOPBACK		250

//
// Protocol headers
//

#pragma pack(push)
#pragma pack (1)

/*
* The number of bytes in an Ethernet (MAC) address.
*/
#define	ETHER_ADDR_LEN		6

/*
* The number of bytes in the type field.
*/
#define	ETHER_TYPE_LEN		2

/*
* The length of the combined header.
*/
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)

/*
* Structure of a 10Mb/s Ethernet header.
*/
typedef struct _ETHER_HEADER
{
	UCHAR	ether_dhost[ETHER_ADDR_LEN];
	UCHAR	ether_shost[ETHER_ADDR_LEN];
	USHORT	ether_type;
} ETHER_HEADER, *PETHER_HEADER;

/*
* Types in an Ethernet (MAC) header.
*/
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define	ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define	ETHERTYPE_LOOPBACK	0x9000	/* used to test interfaces */

/*
* Structure of a DLT_NULL header.
*/
typedef struct _DLT_NULL_HEADER
{
	UINT	null_type;
} DLT_NULL_HEADER, *PDLT_NULL_HEADER;

/*
* The length of the combined header.
*/
#define	DLT_NULL_HDR_LEN	sizeof(DLT_NULL_HEADER)

/*
* Types in a DLT_NULL (Loopback) header.
*/
#define	DLTNULLTYPE_IP		0x0002	/* IP protocol */
#define	DLTNULLTYPE_IPV6	0x0017	/* IPv6 */

/*
* Structure of a IPv4 header, based on netinet/ip.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP_HEADER
{
	UCHAR     ip_hVerLen;			/* Version (4 bits) + Internet header length (4 bits) */
	UCHAR     ip_TOS;				/* TOS Type of service */
	USHORT    ip_Length;			/* Total length */
	USHORT    ip_ID;				/* Identification */
	USHORT    ip_Flags;				/* Flags (3 bits) + Fragment offset (13 bits) */
	UCHAR     ip_TTL;				/* Time to live */
	UCHAR     ip_Protocol;			/* Protocol */
	USHORT    ip_Checksum;			/* Header checksum */
	ULONG     ip_Src;				/* Source address */
	ULONG     ip_Dst;				/* Destination address */
} IP_HEADER, *PIP_HEADER;

/*
* The length of the IPv4 header.
*/
#define	IP_HDR_LEN		sizeof(IP_HEADER)

/*
* Structure of a IPv6 header, based on netinet/ip6.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP6_HEADER
{
	union
	{
		struct _ip6_HeaderCtl
		{
			ULONG ip6_VerFlow;		/* 4 bits version, 8 bits TC, 20 bits flow-ID */
			USHORT ip6_PLength;		/* Payload length */
			UCHAR ip6_NextHeader;	/* Next header */
			UCHAR ip6_HopLimit;		/* Hop limit */
		} ip6_HeaderCtl;
		UCHAR ip6_VFC;				/* 4 bits version, top 4 bits tclass */
	} ip6_CTL;
	struct in6_addr ip6_Src;		/* Source address */
	struct in6_addr ip6_Dst;		/* Destination address */
} IP6_HEADER, *PIP6_HEADER;

/*
* The length of the IPv6 header.
*/
#define	IPV6_HDR_LEN		sizeof(IP6_HEADER)

#pragma pack(pop)

//
// Shared function prototypes
//

#if(NTDDI_VERSION >= NTDDI_WIN7)

void
NPF_NetworkClassify(
_In_ const FWPS_INCOMING_VALUES* inFixedValues,
_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
_Inout_opt_ void* layerData,
_In_opt_ const void* classifyContext,
_In_ const FWPS_FILTER* filter,
_In_ UINT64 flowContext,
_Inout_ FWPS_CLASSIFY_OUT* classifyOut
	);

#else /// (NTDDI_VERSION >= NTDDI_WIN7)

void
NPF_NetworkClassify(
_In_ const FWPS_INCOMING_VALUES* inFixedValues,
_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
_Inout_opt_ void* layerData,
_In_ const FWPS_FILTER* filter,
_In_ UINT64 flowContext,
_Inout_ FWPS_CLASSIFY_OUT* classifyOut
	);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

NTSTATUS
NPF_NetworkNotify(
_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
_In_ const GUID* filterKey,
_Inout_ const FWPS_FILTER* filter
	);

NTSTATUS
NPF_AddFilter(
_In_ const GUID* layerKey,
_In_ const GUID* calloutKey,
_In_ const int iFlag
	);

NTSTATUS
NPF_RegisterCallout(
_In_ const GUID* layerKey,
_In_ const GUID* calloutKey,
_Inout_ void* deviceObject,
_Out_ UINT32* calloutId
	);

NTSTATUS
NPF_RegisterCallouts(
_Inout_ void* deviceObject
	);

void
NPF_UnregisterCallouts(
	);

NTSTATUS
NPF_InitInjectionHandles(
	);

NTSTATUS
NPF_FreeInjectionHandles(
	);

#endif // HAVE_WFP_LOOPBACK_SUPPORT

#endif // __LOOPBACK
