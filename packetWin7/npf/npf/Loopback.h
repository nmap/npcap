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

#endif

#endif // __LOOPBACK
