/*
 * Copyright (c) 2005-2007 CACE Technologies
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
 * 3. Neither the name of CACE Technologies nor the names of its
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
#ifndef __WPCAPNAMES_H_EED6D131C6DB4dd696757D219977A7E5
#define __WPCAPNAMES_H_EED6D131C6DB4dd696757D219977A7E5


//
// Original names
//
//  NOTE: 
//  - please do not use prefix names longer than 70 chars. 
//  - the following characters are surely accepted in the prefixes:  "[A-Z][a-z][0-9]_-',"   
//
#ifdef NPF_NPCAP_RUN_IN_WINPCAP_MODE
	#define NPF_DRIVER_NAME							"NPF"												///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_WIDECHAR				L"NPF"												///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_SMALL					"npf"												///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_SMALL_WIDECHAR			L"npf"												///< (HHH) Packet.dll
#else
	#define NPF_DRIVER_NAME							"NPCAP"												///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_WIDECHAR				L"NPCAP"											///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_SMALL					"npcap"												///< (HHH) Packet.dll
	#define NPF_DRIVER_NAME_SMALL_WIDECHAR			L"npcap"											///< (HHH) Packet.dll
#endif

#define NPF_DRIVER_NAME_NORMAL					"Npcap"												///< (HHH) Packet.dll
#define NPF_DRIVER_NAME_NORMAL_WIDECHAR			L"Npcap"											///< (HHH) Packet.dll
#define NPF_SOFT_REGISTRY_NAME					"NPCAP"												///< (HHH) Packet.dll
#define NPF_SOFT_REGISTRY_NAME_WIDECHAR			L"NPCAP"											///< (HHH) Packet.dll

#define NPF_ORGAN_NAME							"INSECURE"											///< (HHH) Packet.dll
#define NPF_ORGAN_NAME_WIDECHAR					L"INSECURE"											///< (HHH) Packet.dll

//
// Derived strings
//
#define NPF_DEVICE_NAMES_PREFIX				NPF_DRIVER_NAME "_"     								///< (AAA) packet.dll
#define NPF_DEVICE_NAMES_PREFIX_WIDECHAR	NPF_DRIVER_NAME_WIDECHAR L"_"     						///< (AAA) used by the NPF driver, that does not accept the TEXT(a) macro correctly.
#define NPF_EVENTS_NAMES					NPF_DRIVER_NAME											///< (BBB) 
#define NPF_EVENTS_NAMES_WIDECHAR			NPF_DRIVER_NAME_WIDECHAR								///< (BBB) used by the NPF driver, that does not accept the TEXT(a) macro correctly.
#define FAKE_NDISWAN_ADAPTER_NAME			"\\Device\\" NPF_DRIVER_NAME "_GenericDialupAdapter"	///< (CCC) Name of a fake ndiswan adapter that is always available on 2000/XP/2003, used to capture NCP/LCP packets
#define FAKE_NDISWAN_ADAPTER_DESCRIPTION	"Adapter for generic dialup and VPN capture"			///< (DDD) Description of a fake ndiswan adapter that is always available on 2000/XP/2003, used to capture NCP/LCP packets
#define NPF_SERVICE_DESC					NPF_DRIVER_NAME_NORMAL " Packet Driver (" NPF_DRIVER_NAME ")"				///< (FFF) packet.dll
#define NPF_SERVICE_DESC_WIDECHAR			NPF_DRIVER_NAME_NORMAL_WIDECHAR L" Packet Driver (" NPF_DRIVER_NAME_WIDECHAR L")"	///< (FFF) packet.dll
#define NPF_SERVICE_DESC_TCHAR				_T(NPF_DRIVER_NAME_NORMAL) _T(" Packet Driver (") _T(NPF_DRIVER_NAME) _T(")")	///< (FFF) packet.dll
#define NPF_DRIVER_COMPLETE_DEVICE_PREFIX	"\\Device\\" NPF_DRIVER_NAME "_"						///< (III) packet.dll
#define NPF_DRIVER_COMPLETE_PATH			"system32\\drivers\\" NPF_DRIVER_NAME ".sys"			///< (LLL) packet.dll


//
// WinPcap Global Registry Key
//
#define WINPCAP_GLOBAL_KEY				"SOFTWARE\\CaceTech\\WinPcapOem"
#define WINPCAP_GLOBAL_KEY_WIDECHAR		L"SOFTWARE\\CaceTech\\WinPcapOem"
#define WINPCAP_INSTANCE_KEY			WINPCAP_GLOBAL_KEY "\\" NPF_DRIVER_NAME
#define WINPCAP_INSTANCE_KEY_WIDECHAR	WINPCAP_GLOBAL_KEY_WIDECHAR	L"\\" NPF_DRIVER_NAME_WIDECHAR
#define MAX_WINPCAP_KEY_CHARS 512

//
// Subkeys names
//
#define NPF_DEVICES_PREFIX_REG_KEY				"NpfDeviceNamesPrefix"		///< (AAA) 
#define NPF_DEVICES_PREFIX_REG_KEY_WC			L"NpfDeviceNamesPrefix"		///< (AAA) used by the NPF driver, that does not accept the TEXT(a) macro correctly.
#define NPF_EVENTS_NAMES_REG_KEY				"NpfEventsNames"			///< (BBB) 
#define NPF_EVENTS_NAMES_REG_KEY_WC				L"NpfEventsNames"			///< (BBB) used by the NPF driver, that does not accept the TEXT(a) macro correctly.	
#define NPF_FAKE_NDISWAN_ADAPTER_NAME_REG_KEY	"NdiswanAdapterName"		///< (CCC) packet.dll
#define NPF_FAKE_NDISWAN_ADAPTER_DESC_REG_KEY	"NdiswanAdapterDescription"	///< (DDD) packet.dll
#define NPF_SERVICE_DESC_REG_KEY				"NpfServiceDescription"		///< (FFF) packet.dll
#define NPF_DRIVER_NAME_REG_KEY					"NpfDriverName"				///< (HHH) packet.dll
#define NPF_DRIVER_COMPLETE_DEVICE_PREFIX_REG_KEY "NpfCompleteDriverPrefix"	///< (III) packet.dll
#define NPF_DRIVER_COMPLETE_PATH_REG_KEY		"NpfDriverCompletePath"		///< (LLL) 

#endif //__WPCAPNAMES_H_EED6D131C6DB4dd696757D219977A7E5

