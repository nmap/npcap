/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2020 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and may not be redistributed or incorporated   *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
 *                                                                         *
 ***************************************************************************/
/*
 * Copyright (c) 2001 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2007 CACE Technologies, Davis (California)
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

#ifndef _time_calls
#define _time_calls

#ifdef WIN_NT_DRIVER

#include "debug.h"
#include "ndis.h"
#define DEFAULT_TIMESTAMPMODE 0

#define TIMESTAMPMODE_SINGLE_SYNCHRONIZATION 0
#define /* DEPRECATED */ TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP 1
#define TIMESTAMPMODE_QUERYSYSTEMTIME 2
#define /* DEPRECATED */ TIMESTAMPMODE_RDTSC 3
#define TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE 4
#define /* DEPRECATED */ TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP 99

__inline BOOLEAN NPF_TimestampModeSupported(_In_ ULONG mode)
{
	return mode == TIMESTAMPMODE_SINGLE_SYNCHRONIZATION
		|| mode == TIMESTAMPMODE_QUERYSYSTEMTIME
		|| mode == TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE;
}

typedef void(*PQUERYSYSTEMTIME)(
	PLARGE_INTEGER CurrentTime
	);

extern ULONG g_TimestampMode;
extern PQUERYSYSTEMTIME g_ptrQuerySystemTime;

/*!
  \brief A microsecond precise timestamp.

  included in the sf_pkthdr or the bpf_hdr that NPF associates with every packet. 
*/
struct timeval
{
	long tv_sec;		 ///< seconds
	long tv_usec;   	 ///< microseconds
};

#endif /*WIN_NT_DRIVER*/

#ifdef WIN_NT_DRIVER

#pragma optimize ("g",off)  //Due to some weird behaviour of the optimizer of DDK build 2600 

/* KeQueryPerformanceCounter TimeStamps */
__inline void TIME_SYNCHRONIZE(
		_Out_ struct timeval* start)
{
	//	struct timeval *start = (struct timeval*)Data;

	//struct timeval tmp;
	LARGE_INTEGER SystemTime;
	//LARGE_INTEGER i;
	//ULONG tmp2;
	LARGE_INTEGER TimeFreq, PTime;

	// get the absolute value of the system boot time.   
	NT_ASSERT(g_ptrQuerySystemTime != NULL);
	PTime = KeQueryPerformanceCounter(&TimeFreq);
	g_ptrQuerySystemTime(&SystemTime);

	start->tv_sec = (LONG)(SystemTime.QuadPart / 10000000 - 11644473600);

	start->tv_usec = (LONG)((SystemTime.QuadPart % 10000000) / 10);

	start->tv_sec -= (ULONG)(PTime.QuadPart / TimeFreq.QuadPart);

	start->tv_usec -= (LONG)((PTime.QuadPart % TimeFreq.QuadPart) * 1000000 / TimeFreq.QuadPart);

	if (start->tv_usec < 0)
	{
		start->tv_sec --;
		start->tv_usec += 1000000;
	}
}	

__inline void GetTimeKQPC(
		_Out_ struct timeval* dst,
		_In_ struct timeval* start)
{
	LARGE_INTEGER PTime, TimeFreq;
	LONG tmp;

	PTime = KeQueryPerformanceCounter(&TimeFreq);
	tmp = (LONG)(PTime.QuadPart / TimeFreq.QuadPart);

	//it should be only the normal case i.e. TIMESTAMPMODE_SINGLESYNCHRONIZATION
	dst->tv_sec = start->tv_sec + tmp;
	dst->tv_usec = start->tv_usec + (LONG)((PTime.QuadPart % TimeFreq.QuadPart) * 1000000 / TimeFreq.QuadPart);

	if (dst->tv_usec >= 1000000)
	{
		dst->tv_sec ++;
		dst->tv_usec -= 1000000;
	}
}

__inline void GetTimeQST(
		_Out_ struct timeval* dst)
{
	LARGE_INTEGER SystemTime;

	KeQuerySystemTime(&SystemTime);

	dst->tv_sec = (LONG)(SystemTime.QuadPart / 10000000 - 11644473600);
	dst->tv_usec = (LONG)((SystemTime.QuadPart % 10000000) / 10);
}

__inline void GetTimeQST_precise(
		_Out_ struct timeval* dst)
{
	LARGE_INTEGER SystemTime;

	g_ptrQuerySystemTime(&SystemTime);

	dst->tv_sec = (LONG)(SystemTime.QuadPart / 10000000 - 11644473600);
	dst->tv_usec = (LONG)((SystemTime.QuadPart % 10000000) / 10);
}


#pragma optimize ("g",on)  //Due to some weird behaviour of the optimizer of DDK build 2600 


__inline void GET_TIME(
		_Out_ struct timeval* dst,
		_In_ struct timeval* start,
		_In_ ULONG TimestampMode)
{
	switch (TimestampMode)
	{
		case TIMESTAMPMODE_QUERYSYSTEMTIME:
			GetTimeQST(dst);
			break;
		case TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE:
			GetTimeQST_precise(dst);
			break;
		default:
			GetTimeKQPC(dst, start);
			break;
	}
}


#else /*WIN_NT_DRIVER*/

__inline void FORCE_TIME(
		_In_ struct timeval* src,
		_Out_ struct timeval* dest)
{
	*dest = *src;
}

__inline void GET_TIME(
		_Out_ struct timeval* dst,
		_In_ struct timeval* data)
{
	*dst = *data;
}

#endif /*WIN_NT_DRIVER*/


#endif /*_time_calls*/
