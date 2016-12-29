/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2016 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and my not be redistributed or incorporated    *
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
#define	DEFAULT_TIMESTAMPMODE								0

#define TIMESTAMPMODE_SINGLE_SYNCHRONIZATION				0
#define TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP		1
#define TIMESTAMPMODE_QUERYSYSTEMTIME						2
#define TIMESTAMPMODE_RDTSC									3

#define TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP		99

extern ULONG g_TimestampMode;

/* Defined in Packet.c/h */
ULONG
My_NdisGroupMaxProcessorCount(
);

/* Defined in Packet.c/h */
ULONG
My_KeGetCurrentProcessorNumber(
);

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

// Maximum CPU core number, the original value is sizeof(KAFFINITY) * 8, but Amazon instance can return 128 cores, so we make NPF_MAX_CPU_NUMBER to 256 for safe.
#define NPF_MAX_CPU_NUMBER		sizeof(KAFFINITY) * 32

struct time_conv
{
	ULONGLONG reference;
	struct timeval start[NPF_MAX_CPU_NUMBER];
};

#ifdef WIN_NT_DRIVER

__inline void TIME_DESYNCHRONIZE(struct time_conv* data)
{
	data->reference = 0;
	//	data->start.tv_sec = 0;
	//	data->start.tv_usec = 0;
}

#pragma optimize ("g",off)  //Due to some weird behaviour of the optimizer of DDK build 2600 

/* KeQueryPerformanceCounter TimeStamps */
__inline void SynchronizeOnCpu(struct timeval* start)
{
	//	struct timeval *start = (struct timeval*)Data;

	//struct timeval tmp;
	LARGE_INTEGER SystemTime;
	//LARGE_INTEGER i;
	//ULONG tmp2;
	LARGE_INTEGER TimeFreq, PTime;

	// get the absolute value of the system boot time.   

	PTime = KeQueryPerformanceCounter(&TimeFreq);
	KeQuerySystemTime(&SystemTime);

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

//
// inline assembler is not supported with the current AMD64 compilers
// At the moment we simply disable this timestamping mode on AMD64.
// A solution would be to allocate a small memory from the non-paged
// pool, dump the instructions on that buffer, and then execute them.
// The non paged pool is needed since it's the only area of kernel
// data memory that is not subject to the NX protection.
// Or use some lower level trick, like using an assembler to assemble
// a small function for this. 
//

#ifdef _X86_
/*RDTSC timestamps			*/
/* callers must be at IRQL=PASSIVE_LEVEL*/
__inline VOID TimeSynchronizeRDTSC(struct time_conv* data)
{
	struct timeval tmp;
	LARGE_INTEGER system_time;
	ULONGLONG curr_ticks;
	KIRQL old;
	LARGE_INTEGER start_kqpc, stop_kqpc, start_freq, stop_freq;
	ULONGLONG start_ticks, stop_ticks;
	ULONGLONG delta, delta2;
	KEVENT event;
	LARGE_INTEGER i;
	ULONGLONG reference;

	if (data->reference != 0)
		return;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	i.QuadPart = -3500000;

	KeRaiseIrql(HIGH_LEVEL, &old);
	start_kqpc = KeQueryPerformanceCounter(&start_freq);
	__asm
	{
	push eax
	push edx
	push ecx
	rdtsc
	lea ecx, start_ticks
	mov[ecx + 4], edx
	mov[ecx], eax
	pop ecx
	pop edx
	pop eax
	}

	KeLowerIrql(old);

	KeWaitForSingleObject(&event, UserRequest, KernelMode, TRUE, &i);

	KeRaiseIrql(HIGH_LEVEL, &old);
	stop_kqpc = KeQueryPerformanceCounter(&stop_freq);
	__asm
	{
	push eax
	push edx
	push ecx
	rdtsc
	lea ecx, stop_ticks
	mov[ecx + 4], edx
	mov[ecx], eax
	pop ecx
	pop edx
	pop eax
	}
	KeLowerIrql(old);

	delta = stop_ticks - start_ticks;
	delta2 = stop_kqpc.QuadPart - start_kqpc.QuadPart;
	if (delta > 10000000000)
	{
		delta /= 16;
		delta2 /= 16;
	}

	reference = delta * (start_freq.QuadPart) / delta2;

	data->reference = reference / 1000;

	if (reference % 1000 > 500)
		data->reference++;

	data->reference *= 1000;

	reference = data->reference;

	KeQuerySystemTime(&system_time);

	__asm
	{
	push eax
	push edx
	push ecx
	rdtsc
	lea ecx, curr_ticks
	mov[ecx + 4], edx
	mov[ecx], eax
	pop ecx
	pop edx
	pop eax
	}

	tmp.tv_sec = -(LONG)(curr_ticks / reference);

	tmp.tv_usec = -(LONG)((curr_ticks % reference) * 1000000 / reference);

	system_time.QuadPart -= 116444736000000000;

	tmp.tv_sec += (LONG)(system_time.QuadPart / 10000000);
	tmp.tv_usec += (LONG)((system_time.QuadPart % 10000000) / 10);

	if (tmp.tv_usec < 0)
	{
		tmp.tv_sec--;
		tmp.tv_usec += 1000000;
	}

	data->start[0] = tmp;

	IF_LOUD(DbgPrint("Frequency %I64u MHz\n", data->reference);)
}
#endif //_X86_

#pragma optimize ("g",on)  //Due to some weird behaviour of the optimizer of DDK build 2600 

__inline VOID TIME_SYNCHRONIZE(struct time_conv* data)
{
	ULONG NumberOfCpus, i;
	KAFFINITY AffinityMask;

	if (data->reference != 0)
		return;

	NumberOfCpus = My_NdisGroupMaxProcessorCount();

	if (g_TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP || g_TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP)
	{
		for (i = 0 ; i < NumberOfCpus ; i++)
		{
			//
			// the following cast is needed because KAFFINITY is defined as a 32bit value on x86 and a 64bit integer on x64.
			// The constant 1 is implicitely 32bit only, so a shift won't work properly on x64.
			//
			AffinityMask = ((KAFFINITY)1 << i);
			ZwSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &AffinityMask, sizeof(KAFFINITY));
			SynchronizeOnCpu(&(data->start[i]));
		}
		AffinityMask = 0xFFFFFFFF;
		ZwSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &AffinityMask, sizeof(KAFFINITY));
		data->reference = 1;
	}
	else if (g_TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME)
	{
		//do nothing
		data->reference = 1;
	}
	else
		//
		// This timestamp mode is supported on x86 (32 bit) only
		//
		#ifdef _X86_
	if (g_TimestampMode == TIMESTAMPMODE_RDTSC)
	{
		TimeSynchronizeRDTSC(data);
	}
	else
		#endif // _X86_
	{
		//it should be only the normal case i.e. TIMESTAMPMODE_SINGLESYNCHRONIZATION
		SynchronizeOnCpu(data->start);
		data->reference = 1;
	}
	return;
}


#pragma optimize ("g",off)  //Due to some weird behaviour of the optimizer of DDK build 2600 

__inline void GetTimeKQPC(struct timeval* dst, struct time_conv* data)
{
	LARGE_INTEGER PTime, TimeFreq;
	LONG tmp;
	ULONG CurrentCpu;
	static struct timeval old_ts =
	{
		0, 0
	};


	PTime = KeQueryPerformanceCounter(&TimeFreq);
	tmp = (LONG)(PTime.QuadPart / TimeFreq.QuadPart);

	if (g_TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP || g_TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP)
	{
		//actually this code is ok only if we are guaranteed that no thread scheduling will take place. 
		CurrentCpu = My_KeGetCurrentProcessorNumber();

		dst->tv_sec = data->start[CurrentCpu].tv_sec + tmp;
		dst->tv_usec = data->start[CurrentCpu].tv_usec + (LONG)((PTime.QuadPart % TimeFreq.QuadPart) * 1000000 / TimeFreq.QuadPart);

		if (dst->tv_usec >= 1000000)
		{
			dst->tv_sec ++;
			dst->tv_usec -= 1000000;
		}

		if (g_TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP)
		{
			if (old_ts.tv_sec > dst->tv_sec || (old_ts.tv_sec == dst->tv_sec && old_ts.tv_usec > dst->tv_usec))
				*dst = old_ts;
			else
				old_ts = *dst;
		}
	}
	else
	{
		//it should be only the normal case i.e. TIMESTAMPMODE_SINGLESYNCHRONIZATION
		dst->tv_sec = data->start[0].tv_sec + tmp;
		dst->tv_usec = data->start[0].tv_usec + (LONG)((PTime.QuadPart % TimeFreq.QuadPart) * 1000000 / TimeFreq.QuadPart);

		if (dst->tv_usec >= 1000000)
		{
			dst->tv_sec ++;
			dst->tv_usec -= 1000000;
		}
	}
}

//
// inline assembler is not supported with the current AMD64 compilers
// At the moment we simply disable this timestamping mode on AMD64.
// A solution would be to allocate a small memory from the non-paged
// pool, dump the instructions on that buffer, and then execute them.
// The non paged pool is needed since it's the only area of kernel
// data memory that is not subject to the NX protection.
// Or use some lower level trick, like using an assembler to assemble
// a small function for this. 
//

#ifdef _X86_
__inline void GetTimeRDTSC(struct timeval* dst, struct time_conv* data)
{
	ULONGLONG tmp = 0;
	__asm
	{
		push eax
		push edx
		push ecx
		rdtsc
		lea ecx, tmp
		mov [ecx+4], edx
		mov [ecx], eax
		pop ecx
		pop edx
		pop eax
	}

	if (data->reference == 0)
	{
		return;
	}
	dst->tv_sec = (LONG)(tmp / data->reference);

	dst->tv_usec = (LONG)((tmp - dst->tv_sec * data->reference) * 1000000 / data->reference);

	dst->tv_sec += data->start[0].tv_sec;

	dst->tv_usec += data->start[0].tv_usec;

	if (dst->tv_usec >= 1000000)
	{
		dst->tv_sec++;
		dst->tv_usec -= 1000000;
	}
}
#endif //_X86_

__inline void GetTimeQST(struct timeval* dst, struct time_conv* data)
{
	LARGE_INTEGER SystemTime;
	UNREFERENCED_PARAMETER(data);

	KeQuerySystemTime(&SystemTime);

	dst->tv_sec = (LONG)(SystemTime.QuadPart / 10000000 - 11644473600);
	dst->tv_usec = (LONG)((SystemTime.QuadPart % 10000000) / 10);
}

#pragma optimize ("g",on)  //Due to some weird behaviour of the optimizer of DDK build 2600 


__inline void GET_TIME(struct timeval* dst, struct time_conv* data)
{
	//
	// This timestamp mode is supported on x86 (32 bit) only
	//
#ifdef _X86_
	if (g_TimestampMode == TIMESTAMPMODE_RDTSC)
	{
		GetTimeRDTSC(dst, data);
	}
	else
		#endif // _X86_
	if (g_TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME)
	{
		GetTimeQST(dst, data);
	}
	else
	{
		GetTimeKQPC(dst, data);
	}
}


#else /*WIN_NT_DRIVER*/

__inline void FORCE_TIME(struct timeval* src, struct time_conv* dest)
{
	dest->start[0] = *src;
}

__inline void GET_TIME(struct timeval* dst, struct time_conv* data)
{
	*dst = data->start[0];
}

#endif /*WIN_NT_DRIVER*/


#endif /*_time_calls*/
