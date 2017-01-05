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
 * Copyright (c) 2001 - 2003
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

#include "stdafx.h"

#ifdef WIN32
#include "tme.h"
#include "bucket_lookup.h"
#endif

#ifdef __FreeBSD__

#ifdef _KERNEL
#include <net/tme/tme.h>
#include <net/tme/bucket_lookup.h>
#else
#include <tme/tme.h>
#include <tme/bucket_lookup.h>
#endif

#endif

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif

#ifdef WIN32

/* the key is represented by the initial and final value */
/* of the bucket. At the moment bucket_lookup is able to */
/* manage values of 16, 32 bits.						 */
uint32 bucket_lookup(uint8* key, TME_DATA* data, MEM_TYPE* mem_ex, struct time_conv* time_ref)
{
	uint32 value;
	uint32 i, j;
	int found = -1;
	uint32 blocks;
	uint32 block_size;
	uint8* temp;

	UNUSED(mem_ex);

	if ((data->key_len != 1) &&  /*16 bit value*/
		(data->key_len != 2))   /*32 bit value*/
		return TME_ERROR;

	/*32 bit values*/
	blocks = data->filled_blocks - 1;
	block_size = data->block_size;
	i = blocks / 2; /*relative shift*/
	j = i;
	temp = data->shared_memory_base_address + block_size;

	if (data->key_len == 2)
	{
		value = SW_ULONG_AT(key, 0);

		if ((value < SW_ULONG_AT(temp, 0)) || (value > SW_ULONG_AT(temp + block_size * (blocks - 1), 4)))
		{
			uint32* key32 = (uint32*)key;
			key32[0] = key32[1] = 0;

			GET_TIME((struct timeval *)(data->shared_memory_base_address + 8), time_ref);

			data->last_found = NULL;
			return TME_FALSE;
		}

		while (found == -1) /* search routine */
		{
			i = (i == 1) ? 1 : i >> 1;
			if (SW_ULONG_AT(temp + block_size * j, 0) > value)
				if (SW_ULONG_AT(temp + block_size * (j - 1), 4) < value)
					found = -2;
				else
					j -= i;
			else if (SW_ULONG_AT(temp + block_size * j, 4) < value)
				if (SW_ULONG_AT(temp + block_size * j, 0) > value)
					found = -2;
				else
					j += i;
			else
				found = j;
		}	
		if (found < 0)
		{
			uint32* key32 = (uint32*)key;
			key32[0] = key32[1] = 0;

			GET_TIME((struct timeval *)(data->shared_memory_base_address + 8), time_ref);

			data->last_found = NULL;
			return TME_FALSE;
		}

		data->last_found = data->lut_base_address + found * sizeof(RECORD);

		COPY_MEMORY(key, temp + block_size * found, 8);

		GET_TIME((struct timeval *)(temp + block_size * found + 8), time_ref);

		return TME_TRUE;
	}
	else
	{
		value = SW_USHORT_AT(key, 0);

		if ((value < SW_USHORT_AT(temp, 0)) || (value > SW_USHORT_AT(temp + block_size * (blocks - 1), 2)))
		{
			uint16* key16 = (uint16*)key;
			key16[0] = key16[1] = 0;

			GET_TIME((struct timeval *)(data->shared_memory_base_address + 4), time_ref);

			data->last_found = NULL;
			return TME_FALSE;
		}

		while (found == -1) /* search routine */
		{
			i = (i == 1) ? 1 : i >> 1;
			if (SW_USHORT_AT(temp + block_size * j, 0) > value)
				if (SW_USHORT_AT(temp + block_size * (j - 1), 2) < value)
					found = -2;
				else
					j -= i;
			else if (SW_USHORT_AT(temp + block_size * j, 2) < value)
				if (SW_USHORT_AT(temp + block_size * j, 0) > value)
					found = -2;
				else
					j += i;
			else
				found = j;
		}	

		if (found < 0)
		{
			uint16* key16 = (uint16*)key;
			key16[0] = key16[1] = 0;

			GET_TIME((struct timeval *)(data->shared_memory_base_address + 4), time_ref);

			data->last_found = NULL;
			return TME_FALSE;
		}

		data->last_found = data->lut_base_address + found * sizeof(RECORD);

		GET_TIME((struct timeval *)(temp + block_size * found + 4), time_ref);

		COPY_MEMORY(key, temp + block_size * found, 4);

		return TME_TRUE;
	}
}

uint32 bucket_lookup_insert(uint8* key, TME_DATA* data, MEM_TYPE* mem_ex, struct time_conv* time_ref)
{
	RECORD* records = (RECORD*)data->lut_base_address;

	if ((data->key_len != 1) &&  /*16 bit value*/
		(data->key_len != 2))   /*32 bit value*/
		return TME_ERROR;

	if (data->key_len == 2)
	{
		uint32 start, stop;
		uint8* tmp;

		start = SW_ULONG_AT(key, 0);	
		stop = SW_ULONG_AT(key, 4);

		if (start > stop)
			return TME_ERROR;
		if (data->filled_entries > 0)
		{
			tmp = mem_ex->buffer + SW_ULONG_AT(&records[data->filled_entries - 1].block, 0);		
			/*check if it is coherent with the previous block*/
			if (SW_ULONG_AT(tmp, 4) >= start)
				return TME_ERROR;
		}

		if (data->filled_blocks == data->shared_memory_blocks)
			return TME_ERROR;

		if (data->filled_entries == data->lut_entries)
			return TME_ERROR;

		tmp = data->shared_memory_base_address + data->block_size * data->filled_blocks;		

		COPY_MEMORY(tmp, key, 8);

		SW_ULONG_ASSIGN(&records[data->filled_entries].block, tmp - mem_ex->buffer);
		SW_ULONG_ASSIGN(&records[data->filled_entries].exec_fcn, data->default_exec);

		GET_TIME((struct timeval *)(tmp + 8), time_ref);		

		data->filled_blocks++;
		data->filled_entries++;

		return TME_TRUE;
	}
	else
	{
		uint16 start, stop;
		uint8* tmp;

		start = SW_USHORT_AT(key, 0);	
		stop = SW_USHORT_AT(key, 2);

		if (start > stop)
			return TME_ERROR;
		if (data->filled_entries > 0)
		{
			tmp = mem_ex->buffer + SW_ULONG_AT(&records[data->filled_entries - 1].block, 0);		
			/*check if it is coherent with the previous block*/
			if (SW_USHORT_AT(tmp, 2) >= start)
				return TME_ERROR;
		}

		if (data->filled_blocks == data->shared_memory_blocks)
			return TME_ERROR;

		if (data->filled_entries == data->lut_entries)
			return TME_ERROR;

		tmp = mem_ex->buffer + SW_ULONG_AT(&records[data->filled_entries].block, 0);		

		COPY_MEMORY(tmp, key, 4);

		SW_ULONG_ASSIGN(&records[data->filled_entries].block, tmp - mem_ex->buffer);
		SW_ULONG_ASSIGN(&records[data->filled_entries].exec_fcn, data->default_exec);

		GET_TIME((struct timeval *)(tmp + 4), time_ref);		

		data->filled_blocks++;
		data->filled_entries++;

		return TME_TRUE;
	}
}

#endif
