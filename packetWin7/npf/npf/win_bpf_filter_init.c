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
#include "win_bpf.h"
#endif

#ifdef WIN32

#pragma warning(disable : 4131) //old style function declaration
#pragma warning(disable : 4127) // conditional expr is constant (used for while(1) loops)
#pragma warning(disable : 4213) //cast on l-value

/*
 * Initialize the filter machine
 */
uint32 bpf_filter_init(register struct bpf_insn* pc, MEM_TYPE* mem_ex, TME_CORE* tme, struct time_conv* time_ref)
{
	register uint32 A, X;
	int32 mem[BPF_MEMWORDS];
	register int32 k;
	uint32* tmp;
	uint16* tmp2;
	uint32 j;
	if (pc == 0)
	/*
	* No filter means accept all.
	*/
		return (uint32) - 1;

	RtlZeroMemory(mem, sizeof(mem));

	A = 0;
	X = 0;
	--pc;
	while (1)
	{
		++pc;
		switch (pc->code)
		{
		default:
			return 0;

			/* RET INSTRUCTIONS */
		case BPF_RET|BPF_K:
			return (uint32)pc->k;

		case BPF_RET|BPF_A:
			return (uint32)A;
			/* END RET INSTRUCTIONS */

			/* LD NO PACKET INSTRUCTIONS */
		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_B:
			A = mem_ex->buffer[pc->k];
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_B:
			X = mem_ex->buffer[pc->k];
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_H:
			tmp2 = (uint16 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp2
			xor eax, eax
			mov ax,[ebx]
			bswap eax
			mov A, eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_H:
			tmp2 = (uint16 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp2
			xor eax, eax
			mov ax,[ebx]
			bswap eax
			mov X, eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_W:
			tmp = (uint32 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp
			mov eax,[ebx]
			bswap eax
			mov A, eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_W:
			tmp = (uint32 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp
			mov eax,[ebx]
			bswap eax
			mov X, eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_B:
			k = X + pc->k;
			if ((int32)k >= (int32)mem_ex->size)
			{
				return 0;
			}
			A = mem_ex->buffer[k];
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_H:
			k = X + pc->k;
			if ((int32)(k + 1) >= (int32)mem_ex->size)
			{
				return 0;
			}
			tmp2 = (uint16 *)&mem_ex->buffer[k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp2
			xor eax, eax
			mov ax,[ebx]
			bswap eax
			mov A, eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_W:
			k = X + pc->k;
			if ((int32)(k + 3) >= (int32)mem_ex->size)
			{
				return 0;
			}
			tmp = (uint32 *)&mem_ex->buffer[k];
			__asm
			{
			push eax
			push ebx
			mov ebx,tmp
			mov eax,[ebx]
			bswap eax
			mov A, eax
			pop ebx
			pop eax
			}
			continue;
			/* END LD NO PACKET INSTRUCTIONS */

			/* STORE INSTRUCTIONS */
		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k] = (uint8)A;
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k] = (uint8)X;
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_W:
			tmp = (uint32 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp
			mov eax, A
			bswap eax
			mov[ebx], eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_W:
			tmp = (uint32 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp
			mov eax, X
			bswap eax
			mov[ebx], eax
			pop ebx
			pop eax
			}
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_H:
			tmp2 = (uint16 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp2
			mov eax, A
			xchg ah, al
			mov[ebx], ax
			pop ebx
			pop eax
			}
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_H:
			tmp2 = (uint16 *)&mem_ex->buffer[pc->k];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp2
			mov eax, X
			xchg ah, al
			mov[ebx], ax
			pop ebx
			pop eax
			}
			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_B:
			mem_ex->buffer[pc->k + X] = (uint8)A;

		case BPF_ST|BPF_MEM_EX_IND|BPF_W:
			tmp = (uint32 *)&mem_ex->buffer[pc->k + X];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp
			mov eax, A
			bswap eax
			mov[ebx], eax
			pop ebx
			pop eax
			}

			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_H:
			tmp2 = (uint16 *)&mem_ex->buffer[pc->k + X];
			__asm
			{
			push eax
			push ebx
			mov ebx, tmp2
			mov eax, A
			xchg ah, al
			mov[ebx], ax
			pop ebx
			pop eax
			}
			continue;
			/* END STORE INSTRUCTIONS */

			/* JUMP INSTRUCTIONS */
		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += ((int32)A > (int32)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += ((int32)A >= (int32)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += ((int32)A == (int32)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;
			/* END JUMP INSTRUCTIONS */

			/* ARITHMETIC INSTRUCTIONS */
		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			(int32)A = -((int32)A);
			continue;
			/* ARITHMETIC INSTRUCTIONS */

			/* MISC INSTRUCTIONS */
		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
			/* END MISC INSTRUCTIONS */

			/* TME INSTRUCTIONS */
		case BPF_MISC|BPF_TME|BPF_LOOKUP:
			j = lookup_frontend(mem_ex, tme, pc->k, time_ref);
			if (j == TME_ERROR)
				return 0;	
			pc += (j == TME_TRUE) ? pc->jt : pc->jf;
			continue;

		case BPF_MISC|BPF_TME|BPF_EXECUTE:
			if (execute_frontend(mem_ex, tme, 0, pc->k) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_INIT:
			if (init_tme_block(tme, pc->k) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_VALIDATE:
			if (validate_tme_block(mem_ex, tme, A, pc->k) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_MEMORY:
			if (init_extended_memory(pc->k, mem_ex) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_ACTIVE:
			if (set_active_tme_block(tme, pc->k) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_ACTIVE_READ:
			if (set_active_tme_block(tme, pc->k) == TME_ERROR)
				return 0;
			continue;
		case BPF_MISC|BPF_TME|BPF_SET_WORKING:
			if (pc->k >= MAX_TME_DATA_BLOCKS)
				return 0;
			tme->working = pc->k;
			continue;



		case BPF_MISC|BPF_TME|BPF_RESET:
			if (reset_tme(tme) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_GET_REGISTER_VALUE:
			if (get_tme_block_register(&tme->block_data[tme->working], mem_ex, pc->k, &j) == TME_ERROR)
				return 0;
			A = j;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_REGISTER_VALUE:
			if (set_tme_block_register(&tme->block_data[tme->working], mem_ex, pc->k, A, TRUE) == TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_AUTODELETION:
			set_autodeletion(&tme->block_data[tme->working], pc->k);
			continue;

			/* END TME INSTRUCTIONS */
		}
	}
}


#endif
