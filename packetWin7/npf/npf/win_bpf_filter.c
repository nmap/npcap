/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2021 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and the free version may not be redistributed  *
 * or incorporated into other software without special permission from     *
 * the Nmap Project. It also has certain usage limitations described in    *
 * the LICENSE file included with Npcap and also available at              *
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header          *
 * summarizes a few important aspects of the Npcap license, but is not a   *
 * substitute for that full Npcap license agreement.                       *
 *                                                                         *
 * We fund the Npcap project by selling two commercial licenses:           *
 *                                                                         *
 * The Npcap OEM Redistribution License allows companies distribute Npcap  *
 * OEM within their products. Licensees generally use the Npcap OEM        *
 * silent installer, ensuring a seamless experience for end                *
 * users. Licensees may choose between a perpetual unlimited license or    *
 * an annual term license, along with options for commercial support and   *
 * updates. Prices and details: https://nmap.org/npcap/oem/redist.html     *
 *                                                                         *
 * The Npcap OEM Internal-Use License is for organizations that wish to    *
 * use Npcap OEM internally, without redistribution outside their          *
 * organization. This allows them to bypass the 5-system usage cap of the  *
 * Npcap free edition. It includes commercial support and update options,  *
 * and provides the extra Npcap OEM features such as the silent installer  *
 * for automated deployment. Prices and details:                           *
 * https://nmap.org/npcap/oem/internal.html                                *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests, but we normally recommend that such        *
 * authors instead ask their users to download and install Npcap           *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  You are encouraged to submit such patches as Github pull     *
 * requests or by email to fyodor@nmap.org.  If you wish to specify        *
 * special license conditions or restrictions on your contributions, just  *
 * say so when you send them. Otherwise, it is understood that you are     *
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,  *
 * modify, and relicence your code contributions so that we may (but are   *
 * not obligated to) incorporate them into Npcap.                          *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights    *
 * and commercial support are available for the OEM Edition described      *
 * above.                                                                  *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 ***************************************************************************/
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
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

#ifndef _WINDLL
#include "stdafx.h"
#endif

#ifndef WIN_NT_DRIVER 
#include <windows.h>
#else
#include <ndis.h>
#endif

#pragma warning(disable : 4131) //old style function declaration
#pragma warning(disable : 4127) // conditional expr is constant (used for while(1) loops)
#pragma warning(disable : 4213) //cast on l-value

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif

#include "win_bpf.h"

#include "debug.h"

#include "valid_insns.h"

#define EXTRACT_SHORT(p)\
		((((u_short)(((u_char*)p)[0])) << 8) |\
		 (((u_short)(((u_char*)p)[1])) << 0))

#define EXTRACT_LONG(p)\
		((((u_int32)(((u_char*)p)[0])) << 24) |\
		 (((u_int32)(((u_char*)p)[1])) << 16) |\
		 (((u_int32)(((u_char*)p)[2])) << 8 ) |\
		 (((u_int32)(((u_char*)p)[3])) << 0 ))

#ifdef WIN_NT_DRIVER
#define MDLIDX(len, p, k, buf) \
{ \
	NdisQueryMdl(p, &buf, &len, NormalPagePriority); \
	if (buf == NULL) \
		return 0; \
	while (k >= len) { \
		k -= len; \
		p = p->Next; \
		if (p == NULL) \
			return 0; \
		NdisQueryMdl(p, &buf, &len, NormalPagePriority); \
		if (buf == NULL) \
			return 0; \
	} \
}

u_int32 xword(PMDL p, u_int32 k, int *err)
{
	u_int32 len, len0;
	u_char *CurBuf, *NextBuf;
	PMDL p0;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	CurBuf += k;
	if (len - k >= 4) {
		*err = 0;
		return EXTRACT_LONG(CurBuf);
	}
	p0 = p->Next;
	if (p0 == NULL)
		return 0;
	NdisQueryMdl(p0, &NextBuf, &len0, NormalPagePriority);
	if (NextBuf == NULL || (len - k) + len0 < 4)
		return 0;
	*err = 0;

	switch (len - k) {
	case 1:
		return (CurBuf[0] << 24) | (NextBuf[0] << 16) | (NextBuf[1] << 8) | NextBuf[2];
	case 2:
		return (CurBuf[0] << 24) | (CurBuf[1] << 16) | (NextBuf[0] << 8) | NextBuf[1];
	default:
		return (CurBuf[0] << 24) | (CurBuf[1] << 16) | (CurBuf[2] << 8) | NextBuf[0];
	}
}

u_int32 xhalf(PMDL p, u_int32 k, int *err)
{
	u_int32 len, len0;
	u_char *CurBuf, *NextBuf;
	PMDL p0;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	CurBuf += k;
	if (len - k >= 2) {
		*err = 0;
		return EXTRACT_SHORT(CurBuf);
	}
	p0 = p->Next;
	if (p0 == NULL)
		return 0;
	NdisQueryMdl(p0, &NextBuf, &len0, NormalPagePriority);
	if (NextBuf == NULL || len0 < 1)
		return 0;
	*err = 0;

	return (CurBuf[0] << 8) | NextBuf[0];
}

u_int32 xbyte(PMDL p, u_int32 k, int *err)
{
	u_int32 len;
	u_char *CurBuf;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	*err = 0;

	return CurBuf[k];
}

u_int bpf_filter(const struct bpf_insn *pc, const PMDL p, u_int data_offset, u_int wirelen)
#else
u_int bpf_filter(pc, p, wirelen, buflen)
register struct bpf_insn *pc;
register u_char *p;
u_int wirelen;
register u_int buflen;
#endif //WIN_NT_DRIVER
{
	register u_int32 A, X;
	register bpf_u_int32 k;

#ifdef WIN_NT_DRIVER
	int merr = 0;
#endif
	int mem[BPF_MEMWORDS];

	RtlZeroMemory(mem, sizeof(mem));

	if (pc == 0)
	/*
	* No filter means accept all.
	*/
		return (u_int) - 1;
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

		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen || k + sizeof(int) > buflen) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
#else
			A = xword(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen || k + sizeof(short) > buflen) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
#else
			A = xhalf(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen) {
				return 0;
			}
			A = p[k];
#else
			A = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen || k + sizeof(int) > buflen) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
#else
			A = xword(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen || k + sizeof(short) > buflen) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
#else
			A = xhalf(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen) {
				return 0;
			}
			A = p[k];
#else
			A = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
#ifndef WIN_NT_DRIVER
			if (k >= buflen) {
				return 0;
			}
			X = p[k];
#else
			X = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
#endif //WIN_NT_DRIVER
			X = (X & 0xf) << 2;
			continue;

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

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += ((int)A > (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += ((int)A >= (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += ((int)A == (int)pc->k) ? pc->jt : pc->jf;
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
			(int)A = -((int)A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

//-------------------------------------------------------------------

int bpf_validate(f, len)
struct bpf_insn * f;
int len;
{
	register u_int32 i, from;
	register int j;
	register struct bpf_insn* p;
	int flag;

	if (len < 1)
		return 0;

	for (i = 0; i < (u_int32)len; ++i)
	{
		p = &f[i];

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Validating program");

		flag = 0;
		for (j = 0; j < VALID_INSTRUCTIONS_LEN; j++)
			if (p->code == valid_instructions[j])
				flag = 1;
		if (flag == 0)
			return 0;

		TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Validating program: no unknown instructions");

		switch (BPF_CLASS(p->code))
		{
			/*
										 * Check that memory operations use valid addresses.
										 */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code))
			{
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}

			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Validating program: no wrong LD memory locations");
			break;

		case BPF_ST:
		case BPF_STX:
			if (p->k >= BPF_MEMWORDS)
				return 0;

			TRACE_MESSAGE(PACKET_DEBUG_LOUD, "Validating program: no wrong ST memory locations");
			break;

		case BPF_ALU:
			switch (BPF_OP(p->code))
			{
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_OR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
				/*
								 * Check for constant division by 0.
								 */
				if (BPF_SRC(p->code) == BPF_K && p->k == 0)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			/*
											 * Check that jumps are within the code block,
											 * and that unconditional branches don't go
											 * backwards as a result of an overflow.
											 * Unconditional branches have a 32-bit offset,
											 * so they could overflow; we check to make
											 * sure they don't.  Conditional branches have
											 * an 8-bit offset, and the from address is <=
											 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
											 * is sufficiently small that adding 255 to it
											 * won't overflow.
											 *
											 * We know that len is <= BPF_MAXINSNS, and we
											 * assume that BPF_MAXINSNS is < the maximum size
											 * of a u_int, so that i + 1 doesn't overflow.
											 */
			from = i + 1;
			switch (BPF_OP(p->code))
			{
			case BPF_JA:
				if (from + p->k < from || from + p->k >= (u_int32)len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= (u_int32)len || from + p->jf >= (u_int32)len)
					return 0;
				break;
			default:
				return 0;
			}
			IF_LOUD(DbgPrint("Validating program: no wrong JUMPS");)
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		default:
			return 0;
		}
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
