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
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
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

u_short valid_instructions[] =
{
	BPF_RET | BPF_K, BPF_RET | BPF_A, BPF_LD | BPF_IMM, BPF_LDX | BPF_IMM, BPF_LD | BPF_MEM, BPF_LDX | BPF_MEM,
	#ifdef HAVE_BUGGY_TME_SUPPORT
	BPF_LD | BPF_MEM_EX_IMM | BPF_B, BPF_LD | BPF_MEM_EX_IMM | BPF_H, BPF_LD | BPF_MEM_EX_IMM | BPF_W, BPF_LD | BPF_MEM_EX_IND | BPF_B, BPF_LD | BPF_MEM_EX_IND | BPF_H, BPF_LD | BPF_MEM_EX_IND | BPF_W,
	#endif //HAVE_BUGGY_TME_SUPPORT
	BPF_LD | BPF_W | BPF_ABS, BPF_LD | BPF_H | BPF_ABS, BPF_LD | BPF_B | BPF_ABS, BPF_LDX | BPF_W | BPF_ABS, BPF_LDX | BPF_H | BPF_ABS, BPF_LDX | BPF_B | BPF_ABS, BPF_LD | BPF_W | BPF_LEN, BPF_LDX | BPF_W | BPF_LEN, BPF_LD | BPF_W | BPF_IND, BPF_LD | BPF_H | BPF_IND, BPF_LD | BPF_B | BPF_IND, BPF_LDX | BPF_MSH | BPF_B, BPF_ST, BPF_STX,
	#ifdef HAVE_BUGGY_TME_SUPPORT
	BPF_ST | BPF_MEM_EX_IMM | BPF_B, BPF_STX | BPF_MEM_EX_IMM | BPF_B, BPF_ST | BPF_MEM_EX_IMM | BPF_W, BPF_STX | BPF_MEM_EX_IMM | BPF_W, BPF_ST | BPF_MEM_EX_IMM | BPF_H, BPF_STX | BPF_MEM_EX_IMM | BPF_H, BPF_ST | BPF_MEM_EX_IND | BPF_B, BPF_ST | BPF_MEM_EX_IND | BPF_W, BPF_ST | BPF_MEM_EX_IND | BPF_H,
	#endif // HAVE_BUGGY_TME_SUPPORT

	BPF_JMP | BPF_JA, BPF_JMP | BPF_JGT | BPF_K, BPF_JMP | BPF_JGE | BPF_K, BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JSET | BPF_K, BPF_JMP | BPF_JGT | BPF_X, BPF_JMP | BPF_JGE | BPF_X, BPF_JMP | BPF_JEQ | BPF_X, BPF_JMP | BPF_JSET | BPF_X, BPF_ALU | BPF_ADD | BPF_X, BPF_ALU | BPF_SUB | BPF_X, BPF_ALU | BPF_MUL | BPF_X, BPF_ALU | BPF_DIV | BPF_X, BPF_ALU | BPF_AND | BPF_X, BPF_ALU | BPF_OR | BPF_X, BPF_ALU | BPF_LSH | BPF_X, BPF_ALU | BPF_RSH | BPF_X, BPF_ALU | BPF_ADD | BPF_K, BPF_ALU | BPF_SUB | BPF_K, BPF_ALU | BPF_MUL | BPF_K, BPF_ALU | BPF_DIV | BPF_K, BPF_ALU | BPF_AND | BPF_K, BPF_ALU | BPF_OR | BPF_K, BPF_ALU | BPF_LSH | BPF_K, BPF_ALU | BPF_RSH | BPF_K, BPF_ALU | BPF_NEG, BPF_MISC | BPF_TAX, BPF_MISC | BPF_TXA,
	#ifdef HAVE_BUGGY_TME_SUPPORT
	BPF_MISC | BPF_TME | BPF_LOOKUP, BPF_MISC | BPF_TME | BPF_EXECUTE, BPF_MISC | BPF_TME | BPF_SET_ACTIVE, BPF_MISC | BPF_TME | BPF_GET_REGISTER_VALUE, BPF_MISC | BPF_TME | BPF_SET_REGISTER_VALUE
	#endif //HAVE_BUGGY_TME_SUPPORT



};

#define VALID_INSTRUCTIONS_LEN (sizeof(valid_instructions)/sizeof(u_short))
