/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library
 * and is copyright (c) 2013-2022 by Nmap Software LLC ("The Nmap Project").
 * All rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it
 * is not open source software and may not be redistributed or used in
 * other software without special permission from the Nmap
 * Project. The standard (free) version is usually limited to
 * installation on five systems. For more details, see the LICENSE
 * file included with Npcap and also avaialble at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not
 * a substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap
 * OEM within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may
 * choose between a perpetual unlimited license or a quarterly term license,
 * along with options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to
 * use Npcap OEM internally, without redistribution outside their
 * organization. This allows them to bypass the 5-system usage cap of the
 * Npcap free edition. It includes commercial support and update options, and
 * provides the extra Npcap OEM features such as the silent installer for
 * automated deployment. Prices and details:
 * https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a
 * warranty. Npcap OEM also includes a silent installer for unattended
 * installation. Further details about Npcap OEM are available from
 * https://npcap.com/oem/, and you are also welcome to contact us at
 * sales@nmap.com to ask any questions or set up a license for your
 * organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will
 * be free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial
 * licensing customers) has granted you additional rights to Npcap or
 * Npcap OEM, those additional rights take precedence where they
 * conflict with the terms of the license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features.  By
 * sending these changes to the Nmap Project (including through direct email
 * or our mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap.  If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. Warranty rights and commercial
 * support are available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license
 * header. We have kept those for attribution purposes, but any license terms
 * granted by those notices apply only to their original work, and not to any
 * changes made by the Nmap Project or to this entire file.
 *
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
	BPF_LD | BPF_W | BPF_ABS, BPF_LD | BPF_H | BPF_ABS, BPF_LD | BPF_B | BPF_ABS, BPF_LDX | BPF_W | BPF_ABS, BPF_LDX | BPF_H | BPF_ABS, BPF_LDX | BPF_B | BPF_ABS, BPF_LD | BPF_W | BPF_LEN, BPF_LDX | BPF_W | BPF_LEN, BPF_LD | BPF_W | BPF_IND, BPF_LD | BPF_H | BPF_IND, BPF_LD | BPF_B | BPF_IND, BPF_LDX | BPF_MSH | BPF_B, BPF_ST, BPF_STX,

	BPF_JMP | BPF_JA, BPF_JMP | BPF_JGT | BPF_K, BPF_JMP | BPF_JGE | BPF_K, BPF_JMP | BPF_JEQ | BPF_K, BPF_JMP | BPF_JSET | BPF_K, BPF_JMP | BPF_JGT | BPF_X, BPF_JMP | BPF_JGE | BPF_X, BPF_JMP | BPF_JEQ | BPF_X, BPF_JMP | BPF_JSET | BPF_X, BPF_ALU | BPF_ADD | BPF_X, BPF_ALU | BPF_SUB | BPF_X, BPF_ALU | BPF_MUL | BPF_X, BPF_ALU | BPF_DIV | BPF_X, BPF_ALU | BPF_AND | BPF_X, BPF_ALU | BPF_OR | BPF_X, BPF_ALU | BPF_LSH | BPF_X, BPF_ALU | BPF_RSH | BPF_X, BPF_ALU | BPF_ADD | BPF_K, BPF_ALU | BPF_SUB | BPF_K, BPF_ALU | BPF_MUL | BPF_K, BPF_ALU | BPF_DIV | BPF_K, BPF_ALU | BPF_AND | BPF_K, BPF_ALU | BPF_OR | BPF_K, BPF_ALU | BPF_LSH | BPF_K, BPF_ALU | BPF_RSH | BPF_K, BPF_ALU | BPF_NEG, BPF_MISC | BPF_TAX, BPF_MISC | BPF_TXA,

};

#define VALID_INSTRUCTIONS_LEN (sizeof(valid_instructions)/sizeof(u_short))
