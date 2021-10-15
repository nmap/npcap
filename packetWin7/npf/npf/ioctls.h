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
 * Copyright (c) 2007 CACE Technologies, Davis (California)
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

#ifndef __NPF_IOCTLS_H__
#define __NPF_IOCTLS_H__

/***************************/
/*  	   IOCTLs   	   */
/***************************/

/** @addtogroup NPF 
 *  @{
 */

/** @defgroup NPF_ioctl NPF I/O control codes 
 *  @{
 */

/*!
  \brief IOCTL code: set kernel buffer size.

  This IOCTL is used to set a new size of the circular buffer associated with an instance of NPF.
  When a BIOCSETBUFFERSIZE command is received, the driver frees the old buffer, allocates the new one 
  and resets all the parameters associated with the buffer in the OPEN_INSTANCE structure. The currently 
  buffered packets are lost.
*/
#define W_BIOCSETBUFFERSIZE 9592
#define BIOCSETBUFFERSIZE CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa01, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set packet filtering program.

  This IOCTL sets a new packet filter in the driver. Before allocating any memory for the new filter, the 
  bpf_validate() function is called to check the correctness of the filter. If this function returns TRUE, 
  the filter is copied to the driver's memory, its address is stored in the bpfprogram field of the 
  OPEN_INSTANCE structure associated with current instance of the driver, and the filter will be applied to 
  every incoming packet. This command also empties the circular buffer used by current instance 
  to store packets. This is done to avoid the presence in the buffer of packets that do not match the filter.
*/
/* Historical number 9030 */
#define W_BIOCSETF 9030
#define BIOCSETF CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa02, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: get the capture stats

  This command returns to the application the number of packets received and the number of packets dropped by 
  an instance of the driver.
*/
/* Historical number 9031 */
#define W_BIOCGSTATS 9031
#define BIOCGSTATS CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa03, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set the read timeout

  This command sets the maximum timeout after which a read is released, also if no data packets were received.
*/
#define W_BIOCSRTIMEOUT 7416
#define BIOCSRTIMEOUT CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa04, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set working mode

  This IOCTL can be used to set the working mode of a NPF instance. The new mode, received by the driver in the
  buffer associated with the IOCTL command, can be #MODE_CAPT for capture mode (the default), #MODE_STAT for
  statistical mode.
*/
#define W_BIOCSMODE 7412
#define BIOCSMODE CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa05, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set number of physical repetions of every packet written by the app

  Sets the number of times a single write call must be repeated. This command sets the OPEN_INSTANCE::Nwrites 
  member, and is used to implement the 'multiple write' feature of the driver.
*/
#define W_BIOCSWRITEREP 7413
#define BIOCSWRITEREP CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa06, METHOD_BUFFERED, FILE_WRITE_DATA)

/*!
  \brief IOCTL code: set minimum amount of data in the kernel buffer that unlocks a read call

  This command sets the OPEN_INSTANCE::MinToCopy member.
*/
#define W_BIOCSMINTOCOPY 7414
#define BIOCSMINTOCOPY CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa07, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set an OID value

  This IOCTL is used to perform an OID set operation on the NIC driver. 
*/
#define W_BIOCSETOID 0x80000000
#define BIOCSETOID CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa08, METHOD_BUFFERED, FILE_WRITE_DATA)

/*!
  \brief IOCTL code: get an OID value

  This IOCTL is used to perform an OID get operation on the NIC driver. 
*/
#define W_BIOCQUERYOID 0x80000004
#define BIOCQUERYOID CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa09, METHOD_BUFFERED, FILE_READ_DATA)

// kernel dump mode not supported by Npcap.
#define W_BIOCSETDUMPFILENAME 9029
#define BIOCSETDUMPFILENAME CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0a, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: get the name of the event that the driver signals when some data is present in the buffer

  Command used by the application to retrieve the name of the global event associated with a NPF instance.
  The event is signaled by the driver when the kernel buffer contains enough data for a transfer.
*/
#define W_BIOCGEVNAME 7415
#define BIOCGEVNAME CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0b, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: Send a buffer containing multiple packets to the network, ignoring the timestamps.

  Command used to send a buffer of packets in a single system call. Every packet in the buffer is preceded by
  a dump_bpf_hdr structure. The timestamps of the packets are ignored, i.e. the packets are sent as fast as 
  possible. The NPF_BufferedWrite() function is invoked to send the packets.
*/
#define W_BIOCSENDPACKETSNOSYNC 9032
/* Possibly consider METHOD_IN_DIRECT to avoid issues like #1398 */
#define BIOCSENDPACKETSNOSYNC CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0c, METHOD_BUFFERED, FILE_WRITE_DATA)

/*!
  \brief IOCTL code: Send a buffer containing multiple packets to the network, considering the timestamps.

  Command used to send a buffer of packets in a single system call. Every packet in the buffer is preceded by
  a dump_bpf_hdr structure. The timestamps of the packets are used to synchronize the write, i.e. the packets 
  are sent to the network respecting the intervals specified in the dump_bpf_hdr structure assiciated with each
  packet. NPF_BufferedWrite() function is invoked to send the packets. 
*/
#define W_BIOCSENDPACKETSSYNC 9033
#define BIOCSENDPACKETSSYNC CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0d, METHOD_BUFFERED, FILE_WRITE_DATA)

// kernel dump mode not supported by Npcap.
#define W_BIOCSETDUMPLIMITS 9034
#define BIOCSETDUMPLIMITS CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0e, METHOD_BUFFERED, FILE_READ_DATA)

// kernel dump mode not supported by Npcap.
#define W_BIOCISDUMPENDED 7411
#define BIOCISDUMPENDED CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa0f, METHOD_BUFFERED, FILE_READ_DATA)

/*!
  \brief IOCTL code: set the loopback behavior.

  This IOCTL sets the loopback behavior of the driver with packets sent by itself: capture or drop.
*/
#define W_BIOCISETLOBBEH 7410
#define BIOCISETLOBBEH CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa10, METHOD_BUFFERED, FILE_READ_DATA)

/*!
	\brief This IOCTL passes the read event HANDLE allocated by the user (packet.dll) to kernel level

	Parameter: HANDLE
	Parameter size: sizeof(HANDLE). If the caller is 32 bit, the parameter size is 4 bytes, even if sizeof(HANDLE) at kernel level
		is 8 bytes. That's why in this IOCTL code handler we detect a 32bit calling process and do the necessary thunking.

*/
#define W_BIOCSETEVENTHANDLE 7920
#define BIOCSETEVENTHANDLE CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa11, METHOD_BUFFERED, FILE_READ_DATA)

/*
  \brief IOCTL code: set the timestamp mode.

  This IOCTL sets the timestamp mode (DWORD) to one of the supported modes from time_calls.h
*/ 
#define BIOCSTIMESTAMPMODE CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa12, METHOD_BUFFERED, FILE_READ_DATA)
// Get a list of supported timestamp modes. Output is an array of ULONG. First element is the number of modes supported.
#define BIOCGTIMESTAMPMODES CTL_CODE(FILE_DEVICE_TRANSPORT, 0xa13, METHOD_BUFFERED, FILE_READ_DATA)
/** 
 *  @}
 */

/** 
 *  @}
 */

/* IOCTL codes for driver control */

// Get a list of process IDs which have opened or used handles to the driver.
// Because handles can be inherited, this may not be a complete set.
#define BIOCGETPIDS CTL_CODE(FILE_DEVICE_TRANSPORT, 0xb01, METHOD_BUFFERED, FILE_READ_DATA)

#endif //__NPF_IOCTLS_H__
