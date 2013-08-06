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
#define	 BIOCSETBUFFERSIZE 9592

/*!
  \brief IOCTL code: set packet filtering program.

  This IOCTL sets a new packet filter in the driver. Before allocating any memory for the new filter, the 
  bpf_validate() function is called to check the correctness of the filter. If this function returns TRUE, 
  the filter is copied to the driver's memory, its address is stored in the bpfprogram field of the 
  OPEN_INSTANCE structure associated with current instance of the driver, and the filter will be applied to 
  every incoming packet. This command also empties the circular buffer used by current instance 
  to store packets. This is done to avoid the presence in the buffer of packets that do not match the filter.
*/
#define	 BIOCSETF 9030

/*!
  \brief IOCTL code: get the capture stats

  This command returns to the application the number of packets received and the number of packets dropped by 
  an instance of the driver.
*/
#define  BIOCGSTATS 9031

/*!
  \brief IOCTL code: set the read timeout

  This command sets the maximum timeout after which a read is released, also if no data packets were received.
*/
#define	 BIOCSRTIMEOUT 7416

/*!
  \brief IOCTL code: set working mode

  This IOCTL can be used to set the working mode of a NPF instance. The new mode, received by the driver in the
  buffer associated with the IOCTL command, can be #MODE_CAPT for capture mode (the default), #MODE_STAT for
  statistical mode or #MODE_DUMP for dump mode.
*/
#define	 BIOCSMODE 7412

/*!
  \brief IOCTL code: set number of physical repetions of every packet written by the app

  Sets the number of times a single write call must be repeated. This command sets the OPEN_INSTANCE::Nwrites 
  member, and is used to implement the 'multiple write' feature of the driver.
*/
#define	 BIOCSWRITEREP 7413

/*!
  \brief IOCTL code: set minimum amount of data in the kernel buffer that unlocks a read call

  This command sets the OPEN_INSTANCE::MinToCopy member.
*/
#define	 BIOCSMINTOCOPY 7414

/*!
  \brief IOCTL code: set an OID value

  This IOCTL is used to perform an OID set operation on the NIC driver. 
*/
#define	 BIOCSETOID 0x80000000

/*!
  \brief IOCTL code: get an OID value

  This IOCTL is used to perform an OID get operation on the NIC driver. 
*/
#define	 BIOCQUERYOID 0x80000004

/*!
  \brief IOCTL code: set the name of a the file used by kernel dump mode

  This command opens a file whose name is contained in the IOCTL buffer and associates it with current NPf instance.
  The dump thread uses it to copy the content of the circular buffer to file.
  If a file was already opened, the driver closes it before opening the new one.
*/
#define  BIOCSETDUMPFILENAME 9029

/*!
  \brief IOCTL code: get the name of the event that the driver signals when some data is present in the buffer

  Command used by the application to retrieve the name of the global event associated with a NPF instance.
  The event is signaled by the driver when the kernel buffer contains enough data for a transfer.
*/
#define  BIOCGEVNAME 7415

/*!
  \brief IOCTL code: Send a buffer containing multiple packets to the network, ignoring the timestamps.

  Command used to send a buffer of packets in a single system call. Every packet in the buffer is preceded by
  a sf_pkthdr structure. The timestamps of the packets are ignored, i.e. the packets are sent as fast as 
  possible. The NPF_BufferedWrite() function is invoked to send the packets.
*/
#define  BIOCSENDPACKETSNOSYNC 9032

/*!
  \brief IOCTL code: Send a buffer containing multiple packets to the network, considering the timestamps.

  Command used to send a buffer of packets in a single system call. Every packet in the buffer is preceded by
  a sf_pkthdr structure. The timestamps of the packets are used to synchronize the write, i.e. the packets 
  are sent to the network respecting the intervals specified in the sf_pkthdr structure assiciated with each
  packet. NPF_BufferedWrite() function is invoked to send the packets. 
*/
#define  BIOCSENDPACKETSSYNC 9033

/*!
  \brief IOCTL code: Set the dump file limits.

  This IOCTL sets the limits (maximum size and maximum number of packets) of the dump file created when the
  driver works in dump mode.
*/
#define  BIOCSETDUMPLIMITS 9034

/*!
  \brief IOCTL code: Get the status of the kernel dump process.

  This command returns TRUE if the kernel dump is ended, i.e if one of the limits set with BIOCSETDUMPLIMITS
  (amount of bytes or number of packets) has been reached.
*/
#define BIOCISDUMPENDED 7411

/*!
  \brief IOCTL code: set the loopback behavior.

  This IOCTL sets the loopback behavior of the driver with packets sent by itself: capture or drop.
*/
#define  BIOCISETLOBBEH 7410			

/*!
	\brief This IOCTL passes the read event HANDLE allocated by the user (packet.dll) to kernel level

	Parameter: HANDLE
	Parameter size: sizeof(HANDLE). If the caller is 32 bit, the parameter size is 4 bytes, even if sizeof(HANDLE) at kernel level
		is 8 bytes. That's why in this IOCTL code handler we detect a 32bit calling process and do the necessary thunking.

	TODO GV:I will go to hell for this ugly IOCTL definition. We should use CTL_CODE!!
*/
#define BIOCSETEVENTHANDLE 7920

/** 
 *  @}
 */

/** 
 *  @}
 */




#endif //__NPF_IOCTLS_H__
