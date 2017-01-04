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
/*-
* Copyright (c) 2003, 2004 David Young.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. The name of David Young may not be used to endorse or promote
*    products derived from this software without specific prior
*    written permission.
*
* THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
* YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
* OF SUCH DAMAGE.
*
*/
#ifndef _NET_IF_IEEE80211RADIOTAP_H_
#define _NET_IF_IEEE80211RADIOTAP_H_

/* A generic radio capture format is desirable. There is one for
* Linux, but it is neither rigidly defined (there were not even
* units given for some fields) nor easily extensible.
*
* I suggest the following extensible radio capture format. It is
* based on a bitmap indicating which fields are present.
*
* I am trying to describe precisely what the application programmer
* should expect in the following, and for that reason I tell the
* units and origin of each measurement (where it applies), or else I
* use sufficiently weaselly language ("is a monotonically nondecreasing
* function of...") that I cannot set false expectations for lawyerly
* readers.
*/
#if defined(__KERNEL__) || defined(_KERNEL)
#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	/* 802.11 plus WLAN header */
#endif
#endif /* defined(__KERNEL__) || defined(_KERNEL) */

#if defined _WIN32
#define u_int8_t  UCHAR
#define u_int16_t USHORT
#define u_int32_t ULONG
#define u_int64_t ULONGLONG

#define int8_t  CHAR
#define int16_t SHORT
#define int32_t LONG
#define int64_t LONGLONG
#endif

/* The radio capture header precedes the 802.11 header. */

#ifndef __MINGW32__
#pragma pack(push)
#pragma pack(1)
#endif // __MINGW32__
typedef struct _ieee80211_radiotap_header {
	u_int8_t it_version;		/* Version 0. Only increases
								* for drastic changes,
								* introduction of compatible
								* new fields does not count.
								*/
	u_int8_t it_pad;
	u_int16_t it_len;		/* length of the whole
							* header in bytes, including
							* it_version, it_pad,
							* it_len, and data fields.
							*/
	u_int32_t it_present;		/* A bitmap telling which
								* fields are present. Set bit 31
								* (0x80000000) to extend the
								* bitmap by another 32 bits.
								* Additional extensions are made
								* by setting bit 31.
								*/
} IEEE80211_RADIOTAP_HEADER, *PIEEE80211_RADIOTAP_HEADER;
#ifdef __MINGW32__
__attribute__((__packed__))
#endif // __MINGW32__
;

#ifndef __MINGW32__
#pragma pack(pop)
#endif // __MINGW32__

/* Name                                 Data type       Units
* ----                                 ---------       -----
*
* IEEE80211_RADIOTAP_TSFT              u_int64_t       microseconds
*
*      Value in microseconds of the MAC's 64-bit 802.11 Time
*      Synchronization Function timer when the first bit of the
*      MPDU arrived at the MAC. For received frames, only.
*
* IEEE80211_RADIOTAP_CHANNEL           2 x u_int16_t   MHz, bitmap
*
*      Tx/Rx frequency in MHz, followed by flags (see below).
*
* IEEE80211_RADIOTAP_FHSS              u_int16_t       see below
*
*      For frequency-hopping radios, the hop set (first byte)
*      and pattern (second byte).
*
* IEEE80211_RADIOTAP_RATE              u_int8_t        500kb/s
*
*      Tx/Rx data rate
*
* IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
*                                                      one milliwatt (dBm)
*
*      RF signal power at the antenna, decibel difference from
*      one milliwatt.
*
* IEEE80211_RADIOTAP_DBM_ANTNOISE      int8_t          decibels from
*                                                      one milliwatt (dBm)
*
*      RF noise power at the antenna, decibel difference from one
*      milliwatt.
*
* IEEE80211_RADIOTAP_DB_ANTSIGNAL      u_int8_t        decibel (dB)
*
*      RF signal power at the antenna, decibel difference from an
*      arbitrary, fixed reference.
*
* IEEE80211_RADIOTAP_DB_ANTNOISE       u_int8_t        decibel (dB)
*
*      RF noise power at the antenna, decibel difference from an
*      arbitrary, fixed reference point.
*
* IEEE80211_RADIOTAP_LOCK_QUALITY		u_int16_t       unitless
*
*      Quality of Barker code lock. Unitless. Monotonically
*      nondecreasing with "better" lock strength. Called "Signal
*      Quality" in datasheets.  (Is there a standard way to measure
*      this?)
*
* IEEE80211_RADIOTAP_TX_ATTENUATION    u_int16_t       unitless
*
*      Transmit power expressed as unitless distance from max
*      power set at factory calibration.  0 is max power.
*      Monotonically nondecreasing with lower power levels.
*
* IEEE80211_RADIOTAP_DB_TX_ATTENUATION u_int16_t       decibels (dB)
*
*      Transmit power expressed as decibel distance from max power
*      set at factory calibration.  0 is max power.  Monotonically
*      nondecreasing with lower power levels.
*
* IEEE80211_RADIOTAP_DBM_TX_POWER      int8_t          decibels from
*                                                      one milliwatt (dBm)
*
*      Transmit power expressed as dBm (decibels from a 1 milliwatt
*      reference). This is the absolute power level measured at
*      the antenna port.
*
* IEEE80211_RADIOTAP_FLAGS             u_int8_t        bitmap
*
*      Properties of transmitted and received frames. See flags
*      defined below.
*
* IEEE80211_RADIOTAP_ANTENNA           u_int8_t        antenna index
*
*      Unitless indication of the Rx/Tx antenna for this packet.
*      The first antenna is antenna 0.
*
* IEEE80211_RADIOTAP_FCS           	u_int32_t       data
*
*	FCS from frame in network byte order.
*/

/* ethereal does NOT handle the following:
IEEE80211_RADIOTAP_FHSS:
IEEE80211_RADIOTAP_LOCK_QUALITY:
IEEE80211_RADIOTAP_TX_ATTENUATION:
IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
*/

enum ieee80211_radiotap_type
{
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	// IEEE80211_RADIOTAP_FCS = 14, // from ieee80211_radiotap.h (AirPcap)
	// IEEE80211_RADIOTAP_EXT = 31, // from ieee80211_radiotap.h (AirPcap)
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	// IEEE80211_RADIOTAP_TX_FLAGS = 15, // from packet-ieee80211-radiotap-defs.h (Wireshark)
	// IEEE80211_RADIOTAP_RTS_RETRIES = 16, // from packet-ieee80211-radiotap-defs.h (Wireshark)
	// IEEE80211_RADIOTAP_DATA_RETRIES = 17, // from packet-ieee80211-radiotap-defs.h (Wireshark)
	// IEEE80211_RADIOTAP_XCHANNEL = 18,  // from packet-ieee80211-radiotap-defs.h (Wireshark) /* Unofficial, used by FreeBSD */
	IEEE80211_RADIOTAP_MCS = 19,
	IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
	IEEE80211_RADIOTAP_VHT = 21,
};

#define BIT(n)	(1U << n)

#ifndef _KERNEL
/* Channel flags. */
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel. */
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800	/* GFSK channel (FHSS PHY) */
#define	IEEE80211_CHAN_STURBO	0x2000	/* 11a static turbo channel only */
#endif /* !_KERNEL */

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
* during CFP
*/
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
* with short
* preamble
*/
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
* with WEP encryption
*/
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
* with fragmentation
*/
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
* 802.11 header and payload
* (to 32-bit boundary)
*/
#define IEEE80211_RADIOTAP_F_BADFCS	0x40	/* frame failed FCS check */

#endif /* _NET_IF_IEEE80211RADIOTAP_H_ */
