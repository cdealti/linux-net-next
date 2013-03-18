/*
 * Copyright 2011, Siemens AG
 * written by Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

/*
 * Based on patches from Jon Smirl <jonsmirl@gmail.com>
 * Copyright (c) 2011 Jon Smirl <jonsmirl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Jon's code is based on 6lowpan implementation for Contiki which is:
 * Copyright (c) 2008, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __6LOWPAN_H__
#define __6LOWPAN_H__

#define UIP_802154_SHORTADDR_LEN	2  /* compressed ipv6 address length */
#define UIP_IPH_LEN			40 /* ipv6 fixed header size */
#define UIP_PROTO_UDP			17 /* ipv6 next header value for UDP */
#define UIP_FRAGH_LEN			8  /* ipv6 fragment header size */

/*
 * ipv6 address based on mac
 * second bit-flip (Universe/Local) is done according RFC2464
 */
#define is_addr_mac_addr_based(a, m) \
	((((a)->s6_addr[8])  == (((m)[0]) ^ 0x02)) &&	\
	 (((a)->s6_addr[9])  == (m)[1]) &&		\
	 (((a)->s6_addr[10]) == (m)[2]) &&		\
	 (((a)->s6_addr[11]) == (m)[3]) &&		\
	 (((a)->s6_addr[12]) == (m)[4]) &&		\
	 (((a)->s6_addr[13]) == (m)[5]) &&		\
	 (((a)->s6_addr[14]) == (m)[6]) &&		\
	 (((a)->s6_addr[15]) == (m)[7]))

/* ipv6 address is unspecified */
#define is_addr_unspecified(a)		\
	((((a)->s6_addr32[0]) == 0) &&	\
	 (((a)->s6_addr32[1]) == 0) &&	\
	 (((a)->s6_addr32[2]) == 0) &&	\
	 (((a)->s6_addr32[3]) == 0))

/* compare ipv6 addresses prefixes */
#define ipaddr_prefixcmp(addr1, addr2, length) \
	(memcmp(addr1, addr2, length >> 3) == 0)

/* local link, i.e. FE80::/10 */
#define is_addr_link_local(a) (((a)->s6_addr16[0]) == htons(0xFE80))

/*
 * check whether we can compress the IID to 16 bits,
 * it's possible for unicast adresses with first 49 bits are zero only.
 */
#define lowpan_is_iid_16_bit_compressable(a)	\
	((((a)->s6_addr16[4]) == 0) &&		\
	 (((a)->s6_addr[10]) == 0) &&		\
	 (((a)->s6_addr[11]) == 0xff) &&	\
	 (((a)->s6_addr[12]) == 0xfe) &&	\
	 (((a)->s6_addr[13]) == 0))

/* multicast address */
#define is_addr_mcast(a) (((a)->s6_addr[0]) == 0xFF)

/* check whether the 112-bit gid of the multicast address is mappable to: */

/* 9 bits, for FF02::1 (all nodes) and FF02::2 (all routers) addresses only. */
#define lowpan_is_mcast_addr_compressable(a)	\
	((((a)->s6_addr16[1]) == 0) &&		\
	 (((a)->s6_addr16[2]) == 0) &&		\
	 (((a)->s6_addr16[3]) == 0) &&		\
	 (((a)->s6_addr16[4]) == 0) &&		\
	 (((a)->s6_addr16[5]) == 0) &&		\
	 (((a)->s6_addr16[6]) == 0) &&		\
	 (((a)->s6_addr[14])  == 0) &&		\
	 ((((a)->s6_addr[15]) == 1) || (((a)->s6_addr[15]) == 2)))

/* 48 bits, FFXX::00XX:XXXX:XXXX */
#define lowpan_is_mcast_addr_compressable48(a)	\
	((((a)->s6_addr16[1]) == 0) &&		\
	 (((a)->s6_addr16[2]) == 0) &&		\
	 (((a)->s6_addr16[3]) == 0) &&		\
	 (((a)->s6_addr16[4]) == 0) &&		\
	 (((a)->s6_addr[10]) == 0))

/* 32 bits, FFXX::00XX:XXXX */
#define lowpan_is_mcast_addr_compressable32(a)	\
	((((a)->s6_addr16[1]) == 0) &&		\
	 (((a)->s6_addr16[2]) == 0) &&		\
	 (((a)->s6_addr16[3]) == 0) &&		\
	 (((a)->s6_addr16[4]) == 0) &&		\
	 (((a)->s6_addr16[5]) == 0) &&		\
	 (((a)->s6_addr[12]) == 0))

/* 8 bits, FF02::00XX */
#define lowpan_is_mcast_addr_compressable8(a)	\
	((((a)->s6_addr[1])  == 2) &&		\
	 (((a)->s6_addr16[1]) == 0) &&		\
	 (((a)->s6_addr16[2]) == 0) &&		\
	 (((a)->s6_addr16[3]) == 0) &&		\
	 (((a)->s6_addr16[4]) == 0) &&		\
	 (((a)->s6_addr16[5]) == 0) &&		\
	 (((a)->s6_addr16[6]) == 0) &&		\
	 (((a)->s6_addr[14]) == 0))

#define lowpan_is_addr_broadcast(a)	\
	((((a)[0]) == 0xFF) &&	\
	 (((a)[1]) == 0xFF) &&	\
	 (((a)[2]) == 0xFF) &&	\
	 (((a)[3]) == 0xFF) &&	\
	 (((a)[4]) == 0xFF) &&	\
	 (((a)[5]) == 0xFF) &&	\
	 (((a)[6]) == 0xFF) &&	\
	 (((a)[7]) == 0xFF))

/*
 * Check if flow_lbl of a ipv6hdr is zero.
 * First byte need to mask with 0xF0
 * because 0x0F is a part traffic class(dscp).
 */
#define lowpan_is_ipv6_flow_lbl_zero(a)		\
	((!((a)->flow_lbl[0] & 0xF0)) &&	\
	 (!((a)->flow_lbl[1])) &&		\
	 (!((a)->flow_lbl[2])))

/*
 * Check if dscp of a ipv6hdr is zero.
 * This is needed to check on tc compression.
 * Not ECN byte in (priority & 0x3) will never
 * compressed so check only on dscp.
 */
#define lowpan_is_ipv6_dscp_zero(a)		\
	((!((a)->priority & 0xC)) &&		\
	 (!((a)->flow_lbl[0] & 0x0F))) 
/*
 * This part generates a tc_flbl value to handle it 
 * with a ipv6hdr and lowpan_hdr.
 *
 * This is the tc_flbl it's similar how ipv6hdr stores
 * this value. But we don't a have a good access to this,
 * because ipv6hdr struct split it in two elements.
 *
 *  MSB                                          LSB	
 *  27...........8   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 * |  FLOW LABEL   |         DSCP          |  ECN  |
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 * \_______________________________|_______________/
 *             flow_lbl:24             priority:4
 *
 * Construct the 28 bit width tc_flbl value from a ipv6 hdr.
 */

#define LOWPAN_IPV6_TC_FLBL_PRIORITY_MASK	0x000000F
#define LOWPAN_IPV6_TC_FLBL_PRIORITY_SHIFT	0

#define LOWPAN_IPV6_TC_FLBL_FLOWLBL_SHIFT	4
#define LOWPAN_IPV6_TC_FLBL_FLOWLBL_MASK	0xFFFFFF0

#define LOWPAN_IPV6_FLOW_LBL_SIZE		3

#define lowpan_get_tc_flbl_from_ipv6(a)					\
	((a->priority << LOWPAN_IPV6_TC_FLBL_PRIORITY_SHIFT) |		\
	 (*((u32 *)a->flow_lbl) << LOWPAN_IPV6_TC_FLBL_FLOWLBL_SHIFT)) \

/*
 * The other way, fill the ipv6hdr from a tc_flbl value. 
 */
static inline void lowpan_set_tc_flbl_to_ipv6(struct ipv6hdr *hdr,
		const u32 flbl)
{
	u32 tmp;

	hdr->priority = ((flbl & LOWPAN_IPV6_TC_FLBL_PRIORITY_MASK)
			>> LOWPAN_IPV6_TC_FLBL_PRIORITY_SHIFT);
	tmp = ((flbl & LOWPAN_IPV6_TC_FLBL_FLOWLBL_MASK)
			>> LOWPAN_IPV6_TC_FLBL_FLOWLBL_SHIFT);
	memcpy(hdr->flow_lbl, &tmp, LOWPAN_IPV6_FLOW_LBL_SIZE);
}

/*
 * These macros handles to grep FLOW LABEL, DSCP and ECN from a
 * ipv6hdr tc_flbl value.
 */
#define LOWPAN_IPV6_ECN_MASK	0x0000003
#define LOWPAN_IPV6_ECN_SHIFT	0

#define lowpan_get_ecn_from_ipv6_tc_flbl(a)				\
	((a & LOWPAN_IPV6_ECN_MASK) >> LOWPAN_IPV6_ECN_SHIFT)

#define LOWPAN_IPV6_DSCP_MASK	0x00000FC
#define LOWPAN_IPV6_DSCP_SHIFT	2

#define lowpan_get_dscp_from_ipv6_tc_flbl(a)				\
	((a & LOWPAN_IPV6_DSCP_MASK) >> LOWPAN_IPV6_DSCP_SHIFT)

#define LOWPAN_IPV6_FLBL_MASK	0xFFFFF00
#define LOWPAN_IPV6_FLBL_SHIFT	8

#define lowpan_get_flbl_from_ipv6_tc_flbl(a)				\
	((a & LOWPAN_IPV6_FLBL_MASK) >> LOWPAN_IPV6_FLBL_SHIFT)

/*
 * Values for 6lowpan header traffic class
 * and flow label.
 *
 * TIFI means:
 * Traffic class inline and flow label inline.
 *
 * TCFI means:
 * Traffic class compressed and flow label inline.
 *
 * TIFC means:
 * Traffic class inline and flow label compressed.
 *
 * This part construct a inline data value for the case
 * LOWPAN_IPHC0_TIFI:
 *
 *  MSB                                          LSB	
 *  31  30  29......24  23  22  21  20  19.......0
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 * |  ECN  |   DSCP    |      rsv      |FLOW LABEL |
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 *
 */
#define LOWPAN_IPHC0_TIFI_ECN_MASK	0xC0000000
#define LOWPAN_IPHC0_TIFI_ECN_SHIFT	30

#define LOWPAN_IPHC0_TIFI_DSCP_MASK	0x3F000000
#define LOWPAN_IPHC0_TIFI_DSCP_SHIFT	24

#define LOWPAN_IPHC0_TIFI_FLBL_MASK	0x000FFFFF
#define LOWPAN_IPHC0_TIFI_FLBL_SHIFT	0

#define LOWPAN_IPHC0_TIFI_MASK		0xFF0FFFFF
#define LOWPAN_IPHC0_TIFI_SIZE		4

/*
 * Construct the 6lowpan inline data for tifi.
 */
#define lowpan_get_tifi_inline_value(a)				\
	(((lowpan_get_ecn_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TIFI_ECN_SHIFT) |			\
	 (lowpan_get_dscp_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TIFI_DSCP_SHIFT) |			\
	 (lowpan_get_flbl_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TIFI_FLBL_SHIFT)) &			\
	 LOWPAN_IPHC0_TIFI_MASK)

/*
 *  These macros is to generate the tc_flbl ipv6
 *  from a tifi lowpan inline data.
 */
#define lowpan_get_ecn_tifi_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TIFI_ECN_MASK) >>		\
	  LOWPAN_IPHC0_TIFI_ECN_SHIFT)

#define lowpan_get_dscp_tifi_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TIFI_DSCP_MASK) >>		\
	  LOWPAN_IPHC0_TIFI_DSCP_SHIFT)

#define lowpan_get_flbl_tifi_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TIFI_FLBL_MASK) >>		\
	  LOWPAN_IPHC0_TIFI_FLBL_SHIFT)

#define lowpan_get_tc_flbl_tifi_from_lowpan(tc_flbl)		\
	((lowpan_get_ecn_tifi_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_ECN_SHIFT) |				\
	 (lowpan_get_dscp_tifi_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_DSCP_SHIFT) |				\
	 (lowpan_get_flbl_tifi_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_FLBL_SHIFT))

/*
 * Values for 6lowpan header traffic class
 * and flow label.
 *
 * Case for LOWPAN_IPHC0_TCFI
 *
 *  MSB                                          LSB
 *  23  22  21  20  19...........................0
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 * |  ECN  |  rsv  |          FLOW LABEL           |
 * +---+---+---+---+---+---+---+---+---+---+---+---+
 *
 */
#define LOWPAN_IPHC0_TCFI_ECN_MASK	0xC00000
#define LOWPAN_IPHC0_TCFI_ECN_SHIFT	22

#define LOWPAN_IPHC0_TCFI_FLBL_MASK	0x0FFFFF
#define LOWPAN_IPHC0_TCFI_FLBL_SHIFT	0

#define LOWPAN_IPHC0_TCFI_MASK		0xCFFFFF
#define LOWPAN_IPHC0_TCFI_SIZE		3

/*
 * Construct the 6lowpan inline data for tcfi.
 */
#define lowpan_get_tcfi_inline_value(a)				\
	(((lowpan_get_ecn_from_ipv6_tc_flbl(a) <<		\
	   LOWPAN_IPHC0_TCFI_ECN_SHIFT) |			\
	 (lowpan_get_flbl_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TCFI_FLBL_SHIFT)) &			\
	 LOWPAN_IPHC0_TCFI_MASK)

/*
 *  These macros is to generate the tc_flbl ipv6
 *  from a tcfi lowpan inline data.
 */
#define lowpan_get_ecn_tcfi_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TCFI_ECN_MASK) >>		\
	  LOWPAN_IPHC0_TCFI_ECN_SHIFT)

#define lowpan_get_flbl_tcfi_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TCFI_FLBL_MASK) >>		\
	  LOWPAN_IPHC0_TCFI_FLBL_SHIFT)

#define lowpan_get_tc_flbl_tcfi_from_lowpan(tc_flbl)		\
	((lowpan_get_ecn_tcfi_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_ECN_SHIFT) |				\
	 (lowpan_get_flbl_tcfi_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_FLBL_SHIFT))
/*
 * Values for 6lowpan header traffic class
 * and flow label.
 *
 * Case for LOWPAN_IPHC0_TIFC
 *
 *  MSB                         LSB
 *   7   6   5   4   3   2   1   0
 * +---+---+---+---+---+---+---+---+
 * |  ECN  |          DSCP         |
 * +---+---+---+---+---+---+---+---+
 */
#define LOWPAN_IPHC0_TIFC_ECN_MASK	0xC0
#define LOWPAN_IPHC0_TIFC_ECN_SHIFT	6

#define LOWPAN_IPHC0_TIFC_DSCP_MASK	0x3F
#define LOWPAN_IPHC0_TIFC_DSCP_SHIFT	0

#define LOWPAN_IPHC0_TIFC_MASK		0xFF
#define LOWPAN_IPHC0_TIFC_SIZE		1

/*
 * Construct the 6lowpan inline data for tifc.
 */
#define lowpan_get_tifc_inline_value(a)				\
	(((lowpan_get_ecn_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TIFC_ECN_SHIFT) |			\
	 (lowpan_get_dscp_from_ipv6_tc_flbl(a) <<		\
	  LOWPAN_IPHC0_TIFC_DSCP_SHIFT)) &			\
	 LOWPAN_IPHC0_TIFC_MASK)

/*
 *  These macros is to generate the tc_flbl ipv6
 *  from a tifc lowpan inline data.
 */
#define lowpan_get_ecn_tifc_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TIFC_ECN_MASK) >>		\
	  LOWPAN_IPHC0_TIFC_ECN_SHIFT)

#define lowpan_get_dscp_tifc_from_lowpan(tc_flbl)		\
	((tc_flbl & LOWPAN_IPHC0_TIFC_DSCP_MASK) >>		\
	  LOWPAN_IPHC0_TIFC_DSCP_SHIFT)

#define lowpan_get_tc_flbl_tifc_from_lowpan(tc_flbl)		\
	((lowpan_get_ecn_tifc_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_ECN_SHIFT) |				\
	 (lowpan_get_dscp_tifc_from_lowpan(tc_flbl) <<		\
	  LOWPAN_IPV6_DSCP_SHIFT))

#define LOWPAN_DISPATCH_IPV6	0x41 /* 01000001 = 65 */
#define LOWPAN_DISPATCH_HC1	0x42 /* 01000010 = 66 */
#define LOWPAN_DISPATCH_IPHC	0x60 /* 011xxxxx = ... */
#define LOWPAN_DISPATCH_FRAG1	0xc0 /* 11000xxx */
#define LOWPAN_DISPATCH_FRAGN	0xe0 /* 11100xxx */

#define LOWPAN_DISPATCH_MASK	0xf8 /* 11111000 */

#define LOWPAN_FRAG_TIMEOUT	(HZ * 60)	/* time-out 60 sec */

#define LOWPAN_FRAG1_HEAD_SIZE	0x4
#define LOWPAN_FRAGN_HEAD_SIZE	0x5

/*
 * According IEEE802.15.4 standard:
 *   - MTU is 127 octets
 *   - maximum MHR size is 37 octets
 *   - MFR size is 2 octets
 *
 * so minimal payload size that we may guarantee is:
 *   MTU - MHR - MFR = 88 octets
 */
#define LOWPAN_FRAG_SIZE	88

/*
 * IPHC0 + IPHC1 + TF + NH + HLIM + CID + SAM + DAM + (UDP) 
 *   1   +   1   + 4  + 1  +  1   +  1  + 16  + 16  + 7
 */ 
#define LOWPAN_MAX_HEADER_LENGTH 48

/*
 * Values of fields within the IPHC encoding first byte
 * (C stands for compressed and I for inline)
 */
#define LOWPAN_IPHC0_TF_MASK	0x18
#define LOWPAN_IPHC0_TF_SHIFT	3
#define LOWPAN_IPHC0_TIFI	(0 << LOWPAN_IPHC0_TF_SHIFT)
#define LOWPAN_IPHC0_TCFI	(1 << LOWPAN_IPHC0_TF_SHIFT)
#define LOWPAN_IPHC0_TIFC	(2 << LOWPAN_IPHC0_TF_SHIFT)
#define LOWPAN_IPHC0_TCFC	(3 << LOWPAN_IPHC0_TF_SHIFT)

#define LOWPAN_IPHC0_NH_MASK	0x04
#define LOWPAN_IPHC0_NH_SHIFT	2
#define LOWPAN_IPHC0_NH_SIZE	1
#define LOWPAN_IPHC0_NH_C	(1 << LOWPAN_IPHC0_NH_SHIFT)

#define LOWPAN_IPHC0_HLIM_MASK	0x03
#define LOWPAN_IPHC0_HLIM_SHIFT	0
#define LOWPAN_IPHC0_HLIM_SIZE	1
#define LOWPAN_IPHC0_HLIM_I	(0 << LOWPAN_IPHC0_HLIM_SHIFT)
#define LOWPAN_IPHC0_HLIM_1	(1 << LOWPAN_IPHC0_HLIM_SHIFT)
#define LOWPAN_IPHC0_HLIM_64	(2 << LOWPAN_IPHC0_HLIM_SHIFT)
#define LOWPAN_IPHC0_HLIM_255	(3 << LOWPAN_IPHC0_HLIM_SHIFT)

/* Values of fields within the IPHC encoding second byte */
#define LOWPAN_IPHC1_ADDR_C_0	0
#define LOWPAN_IPHC1_ADDR_C_8	1
#define LOWPAN_IPHC1_ADDR_C_2	2
#define LOWPAN_IPHC1_ADDR_C_128	3
#define LOWPAN_IPHC1_ADDR_C_IS_DEST	1
#define LOWPAN_IPHC1_ADDR_C_IS_SRC	0

#define LOWPAN_IPHC1_CID_MASK	0x80

#define LOWPAN_IPHC1_SAC_MASK	0x40

#define LOWPAN_IPHC1_SAM_MASK	0x30
#define LOWPAN_IPHC1_SAM_SHIFT	4
#define LOWPAN_IPHC1_SAM_I	(LOWPAN_IPHC1_ADDR_C_0 <<	\
		LOWPAN_IPHC1_SAM_SHIFT)
#define LOWPAN_IPHC1_SAM_C_64	(LOWPAN_IPHC1_ADDR_C_8 <<	\
		LOWPAN_IPHC1_SAM_SHIFT)
#define LOWPAN_IPHC1_SAM_C_16	(LOWPAN_IPHC1_ADDR_C_2 <<	\
		LOWPAN_IPHC1_SAM_SHIFT)
#define LOWPAN_IPHC1_SAM_C_0	(LOWPAN_IPHC1_ADDR_C_128 <<	\
		LOWPAN_IPHC1_SAM_SHIFT)

#define LOWPAN_IPHC1_M_MASK	0x08
#define LOWPAN_IPHC1_M_SHIFT	3
#define LOWPAN_IPHC1_M_C	(1 << LOWPAN_IPHC1_M_SHIFT)

#define LOWPAN_IPHC1_DAC_MASK	0x04

#define LOWPAN_IPHC1_DAM_MASK	0x03
#define LOWPAN_IPHC1_DAM_SHIFT	0
#define LOWPAN_IPHC1_DAM_I	(0 << LOWPAN_IPHC1_DAM_SHIFT)
#define LOWPAN_IPHC1_DAM_C_48	(1 << LOWPAN_IPHC1_DAM_SHIFT)
#define LOWPAN_IPHC1_DAM_C_32	(2 << LOWPAN_IPHC1_DAM_SHIFT)
#define LOWPAN_IPHC1_DAM_C_8	(3 << LOWPAN_IPHC1_DAM_SHIFT)
/*
 * LOWPAN_UDP encoding (works together with IPHC)
 */
#define LOWPAN_NHC_UDP_MASK		0xF8
#define LOWPAN_NHC_UDP_ID		0xF0
#define LOWPAN_NHC_UDP_CHECKSUMC	0x04
#define LOWPAN_NHC_UDP_CHECKSUMI	0x00

#define LOWPAN_NHC_UDP_4BIT_PORT	0xF0B0
#define LOWPAN_NHC_UDP_4BIT_MASK	0xFFF0
#define LOWPAN_NHC_UDP_8BIT_PORT	0xF000
#define LOWPAN_NHC_UDP_8BIT_MASK	0xFF00

/* values for port compression, _with checksum_ ie bit 5 set to 0 */
#define LOWPAN_NHC_UDP_CS_P_00	0xF0 /* all inline */
#define LOWPAN_NHC_UDP_CS_P_01	0xF1 /* source 16bit inline,
					dest = 0xF0 + 8 bit inline */
#define LOWPAN_NHC_UDP_CS_P_10	0xF2 /* source = 0xF0 + 8bit inline,
					dest = 16 bit inline */
#define LOWPAN_NHC_UDP_CS_P_11	0xF3 /* source & dest = 0xF0B + 4bit inline */


/*
 * This function sets a data to a pointer
 * and increase the current pointer.
 *
 * Parameters:
 *	- hc_ptr: pointer for destination and increasing.
 *	- data: source data.
 *	- len: len of data.
 */
static inline void set_hc_ptr_data(u8 **hc_ptr,
		const void *data, size_t len)
{
	memcpy(*hc_ptr, data, len);
	*hc_ptr += len;
}

/*
 * This function fetch data from skb.
 * NOTE:
 *	Don't forget to translate byte order if len > 1!
 *	This is only necessary if you read the fetched
 *	data afterwards.
 * 
 * Parameters:
 *	- skb: pointer for destination and increasing.
 *	- data: destination of data, if NULL we skip data in skb
 *		without saving it in data buffer.
 *	- len: len of data.
 */
static inline int lowpan_fetch_skb(struct sk_buff *skb, void *data, size_t len)
{
	int ret;

	ret = pskb_may_pull(skb, len);
	if (unlikely(ret < 0))
		return ret;

	if (data)
		memcpy(data, skb->data, len);
	
	skb_pull(skb, len);

	return 0;
}

#endif /* __6LOWPAN_H__ */
