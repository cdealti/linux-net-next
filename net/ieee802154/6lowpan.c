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

#include <linux/bitops.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <net/af_ieee802154.h>
#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>
#include <net/ipv6.h>

#include "6lowpan.h"

/* TTL uncompression values */
static const u8 lowpan_ttl_values[] = {0, 1, 64, 255};

static LIST_HEAD(lowpan_devices);

static DEFINE_SPINLOCK(flist_lock);
static LIST_HEAD(lowpan_fragments);

static u8 lowpan_compress_addr_64(u8 **hc06_ptr,
		u8 shift, const struct in6_addr *ipaddr,
		 const unsigned char *lladdr)
{
	u8 val = 0;

	if (is_addr_mac_addr_based(ipaddr, lladdr)) {
		val = 3; /* 0-bits */
	} else if (lowpan_is_iid_16_bit_compressable(ipaddr)) {
		/* compress IID to 16 bits xxxx::XXXX */
		lowpan_push_hc(hc06_ptr, &ipaddr->s6_addr16[7], 2);
		val = 2; /* 16-bits */
	} else {
		/* do not compress IID => xxxx::IID */
		lowpan_push_hc(hc06_ptr, &ipaddr->s6_addr16[4], 8);
		val = 1; /* 64-bits */
	}

	return rol8(val, shift);
}

/*
 * Uncompress address function for source and
 * destination address(non-multicast).
 *
 * address_mode is sam value or dam value.
 */
static int lowpan_uncompress_addr(struct sk_buff *skb,
		struct in6_addr *ipaddr, const u8 address_mode,
		const struct ieee802154_addr *lladdr)
{
	int err;

	switch (address_mode) {
	case LOWPAN_IPHC_ADDR_00:
		/*
		 * for global link addresses
		 */
		err = lowpan_fetch_skb(skb, ipaddr->s6_addr, 16);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_ADDR_01:
		/*
		 * fe:80::XXXX:XXXX:XXXX:XXXX
		 */
		ipaddr->s6_addr[0] = 0xFE;
		ipaddr->s6_addr[1] = 0x80;
		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[8], 8);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_ADDR_02:
		/*
		 * fe:80::ff:fe00:XXXX
		 */
		ipaddr->s6_addr[0] = 0xFE;
		ipaddr->s6_addr[1] = 0x80;
		ipaddr->s6_addr[11] = 0xFF;
		ipaddr->s6_addr[12] = 0xFE;
		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[14], 2);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_ADDR_03:
		switch (lladdr->addr_type) {
		case IEEE802154_ADDR_LONG:
			/*
			 * fe:80::XXXX:XXXX:XXXX:XXXX
			 *        \_________________/
			 *              hwaddr
			 */
			ipaddr->s6_addr[0] = 0xFE;
			ipaddr->s6_addr[1] = 0x80;
			memcpy(&ipaddr->s6_addr[8], lladdr->hwaddr,
					IEEE802154_ADDR_LEN);
			/*
			 * second bit-flip (Universe/Local)
			 * is done according RFC2464
			 */
			ipaddr->s6_addr[8] ^= 0x02;
			break;
		case IEEE802154_ADDR_SHORT:
			/*
			 * fe:80::ff:fe00:XXXX
			 *		  \__/
			 *	       short_addr
			 *
			 * Universe/Local bit is zero.
			 */
			ipaddr->s6_addr[0] = 0xFE;
			ipaddr->s6_addr[1] = 0x80;
			ipaddr->s6_addr[11] = 0xFF;
			ipaddr->s6_addr[12] = 0xFE;
			memset(&ipaddr->s6_addr[14], lladdr->short_addr,
					UIP_802154_SHORTADDR_LEN);
			break;
		default:
			pr_debug("Invalid addr_type set\n");
			return -EINVAL;
		}
		break;
	default:
		pr_debug("Invalid address mode value: 0x%x\n", address_mode);
		return -EINVAL;
	}

	pr_debug("Reconstructed ipv6 addr is:\n");
	lowpan_raw_dump_inline(NULL, NULL, ipaddr->s6_addr, 16);

	return 0;
parse_err:
	return err;
}

/*
 * Uncompress address function for source context
 * based address(non-multicast).
 */
static int lowpan_uncompress_context_based_src_addr(struct sk_buff *skb,
		struct in6_addr *ipaddr, const u8 sam)
{
	switch (sam) {
	case LOWPAN_IPHC_ADDR_00:
		/*
		 * unspec address ::
		 * Do nothing, address is already ::
		 */
		break;
	case LOWPAN_IPHC_ADDR_01:
		/* TODO */
	case LOWPAN_IPHC_ADDR_02:
		/* TODO */
	case LOWPAN_IPHC_ADDR_03:
		/* TODO */
		netdev_warn(skb->dev, "SAM value 0x%x not supported\n", sam);
		return -EINVAL;
	default:
		pr_debug("Invalid sam value: 0x%x\n", sam);
		return -EINVAL;
	}

	pr_debug("Reconstructed context based ipv6 src addr is:\n");
	lowpan_raw_dump_inline(NULL, NULL, ipaddr->s6_addr, 16);

	return 0;
}

/*
 * Uncompress function for multicast destination address,
 * when M bit is set.
 */
static int lowpan_uncompress_multicast_daddr(struct sk_buff *skb,
		struct in6_addr *ipaddr, const u8 dam)
{
	int err;

	switch (dam) {
	case LOWPAN_IPHC_DAM_00:
		/*
		 * 00:  128 bits.  The full address
		 * is carried in-line.
		 */
		err = lowpan_fetch_skb(skb, ipaddr->s6_addr, 16);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_DAM_01:
		/*
		 * 01:  48 bits.  The address takes
		 * the form ffXX::00XX:XXXX:XXXX.
		 */
		ipaddr->s6_addr[0] = 0xFF;

		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[1], 1);
		if (err < 0)
			goto parse_err;

		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[11], 5);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_DAM_10:
		/*
		 * 10:  32 bits.  The address takes
		 * the form ffXX::00XX:XXXX.
		 */
		ipaddr->s6_addr[0] = 0xFF;
		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[1], 1);
		if (err < 0)
			goto parse_err;

		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[13], 3);
		if (err < 0)
			goto parse_err;
		break;
	case LOWPAN_IPHC_DAM_11:
		/*
		 * 11:  8 bits.  The address takes
		 * the form ff02::00XX.
		 */
		ipaddr->s6_addr[0] = 0xFF;
		ipaddr->s6_addr[1] = 0x02;
		err = lowpan_fetch_skb(skb, &ipaddr->s6_addr[15], 1);
		if (err < 0)
			goto parse_err;
		break;
	default:
		pr_debug("DAM value has a wrong value: 0x%x\n", dam);
		return -EINVAL;
	}

	pr_debug("Reconstructed ipv6 multicast addr is:\n");
	lowpan_raw_dump_inline(NULL, NULL, ipaddr->s6_addr, 16);

	return 0;
parse_err:
	return err;
}

static void lowpan_compress_udp_header(u8 **hc06_ptr,
		struct sk_buff *skb)
{
	struct udphdr *uh = udp_hdr(skb);
	u8 tmp;

	if (((uh->source & LOWPAN_NHC_UDP_4BIT_MASK) ==
				LOWPAN_NHC_UDP_4BIT_PORT) &&
	    ((uh->dest & LOWPAN_NHC_UDP_4BIT_MASK) ==
				LOWPAN_NHC_UDP_4BIT_PORT)) {
		pr_debug("UDP header: both ports compression to 4 bits\n");

		tmp = LOWPAN_NHC_UDP_CS_P_11;
		lowpan_push_hc(hc06_ptr, &tmp, 1);
		
		tmp = ((uh->source & LOWPAN_NHC_UDP_4BIT_PORT) << 4) +
			(uh->dest - LOWPAN_NHC_UDP_4BIT_PORT);
		lowpan_push_hc(hc06_ptr, &tmp, 1);
	} else if ((uh->dest & LOWPAN_NHC_UDP_8BIT_MASK) ==
			LOWPAN_NHC_UDP_8BIT_PORT) {
		pr_debug("UDP header: remove 8 bits of dest\n");

		tmp = LOWPAN_NHC_UDP_CS_P_01;
		lowpan_push_hc(hc06_ptr, &tmp, 1);

		lowpan_push_hc(hc06_ptr, &uh->source, 2);
	
		tmp = uh->dest - LOWPAN_NHC_UDP_8BIT_PORT;	
		lowpan_push_hc(hc06_ptr, &tmp, 1);
	} else if ((uh->source & LOWPAN_NHC_UDP_8BIT_MASK) ==
			LOWPAN_NHC_UDP_8BIT_PORT) {
		pr_debug("UDP header: remove 8 bits of source\n");
	
		tmp = LOWPAN_NHC_UDP_CS_P_10;
		lowpan_push_hc(hc06_ptr, &tmp, 1);
	
		lowpan_push_hc(hc06_ptr, &uh->dest, 2);
	
		tmp = uh->source - LOWPAN_NHC_UDP_8BIT_PORT;
		lowpan_push_hc(hc06_ptr, &tmp, 1);
	} else {
		pr_debug("UDP header: can't compress\n");
		tmp = LOWPAN_NHC_UDP_CS_P_00;
		lowpan_push_hc(hc06_ptr, &tmp, 1);
		
		lowpan_push_hc(hc06_ptr, &uh->source, 2);
		
		lowpan_push_hc(hc06_ptr, &uh->dest, 2);
	}

	/* checksum is always inline */
	lowpan_push_hc(hc06_ptr, &uh->check, 2);

	/* skip the UDP header */
	skb_pull(skb, sizeof(struct udphdr));
}

static int lowpan_uncompress_udp_header(struct sk_buff *skb,
		struct udphdr *uh, unsigned d_size)
{
	int err;
	u8 tmp;

	if (!uh)
		goto parse_err;

	err = lowpan_fetch_skb(skb, &tmp, 1);
	if (err < 0)
		goto parse_err;

	if ((tmp & LOWPAN_NHC_UDP_MASK) == LOWPAN_NHC_UDP_ID) {
		pr_debug("UDP header uncompression\n");
		memset(uh, 0, sizeof(struct udphdr));
		switch (tmp & LOWPAN_NHC_UDP_CS_P_11) {
		case LOWPAN_NHC_UDP_CS_P_00:
			err = lowpan_fetch_skb(skb, &uh->source, 2);
			if (err < 0)
				goto parse_err;

			err = lowpan_fetch_skb(skb, &uh->dest, 2);
			if (err < 0)
				goto parse_err;
			break;
		case LOWPAN_NHC_UDP_CS_P_01:
			err = lowpan_fetch_skb(skb, &uh->source, 2);
			if (err < 0)
				goto parse_err;
			
			err = lowpan_fetch_skb(skb, &uh->dest, 1);
			if (err < 0)
				goto parse_err;
			uh->dest += LOWPAN_NHC_UDP_8BIT_PORT;
			break;
		case LOWPAN_NHC_UDP_CS_P_10:
			err = lowpan_fetch_skb(skb, &uh->source, 1);
			if (err < 0)
				goto parse_err;
			uh->source += LOWPAN_NHC_UDP_8BIT_PORT;
			
			err = lowpan_fetch_skb(skb, &uh->dest, 2);
			if (err < 0)
				goto parse_err;
			break;
		case LOWPAN_NHC_UDP_CS_P_11:
			err = lowpan_fetch_skb(skb, &tmp, 1);
			if (err < 0)
				goto parse_err;

			uh->source = LOWPAN_NHC_UDP_4BIT_PORT +
				(tmp >> 4);
			uh->dest = LOWPAN_NHC_UDP_4BIT_PORT +
				(tmp & 0x0f);
			break;
		default:
			pr_debug("ERROR: unknown UDP format\n");
			goto parse_err;
		}

		pr_debug("uncompressed UDP ports: src = %d, dst = %d\n",
			 uh->source, uh->dest);

		/* copy checksum */
		err = lowpan_fetch_skb(skb, &uh->check, 2);
		if (err < 0)
			goto parse_err;

		/*
		 * UDP lenght needs to be infered from the lower layers
		 * here, we obtain the hint from the remaining size of the
		 * frame
		 */
		if (d_size)
			uh->len = htons(d_size -  sizeof(struct ipv6hdr));
		else
			uh->len = htons(skb->len + sizeof(struct udphdr));
		pr_debug("uncompressed UDP length: src = %d", uh->len);
	} else {
		pr_debug("ERROR: unsupported NH format\n");
		goto parse_err;
	}

	return 0;
parse_err:
	return -EINVAL;
}

static int lowpan_header_create(struct sk_buff *skb, struct net_device *dev,
		unsigned short type, const void *_daddr,
		const void *_saddr, unsigned int len)
{
	u8 tmp, iphc0, iphc1, *hc06_ptr;
	struct ipv6hdr *hdr;
	const u8 *saddr = _saddr;
	const u8 *daddr = _daddr;
	u8 head[100];
	struct ieee802154_addr sa, da;

	/* TODO:
	 * if this package isn't ipv6 one, where should it be routed?
	 */
	if (type != ETH_P_IPV6)
		return 0;

	hdr = ipv6_hdr(skb);
	hc06_ptr = head + 2;

	pr_debug("IPv6 header dump:\n\tversion = %d\n\tlength  = %d\n"
		 "\tnexthdr = 0x%02x\n\thop_lim = %d\n", hdr->version,
		 ntohs(hdr->payload_len), hdr->nexthdr, hdr->hop_limit);

	lowpan_raw_dump_table(__func__, "raw skb network header dump",
		skb_network_header(skb), sizeof(struct ipv6hdr));

	if (!saddr)
		saddr = dev->dev_addr;

	lowpan_raw_dump_inline(__func__, "saddr", (unsigned char *)saddr, 8);

	/*
	 * As we copy some bit-length fields, in the IPHC encoding bytes,
	 * we sometimes use |=
	 * If the field is 0, and the current bit value in memory is 1,
	 * this does not work. We therefore reset the IPHC encoding here
	 */
	iphc0 = LOWPAN_DISPATCH_IPHC;
	iphc1 = 0;

	/* TODO: context lookup */

	lowpan_raw_dump_inline(__func__, "daddr", (unsigned char *)daddr, 8);

	/*
	 * Traffic class, flow label
	 * If flow label is 0, compress it. If traffic class is 0, compress it
	 * We have to process both in the same time as the offset of traffic
	 * class depends on the presence of version and flow label
	 */

	/* hc06 format of TC is ECN | DSCP , original one is DSCP | ECN */
	tmp = (hdr->priority << 4) | (hdr->flow_lbl[0] >> 4);
	tmp = ((tmp & 0x03) << 6) | (tmp >> 2);

	if (((hdr->flow_lbl[0] & 0x0F) == 0) &&
	     (hdr->flow_lbl[1] == 0) && (hdr->flow_lbl[2] == 0)) {
		/* flow label can be compressed */
		iphc0 |= LOWPAN_IPHC_FL_C;
		if ((hdr->priority == 0) &&
		   ((hdr->flow_lbl[0] & 0xF0) == 0)) {
			/* compress (elide) all */
			iphc0 |= LOWPAN_IPHC_TC_C;
		} else {
			/* compress only the flow label */
			*hc06_ptr = tmp;
			hc06_ptr += 1;
		}
	} else {
		/* Flow label cannot be compressed */
		if ((hdr->priority == 0) &&
		   ((hdr->flow_lbl[0] & 0xF0) == 0)) {
			/* compress only traffic class */
			iphc0 |= LOWPAN_IPHC_TC_C;
			*hc06_ptr = (tmp & 0xc0) | (hdr->flow_lbl[0] & 0x0F);
			memcpy(hc06_ptr + 1, &hdr->flow_lbl[1], 2);
			hc06_ptr += 3;
		} else {
			/* compress nothing */
			memcpy(hc06_ptr, &hdr, 4);
			/* replace the top byte with new ECN | DSCP format */
			*hc06_ptr = tmp;
			hc06_ptr += 4;
		}
	}

	/* Next Header is compress if UDP */
	if (hdr->nexthdr == UIP_PROTO_UDP)
		iphc0 |= LOWPAN_IPHC_NH_C;

	if (!(iphc0 & LOWPAN_IPHC_NH_C))
		lowpan_push_hc(&hc06_ptr, &hdr->nexthdr, 1);

	/*
	 * Hop limit
	 * if 1:   compress, encoding is 01
	 * if 64:  compress, encoding is 10
	 * if 255: compress, encoding is 11
	 * else do not compress
	 */
	switch (hdr->hop_limit) {
	case 1:
		iphc0 |= LOWPAN_IPHC_TTL_1;
		break;
	case 64:
		iphc0 |= LOWPAN_IPHC_TTL_64;
		break;
	case 255:
		iphc0 |= LOWPAN_IPHC_TTL_255;
		break;
	default:
		lowpan_push_hc(&hc06_ptr, &hdr->hop_limit, 1);
		break;
	}

	/* source address compression */
	if (is_addr_unspecified(&hdr->saddr)) {
		/* Case SAM = 0 and SAC = 1 */
		pr_debug("source address is unspecified, setting SAC\n");
		iphc1 |= LOWPAN_IPHC_SAC;
		/* TODO: context lookup */
	} else if (is_addr_link_local(&hdr->saddr)) {
		pr_debug("source address is link-local\n");
		iphc1 |= lowpan_compress_addr_64(&hc06_ptr,
				LOWPAN_IPHC_SAM_BIT, &hdr->saddr, saddr);
	} else {
		pr_debug("send the full source address\n");
		lowpan_push_hc(&hc06_ptr, &hdr->saddr.s6_addr[0], 16);
	}

	/* destination address compression */
	if (is_addr_mcast(&hdr->daddr)) {
		pr_debug("destination address is multicast: ");
		iphc1 |= LOWPAN_IPHC_M;
		if (lowpan_is_mcast_addr_compressable8(&hdr->daddr)) {
			pr_debug("compressed to 1 octet\n");
			iphc1 |= LOWPAN_IPHC_DAM_11;
			/* use last byte */
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[15], 1);
		} else if (lowpan_is_mcast_addr_compressable32(&hdr->daddr)) {
			pr_debug("compressed to 4 octets\n");
			iphc1 |= LOWPAN_IPHC_DAM_10;
			/* second byte + the last three */
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[1], 1);
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[13], 3);
		} else if (lowpan_is_mcast_addr_compressable48(&hdr->daddr)) {
			pr_debug("compressed to 6 octets\n");
			iphc1 |= LOWPAN_IPHC_DAM_01;
			/* second byte + the last five */
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[1], 1);
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[11], 5);
		} else {
			pr_debug("using full address\n");
			iphc1 |= LOWPAN_IPHC_DAM_00;
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[0], 16);
		}
	} else {
		/* TODO: context lookup */
		if (is_addr_link_local(&hdr->daddr)) {
			pr_debug("dest address is unicast and link-local\n");
			iphc1 |= lowpan_compress_addr_64(&hc06_ptr,
				LOWPAN_IPHC_DAM_BIT, &hdr->daddr, daddr);
		} else {
			pr_debug("dest address is unicast: using full one\n");
			lowpan_push_hc(&hc06_ptr, &hdr->daddr.s6_addr[0], 16);
		}
	}

	mac_cb(skb)->is_udp_compression = 0;
	/* UDP header compression */
	if (hdr->nexthdr == UIP_PROTO_UDP) {
		mac_cb(skb)->is_udp_compression = 1;
		lowpan_compress_udp_header(&hc06_ptr, skb);
	}

	head[0] = iphc0;
	head[1] = iphc1;

	skb_pull(skb, sizeof(struct ipv6hdr));
	memcpy(skb_push(skb, hc06_ptr - head), head, hc06_ptr - head);

	pr_debug("lowpan header len: %d\n", hc06_ptr - head);

	lowpan_raw_dump_table(__func__, "raw skb data dump", skb->data,
				skb->len);

	/*
	 * NOTE1: I'm still unsure about the fact that compression and WPAN
	 * header are created here and not later in the xmit. So wait for
	 * an opinion of net maintainers.
	 */
	/*
	 * NOTE2: to be absolutely correct, we must derive PANid information
	 * from MAC subif of the 'dev' and 'real_dev' network devices, but
	 * this isn't implemented in mainline yet, so currently we assign 0xff
	 */
	{
		mac_cb(skb)->lowpan_header_len = hc06_ptr - head;
		mac_cb(skb)->flags = IEEE802154_FC_TYPE_DATA;
		mac_cb(skb)->seq = ieee802154_mlme_ops(dev)->get_dsn(dev);

		/* prepare wpan address data */
		sa.addr_type = IEEE802154_ADDR_LONG;
		sa.pan_id = ieee802154_mlme_ops(dev)->get_pan_id(dev);

		memcpy(&(sa.hwaddr), saddr, IEEE802154_ADDR_LEN);
		/* intra-PAN communications */
		da.pan_id = ieee802154_mlme_ops(dev)->get_pan_id(dev);

		/*
		 * if the destination address is the broadcast address, use the
		 * corresponding short address
		 */
		if (lowpan_is_addr_broadcast(daddr)) {
			da.addr_type = IEEE802154_ADDR_SHORT;
			da.short_addr = IEEE802154_ADDR_BROADCAST;
		} else {
			da.addr_type = IEEE802154_ADDR_LONG;
			memcpy(&(da.hwaddr), daddr, IEEE802154_ADDR_LEN);

			/* request acknowledgment */
			//mac_cb(skb)->flags |= MAC_CB_FLAG_ACKREQ;
		}

		return dev_hard_header(skb, lowpan_dev_info(dev)->real_dev,
				type, (void *)&da, (void *)&sa, skb->len);
	}
}

static int lowpan_give_skb_to_devices(struct sk_buff *skb)
{
	struct lowpan_dev_record *entry;
	struct sk_buff *skb_cp;
	int stat = NET_RX_SUCCESS;

	rcu_read_lock();
	list_for_each_entry_rcu(entry, &lowpan_devices, list) {
		if (lowpan_dev_info(entry->ldev)->real_dev == skb->dev) {
			skb_cp = skb_copy(skb, GFP_ATOMIC);
			if (!skb_cp) {
				stat = -ENOMEM;
				break;
			}

			skb_cp->dev = entry->ldev;
			stat = netif_rx(skb_cp);
			break;
		}
	}
	rcu_read_unlock();

	return stat;
}

static int lowpan_skb_deliver(struct sk_buff *skb, struct ipv6hdr *hdr)
{
	struct sk_buff *skb_ipv6hdr;
	
	skb_ipv6hdr = skb_realloc_headroom(skb, sizeof(struct ipv6hdr));
	if (!skb_ipv6hdr)
		return -ENOMEM;

	kfree_skb(skb);

	skb_ipv6hdr->protocol = htons(ETH_P_IPV6);
	skb_ipv6hdr->pkt_type = PACKET_HOST;

	skb_push(skb_ipv6hdr, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb_ipv6hdr);
	skb_copy_to_linear_data(skb_ipv6hdr, hdr, sizeof(struct ipv6hdr));

	return lowpan_give_skb_to_devices(skb_ipv6hdr);
}

static void lowpan_fragment_timer_expired(unsigned long entry_addr)
{
	struct lowpan_fragment *entry = (struct lowpan_fragment *)entry_addr;

	pr_debug("timer expired for frame with tag %d\n", entry->tag);

	list_del(&entry->list);
	dev_kfree_skb(entry->skb);
	kfree(entry);
}

static struct lowpan_fragment *lowpan_alloc_new_frame(
		struct sk_buff *skb, u16 len, u16 tag)
{
	struct lowpan_fragment *frame;

	frame = kzalloc(sizeof(struct lowpan_fragment), GFP_ATOMIC);
	if (!frame)
		goto frame_err;

	frame->length = len;
	frame->tag = tag;

	/* allocate buffer for frame assembling */
	frame->skb = netdev_alloc_skb(skb->dev,
			frame->length + sizeof(struct udphdr));
	if (!frame->skb)
		goto skb_err;

	frame->skb->protocol = htons(ETH_P_IPV6);
	frame->skb->pkt_type = PACKET_HOST;
	frame->skb->priority = skb->priority;
	frame->skb->dev = skb->dev;

	skb_reserve(frame->skb, sizeof(struct udphdr));
	skb_put(frame->skb, frame->length);
	/*
	 * copy the first control block to keep a
	 * trace of the link-layer addresses in case
	 * of a link-local compressed address
	 */
	memcpy(frame->skb->cb, skb->cb, sizeof(skb->cb));

	init_timer(&frame->timer);
	/* time out is the same as for ipv6 - 60 sec */
	frame->timer.expires = jiffies + LOWPAN_FRAG_TIMEOUT;
	frame->timer.data = (unsigned long)frame;
	frame->timer.function = lowpan_fragment_timer_expired;
	add_timer(&frame->timer);
	
	list_add_tail(&frame->list, &lowpan_fragments);

	return frame;
skb_err:
	kfree(frame);
frame_err:
	return NULL;
}

static struct sk_buff *lowpan_process_data(
		struct sk_buff *skb, struct ipv6hdr *hdr,
		unsigned d_size)
{
	u8 tmp, iphc0, iphc1;
	const struct ieee802154_addr *_saddr, *_daddr;
	int err;

	lowpan_raw_dump_table(__func__, "raw skb data dump", skb->data,
				skb->len);
	/* at least two bytes will be used for the encoding */
	if (skb->len < 2)
		goto drop;

	err = lowpan_fetch_skb(skb, &iphc0, 1);
	if (err < 0)
		goto drop;
	err = lowpan_fetch_skb(skb, &iphc1, 1);
	if (err < 0)
		goto drop;

	memset(hdr, 0, sizeof(struct ipv6hdr));

	_saddr = &mac_cb(skb)->sa;
	_daddr = &mac_cb(skb)->da;

	pr_debug("iphc0 = %02x, iphc1 = %02x\n", iphc0, iphc1);

	/* another if the CID flag is set */
	if (iphc1 & LOWPAN_IPHC_CID) {
		/* TODO: implement this */
		netdev_warn(skb->dev, "CID bit is set. Context-based not implemented. Drop packet.\n");
		goto drop;
	}

	hdr->version = 6;

	/* Traffic Class and Flow Label */
	switch ((iphc0 & LOWPAN_IPHC_TF) >> 3) {
	/*
	 * Traffic Class and FLow Label carried in-line
	 * ECN + DSCP + 4-bit Pad + Flow Label (4 bytes)
	 */
	case 0: /* 00b */
		err = lowpan_fetch_skb(skb, &tmp, 1);
		if (err < 0)
			goto drop;

		memcpy(&hdr->flow_lbl, &skb->data[0], 3);
		skb_pull(skb, 3);
		hdr->priority = ((tmp >> 2) & 0x0f);
		hdr->flow_lbl[0] = ((tmp >> 2) & 0x30) | (tmp << 6) |
					(hdr->flow_lbl[0] & 0x0f);
		break;
	/*
	 * Traffic class carried in-line
	 * ECN + DSCP (1 byte), Flow Label is elided
	 */
	case 1: /* 01b */
		err = lowpan_fetch_skb(skb, &tmp, 1);
		if (err < 0)
			goto drop;

		hdr->priority = ((tmp >> 2) & 0x0f);
		hdr->flow_lbl[0] = ((tmp << 6) & 0xC0) | ((tmp >> 2) & 0x30);
		break;
	/*
	 * Flow Label carried in-line
	 * ECN + 2-bit Pad + Flow Label (3 bytes), DSCP is elided
	 */
	case 2: /* 10b */
		err = lowpan_fetch_skb(skb, &tmp, 1);
		if (err < 0)
			goto drop;

		hdr->flow_lbl[0] = (skb->data[0] & 0x0F) | ((tmp >> 2) & 0x30);
		memcpy(&hdr->flow_lbl[1], &skb->data[0], 2);
		skb_pull(skb, 2);
		break;
	/* Traffic Class and Flow Label are elided */
	case 3: /* 11b */
		break;
	default:
		break;
	}

	/* Next Header */
	if ((iphc0 & LOWPAN_IPHC_NH_C) == 0) {
		/* Next header is carried inline */
		err = lowpan_fetch_skb(skb, &hdr->nexthdr, 1);
		if (err < 0)
			goto drop;

		pr_debug("NH flag is set, next header carried inline: %02x\n",
			 hdr->nexthdr);
	} else {
		/* TODO check on other nexthdr */
		hdr->nexthdr = UIP_PROTO_UDP;
	}

	/* Hop Limit */
	if ((iphc0 & 0x03) != LOWPAN_IPHC_TTL_I) {
		hdr->hop_limit = lowpan_ttl_values[iphc0 & 0x03];
	} else {
		err = lowpan_fetch_skb(skb, &hdr->hop_limit, 1);
		if (err < 0)
			goto drop;
	}

	/* Extract SAM to the tmp variable */
	tmp = ((iphc1 & LOWPAN_IPHC_SAM) >> LOWPAN_IPHC_SAM_BIT) & 0x03;

	if (iphc1 & LOWPAN_IPHC_SAC) {
		/* Source address context based uncompression */
		pr_debug("SAC bit is set. Handle context based source address.\n");
		err = lowpan_uncompress_context_based_src_addr(
				skb, &hdr->saddr, tmp);
		if (err)
			goto drop;
	} else {
		/* Source address uncompression */
		pr_debug("source address stateless compression\n");
		err = lowpan_uncompress_addr(skb, &hdr->saddr, tmp, _saddr);
		if (err)
			goto drop;
	}

	/* Extract DAM to the tmp variable */
	tmp = ((iphc1 & LOWPAN_IPHC_DAM_11) >> LOWPAN_IPHC_DAM_BIT) & 0x03;

	if (iphc1 & LOWPAN_IPHC_DAC) {
		/* TODO: implement this */
		netdev_warn(skb->dev, "DAC bit is set. Context-based not implemented. Drop packet.\n");
		goto drop;
	} else {
		/* check for Multicast Compression */
		if (iphc1 & LOWPAN_IPHC_M) {
			err = lowpan_uncompress_multicast_daddr(
					skb, &hdr->daddr, tmp);
			if (err)
				goto drop;
		} else {
			pr_debug("dest: stateless compression\n");
			err = lowpan_uncompress_addr(
					skb, &hdr->daddr, tmp, _daddr);
			if (err)
				goto drop;
		}
	}
	
	/* UDP data uncompression */
	if (iphc0 & LOWPAN_IPHC_NH_C) {
		struct udphdr uh;
		struct sk_buff *skb_udphdr;

		if (lowpan_uncompress_udp_header(skb, &uh, d_size))
			goto drop;

		/*
		 * replace the compressed UDP head by the uncompressed UDP
		 * header
		 */
		skb_udphdr = skb_realloc_headroom(skb, sizeof(struct udphdr));
		if (!skb_udphdr)
			goto drop;

		kfree_skb(skb);
		skb = skb_udphdr;

		skb_push(skb, sizeof(struct udphdr));
		skb_reset_transport_header(skb);
		skb_copy_to_linear_data(skb, &uh, sizeof(struct udphdr));

		lowpan_raw_dump_table(__func__, "raw UDP header dump",
				      (u8 *)&uh, sizeof(uh));
	}

	pr_debug("skb headroom size = %d, data length = %d\n",
		 skb_headroom(skb), skb->len);

	pr_debug("IPv6 header dump:\n\tversion = %d\n\tlength  = %d\n\t"
		 "nexthdr = 0x%02x\n\thop_lim = %d\n", hdr->version,
		 ntohs(hdr->payload_len), hdr->nexthdr, hdr->hop_limit);

	lowpan_raw_dump_table(__func__, "raw header dump", (u8 *)hdr,
			sizeof(struct ipv6hdr));
	
	return skb;
drop:
	kfree_skb(skb);
	return NULL;
}

static int lowpan_set_address(struct net_device *dev, void *priv)
{
	struct sockaddr *sa = priv;

	if (netif_running(dev))
		return -EBUSY;

	/* TODO: validate addr */
	memcpy(dev->dev_addr, sa->sa_data, dev->addr_len);
	return 0;
}

static int lowpan_get_mac_header_length(struct sk_buff *skb)
{
	uint16_t fc;
	/*
	 * fc + sq
	 *  2 + 1  = 3
	 */
	int len = 3;

	/* 
	 * first two bytes of mac is flow control field
	 */
	fc = *((uint16_t *)skb->data);

	switch ((fc & IEEE802154_FC_DAMODE_MASK) >>
			IEEE802154_FC_DAMODE_SHIFT) {
		case IEEE802154_ADDR_NONE:
			break;
		case IEEE802154_ADDR_SHORT:
			/* short len */
			len += 2;
			/* dest pan len */
			len += 2;
			break;
		case IEEE802154_ADDR_LONG:
			len += IEEE802154_ADDR_LEN;
			/* dest pan len */
			len += 2;
			break;
		default:
			BUG();
	}
	
	switch ((fc & IEEE802154_FC_SAMODE_MASK) >>
			IEEE802154_FC_SAMODE_SHIFT) {
		case IEEE802154_ADDR_NONE:
			break;
		case IEEE802154_ADDR_SHORT:
			len += 2;
			/* src pan len */
			if (!(fc & IEEE802154_FC_INTRA_PAN))
				len += 2;
			break;
		case IEEE802154_ADDR_LONG:
			len += IEEE802154_ADDR_LEN;
			/* src pan len */
			if (!(fc & IEEE802154_FC_INTRA_PAN))
				len += 2;
			break;
		default:
			BUG();
	}

	/* 
	 * TODO
	 * Add len operation for currently unsupported security
	 * field;
	 */

	return len;
}

static int lowpan_fragment_xmit(struct sk_buff *skb, u8 *head,
		int mlen, int plen, int offset, int type)
{
	struct sk_buff *frag;
	int hlen;

	hlen = (type == LOWPAN_DISPATCH_FRAG1) ?
			LOWPAN_FRAG1_HEAD_SIZE : LOWPAN_FRAGN_HEAD_SIZE;

	lowpan_raw_dump_inline(__func__, "6lowpan fragment header", head, hlen);

	frag = netdev_alloc_skb(skb->dev, hlen + mlen + plen + IEEE802154_MFR_SIZE);
	if (!frag)
		return -ENOMEM;

	frag->priority = skb->priority;

	/* copy header, MFR and payload */
	memcpy(skb_put(frag, mlen), skb->data, mlen);
	memcpy(skb_put(frag, hlen), head, hlen);
	memcpy(skb_put(frag, plen), skb->data + mlen + offset, plen);

	lowpan_raw_dump_table(__func__, " raw fragment dump",
			frag->data, frag->len);

	return dev_queue_xmit(frag);
}

static int lowpan_skb_fragmentation(struct sk_buff *skb,
		struct net_device *dev)
{
	int  err, header_length, payload_length,
	     datagram_size, datagram_offset, tag, offset = 0;
	u8 head[5];

	header_length = lowpan_get_mac_header_length(skb);
	payload_length = skb->len - header_length;
	tag = lowpan_dev_info(dev)->fragment_tag++;
	datagram_size = payload_length - mac_cb(skb)->lowpan_header_len
		+ sizeof(struct ipv6hdr);
	if (mac_cb(skb)->is_udp_compression)
		datagram_size += sizeof(struct udphdr);

	/* first fragment header */
	head[0] = LOWPAN_DISPATCH_FRAG1 | ((datagram_size >> 8) & 0x7);
	head[1] = datagram_size & 0xff;
	head[2] = tag >> 8;
	head[3] = tag & 0xff;

	err = lowpan_fragment_xmit(skb, head, header_length, LOWPAN_FRAG1_SIZE +
			mac_cb(skb)->lowpan_header_len, 0, LOWPAN_DISPATCH_FRAG1);
	if (err) {
		pr_debug("%s unable to send FRAG1 packet (tag: %d)",
			 __func__, tag);
		goto exit;
	}

	offset = LOWPAN_FRAG1_SIZE + mac_cb(skb)->lowpan_header_len;
	datagram_offset = LOWPAN_FRAG1_SIZE + sizeof(struct ipv6hdr);
	if (mac_cb(skb)->is_udp_compression)
		datagram_offset += sizeof(struct udphdr);

	/* next fragment header */
	head[0] &= ~LOWPAN_DISPATCH_FRAG1;
	head[0] |= LOWPAN_DISPATCH_FRAGN;

	while (payload_length - offset > 0) {
		int len = LOWPAN_FRAGN_SIZE;

		head[4] = datagram_offset / 8;

		if (payload_length - offset < LOWPAN_FRAGN_SIZE)
			len = payload_length - offset;

		err = lowpan_fragment_xmit(skb, head, header_length,
					   len, offset, LOWPAN_DISPATCH_FRAGN);
		if (err) {
			pr_debug("%s unable to send a subsequent FRAGN packet "
				 "(tag: %d, offset: %d", __func__, tag, offset);
			goto exit;
		}

		offset += len;
		datagram_offset += len;
	}

	return 0;
exit:
	return err;
}

static netdev_tx_t lowpan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int err = -1;

	pr_debug("package xmit\n");

	skb->dev = lowpan_dev_info(dev)->real_dev;
	if (skb->dev == NULL) {
		pr_debug("ERROR: no real wpan device found\n");
		goto error;
	}

	/* Send directly if less than the MTU minus the 2 checksum bytes. */
	if (skb->len <= IEEE802154_MTU - IEEE802154_MFR_SIZE) {
		err = dev_queue_xmit(skb);
		goto out;
	}

	pr_debug("frame is too big, fragmentation is needed\n");
	err = lowpan_skb_fragmentation(skb, dev);
error:
	dev_kfree_skb(skb);
out:
	if (err)
		pr_debug("ERROR: xmit failed\n");

	return (err < 0) ? NET_XMIT_DROP : err;
}

static struct wpan_phy *lowpan_get_phy(const struct net_device *dev)
{
	struct net_device *real_dev = lowpan_dev_info(dev)->real_dev;
	return ieee802154_mlme_ops(real_dev)->get_phy(real_dev);
}

static u16 lowpan_get_pan_id(const struct net_device *dev)
{
	struct net_device *real_dev = lowpan_dev_info(dev)->real_dev;
	return ieee802154_mlme_ops(real_dev)->get_pan_id(real_dev);
}

static u16 lowpan_get_short_addr(const struct net_device *dev)
{
	struct net_device *real_dev = lowpan_dev_info(dev)->real_dev;
	return ieee802154_mlme_ops(real_dev)->get_short_addr(real_dev);
}

static u8 lowpan_get_dsn(const struct net_device *dev)
{
	struct net_device *real_dev = lowpan_dev_info(dev)->real_dev;
	return ieee802154_mlme_ops(real_dev)->get_dsn(real_dev);
}

static struct header_ops lowpan_header_ops = {
	.create	= lowpan_header_create,
};

static const struct net_device_ops lowpan_netdev_ops = {
	.ndo_start_xmit		= lowpan_xmit,
	.ndo_set_mac_address	= lowpan_set_address,
};

static struct ieee802154_mlme_ops lowpan_mlme = {
	.get_pan_id = lowpan_get_pan_id,
	.get_phy = lowpan_get_phy,
	.get_short_addr = lowpan_get_short_addr,
	.get_dsn = lowpan_get_dsn,
};

static void lowpan_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);
	dev->type		= ARPHRD_IEEE802154;
	/* Frame Control + Sequence Number + Address fields + Security Header */
	dev->hard_header_len	= 2 + 1 + 20 + 14;
	dev->needed_tailroom	= 2; /* FCS */
	dev->mtu		= 1281;
	dev->tx_queue_len	= 0;
	dev->flags		= IFF_BROADCAST | IFF_MULTICAST;
	dev->watchdog_timeo	= 0;

	dev->netdev_ops		= &lowpan_netdev_ops;
	dev->header_ops		= &lowpan_header_ops;
	dev->ml_priv		= &lowpan_mlme;
	dev->destructor		= free_netdev;
}

static int lowpan_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != IEEE802154_ADDR_LEN)
			return -EINVAL;
	}
	return 0;
}

static int lowpan_get_frag_info(struct sk_buff *skb, u16 *d_tag,
		u16 *d_size, u8 *d_offset)
{
	int err;
	u8 pattern, low;

	err = lowpan_fetch_skb(skb, &pattern, 1);
	if (err < 0)
		goto parse_err;
	err = lowpan_fetch_skb(skb, &low, 1);
	if (err < 0)
		goto parse_err;
        *d_size = (pattern & 7) << 8 | low;

	err = lowpan_fetch_skb(skb, d_tag, 2);
	if (err < 0)
		goto parse_err;
	/* We read this value in comming process */
	*d_tag = ntohs(*d_tag);

        if (d_offset) {
		err = lowpan_fetch_skb(skb, d_offset, 1);
		if (err < 0)
			goto parse_err;
        }

        return 0;
parse_err:
        return -1;
}

static struct lowpan_fragment *lowpan_get_tag_frame(
		struct sk_buff *skb, u16 d_tag, u16 d_size)
{
        struct lowpan_fragment *frame;

        list_for_each_entry(frame, &lowpan_fragments, list) {
                if (frame->tag == d_tag)
                        return frame;
        }

        return lowpan_alloc_new_frame(skb, d_size, d_tag);
}

static int lowpan_check_frag_complete(struct lowpan_fragment *frame)
{
	struct ipv6hdr *hdr = (struct ipv6hdr *)frame->skb->data;

	if (frame->bytes_rcv != frame->length)
		return 0;
	
	list_del(&frame->list);
	
	del_timer_sync(&frame->timer);

	hdr->payload_len = htons(frame->length - sizeof(struct ipv6hdr));
	lowpan_give_skb_to_devices(frame->skb);
	kfree(frame);

	return 1;
}

static int lowpan_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;
	u16 d_tag, d_size = 0;
	u8 d_offset;
	struct ipv6hdr hdr;
	struct lowpan_fragment *frame;

	if (!netif_running(dev))
		goto drop;

	if (dev->type != ARPHRD_IEEE802154)
		goto drop;
	
	/* TODO why we need to handle it?
	 */
	if (*skb->data == LOWPAN_DISPATCH_IPV6) {
		
		skb->protocol = htons(ETH_P_IPV6);
		skb->pkt_type = PACKET_HOST;
		skb_pull(skb, 1);
                
		skb_reset_network_header(skb);
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));

		ret = lowpan_give_skb_to_devices(skb);
		if (ret < 0)
			goto drop;

		goto out;
	}

	/* It's a 6lowpan packet!
	 */
	switch (*skb->data & LOWPAN_DISPATCH_MASK)
	{
	case LOWPAN_DISPATCH_IPHC:	/* ipv6 datagram */
		skb = lowpan_process_data(skb, &hdr, 0);
		if (!skb)
			goto drop;

		hdr.payload_len = htons(skb->len);
		lowpan_skb_deliver(skb, &hdr);
		break;
	case LOWPAN_DISPATCH_FRAG1:	/* first fragment header */
		ret = lowpan_get_frag_info(skb, &d_tag, &d_size, NULL);
		if (ret < 0)
			goto drop;
		spin_lock_bh(&flist_lock);
		
		frame = lowpan_get_tag_frame(skb, d_tag, d_size);

		skb = lowpan_process_data(skb, &hdr, d_size);
		if (!skb)
			goto unlock_and_drop;
		
		skb_copy_to_linear_data(frame->skb,
				&hdr, sizeof(struct ipv6hdr));
		skb_copy_to_linear_data_offset(frame->skb, sizeof(struct ipv6hdr),
				skb->data, skb->len);
		
		frame->bytes_rcv += sizeof(struct ipv6hdr) + skb->len;
		lowpan_check_frag_complete(frame);

		spin_unlock_bh(&flist_lock);
		break;
	case LOWPAN_DISPATCH_FRAGN:	/* next fragments headers */
		ret = lowpan_get_frag_info(skb, &d_tag, &d_size, &d_offset);
		if (ret < 0)
			goto drop;
		spin_lock_bh(&flist_lock);
		
		frame = lowpan_get_tag_frame(skb, d_tag, d_size);
		
		skb_copy_to_linear_data_offset(frame->skb, (d_offset * 8),
				skb->data, skb->len);
		
		frame->bytes_rcv += skb->len;
		lowpan_check_frag_complete(frame);

		spin_unlock_bh(&flist_lock);
		break;
	default:
		goto drop;
	}

out:
	return NET_RX_SUCCESS;
unlock_and_drop:
	spin_unlock_bh(&flist_lock);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int lowpan_newlink(struct net *src_net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[])
{
	struct net_device *real_dev;
	struct lowpan_dev_record *entry;

	pr_debug("adding new link\n");

	if (!tb[IFLA_LINK])
		return -EINVAL;
	/* find and hold real wpan device */
	real_dev = dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (!real_dev)
		return -ENODEV;

	lowpan_dev_info(dev)->real_dev = real_dev;
	lowpan_dev_info(dev)->fragment_tag = 0;
	mutex_init(&lowpan_dev_info(dev)->dev_list_mtx);

	entry = kzalloc(sizeof(struct lowpan_dev_record), GFP_KERNEL);
	if (!entry) {
		dev_put(real_dev);
		lowpan_dev_info(dev)->real_dev = NULL;
		return -ENOMEM;
	}

	entry->ldev = dev;

	mutex_lock(&lowpan_dev_info(dev)->dev_list_mtx);
	INIT_LIST_HEAD(&entry->list);
	list_add_tail(&entry->list, &lowpan_devices);
	mutex_unlock(&lowpan_dev_info(dev)->dev_list_mtx);

	register_netdevice(dev);

	return 0;
}

static void lowpan_dellink(struct net_device *dev, struct list_head *head)
{
	struct lowpan_dev_info *lowpan_dev = lowpan_dev_info(dev);
	struct net_device *real_dev = lowpan_dev->real_dev;
	struct lowpan_dev_record *entry, *tmp;

	ASSERT_RTNL();

	mutex_lock(&lowpan_dev_info(dev)->dev_list_mtx);
	list_for_each_entry_safe(entry, tmp, &lowpan_devices, list) {
		if (entry->ldev == dev) {
			list_del(&entry->list);
			kfree(entry);
		}
	}
	mutex_unlock(&lowpan_dev_info(dev)->dev_list_mtx);

	mutex_destroy(&lowpan_dev_info(dev)->dev_list_mtx);

	unregister_netdevice_queue(dev, head);

	dev_put(real_dev);
}

static struct rtnl_link_ops lowpan_link_ops __read_mostly = {
	.kind		= "lowpan",
	.priv_size	= sizeof(struct lowpan_dev_info),
	.setup		= lowpan_setup,
	.newlink	= lowpan_newlink,
	.dellink	= lowpan_dellink,
	.validate	= lowpan_validate,
};

static struct packet_type lowpan_packet_type = {
	.type = __constant_htons(ETH_P_IEEE802154),
	.func = lowpan_rcv,
};

static int lowpan_device_event(struct notifier_block *unused,
				unsigned long event,
				void *ptr)
{
	struct net_device *dev = ptr;
	LIST_HEAD(del_list);
	struct lowpan_dev_record *entry, *tmp;

	if (dev->type != ARPHRD_IEEE802154)
		goto out;

	if (event == NETDEV_UNREGISTER) {
		list_for_each_entry_safe(entry, tmp, &lowpan_devices, list) {
			if (lowpan_dev_info(entry->ldev)->real_dev == dev)
				lowpan_dellink(entry->ldev, &del_list);
		}

		unregister_netdevice_many(&del_list);
	}

out:
	return NOTIFY_DONE;
}

static struct notifier_block lowpan_dev_notifier = {
	.notifier_call = lowpan_device_event,
};

static int __init lowpan_init_module(void)
{
	int err;

	err = rtnl_link_register(&lowpan_link_ops);
	if (err < 0)
		goto out;

	dev_add_pack(&lowpan_packet_type);

	err = register_netdevice_notifier(&lowpan_dev_notifier);
	if (err < 0) {
		dev_remove_pack(&lowpan_packet_type);
		rtnl_link_unregister(&lowpan_link_ops);
	}
out:
	return err;
}

static void __exit lowpan_cleanup_module(void)
{
	struct lowpan_fragment *frame, *tframe;

	rtnl_link_unregister(&lowpan_link_ops);

	dev_remove_pack(&lowpan_packet_type);

	unregister_netdevice_notifier(&lowpan_dev_notifier);

	/* Now 6lowpan packet_type is removed, so no new fragments are
	 * expected on RX, therefore that's the time to clean incomplete
	 * fragments.
	 */
	spin_lock_bh(&flist_lock);
	list_for_each_entry_safe(frame, tframe, &lowpan_fragments, list) {
		del_timer_sync(&frame->timer);
		list_del(&frame->list);
		dev_kfree_skb(frame->skb);
		kfree(frame);
	}
	spin_unlock_bh(&flist_lock);
}

module_init(lowpan_init_module);
module_exit(lowpan_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("lowpan");
