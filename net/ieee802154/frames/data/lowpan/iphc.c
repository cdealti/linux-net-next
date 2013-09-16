#define DEBUG

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/jiffies.h>
#include <linux/net.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/export.h>

#include "../ieee802154_data.h"
#include "6lowpan.h"
#include "iphc.h"

static const u8 lowpan_ttl_values[] = {0, 1, 64, 255};

/*
 * Uncompress address function for source and
 * destination address(non-multicast).
 *
 * address_mode is sam value or dam value.
 */
static int
lowpan_uncompress_addr(u8 **lowpan_hdr,
		struct in6_addr *ipaddr,
		const u8 address_mode,
		const struct ieee802154_addr *lladdr)
{
	switch (address_mode) {
	case LOWPAN_IPHC_ADDR_00:
		/* for global link addresses */
		memcpy(ipaddr->s6_addr, *lowpan_hdr, 16);
		*lowpan_hdr += 16;
		break;
	case LOWPAN_IPHC_ADDR_01:
		/* fe:80::XXXX:XXXX:XXXX:XXXX */
		ipaddr->s6_addr[0] = 0xFE;
		ipaddr->s6_addr[1] = 0x80;
		memcpy(&ipaddr->s6_addr[8], *lowpan_hdr, 8);
		*lowpan_hdr += 8;
		break;
	case LOWPAN_IPHC_ADDR_02:
		/* fe:80::ff:fe00:XXXX */
		ipaddr->s6_addr[0] = 0xFE;
		ipaddr->s6_addr[1] = 0x80;
		ipaddr->s6_addr[11] = 0xFF;
		ipaddr->s6_addr[12] = 0xFE;
		memcpy(&ipaddr->s6_addr[14], *lowpan_hdr, 2);
		*lowpan_hdr += 2;
		break;
	case LOWPAN_IPHC_ADDR_03:
		switch (lladdr->addr_type) {
		case IEEE802154_ADDR_LONG:
			/* fe:80::XXXX:XXXX:XXXX:XXXX
			 *        \_________________/
			 *              hwaddr
			 */
			ipaddr->s6_addr[0] = 0xFE;
			ipaddr->s6_addr[1] = 0x80;
			memcpy(&ipaddr->s6_addr[8], lladdr->hwaddr,
					IEEE802154_ADDR_LEN);
			/* second bit-flip (Universe/Local)
			 * is done according RFC2464
			 */
			ipaddr->s6_addr[8] ^= 0x02;
			break;
		case IEEE802154_ADDR_SHORT:
			/* fe:80::ff:fe00:XXXX
			 *		  \__/
			 *	       short_addr
			 *
			 * Universe/Local bit is zero.
			 */
			ipaddr->s6_addr[0] = 0xFE;
			ipaddr->s6_addr[1] = 0x80;
			ipaddr->s6_addr[11] = 0xFF;
			ipaddr->s6_addr[12] = 0xFE;
			ipaddr->s6_addr16[7] = htons(lladdr->short_addr);
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

	lowpan_raw_dump_inline(NULL, "Reconstructed ipv6 addr is:\n",
			ipaddr->s6_addr, 16);

	return 0;
}

/* Uncompress address function for source context
 * based address(non-multicast).
 */
static int
lowpan_uncompress_context_based_src_addr(u8 **lowpan_hdr,
		struct in6_addr *ipaddr,
		const u8 sam)
{
	switch (sam) {
	case LOWPAN_IPHC_ADDR_00:
		/* unspec address ::
		 * Do nothing, address is already ::
		 */
		break;
	case LOWPAN_IPHC_ADDR_01:
		/* TODO */
	case LOWPAN_IPHC_ADDR_02:
		/* TODO */
	case LOWPAN_IPHC_ADDR_03:
		/* TODO */
		pr_debug("SAM value 0x%x not supported\n", sam);
		return -EINVAL;
	default:
		pr_debug("Invalid sam value: 0x%x\n", sam);
		return -EINVAL;
	}

	lowpan_raw_dump_inline(NULL,
			"Reconstructed context based ipv6 src addr is:\n",
			ipaddr->s6_addr, 16);

	return 0;
}

/* Uncompress function for multicast destination address,
 * when M bit is set.
 */
static int
lowpan_uncompress_multicast_daddr(u8 **lowpan_hdr,
		struct in6_addr *ipaddr,
		const u8 dam)
{
	switch (dam) {
	case LOWPAN_IPHC_DAM_00:
		/* 00:  128 bits.  The full address
		 * is carried in-line.
		 */
		memcpy(ipaddr->s6_addr, *lowpan_hdr, 16);
		*lowpan_hdr += 16;
		break;
	case LOWPAN_IPHC_DAM_01:
		/* 01:  48 bits.  The address takes
		 * the form ffXX::00XX:XXXX:XXXX.
		 */
		ipaddr->s6_addr[0] = 0xFF;
		memcpy(&ipaddr->s6_addr[1], *lowpan_hdr, 1);
		*lowpan_hdr += 1;
		memcpy(&ipaddr->s6_addr[11], *lowpan_hdr, 5);
		*lowpan_hdr += 5;
		break;
	case LOWPAN_IPHC_DAM_10:
		/* 10:  32 bits.  The address takes
		 * the form ffXX::00XX:XXXX.
		 */
		ipaddr->s6_addr[0] = 0xFF;
		memcpy(&ipaddr->s6_addr[1], *lowpan_hdr, 1);
		*lowpan_hdr += 1;
		memcpy(&ipaddr->s6_addr[13], *lowpan_hdr, 3);
		*lowpan_hdr += 3;
		break;
	case LOWPAN_IPHC_DAM_11:
		/* 11:  8 bits.  The address takes
		 * the form ff02::00XX.
		 */
		ipaddr->s6_addr[0] = 0xFF;
		ipaddr->s6_addr[1] = 0x02;
		memcpy(&ipaddr->s6_addr[15], *lowpan_hdr, 1);
		*lowpan_hdr += 1;
		break;
	default:
		pr_debug("DAM value has a wrong value: 0x%x\n", dam);
		return -EINVAL;
	}

	lowpan_raw_dump_inline(NULL, "Reconstructed ipv6 multicast addr is:\n",
			ipaddr->s6_addr, 16);

	return 0;
}

static int lowpan_iphc_parse(struct sk_buff *skb)
{
	u8 iphc0, iphc1, tmp;
	struct ipv6hdr hdr = {};
	u8 *lowpan_hdr = skb_network_header(skb);
	size_t lowpan_len = 2;
	struct ieee802154_addr mac_saddr, mac_daddr;
	int err;
	
	iphc0 = *lowpan_hdr++;
	iphc1 = *lowpan_hdr++;

	pr_debug("iphc0 = %02x, iphc1 = %02x\n", iphc0, iphc1);

	hdr.version = 6;

	/* Traffic Class and Flow Label */

	/* Next Header */
	if (!(iphc0 & LOWPAN_IPHC_NH_C))
		hdr.nexthdr = *lowpan_hdr++;

	/* Hop Limit */
	if ((iphc0 & 0x03) != LOWPAN_IPHC_TTL_I)
		hdr.hop_limit = lowpan_ttl_values[iphc0 & 0x03];
	else 
		hdr.hop_limit = *lowpan_hdr++;

	/* Extract SAM to the tmp variable */
	tmp = ((iphc1 & LOWPAN_IPHC_SAM) >> LOWPAN_IPHC_SAM_BIT) & 0x03;

	if (iphc1 & LOWPAN_IPHC_SAC) {
		/* Source address context based uncompression */
		pr_debug("SAC bit is set. Handle context based source address.\n");
		err = lowpan_uncompress_context_based_src_addr(
				&lowpan_hdr, &hdr.saddr, tmp);
	} else {
		/* Source address uncompression */
		pr_debug("source address stateless compression\n");
		err = lowpan_uncompress_addr(&lowpan_hdr, &hdr.saddr, tmp, &mac_saddr);
	}

	/* Check on error of previous branch */
	if (err)
		goto drop;

	/* Extract DAM to the tmp variable */
	tmp = ((iphc1 & LOWPAN_IPHC_DAM_11) >> LOWPAN_IPHC_DAM_BIT) & 0x03;

	/* check for Multicast Compression */
	if (iphc1 & LOWPAN_IPHC_M) {
		if (iphc1 & LOWPAN_IPHC_DAC) {
			pr_debug("dest: context-based mcast compression\n");
			/* TODO: implement this */
		} else {
			err = lowpan_uncompress_multicast_daddr(
					&lowpan_hdr, &hdr.daddr, tmp);
			if (err)
				goto drop;
		}
	} else {
		pr_debug("dest: stateless compression\n");
		err = lowpan_uncompress_addr(&lowpan_hdr, &hdr.daddr, tmp, &mac_daddr);
		if (err)
			goto drop;
	}
	
	lowpan_len = lowpan_hdr - skb_network_header(skb);

	skb_pull(skb, skb->mac_len);
	skb->mac_len = 0;
	skb_pull(skb, lowpan_len);

	skb_reset_transport_header(skb);
	hdr.payload_len = htons(skb->len);
	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_copy_to_linear_data(skb, &hdr, sizeof(struct ipv6hdr));

	pr_debug("IPv6 header dump:\n\tversion = %d\n\tlength  = %d\n\t"
		 "nexthdr = 0x%02x\n\thop_lim = %d\n", hdr.version,
		 ntohs(hdr.payload_len), hdr.nexthdr, hdr.hop_limit);

	lowpan_raw_dump_table(__func__, "raw header dump",
			(u8 *)&hdr, sizeof(hdr));

	lowpan_raw_dump_table(__func__, "raw skb dump",
			skb->data, skb->len);

//	skb->pkt_type = PACKET_BROADCAST;
	skb->protocol = htons(ETH_P_IPV6);

	return 0;
drop:
	return -EINVAL;
}

static u8 lowpan_compress_addr_64(u8 **hc06_ptr, u8 shift,
		const struct in6_addr *ipaddr,
		const unsigned char *lladdr)
{
	u8 val = 0;

	if (is_addr_mac_addr_based(ipaddr, lladdr))
		val = 3; /* 0-bits */
	else if (lowpan_is_iid_16_bit_compressable(ipaddr)) {
		/* compress IID to 16 bits xxxx::XXXX */
		memcpy(*hc06_ptr, &ipaddr->s6_addr16[7], 2);
		*hc06_ptr += 2;
		val = 2; /* 16-bits */
	} else {
		/* do not compress IID => xxxx::IID */
		memcpy(*hc06_ptr, &ipaddr->s6_addr16[4], 8);
		*hc06_ptr += 8;
		val = 1; /* 64-bits */
	}

	return rol8(val, shift);
}

static int lowpan_iphc_create(struct sk_buff *skb, struct net_device *dev,
		unsigned short type, const void *daddr,
		const void *saddr, unsigned int len)
{
		u8 tmp, iphc0, iphc1, *hc06_ptr;
	struct ipv6hdr *hdr;
	u8 head[100];

	printk(KERN_INFO "%s\n", __func__);
	hdr = ipv6_hdr(skb);
	hc06_ptr = head + 2;

	pr_debug("IPv6 header dump:\n\tversion = %d\n\tlength  = %d\n"
		 "\tnexthdr = 0x%02x\n\thop_lim = %d\n", hdr->version,
		 ntohs(hdr->payload_len), hdr->nexthdr, hdr->hop_limit);

	lowpan_raw_dump_table(__func__, "raw skb network header dump",
		skb_network_header(skb), sizeof(struct ipv6hdr));

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

	/* NOTE: payload length is always compressed */

	/* Next Header is compress if UDP */
	if (hdr->nexthdr == UIP_PROTO_UDP)
		iphc0 |= LOWPAN_IPHC_NH_C;

	if ((iphc0 & LOWPAN_IPHC_NH_C) == 0) {
		*hc06_ptr = hdr->nexthdr;
		hc06_ptr += 1;
	}

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
		*hc06_ptr = hdr->hop_limit;
		hc06_ptr += 1;
		break;
	}

	/* source address compression */
	if (is_addr_unspecified(&hdr->saddr)) {
		pr_debug("source address is unspecified, setting SAC\n");
		iphc1 |= LOWPAN_IPHC_SAC;
	/* TODO: context lookup */
	} else if (is_addr_link_local(&hdr->saddr)) {
		pr_debug("source address is link-local\n");
		iphc1 |= lowpan_compress_addr_64(&hc06_ptr,
				LOWPAN_IPHC_SAM_BIT, &hdr->saddr, saddr);
	} else {
		pr_debug("send the full source address\n");
		memcpy(hc06_ptr, &hdr->saddr.s6_addr16[0], 16);
		hc06_ptr += 16;
	}

	/* destination address compression */
	if (is_addr_mcast(&hdr->daddr)) {
		pr_debug("destination address is multicast: ");
		iphc1 |= LOWPAN_IPHC_M;
		if (lowpan_is_mcast_addr_compressable8(&hdr->daddr)) {
			pr_debug("compressed to 1 octet\n");
			iphc1 |= LOWPAN_IPHC_DAM_11;
			/* use last byte */
			*hc06_ptr = hdr->daddr.s6_addr[15];
			hc06_ptr += 1;
		} else if (lowpan_is_mcast_addr_compressable32(&hdr->daddr)) {
			pr_debug("compressed to 4 octets\n");
			iphc1 |= LOWPAN_IPHC_DAM_10;
			/* second byte + the last three */
			*hc06_ptr = hdr->daddr.s6_addr[1];
			memcpy(hc06_ptr + 1, &hdr->daddr.s6_addr[13], 3);
			hc06_ptr += 4;
		} else if (lowpan_is_mcast_addr_compressable48(&hdr->daddr)) {
			pr_debug("compressed to 6 octets\n");
			iphc1 |= LOWPAN_IPHC_DAM_01;
			/* second byte + the last five */
			*hc06_ptr = hdr->daddr.s6_addr[1];
			memcpy(hc06_ptr + 1, &hdr->daddr.s6_addr[11], 5);
			hc06_ptr += 6;
		} else {
			pr_debug("using full address\n");
			iphc1 |= LOWPAN_IPHC_DAM_00;
			memcpy(hc06_ptr, &hdr->daddr.s6_addr[0], 16);
			hc06_ptr += 16;
		}
	} else {
		/* TODO: context lookup */
		if (is_addr_link_local(&hdr->daddr)) {
			pr_debug("dest address is unicast and link-local\n");
			iphc1 |= lowpan_compress_addr_64(&hc06_ptr,
				LOWPAN_IPHC_DAM_BIT, &hdr->daddr, daddr);
		} else {
			pr_debug("dest address is unicast: using full one\n");
			memcpy(hc06_ptr, &hdr->daddr.s6_addr16[0], 16);
			hc06_ptr += 16;
		}
	}

	head[0] = iphc0;
	head[1] = iphc1;

	/* Before replace ipv6hdr to 6lowpan header we save the dgram_size */
	mac_cb(skb)->dgram_size = ntohs(hdr->payload_len) +
		sizeof(struct ipv6hdr);
	mac_cb(skb)->dgram_offset += sizeof(struct ipv6hdr);
	
	skb_pull(skb, sizeof(struct ipv6hdr));
	skb_reset_transport_header(skb);
	memcpy(skb_push(skb, hc06_ptr - head), head, hc06_ptr - head);
	skb_reset_network_header(skb);

	lowpan_raw_dump_table(__func__, "raw skb data dump", skb->data,
				skb->len);

	return 0;
}

static struct ieee802154_dataframe lowpan_iphc =
{
	.parse = lowpan_iphc_parse,
	.create = lowpan_iphc_create,
};

int lowpan_init_iphc()
{
	int ret;

	ret = ieee802154_add_dataframe(&lowpan_iphc, LOWPAN_DISPATCH_IPHC);
	if (ret < 0)
		goto out;
out:
	return ret;
}
