#include <net/mac802154.h>
#include <linux/if_ether.h>

#include "dataframe_handler.h"
#include "ieee802154_data.h"
#include "lowpan/iphc.h"
#include "../ieee802154_frame.h"

static int ieee802154_parse_mac(struct sk_buff *skb)
{
	int offset = 3;
	u16 fc;
	
	fc = le16_to_cpu(*((u16 *)skb_mac_header(skb)));

	switch (IEEE802154_FC_DAMODE(fc)) {
	case IEEE802154_ADDR_NONE:
		if (fc & IEEE802154_FC_INTRA_PAN)
			goto malformed;
		break;
	case IEEE802154_ADDR_LONG:
		/* Destination PAN-ID */
		offset += 2;
		/* EUI-64 address */
		offset += IEEE802154_ADDR_LEN;
		break;
	case IEEE802154_ADDR_SHORT:
		/* Destination PAN-ID */
		offset += 2;
		/* Short address */
		offset += 2;
		break;
	default:
		goto malformed;
	}

	switch (IEEE802154_FC_SAMODE(fc)) {
	case IEEE802154_ADDR_NONE:
		break;
	case IEEE802154_ADDR_LONG:
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			/* Destination PAN-ID */
			offset += 2;
		}
		/* EUI-64 address */
		offset += IEEE802154_ADDR_LEN;
		break;
	case IEEE802154_ADDR_SHORT:
		if (!(fc & IEEE802154_FC_INTRA_PAN)) {
			/* Destination PAN-ID */
			offset += 2;
		}
		/* Short address */
		offset += 2;
		break;
	default:
		goto malformed;
	}

	skb_set_network_header(skb, offset);
	skb_reset_mac_len(skb);

	print_hex_dump_bytes("mac header: ", DUMP_PREFIX_NONE,
			skb_mac_header(skb), skb->mac_len);

	return 0;
malformed:
	return -1;
}

static int ieee802154_dataframe_parse(struct sk_buff *skb)
{
	const struct ieee802154_dataframe *dataframe;
	u8 disp_val;
	printk(KERN_INFO "%s\n", __func__);

	ieee802154_parse_mac(skb);

	disp_val = *skb_network_header(skb) & LOWPAN_DISPATCH_MASK;
	dataframe = rcu_dereference(ieee802154_dataframes[disp_val]);
	if (dataframe)
		dataframe->parse(skb);

	return 0;
}

static inline void mac802154_haddr_copy_swap(u8 *dest, const u8 *src)
{
	int i;
	for (i = 0; i < IEEE802154_ADDR_LEN; i++)
		dest[IEEE802154_ADDR_LEN - i - 1] = src[i];
}

static int ieee802154_dataheader_create(struct sk_buff *skb, struct net_device *dev,
		unsigned short type, const void *daddr,
		const void *saddr, unsigned int len)
{
	u8 head[MAC802154_FRAME_HARD_HEADER_LEN];
	int pos = 2;
	u16 fc;

	head[pos++] = 0;

	fc = IEEE802154_FC_TYPE_DATA |
		IEEE802154_ADDR_LONG << IEEE802154_FC_SAMODE_SHIFT |
		IEEE802154_FC_INTRA_PAN;

	head[pos++] = 0xcd;
	head[pos++] = 0xab;

	if (!memcmp(daddr, dev->broadcast, IEEE802154_ADDR_LEN)) {
		fc |= IEEE802154_ADDR_SHORT << IEEE802154_FC_DAMODE_SHIFT;
		memset(head + pos, 0xff, 2);
		pos += 2;
	} else {
		fc |= IEEE802154_ADDR_LONG << IEEE802154_FC_DAMODE_SHIFT;
		mac802154_haddr_copy_swap(head + pos, daddr);
		pos += IEEE802154_ADDR_LEN;
	}


	mac802154_haddr_copy_swap(head + pos, dev->dev_addr);
	pos += IEEE802154_ADDR_LEN;

	head[0] = fc;
	head[1] = fc >> 8;

	memcpy(skb_push(skb, pos), head, pos);
	skb_reset_mac_header(skb);
	skb->mac_len = pos;
	
	return pos;
}

static int ieee802154_map_proto_to_disp(unsigned short type, u8 *disp_val)
{
	switch (type) {
	case ETH_P_IEEE802154:
		//*disp_val = ;
		/* Some reserved DISPATCH val */
		return -EINVAL;
		break;
	case ETH_P_IPV6:
		*disp_val = LOWPAN_DISPATCH_IPHC;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ieee802154_dataframe_create(struct sk_buff *skb, struct net_device *dev,
		unsigned short type, const void *daddr,
		const void *saddr, unsigned int len)
{
	const struct ieee802154_dataframe *dataframe;
	u8 disp_val;
	printk(KERN_INFO "%s\n", __func__);

	ieee802154_map_proto_to_disp(type, &disp_val);
	dataframe = rcu_dereference(ieee802154_dataframes[disp_val]);	
	if (dataframe)
		dataframe->create(skb, dev, type, daddr, saddr, len);

	return ieee802154_dataheader_create(skb, dev, type, daddr, saddr, len);
}

static struct ieee802154_frame ieee802154_frame =
{
	.parse = ieee802154_dataframe_parse,
	.create = ieee802154_dataframe_create,
};

int ieee802154_init_dataframe()
{
	int ret;

	ret = lowpan_init_iphc();
	if (ret < 0)
		goto out;
	
	ret = ieee802154_add_frame(&ieee802154_frame, IEEE802154_FC_TYPE_DATA);
	if (ret < 0)
		goto out;

out:
	return ret;
}
