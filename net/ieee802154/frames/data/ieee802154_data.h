#ifndef __IEEE802154_FRAME_DATA_H__
#define __IEEE802154_FRAME_DATA_H__

#define MAX_LOWPAN_DISPATCHES	0xFF

#define LOWPAN_DISPATCH_IPV6	0x41 /* 01000001 = 65 */
#define LOWPAN_DISPATCH_IPHC	0x60 /* 011xxxxx = ... */
#define LOWPAN_DISPATCH_FRAG1	0xC0 /* 11000xxx */
#define LOWPAN_DISPATCH_FRAGN	0xE0 /* 11100xxx */

#define LOWPAN_DISPATCH_MASK	0xE0 /* 11100000 */

struct ieee802154_dataframe {
	/* Parse data frame header for registered type */
	int (*parse)(struct sk_buff *skb);
	/* Create data frame header for registered type */
	int (*create)(struct sk_buff *skb, struct net_device *dev,
			unsigned short type, const void *daddr,
			const void *saddr, unsigned int len);
#if 0
	/* Some protocols like 6LoWPAN need to set some things directly into mac header 
	 * For example: Multicast/Broadcast addresses need to set a dest mac address for
	 * broadcasting. This callback can be set of upper layers to generate a mac header
	 * which need to get some information from upper layers */
	int (*create_mac_header)(struct sk_buff *skb, struct net_device *dev,
			unsigned short type, const void *daddr,
			const void *saddr, unsigned int len);
#endif
};

int ieee802154_add_dataframe(const struct ieee802154_dataframe *dataframe, unsigned char dispatch);
int ieee802154_del_dataframe(const struct ieee802154_dataframe *dataframe, unsigned char dispatch);

extern const struct ieee802154_dataframe __rcu *ieee802154_dataframes[MAX_LOWPAN_DISPATCHES];

#endif /* __IEEE802154_FRAME_DATA_H__ */
