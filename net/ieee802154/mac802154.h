#ifndef __MAC802154_H__
#define __MAC802154_H__

#include <linux/netdevice.h>
#include <net/ieee802154_netdev.h>

#define MAC802154_FC(x)		ntohs(IEEE802154_FC(*x))

/* The IEEE 802.15.4 standard defines 4 MAC packet types:
 * - beacon frame
 * - MAC command frame
 * - acknowledgement frame
 * - data frame
 *
 * and only the data frame should be pushed to the upper layers, other types
 * are just internal MAC layer management information. So only data packets
 * are going to be sent to the networking queue, all other will be processed
 * right here by using the device workqueue.
 */
struct mac802154_rx_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct ieee802154_dev *dev;
	u8 lqi;
};

int mac802154_header_parse_tmp(struct sk_buff *skb);
void mac802154_netdev_setup(struct net_device *netdev);

#if 0
static inline void mac802154_fill_ieee802154_dst_addr(
		const u8 *mac_hdr, struct ieee802154_addr *addr);
{

}

static inline void mac802154_fill_ieee802154_src_addr(
		const u8 *mac_hdr, struct ieee802154_addr *addr);
{

}
#endif

static inline bool mac802154_fetch_skb(struct sk_buff *skb,
                void *data, const unsigned int len)
{
        if (unlikely(!pskb_may_pull(skb, len)))
                return true;

        skb_copy_from_linear_data(skb, data, len);
        skb_pull(skb, len);

        return false;
}


#endif /* __MAC802154_H__ */
