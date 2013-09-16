#include <linux/if_arp.h>
#include <linux/nl802154.h>
#include <linux/crc-ccitt.h>

#include <net/mac802154.h>
#include <net/ieee802154.h>

#include "frames/data/dataframe_handler.h"
#include "frames/ieee802154_frame.h"
#include "mac802154.h"

/* IEEE 802.15.4 transceivers can sleep during the xmit session, so process
 * packets through the workqueue.
 */
struct xmit_work {
	struct work_struct work;
	struct sk_buff *skb;
};

static void mac802154_xmit_worker(struct work_struct *work)
{
	int ret;
	struct xmit_work *xw = container_of(work, struct xmit_work, work);
	struct sk_buff *skb = xw->skb;
	struct net_device *dev = skb->dev;
        struct ieee802154_dev *ieee_dev = netdev_priv(dev);

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	if (!(ieee_dev->flags & IEEE802154_HW_OMIT_CKSUM)) {
		u16 crc = crc_ccitt(0, skb->data, skb->len);
		u8 *data = skb_put(skb, 2);
		data[0] = crc & 0xff;
		data[1] = crc >> 8;
	}

	ret = ieee_dev->ops->xmit(ieee_dev, skb);
	if (ret)
		pr_debug("transmission failed\n");

	consume_skb(skb);
}

static netdev_tx_t mac802154_netdev_xmit(
		struct sk_buff *skb, struct net_device *dev)
{
	struct xmit_work *work;
        struct ieee802154_dev *ieee_dev = netdev_priv(dev);

	work = kzalloc(sizeof(struct xmit_work), GFP_ATOMIC);
	if (!work) {
		kfree_skb(skb);
		return NETDEV_TX_BUSY;
	}

	work->skb = skb;
	INIT_WORK(&work->work, mac802154_xmit_worker);
	queue_work(ieee_dev->workqueue, &work->work);

	return NETDEV_TX_OK;
}

static int mac802154_netdev_mac_addr(struct net_device *dev, void *p)
{
        struct sockaddr *addr = p;

        /* FIXME: validate addr */
        memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
//        mac802154_dev_set_ieee_addr(dev);
        return 0;
}

static int mac802154_netdev_ioctl(struct net_device *dev,
		struct ifreq *ifr, int cmd)
{
	printk("%s cmd %x\n", __func__, cmd);
	return 0;
}

static int mac802154_open(struct net_device *dev)
{
	int ret;
        struct ieee802154_dev *ieee_dev = netdev_priv(dev);

	ret = ieee_dev->ops->start(ieee_dev);
	if (ret < 0)
		return ret;

	netif_start_queue(dev);
        return 0;
}

static int mac802154_stop(struct net_device *dev)
{
        struct ieee802154_dev *ieee_dev = netdev_priv(dev);
	ieee_dev->ops->stop(ieee_dev);
	netif_stop_queue(dev);
	return 0;
}

static const struct net_device_ops mac802154_netdev_ops = {
        .ndo_open               = mac802154_open,
        .ndo_stop               = mac802154_stop,
        .ndo_start_xmit         = mac802154_netdev_xmit,
        .ndo_do_ioctl           = mac802154_netdev_ioctl,
        .ndo_set_mac_address    = mac802154_netdev_mac_addr,
};

static int ieee802154_map_proto_to_frame(unsigned short type, u8 *frame_type)
{
	switch (type) {
	case ETH_P_IEEE802154:
	case ETH_P_IPV6:
		*frame_type = IEEE802154_FC_TYPE_DATA;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int mac802154_header_create(struct sk_buff *skb,
                                   struct net_device *dev,
                                   unsigned short type,
                                   const void *daddr,
                                   const void *saddr,
                                   unsigned len)
{
	const struct ieee802154_frame *frame;
	int ret = -1;
	u8 frame_type;

	printk(KERN_INFO "%s protocol %x\n", __func__, type);

	ieee802154_map_proto_to_frame(type, &frame_type);
	frame = rcu_dereference(ieee802154_frames[frame_type]);
	if (frame)
		ret = frame->create(skb, dev, type, daddr,
				saddr ? saddr : dev->dev_addr, len);

	return ret;
}

/* sepate this function call it from non callback */
static int mac802154_header_parse(const struct sk_buff *skb,
		unsigned char *haddr)
{
	printk(KERN_INFO "%s\n", __func__);
        memset(haddr, 0xff, IEEE802154_ADDR_LEN);
	return 8;
}

static struct header_ops mac802154_header_ops = {
        .create         = mac802154_header_create,
        .parse          = mac802154_header_parse,
};


static int ieee802154_init_frames(void)
{
	int ret;

	ret = ieee802154_init_dataframe();
	if (ret < 0)
		goto out;

out:
	return ret;
}

void mac802154_netdev_setup(struct net_device *netdev)
{
        struct ieee802154_dev *ieee_dev = netdev_priv(netdev);

        netdev->addr_len           = IEEE802154_ADDR_LEN;
        memset(netdev->broadcast, 0xff, IEEE802154_ADDR_LEN);

        netdev->hard_header_len    = MAC802154_FRAME_HARD_HEADER_LEN;
        netdev->needed_tailroom    = 2; /* FCS */
        netdev->mtu                = IEEE802154_MTU;
        netdev->tx_queue_len       = 300;
        netdev->type               = ARPHRD_IEEE802154;
        netdev->flags              = IFF_BROADCAST | IFF_MULTICAST;
//	netdev->flags              = IFF_NOARP | IFF_BROADCAST;
        netdev->watchdog_timeo     = 0;

        netdev->destructor         = free_netdev;
	netdev->header_ops         = &mac802154_header_ops;
	netdev->netdev_ops         = &mac802154_netdev_ops;

        ieee_dev->type = IEEE802154_DEV_WPAN;

        ieee_dev->chan = MAC802154_CHAN_NONE;
        ieee_dev->page = 0;

        spin_lock_init(&ieee_dev->mib_lock);

        get_random_bytes(&ieee_dev->bsn, 1);
        get_random_bytes(&ieee_dev->dsn, 1);

        ieee_dev->pan_id = IEEE802154_PANID_BROADCAST;
        ieee_dev->short_addr = IEEE802154_ADDR_BROADCAST;

	ieee802154_init_frames();
}
EXPORT_SYMBOL(mac802154_netdev_setup);
