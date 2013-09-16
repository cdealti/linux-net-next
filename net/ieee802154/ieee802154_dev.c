/*
 * Copyright (C) 2007-2012 Siemens AG
 *
 * Written by:
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 *
 * Based on the code from 'linux-zigbee.sourceforge.net' project.
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

#define DEBUG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#include <net/netlink.h>
#include <linux/nl802154.h>
#include <net/ieee802154.h>
#include <net/mac802154.h>
#include <net/route.h>
#include <net/wpan-phy.h>
#include <linux/crc-ccitt.h>

#include "frames/ieee802154_frame.h"
#include "mac802154.h"

struct ieee802154_dev *ieee802154_alloc_device(
		size_t priv_data_len, struct ieee802154_ops *ops)
{
	struct net_device *netdev;
	struct ieee802154_dev *ieee_dev;

	if (!ops || !ops->xmit || !ops->ed || !ops->start ||
	    !ops->stop || !ops->set_channel) {
		printk(KERN_ERR
		       "undefined IEEE802.15.4 device operations\n");
		return ERR_PTR(-EINVAL);
	}

	netdev = alloc_netdev(sizeof(struct ieee802154_dev),
			"wpan%d", mac802154_netdev_setup);
	if (!netdev) {
		printk(KERN_ERR
		       "failure to allocate master IEEE802.15.4 device\n");
		return ERR_PTR(-ENOMEM);
	}

	ieee_dev = netdev_priv(netdev);
	ieee_dev->netdev = netdev;

	ieee_dev->priv = kzalloc(priv_data_len, GFP_KERNEL);
	if (!ieee_dev->priv) {
		printk(KERN_ERR
		       "failure to allocate master IEEE802.15.4 device\n");
		free_netdev(netdev);
		return ERR_PTR(-ENOMEM);
	}

	ieee_dev->current_channel = -1;
	ieee_dev->current_page = 0;
	ieee_dev->ops = ops;

	return ieee_dev;
}
EXPORT_SYMBOL(ieee802154_alloc_device);

int ieee802154_register_device(struct ieee802154_dev *ieee_dev)
{
	int ret;
#if 1
	ieee_dev->hw_filt.pan_id = 0xABCD;
	ieee_dev->hw_filt.short_addr = 1;
	ieee_dev->hw_filt.ieee_addr[0] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[1] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[2] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[3] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[4] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[5] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[6] = 0xAA;
	ieee_dev->hw_filt.ieee_addr[7] = 0xAA;

	ieee_dev->ops->set_channel(ieee_dev, 0, 26);
	ieee_dev->ops->set_hw_addr_filt(ieee_dev,
					&ieee_dev->hw_filt,
					IEEE802515_AFILT_SADDR_CHANGED |
					IEEE802515_AFILT_PANID_CHANGED |
					IEEE802515_AFILT_IEEEADDR_CHANGED);
#endif

	ieee_dev->workqueue =
		create_singlethread_workqueue(netdev_name(ieee_dev->netdev));
	if (!ieee_dev->workqueue) {
		ret = -ENOMEM;
		goto out;
	}

        ret = register_netdev(ieee_dev->netdev);
	if (ret < 0)
		goto out_wq;

	return ret;
out_wq:
	destroy_workqueue(ieee_dev->workqueue);
out:
	return ret;
}
EXPORT_SYMBOL(ieee802154_register_device);

void ieee802154_unregister_device(struct ieee802154_dev *ieee_dev)
{
	flush_workqueue(ieee_dev->workqueue);
	destroy_workqueue(ieee_dev->workqueue);
	unregister_netdev(ieee_dev->netdev);
}
EXPORT_SYMBOL(ieee802154_unregister_device);

void ieee802154_free_device(struct ieee802154_dev *ieee_dev)
{
	kfree(ieee_dev->priv);
	free_netdev(ieee_dev->netdev);
}
EXPORT_SYMBOL(ieee802154_free_device);

void ieee802154_rx_irqsafe(struct ieee802154_dev *ieee_dev,
		struct sk_buff *skb, u8 lqi)
{
	int ret;
	u8 frame_type;
	const struct ieee802154_frame *frame;

	mac_cb(skb)->lqi = lqi;
	skb->protocol = htons(ETH_P_IEEE802154);
	skb->dev = ieee_dev->netdev;

	BUILD_BUG_ON(sizeof(struct ieee802154_mac_cb) > sizeof(skb->cb));

	if (!(ieee_dev->flags & IEEE802154_HW_OMIT_CKSUM)) {
		u16 crc;

		if (skb->len < 2) {
			pr_debug("got invalid frame\n");
			return;
		}
		crc = crc_ccitt(0, skb->data, skb->len);
		if (crc) {
			pr_debug("CRC mismatch\n");
			return;
		}
		skb_trim(skb, skb->len - 2); /* CRC */
	}


	ieee_dev->netdev->stats.rx_packets++;
        ieee_dev->netdev->stats.rx_bytes += skb->len;

	skb_reset_mac_header(skb);
	frame_type = *skb_mac_header(skb) & 0x3;
	frame = rcu_dereference(ieee802154_frames[frame_type]);
	if (frame)
		frame->parse(skb);

	ret = netif_rx_ni(skb);
	if (ret != NET_RX_SUCCESS)
		pr_debug("receive failed\n");
}
EXPORT_SYMBOL(ieee802154_rx_irqsafe);

MODULE_DESCRIPTION("IEEE 802.15.4 implementation");
MODULE_LICENSE("GPL v2");
