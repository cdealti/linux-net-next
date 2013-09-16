#ifndef __IEEE802154_FRAME_H__
#define __IEEE802154_FRAME_H__

#include <net/ieee802154.h>

#define MAX_IEEE802154_FRAMES	7

struct ieee802154_frame {
	/* Parse compressed header for registered type */
	int (*parse)(struct sk_buff *skb);
	/* Create compressed header for registered type */
	int (*create)(struct sk_buff *skb, struct net_device *dev,
			unsigned short type, const void *daddr,
			const void *saddr, unsigned int len);
};

int ieee802154_add_frame(const struct ieee802154_frame *frame, unsigned char type);
int ieee802154_del_frame(const struct ieee802154_frame *frame, unsigned char type);

extern const struct ieee802154_frame __rcu *ieee802154_frames[MAX_IEEE802154_FRAMES];

#endif /* __IEEE802154_FRAME_H__ */
