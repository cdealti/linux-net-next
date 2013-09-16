#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>

#include "ieee802154_frame.h"

const struct ieee802154_frame __rcu *ieee802154_frames[MAX_IEEE802154_FRAMES] __read_mostly;
EXPORT_SYMBOL(ieee802154_frames);

int ieee802154_add_frame(const struct ieee802154_frame *frame, unsigned char type)
{
	return !cmpxchg((const struct ieee802154_frame **)&ieee802154_frames[type],
			NULL, frame) ? 0 : -1;
}
EXPORT_SYMBOL(ieee802154_add_frame);

int ieee802154_del_frame(const struct ieee802154_frame *frame, unsigned char type)
{
	int ret;

	ret = (cmpxchg((const struct ieee802154_frame **)&ieee802154_frames[type],
		       frame, NULL) == frame) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(ieee802154_del_frame);

