#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>

#include "ieee802154_data.h"

const struct ieee802154_dataframe __rcu *ieee802154_dataframes[MAX_LOWPAN_DISPATCHES];
EXPORT_SYMBOL(ieee802154_dataframes);

int ieee802154_add_dataframe(const struct ieee802154_dataframe *dataframe, unsigned char dispatch)
{
	return !cmpxchg((const struct ieee802154_dataframe **)&ieee802154_dataframes[dispatch],
			NULL, dataframe) ? 0 : -1;
}
EXPORT_SYMBOL(ieee802154_add_dataframe);

int ieee802154_del_dataframe(const struct ieee802154_dataframe *dataframe, unsigned char dispatch)
{
	int ret;

	ret = (cmpxchg((const struct ieee802154_dataframe **)&ieee802154_dataframes[dispatch],
		       dataframe, NULL) == dataframe) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(ieee802154_del_dataframe);
