
#include <linux/export.h>

#include "protocol.h"

#if 0
static struct ieee802154_dataframe lowpan_iphc =
{
	.parse = lowpan_udp_parse,
	.create = lowpan_udp_create,
};

int lowpan_protocol_init_udp()
{
	int ret;

	ret = ieee802154_add_dataframe(&lowpan_iphc, LOWPAN_DISPATCH_IPHC);
	if (ret < 0)
		goto out;
out:
	return ret;
}
#endif
