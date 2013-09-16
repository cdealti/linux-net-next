#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>

#include "protocol.h"

const struct lowpan_prot __rcu *lowpan_prots[MAX_LOWPAN_EID_VALUE];
EXPORT_SYMBOL(lowpan_prots);

int lowpan_add_prot(const struct lowpan_prot *prot, unsigned char eid)
{
	return !cmpxchg((const struct lowpan_prot **)&lowpan_prots[eid],
			NULL, prot) ? 0 : -1;
}
EXPORT_SYMBOL(lowpan_add_prot);

int lowpan_del_prot(const struct lowpan_prot *prot, unsigned char eid)
{
	int ret;

	ret = (cmpxchg((const struct lowpan_prot **)&lowpan_prots[eid],
		       prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}
EXPORT_SYMBOL(lowpan_del_prot);

int lowpan_init_prots()
{
	return 0;
}
EXPORT_SYMBOL(lowpan_init_prots);
