#ifndef __IEEE802154_LOWPAN_PROTOCOL_H__
#define __IEEE802154_LOWPAN_PROTOCOL_H__

#include <linux/skbuff.h>

#define MAX_LOWPAN_EID_VALUE	0xF

struct lowpan_prot {
	/* Parse protocol header for registered type */
	int (*parse)(struct sk_buff *skb);
	/* Create protocol header for registered type */
	int (*create)(struct sk_buff *skb);
};

int lowpan_add_prot(const struct lowpan_prot *prot, unsigned char eid);
int lowpan_del_prot(const struct lowpan_prot *prot, unsigned char eid);
int lowpan_init_prots(void);

extern const struct lowpan_prot __rcu *lowpan_prots[MAX_LOWPAN_EID_VALUE];

#endif /* __IEEE802154_LOWPAN_PROTOCOL_H__ */
