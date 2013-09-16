
#include "protocols/protocol.h"
#include "lowpan.h"
#include "iphc.h"

int lowpan_init_dispatches()
{
	int ret;

	ret = lowpan_init_prots();
	if (ret < 0)
		goto out;

	ret = lowpan_init_iphc();
	if (ret < 0)
		goto out;

out:
	return ret;
}
EXPORT_SYMBOL(lowpan_init_dispatches);
