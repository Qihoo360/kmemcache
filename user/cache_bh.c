#include <sys/types.h>

#include "umemcached.h"

/*
 * enable kmemcache bottom half 
 */
int netlink_send_cache_bh(int sock)
{
	struct cn_msg msg = {
		.id	= {
			.idx = CN_IDX_CACHE_BH,
			.val = CN_VAL_CACHE_BH
		},
		.len	= 0
	};

	return netlink_send(sock, &msg);
}
