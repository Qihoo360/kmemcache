#include <sys/types.h>

#include "umemcached.h"

int netlink_send_shutdown(int sock, struct cn_id *id)
{
	struct cn_msg msg;

	msg.id.idx = id->idx;
	msg.id.val = id->val;
	msg.len	   = 0;

	return netlink_send(sock, &msg);
}
