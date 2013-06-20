#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kmod.h>

#include "mc.h"

struct cn_id cache_bh_id = {
	.idx = CN_IDX_CACHE_BH,
	.val = CN_VAL_CACHE_BH
};

struct settings settings __read_mostly;
parser_sock_t *sock_info = NULL;

static void* default_callback(struct cn_msg *msg,
			      struct netlink_skb_parms *pm)
{
	return (void *)1;
}

static void* settings_init_callback(struct cn_msg *msg,
				    struct netlink_skb_parms *pm)
{
	size_t size;
	settings_init_t *data = (settings_init_t *)msg->data;

	if (!data->len || IS_ERR_OR_NULL(data))
		return ERR_PTR(-EFAULT);

	size = sizeof(parser_sock_t) + data->len;
	sock_info = kmalloc(size, GFP_KERNEL);
	if (!sock_info) {
		PRINTK("alloc socket-parser vectory error\n");
		return ERR_PTR(-ENOMEM);
	}

	sock_info->flags = data->flags;
	sock_info->len = data->len;
	memcpy(sock_info->data, data->data, data->len);
	memcpy(&settings, data, sizeof(settings));

	return &settings;
}

int settings_init(void)
{
	int ret = 0;
	void *out;
	struct cn_msg msg;

	msg.id.idx = CN_IDX_INIT_SET;
	msg.id.val = mc_get_unique_val();
	msg.len	= 0;

	ret = mc_add_callback(&msg.id, settings_init_callback, 1);
	if (unlikely(ret)) {
		PRINTK("add settings init callback error\n");
		goto out;
	}
	out = mc_send_msg_timeout(&msg, msecs_to_jiffies(timeout * 1000));
	if (IS_ERR_OR_NULL(out)) {
		PRINTK("send settings init error\n");
		ret = -EFAULT;
	}

	mc_del_callback(&msg.id, 1);
out:
	mc_put_unique_val(msg.id.val);
	return ret;
}

void settings_exit(void)
{
	if (sock_info)
		kfree(sock_info);
}

void report_cache_bh_status(bool success)
{
#define CACHE_BH_STATUS	(sizeof(struct cn_msg) + sizeof(cache_status_t))

	int ret = 0;
	struct cn_msg *msg;
	cache_status_t *sta;
	char buf[CACHE_BH_STATUS];

	msg = (struct cn_msg *)buf;
	sta = (cache_status_t *)msg->data;

	msg->id.idx = CN_IDX_CACHE_BH_STATUS;
	msg->id.val = mc_get_unique_val();
	msg->len    = sizeof(cache_status_t);
	sta->status = success;

	ret = mc_add_callback(&msg->id, default_callback, 0);
	if (unlikely(ret)) {
		PRINTK("add report cache bh callback error\n");
		goto out;
	}
	if (IS_ERR(mc_send_msg(msg))) {
		PRINTK("send cache bh status error\n");
	}

	mc_del_callback(&msg->id, 0);
out:
	mc_put_unique_val(msg->id.val);
#undef CACHE_BH_STATUS
}

static void try_shutdown(void)
{
	char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	char *argv[] = {
		"/sbin/rmmod",
		"kmemcache",
		NULL
	};

	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

void shutdown_cmd(void)
{
	int ret;
	struct cn_msg msg;

	msg.id.idx = CN_IDX_SHUTDOWN;
	msg.id.val = mc_get_unique_val();
	msg.len	= 0;

	ret = mc_add_callback(&msg.id, default_callback, 1);
	if (unlikely(ret)) {
		PRINTK("add shutdown callback error\n");
		goto out;
	}
	mc_send_msg_timeout(&msg, msecs_to_jiffies(timeout * 1000));

	mc_del_callback(&msg.id, 1);
out:
	mc_put_unique_val(msg.id.val);

	try_shutdown();
}
