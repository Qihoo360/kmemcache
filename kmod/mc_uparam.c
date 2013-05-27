#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kmod.h>

#include "mc.h"

struct settings settings __read_mostly;
parser_sock_t *sock_info;

static void* settings_init_callback(struct cn_msg *msg,
				    struct netlink_skb_parms *pm)
{
	size_t size;
	settings_init_t *data = (settings_init_t *)msg->data;

	if (IS_ERR_OR_NULL(data))
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
	if (IS_ERR(out)) {
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

static void* shutdown_callback(struct cn_msg *msg, struct netlink_skb_parms *pm)
{
	return ERR_PTR(1);
}

void shutdown_cmd(void)
{
	int ret;
	struct cn_msg msg;

	msg.id.idx = CN_IDX_SHUTDOWN;
	msg.id.val = mc_get_unique_val();
	msg.len	= 0;

	ret = mc_add_callback(&msg.id, shutdown_callback, 1);
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
