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
	int pos = 0;
	str_t *str = NULL;
	char *factor = NULL, *inter = NULL, *domain = NULL;
	settings_init_t *data = (settings_init_t *)msg->data;

	if (!data->len || IS_ERR_OR_NULL(data))
		goto err;

	/* parse slab allocator's factor */
	if (data->flags & SLAB_FACTOR) {
		str = (str_t *)(data->data + pos);
		factor = kzalloc(str->len + 1, GFP_KERNEL);
		if (!factor) {
			PRINTK("alloc slab growth factor error\n");
			goto err;
		}
		memcpy(factor, (char *)str->buf, str->len);
		pos += str->len + sizeof(str_t);
	}

	/* parse listen interface */
	if (data->flags & INET_INTER) {
		str = (str_t *)(data->data + pos);
		inter = kzalloc(str->len + 1, GFP_KERNEL);
		if (!inter) {
			PRINTK("alloc listen interface error\n");
			goto free_factor;
		}
		memcpy(inter, (char *)str->buf, str->len);
		pos += str->len + sizeof(str_t);
	}

	/* parse unix domain path */
	if (data->flags & UNIX_SOCK) {
		domain = kzalloc(data->len - pos, GFP_KERNEL);
		if (!domain) {
			PRINTK("alloc unix domain path error\n");
			goto free_inter;
		}
		memcpy(domain, (char *)data->data + pos, data->len - pos - 1);
	}

	/* parse delayed, see mc_dispatcher.c */
	size = sizeof(parser_sock_t) + data->len - pos;
	sock_info = kmalloc(size, GFP_KERNEL);
	if (!sock_info) {
		PRINTK("alloc socket-parser vectory error\n");
		goto free_unix;
	}
	sock_info->flags = data->flags;
	sock_info->len = data->len - pos;
	memcpy(sock_info->data, data->data + pos, data->len - pos);

	/* init struct settings */
	memcpy(&settings, data, sizeof(settings));
	settings.factor	    = factor;
	settings.inter	    = inter;
	settings.socketpath = domain;

	return &settings;

free_unix:
	kfree(domain);
free_inter:
	kfree(inter);
free_factor:
	kfree(factor);
err:
	return ERR_PTR(-ENOMEM);
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

void __settings_exit(void)
{
	if (sock_info)
		kfree(sock_info);
}

void settings_exit(void)
{
	kfree(settings.factor);
	kfree(settings.inter);
	kfree(settings.socketpath);
}

static void* user_env_callback(struct cn_msg *msg,
			       struct netlink_skb_parms *pm)
{
	void *res = NULL;
	ack_env_t *penv = (ack_env_t *)msg->data;

	union {
		char		*_str;
		int		*_int;
		unsigned long 	*_ul;
	} data;

	switch (penv->env) {
	case T_MEMD_INITIAL_MALLOC:
		data._ul = (unsigned long *)penv->data;
		res = (void *)*data._ul;
		break;
	case T_MEMD_SLABS_LIMIT:
		data._int = (int *)penv->data;
		res = (void *)(long)*data._int;
		break;
	default:
		WARN(1, "not define environment: %d\n", penv->env);
		break;
	}

	return res;
}

void* user_env(ask_env_t env)
{
	int ret;
	void *res = NULL;
	struct cn_msg *msg;
	ask_env_t *penv;
	char buf[KMC_V_ASK_ENV];

	msg  = (struct cn_msg *)buf;
	penv = (env_t *)msg->data;

	msg->id.idx = CN_IDX_ENV;
	msg->id.val = mc_get_unique_val();
	msg->len    = sizeof(ask_env_t);
	*penv	    = env;

	ret = mc_add_callback(&msg->id, user_env_callback, 1);
	if (unlikely(ret)) {
		PRINTK("add settings init callback error\n");
		goto out;
	}
	res = mc_send_msg_timeout(msg, msecs_to_jiffies(timeout * 1000));
	if (IS_ERR(res)) {
		PRINTK("send settings init error\n");
		res = NULL;
	}

	mc_del_callback(&msg->id, 1);
out:
	mc_put_unique_val(msg->id.val);
	return res;
}

void report_cache_bh_status(bool success)
{
	int ret = 0;
	struct cn_msg *msg;
	__s32 *status;
	char buf[KMC_V_BH_STATUS];

	msg	= (struct cn_msg *)buf;
	status	= (__s32 *)msg->data;

	msg->id.idx = CN_IDX_CACHE_BH_STATUS;
	msg->id.val = mc_get_unique_val();
	msg->len    = sizeof(__s32);
	*status	    = success;

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
