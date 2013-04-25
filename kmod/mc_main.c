#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/param.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/fs.h>

#include "mc.h"
#include "kmodhelper.h"

int timeout = 5;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "timeout in seconds for msg from umemcached");

int single_dispatch = 1;
module_param(single_dispatch, int, 0);
MODULE_PARM_DESC(single_dispatch, "value 0 means one thread for each CPU");

volatile rel_time_t current_time;
rel_time_t process_started __read_mostly;

rel_time_t realtime(rel_time_t exptime)
{
	/* no. of seconds in 30 days - largest possible delta exptime */

	if (exptime == 0)
		return 0;	/* 0 means never expire */

	if (exptime > REALTIME_MAXDELTA) {
		/* 
		 * if item expiration is at/before the server started, give it an
		 * expiration time of 1 second after the server started.
		 * (because 0 means don't expire).  without this, we'd
		 * underflow and wrap around to some large value way in the
		 * future, effectively making items expiring in the past
		 * really expiring never
		 */
		if (exptime <= process_started)
			return (rel_time_t)1;
		return (rel_time_t)(exptime - process_started);
	} else {
		return (rel_time_t)(exptime + current_time);
	}
}

#define TIMER_CYCLE	((unsigned long) ~0)
static struct time_updater {
#define TIMER_DEL	0x1
	u32 flags;
	struct timer_list timer;
} time_updater;

static void mc_timer_update(unsigned long arg)
{
	struct time_updater *t = 
		(struct time_updater *)arg;

	if (unlikely(t->flags & TIMER_DEL))
		return;
	current_time++;
	t->timer.expires = jiffies + HZ;
	add_timer(&t->timer);
}

static int INIT timer_init(void)
{
	current_time = 0;

	init_timer(&time_updater.timer);

	time_updater.timer.expires = jiffies + HZ;
	time_updater.timer.data	   = (unsigned long)&time_updater;
	time_updater.timer.function= mc_timer_update;

	add_timer(&time_updater.timer);

	return 0;
}

static void timer_exit(void)
{
	time_updater.flags |= TIMER_DEL;
	del_timer_sync(&time_updater.timer);
}

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
		PRINTK("alloc socket-parser vectory error");
		return ERR_PTR(-ENOMEM);
	}

	sock_info->flags = data->flags;
	sock_info->len = data->len;
	memcpy(sock_info->data, data->data, data->len);
	memcpy(&settings, data, sizeof(settings));

	return &settings;
}

static inline void INIT settings_exit(void)
{
	kfree(sock_info);
}

static int INIT settings_init(void)
{
	int ret = 0;
	void *out;
	struct cn_msg msg;

	msg.id.idx = CN_IDX_INIT_SET;
	msg.id.val = mc_get_unique_val();
	msg.len	= 0;

	ret = mc_add_callback(&msg.id, settings_init_callback);
	if (unlikely(ret)) {
		PRINTK("add settings init callback error");
		goto out;
	}
	out = mc_send_msg_timeout(&msg, msecs_to_jiffies(timeout * 1000));
	if (IS_ERR(out)) {
		PRINTK("send settings init error");
		ret = -EFAULT;
	}

	mc_del_callback(&msg.id);
out:
	mc_put_unique_val(msg.id.val);
	return ret;
}

static struct cache_info {
	struct kmem_cache **cachep;
	char *name;
	size_t size;
	void (*ctor)(void *);
} caches_info[] = {
#ifdef CONFIG_BUFFER_CACHE
	{
		.cachep = &buffer_cachep,
		.name	= "mc_buffer_cache",
		.size	= sizeof(struct buffer),
		.ctor	= NULL
	},
#endif
#ifdef CONFIG_LISTEN_CACHE
	{
		.cachep = &listen_cachep,
		.name	= "mc_listen_cache",
		.size	= sizeof(struct server_work),
		.ctor	= NULL
	},
#endif
	{
		.cachep	= &prefix_cachep,
		.name	= "mc_prefix_cache",
		.size	= sizeof(struct prefix_stats),
		.ctor	= NULL
	},
	{
		.cachep	= &suffix_cachep,
		.name	= "mc_suffix_cache",
		.size	= SUFFIX_SIZE,
		.ctor	= NULL
	},
	{
		.cachep	= &conn_req_cachep,
		.name	= "mc_conn_req_cache",
		.size	= sizeof(struct conn_req),
		.ctor	= NULL
	},
	{
		.cachep	= &lock_xchg_req_cachep,
		.name	= "mc_lock_xchg_req_cache",
		.size	= sizeof(struct lock_xchg_req),
		.ctor	= NULL
	},
	{
		.cachep	= &conn_cachep,
		.name	= "mc_conn_cache",
		.size	= sizeof(struct conn),
		.ctor	= NULL
	},
};

static void caches_info_exit(void)
{
	int i;
	struct cache_info *cache;

	for (i = 0; i < ARRAY_SIZE(caches_info); i++) {
		cache = &caches_info[i];
		if (*cache->cachep) {
			kmem_cache_destroy(*cache->cachep);
		}
	}
}

static int INIT  caches_info_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(caches_info); i++) {
		struct cache_info *cache = &caches_info[i];

		*cache->cachep = kmem_cache_create(cache->name,
						   cache->size,
						   0,
						   SLAB_HWCACHE_ALIGN |
						   SLAB_PANIC,
						   cache->ctor);
		if (!*cache->cachep) {
			PRINTK("create kmem cache error");
			goto out;
		}
	}

	return 0;
out:
	caches_info_exit();
	return -ENOMEM;
}

#ifdef CONFIG_DEBUG
static int init_status = -EFAULT;
#endif

#ifdef CONFIG_DEBUG
static void _kmemcache_init(void *unused)
#else
static int INIT _kmemcache_init(void)
#endif
{
	int ret = 0;

	if ((ret = settings_init())) {
		PRINTK("init settings error");
		goto out;
	}
	if ((ret = caches_info_init())) {
		PRINTK("init caches error");
		goto del_set;
	}
	if ((ret = stats_init())) {
		PRINTK("init stats error");
		goto del_caches;
	}
	if ((ret = slabs_init(settings.maxbytes,
			      settings.factor,
			      settings.preallocate))) {
		PRINTK("init slabs error");
		goto del_stats;
	}
	if ((ret = assoc_init(settings.hashpower_init))) {
		PRINTK("init assoc error");
		goto del_slabs;
	}
	if ((ret = dispatcher_init())) {
		PRINTK("init dispatcher error");
		goto del_assoc;
	}
	if ((ret = workers_init())) {
		PRINTK("init workers error");
		goto del_dispatcher;
	}
	if ((ret = start_assoc_thread())) {
		PRINTK("init assoc kthread error");
		goto del_workers;
	}
	if (settings.slab_reassign &&
	    (ret = start_slab_thread())) {
		PRINTK("init slab kthread error");
		goto del_assoc_thread;
	}
	if ((ret = timer_init())) {
		PRINTK("init timer error");
		goto del_slab_thread;
	}
	if ((ret = server_init())) {
		PRINTK("init server socket error");
		goto del_timer;
	}

#ifdef CONFIG_DEBUG
	init_status = 0;
	return; 
#else
	return 0;
#endif

del_timer:
	timer_exit();
del_slab_thread:
	if (settings.slab_reassign)
		stop_slab_thread();
del_assoc_thread:
	stop_assoc_thread();
del_workers:
	workers_exit();
del_dispatcher:
	dispatcher_exit();
del_assoc:
	assoc_exit();
del_slabs:
	slabs_exit();
del_stats:
	stats_exit();
del_caches:
	caches_info_exit();
del_set:
	settings_exit();
out:
#ifdef CONFIG_DEBUG
	init_status = ret;
	return;
#else
	return ret;
#endif
}

static INIT int kmemcache_init(void)
{
	int ret = 0;

#ifdef CONFIG_DEBUG
	ret = register_callback(_kmemcache_init, NULL);
	if (ret) {
		PRINTK("register init callback function error");
		ret = -EFAULT;
	}
#else
	ret = _kmemcache_init();
#endif

	return ret;
}

static void EXIT kmemcache_exit(void)
{
#ifdef CONFIG_DEBUG
	if (init_status)
		return;
#endif
	server_exit();
	timer_exit();
	if (settings.slab_reassign)
		stop_slab_thread();
	stop_assoc_thread();
	workers_exit();
	dispatcher_exit();
	assoc_exit();
	slabs_exit();
	stats_exit();
	caches_info_exit();
	pages_cache_exit();
}

module_init(kmemcache_init);
module_exit(kmemcache_exit);

MODULE_AUTHOR("Li Jianguo <byjgli@gmail.com>");
MODULE_DESCRIPTION("kmemcache");
MODULE_LICENSE("GPL v2");
