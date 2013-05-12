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
#include <linux/kthread.h>

#include "mc.h"

int timeout __read_mostly = 10;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "timeout in seconds for msg from umemcached");

unsigned long slabsize __read_mostly = 95;
module_param(slabsize, ulong, 0);
MODULE_PARM_DESC(slabsize, "percent of totalram that slabs could use");

/* initialize command from umemcached */
static int cache_bh_status;
static struct cn_id cache_bh_id = {
	.idx = CN_IDX_CACHE_BH,
	.val = CN_VAL_CACHE_BH
};

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

static int timer_init(void)
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

static struct cache_info {
	struct kmem_cache **cachep;
	char *name;
	size_t size;
	void (*ctor)(void *);
} caches_info[] = {
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

static int caches_info_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(caches_info); i++) {
		struct cache_info *cache = &caches_info[i];

		*cache->cachep = kmem_cache_create(cache->name,
						   cache->size,
						   0,
						   SLAB_HWCACHE_ALIGN,
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

static int __kmemcache_bh_init(void *unused)
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
			      settings.factor_numerator,
			      settings.factor_denominator,
			      settings.preallocate))) {
		PRINTK("init slabs error");
		goto del_stats;
	}
	if ((ret = hash_init(settings.hashpower_init))) {
		PRINTK("init hashtable error");
		goto del_slabs;
	}
	if ((ret = dispatcher_init())) {
		PRINTK("init dispatcher error");
		goto del_hash;
	}
	if ((ret = workers_init())) {
		PRINTK("init workers error");
		goto del_dispatcher;
	}
	if ((ret = start_hash_thread())) {
		PRINTK("init hashtable kthread error");
		goto del_workers;
	}
	if ((ret = start_slab_thread())) {
		PRINTK("init slab kthread error");
		goto del_hash_thread;
	}
	if ((ret = timer_init())) {
		PRINTK("init timer error");
		goto del_slab_thread;
	}
	if ((ret = server_init())) {
		PRINTK("init server socket error");
		goto del_timer;
	}
	if ((ret = oom_init())) {
		PRINTK("init oom error");
		goto del_server;
	}

	cache_bh_status = 1;
	PRINTK("start server success");
	return 0;

del_server:
	server_exit();
del_timer:
	timer_exit();
del_slab_thread:
	if (settings.slab_reassign)
		stop_slab_thread();
del_hash_thread:
	stop_hash_thread();
del_workers:
	workers_exit();
del_dispatcher:
	dispatcher_exit();
del_hash:
	hash_exit();
del_slabs:
	slabs_exit();
del_stats:
	stats_exit();
del_caches:
	caches_info_exit();
del_set:
	settings_exit();
out:
	PRINTK("start server error");
	return ret;
}

static inline void unregister_kmemcache_bh(void)
{
	mc_del_callback(&cache_bh_id, 0);
}

static void* kmemcache_bh_init(struct cn_msg *msg,
		struct netlink_skb_parms *pm)
{
	struct task_struct *helper;

	helper = kthread_run(__kmemcache_bh_init, NULL, "kmcbh");
	if (IS_ERR(helper)) {
		PRINTK("create kmemcache bh kthread error");
	}

	return NULL;
}

static inline int register_kmemcache_bh(void)
{
	return mc_add_callback(&cache_bh_id, kmemcache_bh_init, 0);
}

static int __init kmemcache_init(void)
{
	int ret = 0;

	ret = connector_init();
	if (ret) {
		PRINTK("init connector error");
		goto out;
	}
	ret = register_kmemcache_bh();
	if (ret) {
		PRINTK("register kmemcache bh error");
		goto cn_exit;
	}

	return 0;

cn_exit:
	connector_exit();
out:
	return ret;
}

static void __exit kmemcache_exit(void)
{
	if (cache_bh_status) {
		server_exit();
		timer_exit();
		stop_slab_thread();
		stop_hash_thread();
		workers_exit();
		dispatcher_exit();
		hash_exit();
		slabs_exit();
		stats_exit();
		caches_info_exit();
		oom_exit();

		PRINTK("stop server success");
	} else {
		unregister_kmemcache_bh();
	}
	connector_exit();
}

module_init(kmemcache_init);
module_exit(kmemcache_exit);

MODULE_AUTHOR("Li Jianguo <byjgli@gmail.com>");
MODULE_DESCRIPTION("kmemcache");
MODULE_LICENSE("GPL v2");
