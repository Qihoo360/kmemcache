#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <asm/atomic.h>

#include "mc.h"

/* sync in all worker threads */
static atomic_t sync_workers = ATOMIC_INIT(0);
static DECLARE_COMPLETION(sync_comp);

#define BEGIN_WAIT_FOR_THREAD_REGISTRATION()			\
	do {							\
		atomic_set(&sync_workers, settings.num_threads);\
	} while (0)

#define WAIT_FOR_THREAD_REGISTRATION()		\
	do {					\
		wait_for_completion(&sync_comp);\
	} while (0)

#define REGISTER_THREAD_INITIALIZED()			\
	do {						\
		if (atomic_dec_and_test(&sync_workers))	\
			complete(&sync_comp);		\
	} while (0)

struct kmem_cache *conn_req_cachep;
struct kmem_cache *lock_xchg_req_cachep;

static struct worker_thread *worker_threads;

static void mc_lock_xchg_work(struct work_struct *work);

/*********************************************************************
 * thread-item locks
 ********************************************************************/

/* size of the item lock hash table */
static u32 item_lock_count;
static struct mutex *item_locks;
/* this lock is temporarily engaged during a hash table expansion */
static DEFINE_MUTEX(item_global_lock);

#define hashsize(n)	((unsigned long int)1 << (n))
#define hashmask(n)	(hashsize(n) - 1)

static int item_lock_init(int nthreads)
{
	int ret = 0;
	int i, power, order;
	unsigned long addr;

	/* want a wide lock table, but don't waste memory */
	if (nthreads < 3)
		power = 10;
	else if (nthreads < 4)
		power = 11;
	else if (nthreads < 5)
		power = 12;
	else
		power = 13;

	item_lock_count = hashsize(power);
	order = get_order(item_lock_count * sizeof(struct mutex));

	addr = __get_free_pages(GFP_KERNEL, order);
	if (!addr) {
		PRINTK("alloc item locks error\n");
		ret = -ENOMEM;
		goto out;
	}
	item_locks = (struct mutex *)addr;
	for (i = 0; i < item_lock_count; i++) {
		mutex_init(&item_locks[i]);
	}

out:
	return ret;
}

static void item_lock_exit(void)
{
	int order;

	order = get_order(item_lock_count * sizeof(struct mutex));
	free_pages((unsigned long)item_locks, order);
}

void mc_item_lock(struct worker_thread *worker, u32 hv)
{
	int lock_type = worker->lock_type;

	if (likely(lock_type == ITEM_LOCK_GRANULAR)) {
		u32 idx = (hv & hashmask(hashpower)) % item_lock_count;
		mutex_lock(&item_locks[idx]);
	} else {
		mutex_lock(&item_global_lock);
	}
}

void mc_item_unlock(struct worker_thread *worker, u32 hv)
{
	int lock_type = worker->lock_type;

	if (likely(lock_type == ITEM_LOCK_GRANULAR)) {
		u32 idx = (hv & hashmask(hashpower)) % item_lock_count;
		mutex_unlock(&item_locks[idx]);
	} else {
		mutex_unlock(&item_global_lock);
	}
}

/**
 * Special case. When ITEM_LOCK_GLOBAL mode is enabled, this should become a
 * no-op, as it's only called from within the item lock if necessary.
 * However, we can't mix a no-op and threads which are still synchronizing to
 * GLOBAL. So instead we just always try to lock. When in GLOBAL mode this
 * turns into an effective no-op. Threads re-synchronize after the power level
 * switch so it should stay safe.
 */
void* mc_item_trylock(u32 hv)
{
	u32 idx = (hv & hashmask(hashpower)) % item_lock_count;
	struct mutex *lock = &item_locks[idx];

	if (mutex_trylock(lock))
		return lock;
	else
		return NULL;
}

void mc_item_trylock_unlock(void *lock)
{
	mutex_unlock((struct mutex *)lock);
}

/* Convenience functions for calling *only* when in ITEM_LOCK_GLOBAL mode */
void mc_item_lock_global(void)
{
	mutex_lock(&item_global_lock);
}

void mc_item_unlock_global(void)
{
	mutex_unlock(&item_global_lock);
}

void mc_switch_item_lock_type(item_lock_t type)
{
	int i, ret = 0;

	BEGIN_WAIT_FOR_THREAD_REGISTRATION();

	for (i = 0; i < settings.num_threads; i++) {
		struct lock_xchg_req *rq = new_lock_xchg_req();
		if (unlikely(!rq)) {
			PRINTK("alloc new lock-xchg request error, "
			       "this is a fatal problem.\n");
			msleep(2000);
			i--;
			continue;
		}

		rq->type = type;
		rq->who  = &worker_threads[i];
		INIT_WORK(&rq->work, mc_lock_xchg_work);

		ret = queue_work(worker_threads[i].wq, &rq->work);
		if (unlikely(!ret)) {
			PRINTK("lock xchg work already in the workqueue\n");
			free_lock_xchg_req(rq);
			msleep(2000);
			i--;
			continue;
		}
	}

	WAIT_FOR_THREAD_REGISTRATION();
}

/*********************************************************************
 * item ops
 ********************************************************************/

/**
 * Alloc a new item.
 */
item* mc_item_alloc(char *key, size_t nkey, int flags,
		    rel_time_t exptime, int nbytes)
{
	item *it;

	/* mc_do_item_alloc handles its own locks */
	it = mc_do_item_alloc(key, nkey, flags, exptime, nbytes, 0);
	return it;
}

/** 
 * Get an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
item* mc_item_get(struct worker_thread *worker,
		  const char *key, const size_t nkey)
{
	item *it;
	u32 hv;

	hv = hash(key, nkey, 0);
	mc_item_lock(worker, hv);
	it = mc_do_item_get(key, nkey, hv);
	mc_item_unlock(worker, hv);

	return it;
}

item* mc_item_touch(struct worker_thread *worker,
		    const char *key, size_t nkey, u32 exptime)
{
	item *it;
	u32 hv;

	hv = hash(key, nkey, 0);
	mc_item_lock(worker, hv);
	it = mc_do_item_touch(key, nkey, exptime, hv);
	mc_item_unlock(worker, hv);

	return it;
}

/**
 * Link an item into the LRU and hashtable.
 */
int mc_item_link(struct worker_thread *worker, item *item)
{
	int ret;
	u32 hv;

	hv = hash(ITEM_key(item), item->nkey, 0);
	mc_item_lock(worker, hv);
	ret = mc_do_item_link(item, hv);
	mc_item_unlock(worker, hv);

	return ret;
}

/**
 * Decrement the reference count on an item and
 * add it to the freelist if needed. 
 */
void mc_item_remove(struct worker_thread *worker, item *item)
{
	u32 hv;

	hv = hash(ITEM_key(item), item->nkey, 0);
	mc_item_lock(worker, hv);
	mc_do_item_remove(item);
	mc_item_unlock(worker, hv);
}

/**
 * Replace an item with another in the hashtable.
 * Unprotected by a mutex lock since the core server
 * don't require it to be thread-safe.
 */
int mc_item_replace(item *old_it, item *new_it, u32 hv)
{
	return mc_do_item_replace(old_it, new_it, hv);
}

/**
 * Unlink an item from the LRU and hashtable.
 */
void mc_item_unlink(struct worker_thread *worker, item *item)
{
	u32 hv;

	hv = hash(ITEM_key(item), item->nkey, 0);
	mc_item_lock(worker, hv);
	mc_do_item_unlink(item, hv);
	mc_item_unlock(worker, hv);
}

/**
 * Move an item to the back of the LRU queue.
 */
void mc_item_update(struct worker_thread *worker, item *item)
{
	u32 hv;

	hv = hash(ITEM_key(item), item->nkey, 0);
	mc_item_lock(worker, hv);
	mc_do_item_update(item);
	mc_item_unlock(worker, hv);
}

/**
 * Do arithmetic on a numeric item value.
 */
delta_result_t mc_add_delta(struct worker_thread *worker, conn *c,
			    const char *key, size_t nkey,
			    int incr, s64 delta, char *buf, u64 *cas)
{
	delta_result_t ret;
	u32 hv;

	hv = hash(key, nkey, 0);
	mc_item_lock(worker, hv);
	ret = mc_do_add_delta(c, key, nkey, incr, delta, buf, cas, hv);
	mc_item_unlock(worker, hv);

	return ret;
}

/**
 * Store an item in the cache (high level, obeys set/add/replace semantics)
 */
store_item_t mc_store_item(struct worker_thread *worker, item *item,
			   int comm, conn *c)
{
	store_item_t ret;
	u32 hv;

	hv = hash(ITEM_key(item), item->nkey, 0);
	mc_item_lock(worker, hv);
	ret = mc_do_store_item(item, comm, c, hv);
	mc_item_unlock(worker, hv);

	return ret;
}

/* lock for cache operations (item_*, assoc_*) */
DEFINE_MUTEX(cache_lock);

/**
 * Flush expired items after a flush_all call
 */
void mc_item_flush_expired(void)
{
	mutex_lock(&cache_lock);
	mc_do_item_flush_expired();
	mutex_unlock(&cache_lock);
}

/**
 * Dump part of the cache
 */
int mc_item_cachedump(unsigned int slabs_clsid, unsigned int limit,
		      struct buffer *buf)
{
	int ret;

	mutex_lock(&cache_lock);
	ret = mc_do_item_cachedump(slabs_clsid, limit, buf);
	mutex_unlock(&cache_lock);

	return ret;
}

/**
 * Dump statistics about slab classes
 */
void mc_item_stats(add_stat_fn f, void *c)
{
	mutex_lock(&cache_lock);
	mc_do_item_stats(f, c);
	mutex_unlock(&cache_lock);
}

void mc_item_stats_totals(add_stat_fn f, void *c)
{
	mutex_lock(&cache_lock);
	mc_do_item_stats_totals(f, c);
	mutex_unlock(&cache_lock);
}

/**
 * Dump a list of objects of each size in 32-byte increments
 */
void mc_item_stats_sizes(add_stat_fn f, void *c)
{
	mutex_lock(&cache_lock);
	mc_do_item_stats_sizes(f, c);
	mutex_unlock(&cache_lock);
}

/*********************************************************************
 * thread ops
 ********************************************************************/

void mc_threadlocal_stats_reset(void)
{
	int i;

	for (i = 0; i < settings.num_threads; ++i) {
		struct thread_stats *sts =
				&worker_threads[i].stats;
		size_t size = sizeof(struct thread_stats)
			      - ((char *)(&sts->get_cmds)
			      - (char *)sts);

		spin_lock(&sts->lock);
		memset((char *)(&sts->get_cmds), 0, size);
		spin_unlock(&sts->lock);
	}
}

void mc_threadlocal_stats_aggregate(struct thread_stats *stats)
{
	int i, sid;

	/* The struct has a mutex, but we can safely set the whole thing
	 * to zero since it is unused when aggregating. */
	memset(stats, 0, sizeof(*stats));

	for (i = 0; i < settings.num_threads; ++i) {
		struct thread_stats *sts =
				&worker_threads[i].stats;
		spin_lock(&sts->lock);

		stats->get_cmds	     += sts->get_cmds;
		stats->get_misses    += sts->get_misses;
		stats->touch_cmds    += sts->touch_cmds;
		stats->touch_misses  += sts->touch_misses;
		stats->delete_misses += sts->delete_misses;
		stats->decr_misses   += sts->decr_misses;
		stats->incr_misses   += sts->incr_misses;
		stats->cas_misses    += sts->cas_misses;
		stats->bytes_read    += sts->bytes_read;
		stats->bytes_written += sts->bytes_written;
		stats->flush_cmds    += sts->flush_cmds;
		stats->conn_yields   += sts->conn_yields;
		stats->auth_cmds     += sts->auth_cmds;
		stats->auth_errors   += sts->auth_errors;

		for (sid = 0; sid < MAX_SLAB_CLASSES; sid++) {
			stats->slab_stats[sid].set_cmds +=
				sts->slab_stats[sid].set_cmds;
			stats->slab_stats[sid].get_hits +=
				sts->slab_stats[sid].get_hits;
			stats->slab_stats[sid].touch_hits +=
				sts->slab_stats[sid].touch_hits;
			stats->slab_stats[sid].delete_hits +=
				sts->slab_stats[sid].delete_hits;
			stats->slab_stats[sid].decr_hits +=
				sts->slab_stats[sid].decr_hits;
			stats->slab_stats[sid].incr_hits +=
				sts->slab_stats[sid].incr_hits;
			stats->slab_stats[sid].cas_hits +=
				sts->slab_stats[sid].cas_hits;
			stats->slab_stats[sid].cas_badval +=
				sts->slab_stats[sid].cas_badval;
		}

		spin_unlock(&sts->lock);
	}
}

void mc_slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out)
{
	int sid;

	memset(out, 0, sizeof(*out));

	//spin_lock(&stats->lock);
	for (sid = 0; sid < MAX_SLAB_CLASSES; sid++) {
		out->set_cmds    += stats->slab_stats[sid].set_cmds;
		out->get_hits    += stats->slab_stats[sid].get_hits;
		out->touch_hits  += stats->slab_stats[sid].touch_hits;
		out->delete_hits += stats->slab_stats[sid].delete_hits;
		out->decr_hits   += stats->slab_stats[sid].decr_hits;
		out->incr_hits   += stats->slab_stats[sid].incr_hits;
		out->cas_hits    += stats->slab_stats[sid].cas_hits;
		out->cas_badval  += stats->slab_stats[sid].cas_badval;
	}
	//spin_unlock(&stats->lock);
}

static void mc_lock_xchg_work(struct work_struct *work)
{
	struct lock_xchg_req *rq =
		container_of(work, struct lock_xchg_req, work);

	rq->who->lock_type = rq->type;
	REGISTER_THREAD_INITIALIZED();

	free_lock_xchg_req(rq);
}

static void mc_conn_new_work(struct work_struct *work)
{
	conn *c;
	struct conn_req *rq =
		container_of(work, struct conn_req, work);

	c = mc_conn_new(rq);
	if (IS_ERR(c)) {
		PRINTK("create new conn error\n");
		goto err_out;
	} else {
		mc_queue_conn(c);
	}

	goto out;

err_out:
	if (IS_UDP(rq->transport)) {
		PRINTK("can't listen on UDP socket\n");
	}
	sock_release(rq->sock);
out:
	free_conn_req(rq);
}

void mc_conn_work(struct work_struct *work)
{
	conn *c = container_of(work, conn, work);

	if (test_bit(EV_DEAD, &c->event))
		goto put_con;

	mc_worker_machine(c);
	mc_requeue_conn(c);

put_con:
	mc_conn_put(c);
}

/**
 * Dispatches a new connection to another thread.
 *
 * Returns 0 on success, error code other wise
 */
int mc_dispatch_conn_new(struct socket *sock, conn_state_t state,
			 int rbuflen, net_transport_t transport)
{
	static int last = -1;

	int ret = 0, tid;
	struct conn_req *rq;
	struct worker_thread *worker;

	rq = new_conn_req();
	if (unlikely(!rq)) {
		PRINTK("alloc new connection request error\n");
		ret = -ENOMEM;
		goto out;
	}

	tid = (last + 1) % settings.num_threads;
	last= tid;
	worker = &worker_threads[tid];

	rq->state = state;
	rq->transport = transport;
	rq->sock = sock;
	rq->rsize = rbuflen;
	rq->who	= worker;
	INIT_WORK(&rq->work, mc_conn_new_work);

	ret = queue_work(worker->wq, &rq->work);
	if (unlikely(!ret)) {
		PRINTK("new conn work already in the workqueue\n");
		ret = -EFAULT;
		goto free_req;
	}

	return 0;

free_req:
	free_conn_req(rq);
out:
	return ret;
}

/** 
 * create various worker kthreads.
 *
 * Returns 0 on success, error code other wise.
 */
int workers_init(void)
{
	int i, ret = 0;
	int nthreads = settings.num_threads;

	if ((ret = item_lock_init(nthreads))) {
		PRINTK("init item locks error\n");
		goto out;
	}

	worker_threads = kzalloc(nthreads * sizeof(struct worker_thread),
				 GFP_KERNEL);
	if (!worker_threads) {
		PRINTK("alloc worker threads error\n");
		ret = -ENOMEM;
		goto free_item_locks;
	}
	for (i = 0; i < nthreads; i++) {
		char thread[TASK_COMM_LEN] = {0};
		struct workqueue_struct *wq;

		sprintf(thread, "kmcworker%d", i);
		wq = create_singlethread_workqueue(thread);
		if (!wq) {
			PRINTK("create worker kthread error\n");
			ret = -ENOMEM;
			goto rollback_workers;
		}

		worker_threads[i].wq = wq;
		INIT_LIST_HEAD(&worker_threads[i].list);
		spin_lock_init(&worker_threads[i].lock);
		spin_lock_init(&worker_threads[i].stats.lock);
		worker_threads[i].lock_type = ITEM_LOCK_GRANULAR;
	}

	return 0;

rollback_workers:
	for (i--; i >= 0; i--) {
		destroy_workqueue(worker_threads[i].wq);
	}
	kfree(worker_threads);
free_item_locks:
	item_lock_exit();
out:
	return ret;
}

/**
 * wait for all worker threads to drop requests.
 *
 * NOTE!!! udp socket links to the list of dispatcher
 */
void workers_exit(void)
{
	int i;
	conn *c, *n;
	int nthreads = settings.num_threads;
	struct worker_thread *worker;

	for (i = 0; i < nthreads; i++) {
		worker = &worker_threads[i];
		spin_lock(&worker->lock);
		list_for_each_entry(c, &worker->list, list) {
			set_bit(EV_DEAD, &c->event);
		}
		spin_unlock(&worker->lock);
	}
	for (i = 0; i < nthreads; i++) {
		worker = &worker_threads[i];
		flush_workqueue(worker->wq);
		destroy_workqueue(worker->wq);
	}
	for (i = 0; i < nthreads; i++) {
		worker = &worker_threads[i];
		/* don't need to lock here */
		list_for_each_entry_safe(c, n, &worker->list, list) {
			if (IS_UDP(c->transport)) {
				c->sock->ops->shutdown(c->sock, SHUT_RDWR);
				sock_release(c->sock);
			} else
				mc_conn_close(c);
			mc_conn_put(c);
		}
	}

	kfree(worker_threads);
	item_lock_exit();
}

