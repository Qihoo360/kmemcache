#ifndef __MC_WORKER_H
#define __MC_WORKER_H

/* stats stored per-slab and per-thread */
struct slab_stats {
	u64 set_cmds;
	u64 get_hits;
	u64 touch_hits;
	u64 delete_hits;
	u64 cas_hits;
	u64 cas_badval;
	u64 incr_hits;
	u64 decr_hits;
};

/* stats stored per-thread */
struct thread_stats {
	u64 get_cmds;
	u64 get_misses;
	u64 touch_cmds;
	u64 touch_misses;
	u64 delete_misses;
	u64 incr_misses;
	u64 decr_misses;
	u64 cas_misses;
	u64 bytes_read;
	u64 bytes_written;
	u64 flush_cmds;
	u64 conn_yields;	/* # of yields for connections (-R option)*/
	u64 auth_cmds;
	u64 auth_errors;
	struct slab_stats slab_stats[MAX_SLAB_CLASSES];
};

#define ATOMIC64_SET(ptr, val)	atomic64_set((atomic64_t *)&(ptr), (val))
#define ATOMIC64_INC(ptr)	atomic64_inc((atomic64_t *)&(ptr))
#define ATOMIC64_DEC(ptr)	atomic64_dec((atomic64_t *)&(ptr))
#define ATOMIC64_ADD(ptr, val)	atomic64_add((val), (atomic64_t *)&(ptr))
#define ATOMIC64_SUB(ptr, val)	atomic64_sub((val), (atomic64_t *)&(ptr))
#define ATOMIC64_READ(ptr)	atomic64_read((atomic64_t *)&(ptr))
#define ATOMIC32_SET(ptr, val)	atomic_set((atomic_t *)&(ptr), (val))
#define ATOMIC32_INC(ptr)	atomic_inc((atomic_t *)&(ptr))
#define ATOMIC32_DEC(ptr)	atomic_dec((atomic_t *)&(ptr))
#define ATOMIC32_ADD(ptr, val)	atomic_add((val), (atomic_t *)&(ptr))
#define ATOMIC32_SUB(ptr, val)	atomic_sub((val), (atomic_t *)&(ptr))
#define ATOMIC32_READ(ptr)	atomic_read((atomic_t *)&(ptr))

/* slaved info storage */
struct worker_storage {
	spinlock_t lock;
	struct list_head list;	/* conn list */

#ifdef CONFIG_SLOCK
	spinlock_t slock;	/* thread_stats */
#endif
	struct thread_stats stats;
	item_lock_t lock_type;
};

extern struct worker_storage *storage __percpu;
extern struct workqueue_struct *slaved;

/* new conn from master */
struct conn_req {
	conn_state_t state;
	net_transport_t transport;
	struct socket *sock;
	int rsize;
	struct work_struct work;
};
extern struct kmem_cache *conn_req_cachep;

/* items lock for slaved */
struct lock_xchg_req {
	item_lock_t type;
	struct worker_storage *who;
	struct work_struct work;
};
extern struct kmem_cache *lock_xchg_req_cachep;

static inline void* new_conn_req(void)
{
	return kmem_cache_alloc(conn_req_cachep, GFP_ATOMIC);
}

static inline void free_conn_req(void *obj)
{
	kmem_cache_free(conn_req_cachep, obj);
}

static inline void* new_lock_xchg_req(void)
{
	return kmem_cache_alloc(lock_xchg_req_cachep, GFP_KERNEL);
}

static inline void free_lock_xchg_req(void *obj)
{
	kmem_cache_free(lock_xchg_req_cachep, obj);
}

item*	mc_item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes);
int	mc_item_cachedump(unsigned int slabs_clsid, unsigned int limit, struct buffer *buf);
void	mc_item_flush_expired(void);
item*	mc_item_get(struct worker_storage *worker, const char *key, size_t nkey);
item*	mc_item_touch(struct worker_storage *worker, const char *key, size_t nkey, u32 exptime);
int	mc_item_link(struct worker_storage *worker, item *it);
void	mc_item_remove(struct worker_storage *worker, item *it);
int	mc_item_replace(item *it, item *new_it, u32 hv);
void	mc_item_stats(add_stat_fn f, void *c);
void	mc_item_stats_totals(add_stat_fn f, void *c);
void	mc_item_stats_sizes(add_stat_fn f, void *c);
void	mc_item_unlink(struct worker_storage *worker, item *it);
void	mc_item_update(struct worker_storage *worker, item *it);
delta_result_t mc_add_delta(struct worker_storage *worker, conn *c,
			    const char *key, size_t nkey,
			    int incr, s64 delta, char *buf, u64 *cas);
store_item_t mc_store_item(struct worker_storage *worker, item *item, int comm, conn *c);
void	mc_item_lock_global(void);
void	mc_item_unlock_global(void);
void*	mc_item_trylock(u32 hv);
void	mc_item_trylock_unlock(void *arg);
void	mc_threadlocal_stats_reset(void);
void	mc_threadlocal_stats_aggregate(struct thread_stats *stats);
void	mc_slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out);
void	mc_switch_item_lock_type(item_lock_t type);
int	mc_dispatch_conn_udp(struct socket *sock, conn_state_t state,
			     int rbuflen, int udp);
int	mc_dispatch_conn_new(struct socket *sock, conn_state_t state,
			     int rbuflen, net_transport_t transport);
void	mc_conn_work(struct work_struct *work);
int	workers_init(void);
void	workers_exit(void);

#endif /* __MC_WORKER_H */
