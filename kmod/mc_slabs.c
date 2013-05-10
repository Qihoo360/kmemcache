#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/atomic.h>

#include "mc.h"

/*
 * Slabs memory allocation, based on powers-of-N. Slabs are up to 1MB in size
 * and are divided into chunks. The chunk sizes start off at the size of the
 * "item" structure plus space for a small key and value. They increase by
 * a multiplier factor from there, up to half the maximum slab size. The last
 * slab size is always 1MB, since that's the maximum item size allowed by the
 * memcached protocol.
 */

/* powers-of-N allocation structures */

typedef struct {
	unsigned int size;	/* sizes of items */
	unsigned int perslab;	/* how many items per slab */

	void *slots;		/* list of item ptrs */
	unsigned int sl_curr;	/* total free items in list */

	unsigned int slabs;	/* how many slabs were allocated for this class */

	void **slab_list;	/* array of slab pointers(krealloc) */
	unsigned int list_size;	/* size of prev array */

	unsigned int killing;	/* index+1 of dying slab, or zereo if none */
	size_t requested;	/* the number of requested bytes */
} slabclass_t;

static slabclass_t slabclass[MAX_SLAB_CLASSES];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

/* for prealloc */
static void *mem_base __read_mostly = NULL;
static void *mem_current = NULL;
static size_t mem_avail = 0;

/*
 * Access to the slab allocator is protected by this lock
 */
static DEFINE_MUTEX(slabs_lock);

/*
 * Forward Declarations
 */
static int mc_do_slabs_newslab(unsigned int id);

static void *mc_memory_allocate(size_t size)
{
	void *ret = NULL;

	if (mem_base == NULL) {
		/* not use a preallocated large memory chunk */
#ifdef CONFIG_BUFFER_CACHE
		ret = kmem_cache_alloc(buffer_cachep, GFP_KERNEL);
		if (likely(ret)) {
			if (alloc_buffer(ret, size)) {
				kmem_cache_free(buffer_cachep, ret);
				ret = NULL;
			} else {
				BUFFER_PTR((struct buffer *)ret, ret);
			}
		}
#else
		ret = vmalloc(size);
#endif
	} else {
		ret = mem_current;

		if (size > mem_avail)
			return NULL;

		/* XXX: mem_current pointer _must_ be aligned */
		if (size % CHUNK_ALIGN_BYTES) {
			size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);
		}

		mem_current = ((char *)mem_current) + size;
		if (size < mem_avail)
			mem_avail -= size;
		else
			mem_avail = 0;
	}
	
	return ret;
}

/**
 * mc_do_slabs_alloc() - alloc item from free list, alloc a new slab page if needed
 * @size	:
 * @id		: idex of slabclass
 * 
 * Returns ptr of item on success, otherwise NULL
 */
static void *mc_do_slabs_alloc(size_t size, unsigned int id)
{
	slabclass_t *p;
	void *ret = NULL;
	item *it = NULL;

	if (unlikely(id < POWER_SMALLEST || id > power_largest)) {
		return NULL;
	}

	p = &slabclass[id];

	/* 
	 * fail unless we have space at the end of a recently allocated page,
	 * we hava something on our freelist, or we could allocate a new page.
	 */
	if (!p->sl_curr && mc_do_slabs_newslab(id)) {
		/* we don't have more memory available */
		ret = NULL;
	} else if (p->sl_curr != 0) {
		/* return off our freelist */
		it = (item *)p->slots;
		p->slots = it->next;
		if (it->next)
			it->next->prev = 0;
		p->sl_curr--;
		ret = (void *)it;
	}

	if (ret) {
		p->requested += size;
	} else {
		PRINFO("alloc slab page error");
	}

	return ret;
}

/**
 * mc_do_slabs_free() - free item into the free list (->slots)
 * @ptr		: item ptr
 * @size	:
 * @id		: idx of slabclass
 */
static void mc_do_slabs_free(void *ptr, size_t size, unsigned int id)
{
	item *it;
	slabclass_t *p;

	BUG_ON(((item *)ptr)->slabs_clsid != 0);
	BUG_ON(id < POWER_SMALLEST || id > power_largest);
	if (id < POWER_SMALLEST || id > power_largest)
		return;

	p = &slabclass[id];

	it = (item *)ptr;
	it->it_flags |= ITEM_SLABBED;
	it->prev = 0;
	it->next = p->slots;
	if (it->next)
		it->next->prev = it;
	p->slots = it;

	p->sl_curr++;
	p->requested -= size;
	return;
}

static void mc_split_slab_page_into_freelist(char *ptr, unsigned int id)
{
	int i;
	slabclass_t *p = &slabclass[id];

	for (i = 0; i < p->perslab; i++) {
		mc_do_slabs_free(ptr, 0, id);
		ptr += p->size;
	}
}

/**
 * mc_grow_slab_list() - realloc slab list 
 * @id	: idx of slabclass
 *
 * Returns 0 on success, otherwise errno.
 */
static int mc_grow_slab_list(unsigned int id)
{
	slabclass_t *p = &slabclass[id];

	if (p->slabs == p->list_size) {
		size_t new_size = (p->list_size != 0) ? p->list_size * 2 : 16;
		void *new_list = krealloc(p->slab_list, new_size * sizeof(void *),
					  GFP_KERNEL);
		if (!new_list) {
			PRINTK("grow slab list error");
			return -ENOMEM;
		}
		p->list_size = new_size;
		p->slab_list = new_list;

	}
	return 0;
}

/**
 * mc_do_slabs_newslab() - alloc a new slab page, and add it to the free list(->slots)
 * @id	: idx of slabclass
 *
 * Returns 0 on success, otherwise errno.
 */
static int mc_do_slabs_newslab(unsigned int id)
{
	slabclass_t *p = &slabclass[id];
	int len = settings.slab_reassign ? settings.item_size_max
		: p->size * p->perslab;
	char *ptr;

	if ((mem_limit && (mem_malloced + len > mem_limit) && p->slabs > 0) ||
	    (mc_grow_slab_list(id)) ||
	    ((ptr = mc_memory_allocate((size_t)len)) == NULL)) {
		return -ENOMEM;
	}

	memset(ptr, 0, (size_t)len);
	mc_split_slab_page_into_freelist(ptr, id);

	p->slab_list[p->slabs++] = ptr;
	mem_malloced += len;

	return 0;
}

/**
 * mc_slabs_preallocate() - preallocate as many slab pages as possible
 * (called from slabs_init) on start-up, so users don't get confused 
 * out-of-memory errors when they do have free (in-slab) space, but no 
 * space to make new slabs. if maxslabs is 18 (POWER_LARGEST - POWER_SMALLEST + 1), 
 * then all slab types can be made.  if max memory is less than 18 MB, only the
 * smaller ones will be made.
 *
 * Returns 0 if all slab pages allocated success, otherwise -ENOMEM means that a few
 * slabs allocated success.
 */
static int mc_slabs_preallocate (unsigned int maxslabs)
{
	int i, ret = 0;
	unsigned int prealloc = 0;

    	/* 
	 * pre-allocate a 1MB slab in every size class so people don't get
         * confused by non-intuitive "SERVER_ERROR out of memory"
         * messages.  this is the most common question on the mailing
         * list.  if you really don't want this, you can rebuild without
         * these three lines
	 */
	for (i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
		if (++prealloc > maxslabs)
			goto out;
		if (mc_do_slabs_newslab(i)) {
			PRINTK("error while preallocating slab memory!\n"
			       "If using -L or other prealloc options, max "
			       "memory must be at least %d megabytes.",
			       power_largest);
			ret = -ENOMEM;
			goto out;
		}
	}

out:
	return ret;
}

static int nz_strcmp(int nzlen, const char *nz, const char *z)
{
	int zlen = strlen(z);

	return (zlen == nzlen) && (strncmp(nz, z, zlen) == 0) ? 0 : -1;
}

/**
 * mc_get_stats() - get a datum for stats in binary protocol
 * @stat_type	:
 * @nkey	:
 * @add_stats	:
 * @c		:
 *
 * Return 0 on success, otherwise errno.
 */
int mc_get_stats(const char *stat_type, int nkey, add_stat_callback add_stats, void *c)
{
	int ret = 0;

	if (add_stats != NULL) {
		if (!stat_type) {
			/* prepare general statistics for the engine */
			u32 curr_items;
			u32 total_items;
			u64 curr_bytes;

			spin_lock(&stats_lock);
			curr_items = stats.curr_items;
			curr_bytes = stats.curr_bytes;
			total_items= stats.total_items;
			spin_unlock(&stats_lock);

			APPEND_STAT("bytes", "%llu", (unsigned long long)curr_bytes);
			APPEND_STAT("curr_items", "%u", curr_items);
			APPEND_STAT("total_items", "%u", total_items);

			mc_item_stats_totals(add_stats, c);
		} else if (nz_strcmp(nkey, stat_type, "items") == 0) {
			mc_item_stats(add_stats, c);
		} else if (nz_strcmp(nkey, stat_type, "slabs") == 0) {
			mc_slabs_stats(add_stats, c);
		} else if (nz_strcmp(nkey, stat_type, "sizes") == 0) {
			mc_item_stats_sizes(add_stats, c);
		} else {
			ret = -EFAULT;
		}
	} else {
		ret = -EFAULT;
	}

	return ret;
}

static void mc_do_slabs_stats(add_stat_callback add_stats, void *c)
{
	int i, total;
	struct thread_stats *thread_stats;

	thread_stats = kmalloc(sizeof(*thread_stats), GFP_KERNEL);
	if (!thread_stats) {
		PRINTK("alloc thread_stats error");
		return;
	}
	mc_threadlocal_stats_aggregate(thread_stats);

	total = 0;
	for(i = POWER_SMALLEST; i <= power_largest; i++) {
		slabclass_t *p = &slabclass[i];
		if (p->slabs != 0) {
			int klen = 0, vlen = 0;
			char key_str[STAT_KEY_LEN];
			char val_str[STAT_VAL_LEN];

			u32 perslab, slabs;
			slabs = p->slabs;
			perslab = p->perslab;

			APPEND_NUM_STAT(i, "chunk_size", "%u", p->size);
			APPEND_NUM_STAT(i, "chunks_per_page", "%u", perslab);
			APPEND_NUM_STAT(i, "total_pages", "%u", slabs);
			APPEND_NUM_STAT(i, "total_chunks", "%u", slabs * perslab);
			APPEND_NUM_STAT(i, "used_chunks", "%u",
				    slabs*perslab - p->sl_curr);
			APPEND_NUM_STAT(i, "free_chunks", "%u", p->sl_curr);
			/* Stat is dead, but displaying zero instead of removing it. */
			APPEND_NUM_STAT(i, "free_chunks_end", "%u", 0);
			APPEND_NUM_STAT(i, "mem_requested", "%llu",
				    (unsigned long long)p->requested);
			APPEND_NUM_STAT(i, "get_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].get_hits);
			APPEND_NUM_STAT(i, "cmd_set", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].set_cmds);
			APPEND_NUM_STAT(i, "delete_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].delete_hits);
			APPEND_NUM_STAT(i, "incr_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].incr_hits);
			APPEND_NUM_STAT(i, "decr_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].decr_hits);
			APPEND_NUM_STAT(i, "cas_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].cas_hits);
			APPEND_NUM_STAT(i, "cas_badval", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].cas_badval);
			APPEND_NUM_STAT(i, "touch_hits", "%llu",
			    (unsigned long long)thread_stats->slab_stats[i].touch_hits);
			total++;
		}
	}

	/* add overall slab stats and append terminator */

	APPEND_STAT("active_slabs", "%d", total);
	APPEND_STAT("total_malloced", "%llu", (unsigned long long)mem_malloced);
	add_stats(NULL, 0, NULL, 0, c);

	kfree(thread_stats);
}

/**
 * mc_slabs_clsid() - Figures out which slab class (chunk size) is required 
 * 		      to store an item of a given size.
 * @size	: object size
 *
 * Returns zero on error means that can't store such a large object,
 * 	clsid otherwise.	
 */
unsigned int mc_slabs_clsid(size_t size)
{
	int res = POWER_SMALLEST;

	if (size == 0)
		return 0;
	while (size > slabclass[res].size) {
		if (res++ == power_largest) /* won't fit in the biggest slab */
			return 0;
	}
	return res;
}

/**
 * slabs_init() - Init the subsystem
 * @limit	: the limit on no. of bytes to allocate, 0 if no limit.
 * @factor	: the growth factor; each slab will use a chunk size equal to 
 * 		  the previous slab's chunk size times this factor.
 * @prealloc	: specifies if the slab allocator should allocate all memory
 * 		  up front (if true), or allocate memory in chunks as it is 
 * 		  needed (if false).
 *
 * Returns zero on success, errno otherwise.
 */
int slabs_init(size_t limit, int factor_nume, int factor_deno, int prealloc)
{
	int ret = 0;
	int i = POWER_SMALLEST - 1;
	unsigned int size = sizeof(item) + settings.chunk_size;

	mem_limit = limit;

	if (prealloc) {
		mem_base = vmalloc(mem_limit);
		if (mem_base == NULL) {
			PRINTK("failed to allocate requested memory in "
			       "one large chunk. Will allocate in smaller chunks.");
		} else {
			mem_current = mem_base;
			mem_avail = mem_limit;
		}
	}

	while (++i < POWER_LARGEST && size <= settings.item_size_max * factor_deno / factor_nume) {
		/* Make sure items are always n-byte aligned */
		if (size % CHUNK_ALIGN_BYTES)
			size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

		slabclass[i].size = size;
		slabclass[i].perslab = settings.item_size_max / slabclass[i].size;
		size = size * factor_nume / factor_deno;
		if (settings.verbose > 1) {
			PRINTK("slab class %3d: chunk size %9u perslab %7u",
			       i, slabclass[i].size, slabclass[i].perslab);
		}
	}

	power_largest = i;
	slabclass[power_largest].size = settings.item_size_max;
	slabclass[power_largest].perslab = 1;
	if (settings.verbose > 1) {
		PRINTK("slab class %3d: chunk size %9u perslab %7u",
		       i, slabclass[i].size, slabclass[i].perslab);
	}

	if (prealloc) {
		ret = mc_slabs_preallocate(power_largest);
	}

	return ret;
}

void slabs_exit(void)
{
	int i;
	slabclass_t *p;

	if (mem_base) {
		vfree(mem_base);
	} else {
		for (i = POWER_SMALLEST; i <= power_largest; i++) {
			int j;
			p = &slabclass[i];

			if (p->slabs == 0)
				continue;
			for (j = 0; j < p->slabs; j++) {
				vfree(p->slab_list[j]);
			}
		}
	}

	for (i = POWER_SMALLEST; i <= power_largest; i++) {
		p = &slabclass[i];
		if (p->slab_list) {
			kfree(p->slab_list);
		}
	}
}

/** 
 * mc_slabs_alloc() - Allocate object of given length.
 *
 * Returns ptr or err_ptr
 */
void *mc_slabs_alloc(size_t size, unsigned int id)
{
	void *ret;

	mutex_lock(&slabs_lock);
	ret = mc_do_slabs_alloc(size, id);
	mutex_unlock(&slabs_lock);
	return ret;
}

/**
 * Free previously allocated object
 */
void mc_slabs_free(void *ptr, size_t size, unsigned int id)
{
	mutex_lock(&slabs_lock);
	mc_do_slabs_free(ptr, size, id);
	mutex_unlock(&slabs_lock);
}

/**
 * Fill buffer with stats
 */
void mc_slabs_stats(add_stat_callback add_stats, void *c)
{
	mutex_lock(&slabs_lock);
	mc_do_slabs_stats(add_stats, c);
	mutex_unlock(&slabs_lock);
}

/**
 * Adjust the stats for memory requested
 */
void mc_slabs_adjust_mem_requested(unsigned int id, size_t old, size_t ntotal)
{
	slabclass_t *p;

	if (id < POWER_SMALLEST || id > power_largest) {
		PRINTK("internal error, invalid slab class!!!\n");
		return;
	}

	p = &slabclass[id];
	mutex_lock(&slabs_lock);
	p->requested = p->requested - old + ntotal;
	mutex_unlock(&slabs_lock);
}

struct slab_rebal slab_rebal;

static struct {
	unsigned long flag;
	struct task_struct *tsk;
	wait_queue_head_t wq;
} slab_mten;

static int mc_slab_rebalance_start(void)
{
	slabclass_t *s_cls;
	int ret = 0;

	mutex_lock(&cache_lock);
	mutex_lock(&slabs_lock);

	if (slab_rebal.s_clsid < POWER_SMALLEST ||
	    slab_rebal.s_clsid > power_largest  ||
	    slab_rebal.d_clsid < POWER_SMALLEST ||
	    slab_rebal.d_clsid > power_largest  ||
	    slab_rebal.s_clsid == slab_rebal.d_clsid) {
		ret = -EFAULT;
		goto out;
	}

	s_cls = &slabclass[slab_rebal.s_clsid];

	if (mc_grow_slab_list(slab_rebal.d_clsid)) {
		ret = -EFAULT;
		goto out;
	}

	if (s_cls->slabs < 2) {
		ret = -EFAULT;
		goto out;
	}

	s_cls->killing = 1;

	slab_rebal.slab_start	=
		s_cls->slab_list[s_cls->killing - 1];
	slab_rebal.slab_end	=
		(char *)slab_rebal.slab_start
		+ (s_cls->size * s_cls->perslab);
	slab_rebal.slab_pos	= 
		slab_rebal.slab_start;
	slab_rebal.done		= 0;

	/* Also tells mc_do_item_get to search for items in this slab */
	slab_rebal.signal = 2;

	if (settings.verbose > 1) {
		PRINTK("started a slab rebalance");
	}

	mutex_unlock(&slabs_lock);
	mutex_unlock(&cache_lock);

	spin_lock(&stats_lock);
	stats.slab_reassign_running = 1;
	spin_unlock(&stats_lock);

	return 0;

out:
	mutex_unlock(&slabs_lock);
	mutex_unlock(&cache_lock);
	return ret;
}

typedef enum {
	MOVE_PASS = 0,
	MOVE_DONE,
	MOVE_BUSY,
	MOVE_LOCKED
} move_status;

/** 
 * refcount == 0 is safe since nobody can incr while cache_lock is held.
 * refcount != 0 is impossible since flags/etc can be modified in other thread.
 * instead, note we found a busy one and bail. logic in mc_do_item_get will
 * prevent busy items form continuing to be busy.
 */
static int mc_slab_rebalance_move(void)
{
	int i;
	int was_busy = 0;
	int refcount = 0;
	slabclass_t *s_cls;
	move_status status = MOVE_PASS;

	mutex_lock(&cache_lock);
	mutex_lock(&slabs_lock);

	s_cls = &slabclass[slab_rebal.s_clsid];

	for (i = 0; i < settings.slab_bulk_check; i++) {
		item *it = slab_rebal.slab_pos;
		status = MOVE_PASS;

		if (it->slabs_clsid != 255) {
			void *hold_lock = NULL;
			u32 hv = hash(ITEM_key(it), it->nkey, 0);

			if ((hold_lock = mc_item_trylock(hv)) == NULL) {
				status = MOVE_LOCKED;
			} else {
				refcount = atomic_inc_return(&it->refcount);

				if (refcount == 1) { /* item is unlinked, unused */
					if (it->it_flags & ITEM_SLABBED) {
						/* remove from slab freelist */
						if (s_cls->slots == it) {
							s_cls->slots = it->next;
						}
						if (it->next)
							it->next->prev = it->prev;
						if (it->prev)
							it->prev->next = it->next;

						s_cls->sl_curr--;
						status = MOVE_DONE;
					} else {
						status = MOVE_BUSY;
					}
				} else if (refcount == 2) { /* item is linked but not busy */
					if ((it->it_flags & ITEM_LINKED) != 0) {
						mc_do_item_unlink_nolock(it,
									 hash(ITEM_key(it),
									 it->nkey, 0));
						status = MOVE_DONE;
					} else {
						/*
						 * refcount == 1 + !ITEM_LINKED means the item
						 * is being uploaded to, or was just unlinked 
						 * but hasn't been freed yet. Let it bleed
						 * off on its own and try again later.
						 */
						status = MOVE_BUSY;
					}
				} else {
					if (settings.verbose > 2) {
						PRINTK("slab reassign hit a busy item: "
						       "refcount: %d (%d -> %d)",
						       atomic_read(&it->refcount),
						       slab_rebal.s_clsid,
						       slab_rebal.d_clsid);
					}
					status = MOVE_BUSY;
				}

				mc_item_trylock_unlock(hold_lock);
			}
		}

		switch (status) {
		case MOVE_DONE:
			atomic_set(&it->refcount, 0);
			it->it_flags = 0;
			it->slabs_clsid = 255;
			break;
		case MOVE_BUSY:
			atomic_dec(&it->refcount);
		case MOVE_LOCKED:
			slab_rebal.busy_items++;
			was_busy++;
			break;
		case MOVE_PASS:
			break;
		}

		slab_rebal.slab_pos = (char *)slab_rebal.slab_pos + s_cls->size;
		if (slab_rebal.slab_pos >= slab_rebal.slab_end) {
			break;
		}
	}

	if (slab_rebal.slab_pos >= slab_rebal.slab_end) {
		/* some items were busy, start again from the top */
		if (slab_rebal.busy_items) {
			slab_rebal.slab_pos = slab_rebal.slab_start;
			slab_rebal.busy_items = 0;
		} else {
			slab_rebal.done++;
		}
	}

	mutex_unlock(&slabs_lock);
	mutex_unlock(&cache_lock);

	return was_busy;
}

static void mc_slab_rebalance_finish(void)
{
	slabclass_t *s_cls;
	slabclass_t *d_cls;

	mutex_lock(&cache_lock);
	mutex_lock(&slabs_lock);

	s_cls = &slabclass[slab_rebal.s_clsid];
	d_cls = &slabclass[slab_rebal.d_clsid];

	/* At this point the stolen slab is completely clear */
	s_cls->slab_list[s_cls->killing - 1] = 
		s_cls->slab_list[s_cls->slabs - 1];
	s_cls->slabs--;
	s_cls->killing = 0;

	memset(slab_rebal.slab_start, 0,
	       (size_t)settings.item_size_max);

	d_cls->slab_list[d_cls->slabs++] = slab_rebal.slab_start;
	mc_split_slab_page_into_freelist(slab_rebal.slab_start,
					 slab_rebal.d_clsid);

	slab_rebal.done		= 0;
	slab_rebal.s_clsid	= 0;
	slab_rebal.d_clsid	= 0;
	slab_rebal.slab_start	= NULL;
	slab_rebal.slab_end	= NULL;
	slab_rebal.slab_pos	= NULL;

	slab_rebal.signal = 0;

	mutex_unlock(&slabs_lock);
	mutex_unlock(&cache_lock);

	spin_lock(&stats_lock);
	stats.slab_reassign_running = 0;
	stats.slabs_moved++;
	spin_unlock(&stats_lock);

	if (settings.verbose > 1) {
		PRINTK("finished a slab move");
	}
}

/**
 * Move to its own thread (created/destroyed as needed) once automover
 * is more complex.
 *
 * Returns 1 means a decision was reached.
 */
static int mc_slab_automove_decision(int *src, int *dst)
{
	static u64 evicted_old[POWER_LARGEST];
	static unsigned int slab_zeroes[POWER_LARGEST];
	static unsigned int slab_winner = 0;
	static unsigned int slab_wins   = 0;
	static rel_time_t next_run;
#ifdef CONFIG_STACK_OPT
	static u64 evicted_new[POWER_LARGEST];
	static unsigned int total_pages[POWER_LARGEST];
#else
	u64 *evicted_new;
	unsigned int *total_pages;
#endif
	int i;
	int res = 0;
	int source = 0;
	int dest = 0;
	u64 evicted_diff = 0;
	u64 evicted_max  = 0;
	unsigned int highest_slab = 0;

	/* run less frequently than the slabmove tester */
	if (current_time >= next_run)
		next_run = current_time + 10;
	else
		return 0;

#ifndef CONFIG_STACK_OPT
	evicted_new = kmalloc(POWER_LARGEST, GFP_KERNEL);
	if (!evicted_new) {
		PRINTK("alloc evicted buffer error");
		goto out;
	}
	total_pages = kmalloc(POWER_LARGEST, GFP_KERNEL);
	if (!total_pages) {
		PRINTK("alloc temp buffer error");
		goto free_evic;
	}
#endif
	mc_item_stats_evictions(evicted_new);
	mutex_lock(&cache_lock);
	for (i = POWER_SMALLEST; i < power_largest; i++) {
		total_pages[i] = slabclass[i].slabs;
	}
	mutex_unlock(&cache_lock);

	/* Find a candidate source; something with zero evicts 3+ times */
	for (i = POWER_SMALLEST; i < power_largest; i++) {
		evicted_diff = evicted_new[i] - evicted_old[i];
		if (evicted_diff == 0 && total_pages[i] > 2) {
			slab_zeroes[i]++;
			if (source == 0 && slab_zeroes[i] >= 3)
				source = i;
		} else {
			slab_zeroes[i] = 0;
			if (evicted_diff > evicted_max) {
				evicted_max = evicted_diff;
				highest_slab = i;
			}
		}
		evicted_old[i] = evicted_new[i];
	}

	/* Pick a valid destination */
	if (slab_winner != 0 && slab_winner == highest_slab) {
		slab_wins++;
		if (slab_wins >= 3)
			dest = slab_winner;
	} else {
		slab_wins = 1;
		slab_winner = highest_slab;
	}

	if (source && dest) {
		*src = source;
		*dst = dest;
		res = 1;
	}

#ifndef CONFIG_STACK_OPT
	kfree(total_pages);
free_evic:
	kfree(evicted_new);
out:
#endif
	return res;
}

/**
 * Slab rebalancer thread.
 * Does not use spinlocks since it is not timing sensiteve. Burn less CPU and
 * goto to sleep if locks are contended
 */
static int mc_slab_maintenance(void *ignore)
{
	int src = 0, dest = 0;

	set_freezable();
	while (1) {
		wait_event_freezable(slab_mten.wq,
				     settings.slab_automove == 1 ||
				     kthread_should_stop());
		if (test_bit(SLAB_KTHREAD_ZOMBIE, &slab_mten.flag)) {
			goto out;
		}
		if (mc_slab_automove_decision(&src, &dest) == 1) {
			/* 
			 * Blind to the return codes. It will
			 * retry on its own
			 */
			mc_slabs_reassign(src, dest);
		}
		msleep(1000);
	}

out:
	return 0;
}

/**
 * Slab mover thread.
 * Sits waiting for a condition to jump off and shovel some memory about
 */
static int mc_slab_rebalance(void *ignore)
{
	int was_busy = 0;

	set_freezable();
	while (1) {
		wait_event_freezable(slab_rebal.wq,
				     slab_rebal.signal ||
				     kthread_should_stop());

		mutex_lock(&slab_rebal.lock);
		if (test_bit(SLAB_KTHREAD_ZOMBIE, &slab_rebal.flag)) {
			mutex_unlock(&slab_rebal.lock);
			goto out;
		}
		if (slab_rebal.signal == 1) {
			if (mc_slab_rebalance_start() < 0) {
				/* Handle errors with more specifity as required. */
				slab_rebal.signal = 0;
			}
			was_busy = 0;
		} else if (slab_rebal.signal &&
			   slab_rebal.slab_start) {
			was_busy = mc_slab_rebalance_move();
		}

		if (slab_rebal.done) {
			mc_slab_rebalance_finish();
		} else if (was_busy) {
			/*
			 * Stuck waiting for some items to unlock, so slow down
			 * a bit to give them a change to free up.
			 */
			msleep(1000);
		}
		mutex_unlock(&slab_rebal.lock);
	}

out:
	return 0;
}

/**
 * Iterate at most once through the slab classes and pick a "random" source.
 * I like this better than calling get_random_xx() since get_random_xx() is
 * slow enough that we can just check all of the classes once instead.
 */
static int mc_slabs_reassign_pick_any(int dst)
{
	static int cur = POWER_SMALLEST - 1;
	int tries = power_largest - POWER_SMALLEST + 1;

	for (; tries > 0; tries--) {
		cur++;
		if (cur > power_largest)
			cur = POWER_SMALLEST;
		if (cur == dst)
			continue;
		if (slabclass[cur].slabs > 1)
			return cur;
	}
	return -1;
}

static reassign_result_t mc_do_slabs_reassign(int src, int dst)
{
	if (slab_rebal.signal != 0)
		return REASSIGN_RUNNING;

	if (src == dst)
		return REASSIGN_SRC_DST_SAME;

	/* Special indicator to choose ourselves */
	if (src == -1) {
		src = mc_slabs_reassign_pick_any(dst);
		/* TODO: if we end up back at -1, return a new error type */
	}

	if (src < POWER_SMALLEST || src > power_largest ||
	    dst < POWER_SMALLEST || dst > power_largest) {
		return REASSIGN_BADCLASS;
	}

	if (slabclass[src].slabs < 2)
		return REASSIGN_NOSPACE;

	slab_rebal.s_clsid = src;
	slab_rebal.d_clsid = dst;

	slab_rebal.signal = 1;
	wake_up(&slab_rebal.wq);

	return REASSIGN_OK;
}

reassign_result_t mc_slabs_reassign(int src, int dst)
{
	reassign_result_t ret;

	if (!mutex_trylock(&slab_rebal.lock)) {
		return REASSIGN_RUNNING;
	}
	ret = mc_do_slabs_reassign(src, dst);
	mutex_unlock(&slab_rebal.lock);
	return ret;
}

/**
 * If we hold this lock, rebalancer can't wake up or move
 */
void mc_slabs_rebalancer_pause(void)
{
	mutex_lock(&slab_rebal.lock);
}

void mc_slabs_rebalancer_resume(void)
{
	mutex_unlock(&slab_rebal.lock);
}

int start_slab_thread(void)
{
	int ret = 0;

	init_waitqueue_head(&slab_mten.wq);
	slab_mten.tsk = kthread_run(mc_slab_maintenance,
				    NULL, "mc_slab_mten");
	if (IS_ERR(slab_mten.tsk)) {
		PRINTK("create slab maintenance thread error");
		ret = -ENOMEM;
		goto out;
	}

	mutex_init(&slab_rebal.lock);
	init_waitqueue_head(&slab_rebal.wq);
	slab_rebal.tsk = kthread_run(mc_slab_rebalance,
				     NULL, "mc_slab_rebal");
	if (IS_ERR(slab_rebal.tsk)) {
		PRINTK("create slab rebalance thread error");
		ret = -ENOMEM;
		goto out_rebl_err;
	}

	return 0;

out_rebl_err:
	set_bit(SLAB_KTHREAD_ZOMBIE, &slab_mten.flag);
	kthread_stop(slab_mten.tsk);
out:
	return ret;
}

void stop_slab_thread(void)
{
	set_bit(SLAB_KTHREAD_ZOMBIE, &slab_mten.flag);
	set_bit(SLAB_KTHREAD_ZOMBIE, &slab_rebal.flag);

	kthread_stop(slab_mten.tsk);
	kthread_stop(slab_rebal.tsk);
}

