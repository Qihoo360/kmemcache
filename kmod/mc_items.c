#include <linux/string.h>
#include <linux/vmalloc.h>
#include "mc.h"

/* forward declarations */
static void mc_item_link_q(item *it);
static void mc_item_unlink_q(item *it);

/*
 * we only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed items.
 */
#define ITEM_UPDATE_INTERVAL	60

#define LARGEST_ID	POWER_LARGEST
typedef struct {
	u64 evicted;
	u64 evicted_nonzero;
	rel_time_t evicted_time;
	u64 reclaimed;
	u64 outofmemory;
	u64 tailrepairs;
	u64 expired_unfetched;
	u64 evicted_unfetched;
} itemstats_t;

/*
 *
 *  head                     tail          size         itemstats
 * +-----+                  +-----+       +----+         +-----+
 * |     |--> i ... -->i <--|     |       | n  |         |     |
 * +-----+                  +-----+       +----+         +-----+
 * |     |                  |     |       |    |         |     |
 * +-----+                  +-----+       +----+         +-----+
 * |     |                  |     |       |    |         |     |
 * +-----+                  +-----+       +----+         +-----+
 * |     |                  |     |       |    |         |     |
 * | ... |                  | ... |       | .. |         | ... |
 * |     |                  |     |       |    |         |     |
 * +-----+                  +-----+       +----+         +-----+
 *                                             
 */
static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
static itemstats_t itemstats[LARGEST_ID];
static unsigned int sizes[LARGEST_ID];

void mc_item_stats_reset(void)
{
	mutex_lock(&cache_lock);
	memset(itemstats, 0, sizeof(itemstats));
	mutex_unlock(&cache_lock);
}

/**
 * get the next CAS id for a new item 
 */
u64 mc_get_cas_id(void)
{
	static u64 cas_id = 0;
	return ++cas_id;
}

/* Enable this for reference-count debugging. */
#if 0
# define DEBUG_REFCNT(it,op) \
                fprintf(stderr, "item %x refcnt(%c) %d %c%c%c\n", \
                        it, op, it->refcount, \
                        (it->it_flags & ITEM_LINKED) ? 'L' : ' ', \
                        (it->it_flags & ITEM_SLABBED) ? 'S' : ' ')
#else
# define DEBUG_REFCNT(it,op) do { } while(0)
#endif

/**
 * Generates the variable-sized part of the header for an object.
 *
 * key     - The key
 * nkey    - The length of the key
 * flags   - key flags
 * nbytes  - Number of bytes to hold value and addition CRLF terminator
 * suffix  - Buffer for the "VALUE" line suffix (flags, size).
 * nsuffix - The length of the suffix is stored here.
 *
 * Returns the total size of the header.
 */
static size_t item_make_header(u8 nkey, int flags,
			       int nbytes, char *suffix, u8 *nsuffix)
{
	/* suffix is defined at 40 chars elsewhere.. */
	*nsuffix = (u8)snprintf(suffix, 40, " %d %d\r\n", flags, nbytes - 2);
	return sizeof(item) + nkey + *nsuffix + nbytes;
}

item *mc_do_item_alloc(char *key, size_t nkey, int flags,
		       rel_time_t exptime, int nbytes, u32 cur_hv)
{
	u8 nsuffix;
	item *it = NULL;
	char suffix[40];
	size_t ntotal;
	unsigned int id;
	int tries = 5;
	int tried_alloc = 0;
	void *hold_lock = NULL;
	item *search;
	rel_time_t oldest_live = settings.oldest_live;
       
	ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);
	if (settings.use_cas) {
		ntotal += sizeof(u64);
	}

	id = mc_slabs_clsid(ntotal);
	if (id == 0)
		return 0;

	mutex_lock(&cache_lock);
	/* do a quick check if we have any expired items in the tail.. */

	search = tails[id];
	/* We walk up *only* for locked items. Never searching for expired.
	 * Waste of CPU for almost all deployments */
	for (; tries > 0 && search != NULL; tries--, search=search->prev) {
		u32 hv = hash(ITEM_key(search), search->nkey, 0);
		/* Attempt to hash item lock the "search" item. If locked, no
		 * other callers can incr the refcount
		 */
		/* FIXME: I think we need to mask the hv here for comparison? */
		if (hv != cur_hv && (hold_lock = mc_item_trylock(hv)) == NULL)
			continue;
		/* Now see if the item is refcount locked */
		if (atomic_inc_return(&search->refcount) != 2) {
			atomic_dec(&search->refcount);
			/* Old rare bug could cause a refcount leak. We haven't seen
			 * it in years, but we leave this code in to prevent failures
			 * just in case */
			if (search->time + TAIL_REPAIR_TIME < current_time) {
				itemstats[id].tailrepairs++;
				atomic_set(&search->refcount, 1);
				mc_do_item_unlink_nolock(search, hv);
			}
			if (hold_lock)
				mc_item_trylock_unlock(hold_lock);
			continue;
		}

		/* Expired or flushed */
		if ((search->exptime != 0 && search->exptime < current_time) ||
		    (search->time <= oldest_live && oldest_live <= current_time)) {
			itemstats[id].reclaimed++;
			if ((search->it_flags & ITEM_FETCHED) == 0) {
				itemstats[id].expired_unfetched++;
			}
			it = search;
			mc_slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal);
			mc_do_item_unlink_nolock(it, hv);
			/* Initialize the item block: */
			it->slabs_clsid = 0;
		} else if ((it = mc_slabs_alloc(ntotal, id)) == NULL) {
			tried_alloc = 1;
			if (settings.evict_to_free == 0) {
				itemstats[id].outofmemory++;
			} else {
				itemstats[id].evicted++;
				itemstats[id].evicted_time = current_time - search->time;
				if (search->exptime != 0)
					itemstats[id].evicted_nonzero++;
				if ((search->it_flags & ITEM_FETCHED) == 0) {
					itemstats[id].evicted_unfetched++;
				}
				it = search;
				mc_slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal);
				mc_do_item_unlink_nolock(it, hv);
				/* Initialize the item block: */
				it->slabs_clsid = 0;

				/* If we've just evicted an item, and the automover is set to
				 * angry bird mode, attempt to rip memory into this slab class.
				 * TODO: Move valid object detection into a function, and on a
				 * "successful" memory pull, look behind and see if the next alloc
				 * would be an eviction. Then kick off the slab mover before the
				 * eviction happens.
				 */
				if (settings.slab_automove == 2)
					mc_slabs_reassign(-1, id);
			}
		}

		atomic_dec(&search->refcount);
		/* If hash values were equal, we don't grab a second lock */
		if (hold_lock)
			mc_item_trylock_unlock(hold_lock);
		break;
	}

	if (!tried_alloc && (tries == 0 || search == NULL))
		it = mc_slabs_alloc(ntotal, id);

	if (it == NULL) {
		itemstats[id].outofmemory++;
		mutex_unlock(&cache_lock);
		return NULL;
	}

	BUG_ON(it->slabs_clsid);
	BUG_ON(it == heads[id]);

	/* Item initialization can happen outside of the lock; the item's already
	 * been removed from the slab LRU.
	 */
	atomic_set(&it->refcount, 1);     /* the caller will have a reference */
	mutex_unlock(&cache_lock);
	it->next = it->prev = it->h_next = 0;
	it->slabs_clsid = id;

	DEBUG_REFCNT(it, '*');
	it->it_flags = settings.use_cas ? ITEM_CAS : 0;
	it->nkey = nkey;
	it->nbytes = nbytes;
	memcpy(ITEM_key(it), key, nkey);
	it->exptime = exptime;
	memcpy(ITEM_suffix(it), suffix, (size_t)nsuffix);
	it->nsuffix = nsuffix;
	return it;
}

void mc_item_free(item *it)
{
	unsigned int clsid;
	size_t ntotal = ITEM_ntotal(it);

	BUG_ON(it->it_flags & ITEM_LINKED);
	BUG_ON(it == heads[it->slabs_clsid]);
	BUG_ON(it == tails[it->slabs_clsid]);
	BUG_ON(atomic_read(&it->refcount));

	/* so slab size changer can tell later if item is
	 * already free or not */
	clsid = it->slabs_clsid;
	it->slabs_clsid = 0;
	DEBUG_REFCNT(it, 'F');
	mc_slabs_free(it, ntotal, clsid);
}

/**
 * returns 1 if an item will fit in the cache (its size does not exceed
 * the maximum for a cache entry
 */
int mc_item_size_ok(size_t nkey, int flags, int nbytes)
{
	char prefix[40];
	u8 nsuffix;

	size_t ntotal = item_make_header(nkey + 1, flags,
					 nbytes, prefix, &nsuffix);
	if (settings.use_cas) {
		ntotal += sizeof(u64);
	}
	return mc_slabs_clsid(ntotal) != 0;
}

/**
 * mc_item_link_q() - add item into the queue,
 * item is the new head
 */
static void mc_item_link_q(item *it)
{
	item **head, **tail;

	BUG_ON(it->slabs_clsid >= LARGEST_ID);
	BUG_ON(it->it_flags & ITEM_SLABBED);

	head = &heads[it->slabs_clsid];
	tail = &tails[it->slabs_clsid];
	BUG_ON(it == *head);
	BUG_ON((*head && !*tail) || (!*head && *tail));
	it->prev = 0;
	it->next = *head;
	if (it->next)
		it->next->prev = it;
	*head = it;
	if (!*tail)
		*tail = it;
	sizes[it->slabs_clsid]++;
}

static void mc_item_unlink_q(item *it)
{
	item **head, **tail;

	BUG_ON(it->slabs_clsid >= LARGEST_ID);
	head = &heads[it->slabs_clsid];
	tail = &tails[it->slabs_clsid];

	if (*head == it) {
		BUG_ON(it->prev);
		*head = it->next;
	}
	if (*tail == it) {
		BUG_ON(it->next);
		*tail = it->prev;
	}
	BUG_ON(it->next == it);
	BUG_ON(it->prev == it);

	if (it->next)
		it->next->prev = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	sizes[it->slabs_clsid]--;
}

int mc_do_item_link(item *it, u32 hv)
{
	BUG_ON(it->it_flags & (ITEM_LINKED | ITEM_SLABBED));
	mutex_lock(&cache_lock);
	it->it_flags |= ITEM_LINKED;
	it->time = current_time;

	ATOMIC64_ADD(stats.curr_bytes, ITEM_ntotal(it));
	ATOMIC64_INC(stats.curr_items);
	ATOMIC64_INC(stats.total_items);

	/* allocate a new CAS ID on link */
	ITEM_set_cas(it, (settings.use_cas) ? mc_get_cas_id() : 0);
	mc_hash_insert(it, hv);
	mc_item_link_q(it);
	atomic_inc(&it->refcount);
	mutex_unlock(&cache_lock);

	return 0;
}

void mc_do_item_unlink(item *it, u32 hv)
{
	mutex_lock(&cache_lock);
	if (it->it_flags & ITEM_LINKED) {
		it->it_flags &= ~ITEM_LINKED;

		ATOMIC64_SUB(stats.curr_bytes, ITEM_ntotal(it));
		ATOMIC32_DEC(stats.curr_items);

		mc_hash_delete(ITEM_key(it), it->nkey, hv);
		mc_item_unlink_q(it);
		mc_do_item_remove(it);
	}
	mutex_unlock(&cache_lock);
}

/* FIXME: is it necessary to keep this copy/pasted code? */
void mc_do_item_unlink_nolock(item *it, u32 hv)
{
	if (it->it_flags & ITEM_LINKED) {
		it->it_flags &= ~ITEM_LINKED;

		ATOMIC64_SUB(stats.curr_bytes, ITEM_ntotal(it));
		ATOMIC32_DEC(stats.curr_items);

		mc_hash_delete(ITEM_key(it), it->nkey, hv);
		mc_item_unlink_q(it);
		mc_do_item_remove(it);
	}
}

void mc_do_item_remove(item *it)
{
	BUG_ON(it->it_flags & ITEM_SLABBED);

	if (atomic_dec_return(&it->refcount)  == 0) {
		mc_item_free(it);
	}
}

void mc_do_item_update(item *it)
{
	if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
		BUG_ON(it->it_flags & ITEM_SLABBED);
		mutex_lock(&cache_lock);
		if (it->it_flags & ITEM_LINKED) {
			mc_item_unlink_q(it);
			it->time = current_time;
			mc_item_link_q(it);
		}
		mutex_unlock(&cache_lock);
	}
}

int mc_do_item_replace(item *it, item *new_it, u32 hv)
{
	BUG_ON(it->it_flags & ITEM_SLABBED);

	mc_do_item_unlink(it, hv);
	return mc_do_item_link(new_it, hv);
}

/**
 * mc_do_item_cachedump() -
 *
 * returns dump size on success, errno otherwise
 */
int mc_do_item_cachedump(unsigned int slabs_clsid,
			 unsigned int limit, struct buffer *buf)
{
#define ROUND_SIZE	512
#define BUFFER_SIZE	2 * 1024 * 1024	/* 2MB max response size */
	int ret = 0;
	unsigned int bufcurr;
	item *it;
	unsigned int len;
	unsigned int shown = 0;
	char *key_temp, *temp, *dumpstr;

	it = heads[slabs_clsid];

	key_temp = kmalloc(KEY_MAX_LEN + 1, GFP_KERNEL);
	if (!key_temp) {
		ret = -ENOMEM;
		goto out;
	}
	temp = kmalloc(ROUND_SIZE, GFP_KERNEL);
	if (!temp) {
		ret = -ENOMEM;
		goto free_key;
	}
	ret = alloc_buffer(buf, BUFFER_SIZE, 0);
	if (ret) {
		PRINTK("mc_do_item_cachedump alloc mem error\n");
		goto free_temp;
	}
	BUFFER_PTR(buf, dumpstr);
	bufcurr = 0;

	while (it && (!limit || shown < limit)) {
		BUG_ON(it->nkey > KEY_MAX_LEN);
		/* copy the key since it may not be null-terminated in the struct */
		memcpy(key_temp, ITEM_key(it), it->nkey);
		key_temp[it->nkey] = 0x0;	/* terminate */
		len = snprintf(temp, ROUND_SIZE, "ITEM %s [%d b; %lu s]\r\n",
			       key_temp, it->nbytes - 2,
			       (unsigned long)it->exptime + process_started);
		if (bufcurr + len + 6 > BUFFER_SIZE)	/* 6 is END\r\n\0 */
			break;
		memcpy(dumpstr + bufcurr, temp, len);
		bufcurr += len;
		shown++;
		it = it->next;
	}

	memcpy(dumpstr + bufcurr, "END\r\n", 6);
	bufcurr += 5;

	ret = bufcurr;

free_temp:
	kfree(temp);
free_key:
	kfree(key_temp);
out:
	return ret;
}

void mc_item_stats_evictions(u64 *evicted)
{
	int i;

	mutex_lock(&cache_lock);
	for (i = 0; i < LARGEST_ID; i++)
		evicted[i] = itemstats[i].evicted;
	mutex_unlock(&cache_lock);
}

void mc_do_item_stats_totals(add_stat_fn f, void *c)
{
	int i;
	itemstats_t totals;

	memset(&totals, 0, sizeof(itemstats_t));
	for ( i = 0; i < LARGEST_ID; i++) {
		totals.expired_unfetched += itemstats[i].expired_unfetched;
		totals.evicted_unfetched += itemstats[i].evicted_unfetched;
		totals.evicted += itemstats[i].evicted;
		totals.reclaimed += itemstats[i].reclaimed;
	}
	APPEND_STAT("expired_unfetched", "%llu",
		    (unsigned long long)totals.expired_unfetched);
	APPEND_STAT("evicted_unfetched", "%llu",
		    (unsigned long long)totals.evicted_unfetched);
	APPEND_STAT("evictions", "%llu",
		    (unsigned long long)totals.evicted);
	APPEND_STAT("reclaimed", "%llu",
		    (unsigned long long)totals.reclaimed);
}

void mc_do_item_stats(add_stat_fn f, void *c)
{
	int i;

	for (i = 0; i < LARGEST_ID; i++) {
		if (tails[i] != NULL) {
			const char *fmt = "items:%d:%s";
			char key_str[STAT_KEY_LEN];
			char val_str[STAT_VAL_LEN];
			int klen = 0, vlen = 0;
			if (tails[i] == NULL) {
				/* We removed all of the items in this slab class */
				continue;
			}
			APPEND_NUM_FMT_STAT(fmt, i, "number", "%u", sizes[i]);
			APPEND_NUM_FMT_STAT(fmt, i, "age", "%u",
					    current_time - tails[i]->time);
			APPEND_NUM_FMT_STAT(fmt, i, "evicted",
					    "%llu", (unsigned long long)itemstats[i].evicted);
			APPEND_NUM_FMT_STAT(fmt, i, "evicted_nonzero",
					    "%llu", (unsigned long long)itemstats[i].evicted_nonzero);
			APPEND_NUM_FMT_STAT(fmt, i, "evicted_time",
					    "%u", itemstats[i].evicted_time);
			APPEND_NUM_FMT_STAT(fmt, i, "outofmemory",
					    "%llu", (unsigned long long)itemstats[i].outofmemory);
			APPEND_NUM_FMT_STAT(fmt, i, "tailrepairs",
					    "%llu", (unsigned long long)itemstats[i].tailrepairs);
			APPEND_NUM_FMT_STAT(fmt, i, "reclaimed",
					    "%llu", (unsigned long long)itemstats[i].reclaimed);
			APPEND_NUM_FMT_STAT(fmt, i, "expired_unfetched",
					    "%llu", (unsigned long long)itemstats[i].expired_unfetched);
			APPEND_NUM_FMT_STAT(fmt, i, "evicted_unfetched",
					    "%llu", (unsigned long long)itemstats[i].evicted_unfetched);
		}
	}

	/* getting here means both ascii and binary terminators fit */
	f(NULL, 0, NULL, 0, c);
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
void mc_do_item_stats_sizes(add_stat_fn f, void *c)
{
	/* max 1MB object, divided into 32 bytes size buckets */
	const int num_buckets = 32768;
	unsigned int *histogram = vmalloc(num_buckets * sizeof(int));

	if (histogram != NULL) {
		int i;

		memset(histogram, 0, num_buckets * sizeof(int));

		/* build the histogram */
		for (i = 0; i < LARGEST_ID; i++) {
			item *iter = heads[i];
			while (iter) {
				int ntotal = ITEM_ntotal(iter);
				int bucket = ntotal / 32;
				if ((ntotal % 32) != 0) bucket++;
				if (bucket < num_buckets) histogram[bucket]++;
				iter = iter->next;
			}
		}

		/* write the buffer */
		for (i = 0; i < num_buckets; i++) {
			if (histogram[i] != 0) {
				char key[8];
				snprintf(key, sizeof(key), "%d", i * 32);
				APPEND_STAT(key, "%u", histogram[i]);
			}
		}
		vfree(histogram);
	}
	f(NULL, 0, NULL, 0, c);
}

/** wrapper around hash_find which does the lazy expiration logic */
item *mc_do_item_get(const char *key, size_t nkey, u32 hv)
{
	int was_found = 0;

	//mutex_lock(&cache_lock);
	item *it = mc_hash_find(key, nkey, hv);
	if (it != NULL) {
		atomic_inc(&it->refcount);
		/* Optimization for slab reassignment. prevents popular items from
		 * jamming in busy wait. Can only do this here to satisfy lock order
		 * of item_lock, cache_lock, slabs_lock. */
		if (slab_rebal.signal &&
		    ((void *)it >= slab_rebal.slab_start &&
		    (void *)it < slab_rebal.slab_end)) {
			mc_do_item_unlink_nolock(it, hv);
			mc_do_item_remove(it);
			it = NULL;
		}
	}
	//mutex_unlock(&cache_lock);

	if (settings.verbose > 2) {
		if (it == NULL) {
			PRINTK("> NOT FOUND %s\n", key);
		} else {
			PRINTK("> FOUND KEY %s\n", ITEM_key(it));
			was_found++;
		}
	}

	if (it != NULL) {
		if (settings.oldest_live != 0 && settings.oldest_live <= current_time &&
		    it->time <= settings.oldest_live) {
			mc_do_item_unlink(it, hv);
			mc_do_item_remove(it);
			it = NULL;
			if (was_found) {
				PRINTK(" -nuked by flush\n");
			}
		} else if (it->exptime != 0 && it->exptime <= current_time) {
			mc_do_item_unlink(it, hv);
			mc_do_item_remove(it);
			it = NULL;
			if (was_found) {
				PRINTK(" -nuked by expire\n");
			}
		} else {
			it->it_flags |= ITEM_FETCHED;
			DEBUG_REFCNT(it, '+');
		}
	}

	PVERBOSE(2, "\n");

	return it;
}

item *mc_do_item_touch(const char *key, size_t nkey, u32 exptime, u32 hv)
{
	item *it = mc_do_item_get(key, nkey, hv);
	if (it != NULL) {
		it->exptime = exptime;
	}
	return it;
}

/* expires items that are more recent than the oldest_live setting. */
void mc_do_item_flush_expired(void)
{
	int i;
	item *iter, *next;
	if (settings.oldest_live == 0)
		return;
	for (i = 0; i < LARGEST_ID; i++) {
		/* The LRU is sorted in decreasing time order, and an item's timestamp
		 * is never newer than its last access time, so we only need to walk
		 * back until we hit an item older than the oldest_live time.
		 * The oldest_live checking will auto-expire the remaining items.
		 */
		for (iter = heads[i]; iter != NULL; iter = next) {
			if (iter->time >= settings.oldest_live) {
				next = iter->next;
				if ((iter->it_flags & ITEM_SLABBED) == 0) {
					mc_do_item_unlink_nolock(iter, hash(ITEM_key(iter), iter->nkey, 0));
				}
			} else {
				/* We've hit the first old item. Continue to the next queue. */
				break;
			}
		}
	}
}

