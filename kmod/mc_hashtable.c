#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#include "mc.h"

typedef struct buffer hash_table_storage_t;

static DECLARE_WAIT_QUEUE_HEAD(hash_wait_queue);
static struct task_struct *hash_kthread;

/* how many powers of 2's worth of buckets we use */
unsigned int hashpower = HASHPOWER_DEFAULT;

#define hashsize(n)	((u32)1 << (n))
#define hashmask(n)	(hashsize(n) -1)

/* main hash table. This is where we look except during expansion. */
static hash_table_storage_t primary_hts;
static item** primary_hashtable = 0;

/* 
 * previous hash table. During expansion, we look here for keys that
 * haven't been moved over to the primary yet.
 */
static hash_table_storage_t old_hts;
static item** old_hashtable = 0;

/* number of items in the hash table */
static unsigned int hash_items = 0;

/* flag: are we in the middle of expanding now? */
#define ZOMBIE		0
#define EXPANDING	1
#define SEXPANDING	2
static unsigned long hashflags;

/* 
 * during expansion we migrate values with bucket granularity; this is how
 * far we've gotten so far. Ranges from 0 .. hashsize(hashpower - 1) - 1.
 */
static unsigned int expand_bucket = 0;

int hash_init(int power) 
{
	size_t bytes;
	int ret = 0;

	if (power)
		hashpower = power;
	bytes = hashsize(hashpower) * sizeof(void *);
	ret = alloc_buffer(&primary_hts, bytes, __GFP_ZERO);
	if (ret) {
		PRINTK("alloc primary_hashtable error\n");
		goto out;
	} else {
		BUFFER_PTR(&primary_hts, primary_hashtable);
	}

#ifdef CONFIG_GSLOCK
	spin_lock(&stats_lock);
	stats.hash_power_level = hashpower;
	stats.hash_bytes = bytes;
	spin_unlock(&stats_lock);
#else
	ATOMIC32_SET(stats.hash_power_level, hashpower);
	ATOMIC64_SET(stats.hash_bytes, bytes);
#endif

out:
	return ret;
}

void hash_exit(void)
{
	if (test_bit(EXPANDING, &hashflags)) {
		free_buffer(&old_hts);
		old_hashtable = NULL;
	}
	free_buffer(&primary_hts);
	primary_hashtable = NULL;
}

item* mc_hash_find(const char *key, u32 nkey, u32 hv)
{
	item *it, *ret = NULL;
	unsigned int oldbucket;

	if (test_bit(EXPANDING, &hashflags) &&
	    (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket) {
		it = old_hashtable[oldbucket];
	} else {
		it = primary_hashtable[hv & hashmask(hashpower)];
	}

	while (it) {
		if ((nkey == it->nkey) &&
		    !memcmp(key, ITEM_key(it), nkey)) {
			ret = it;
			break;
		}
		it = it->h_next;
	}

	return ret;
}

/**
 * returns the address of the item pointer before the key,
 * if *item == 0, the item wasn't found.
 */
static item** _mc_hashitem_before(const char *key, size_t nkey, u32 hv)
{
	item **pos;
	unsigned int oldbucket;

	if (test_bit(EXPANDING, &hashflags) &&
	    (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket) {
		pos = &old_hashtable[oldbucket];
	} else {
		pos = &primary_hashtable[hv & hashmask(hashpower)];
	}

	while (*pos && ((nkey != (*pos)->nkey) || memcmp(key, ITEM_key(*pos), nkey))) {
		pos = &(*pos)->h_next;
	}
	return pos;
}

/**
 * grows the hashtable to the next power of 2 
 */
static void mc_hash_expand(void)
{
	size_t bytes;
	int ret = 0;

	old_hashtable = primary_hashtable;
	memcpy(&old_hts, &primary_hts, sizeof(old_hts));

	bytes = hashsize(hashpower + 1) * sizeof(void *);
	ret = alloc_buffer(&primary_hts, bytes, __GFP_ZERO);
	if (!ret) {
		PVERBOSE(1, "hash table expansion starting\n");
		BUFFER_PTR(&primary_hts, primary_hashtable);
		hashpower++;
		set_bit(EXPANDING, &hashflags);
		expand_bucket = 0;

#ifdef CONFIG_GSLOCK
		spin_lock(&stats_lock);
		stats.hash_power_level = hashpower;
		stats.hash_bytes += bytes;
		stats.hash_is_expanding = 1;
		spin_unlock(&stats_lock);
#else
		ATOMIC32_SET(stats.hash_power_level, hashpower);
		ATOMIC64_ADD(stats.hash_bytes, bytes);
		set_bit(STATS_HASH_EXP, &stats.flags);
#endif
	} else {
		/* bad news, but we can keep running */
		PRINTK("hash table expansion error\n");
		memcpy(&primary_hts, &old_hts, sizeof(old_hts));
		primary_hashtable = old_hashtable;
	}
}

static void mc_hash_start_expand(void)
{
	if (test_and_set_bit(SEXPANDING, &hashflags))
		return;
	wake_up(&hash_wait_queue);
}

/*
 * Note: this isn't an hash_update. The key must not already exist
 * to call this.
 */
int mc_hash_insert(item *it, u32 hv)
{
	unsigned int oldbucket;

	/* shouldn't have duplicately named things defined */
	//BUG_ON(mc_hash_find(ITEM_key(it), it->nkey));	
	
	if (test_bit(EXPANDING, &hashflags) &&
	    (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket) {
		it->h_next = old_hashtable[oldbucket];
		old_hashtable[oldbucket] = it;
	} else {
		it->h_next = primary_hashtable[hv & hashmask(hashpower)];
		primary_hashtable[hv & hashmask(hashpower)] = it;
	}

	hash_items++;
	if (!test_bit(EXPANDING, &hashflags) && hash_items > (hashsize(hashpower) * 3) / 2) {
		mc_hash_start_expand();
	}

	return 0;
}

void mc_hash_delete(const char *key, size_t nkey, u32 hv)
{
	item **before = _mc_hashitem_before(key, nkey, hv);

	if (*before) {
		item *nxt;
		hash_items--;

		/* 
		 * The DTrace probe can't be triggered as the last instruction
		 * due to possible tail-optimization by the compiler
		 */
		nxt = (*before)->h_next;
		(*before)->h_next = 0;	/* probably pointless, but whatever */
		*before = nxt;
		return;
	}

	/*
	 * Note: we never actually get here, the callers don't delete things
	 * they can't find.
	 */
	BUG_ON(!*before);
}

static int mc_hash_thread(void *ignore)
{
	set_freezable();
	while (!test_bit(ZOMBIE, &hashflags)) {
		int ii = 0;

		/* 
		 * Lock the cache, and bulk move multiple buckets to
		 * the new hash table.
		 */
		mc_item_lock_global();
		mutex_lock(&cache_lock);

		for (ii = 0; ii < settings.hash_bulk_move && test_bit(EXPANDING, &hashflags); ii++) {
			item *it, *next;
			int bucket;

			for (it = old_hashtable[expand_bucket]; it; it = next) {
				next = it->h_next;

				bucket = hash(ITEM_key(it), it->nkey, 0) &
					 hashmask(hashpower);
				it->h_next = primary_hashtable[bucket];
				primary_hashtable[bucket] = it;
			}

			old_hashtable[expand_bucket] = NULL;
			expand_bucket++;

			if (expand_bucket == hashsize(hashpower - 1)) {
				clear_bit(EXPANDING, &hashflags);
				clear_bit(SEXPANDING, &hashflags);
				free_buffer(&old_hts);

#ifdef CONFIG_GSLOCK
				spin_lock(&stats_lock);
				stats.hash_bytes -= hashsize(hashpower - 1) *
						    sizeof(void *);
				stats.hash_is_expanding = 0;
				spin_unlock(&stats_lock);
#else
				ATOMIC64_SUB(stats.hash_bytes,
					     hashsize(hashpower - 1) *
					     sizeof(void *));
				clear_bit(STATS_HASH_EXP, &stats.flags);
#endif
				PVERBOSE(1, "hash table expansion done\n");
			}
		}

		mutex_unlock(&cache_lock);
		mc_item_unlock_global();

		if (!test_bit(EXPANDING, &hashflags)) {
			/* 
			 * finished expanding. tell all threads to use
			 * fine-grained locks.
			 */
			mc_switch_item_lock_type(ITEM_LOCK_GRANULAR);
			mc_slabs_rebalancer_resume();

			/*
			 * We are done expanding.. just wait for next invocation
			 */
			wait_event_freezable(hash_wait_queue,
					     test_bit(SEXPANDING, &hashflags) ||
					     kthread_should_stop());
			if (test_bit(ZOMBIE, &hashflags)) {
				goto out;
			}
			/* before doing anything, tell threads to use a global lock */
			mc_slabs_rebalancer_pause();
			mc_switch_item_lock_type(ITEM_LOCK_GLOBAL);
			mutex_lock(&cache_lock);
			mc_hash_expand();
			mutex_unlock(&cache_lock);
		}
	}

out:
	return 0;
}

int start_hash_thread(void)
{
	int ret = 0;

	hash_kthread = kthread_run(mc_hash_thread,
				   NULL, "kmchash");
	if (IS_ERR(hash_kthread)) {
		ret = PTR_ERR(hash_kthread);
		PRINTK("create hash kthread error\n");
		goto out;
	}

out:
	return ret;
}

void stop_hash_thread(void)
{
	set_bit(ZOMBIE, &hashflags);
	kthread_stop(hash_kthread);
}

