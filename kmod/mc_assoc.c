#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#include "mc.h"

static DECLARE_WAIT_QUEUE_HEAD(assoc_wait_queue);
static struct task_struct *assoc_kthread;

typedef unsigned long int ub4;	/* unsigned 4-byte quantities */
typedef unsigned char	  ub1;	/* unsigned 1-byte quantities */

/* how many powers of 2's worth of buckets we use */
unsigned int hashpower = HASHPOWER_DEFAULT;

#define hashsize(n)	((ub4)1 << (n))
#define hashmask(n)	(hashsize(n) -1)

/* main hash table. This is where we look except during expansion. */
static item** primary_hashtable = 0;

/* 
 * previous hash table. During expansion, we look here for keys that
 * haven't been moved over to the primary yet.
 */
static item** old_hashtable = 0;

/* number of items in the hash table */
static unsigned int hash_items = 0;

/* flag: are we in the middle of expanding now? */
static u8 expanding = 0;
static u8 started_expanding = 0;

/* 
 * during expansion we migrate values with bucket granularity; this is how
 * far we've gotten so far. Ranges from 0 .. hashsize(hashpower - 1) - 1.
 */
static unsigned int expand_bucket = 0;

int INIT assoc_init(int hashtable_init)
{
	int ret = 0;

	if (hashtable_init)
		hashpower = hashtable_init;
	primary_hashtable = kzalloc(hashsize(hashpower) * sizeof(void *),
				    GFP_KERNEL);
	if (!primary_hashtable) {
		PRINTK("alloc primary_hashtable error");
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&stats_lock);
	stats.hash_power_level = hashpower;
	stats.hash_bytes = hashsize(hashpower) * sizeof(void *);
	spin_unlock(&stats_lock);

out:
	return ret;
}

void assoc_exit(void)
{
	if (expanding) {
		kfree(old_hashtable);
		old_hashtable = NULL;
	}
	kfree(primary_hashtable);
	primary_hashtable = NULL;
}

item* mc_assoc_find(const char *key, size_t nkey, u32 hv)
{
	int depth = 0;
	item *it, *ret = NULL;
	unsigned int oldbucket;

	if (expanding &&
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
		} else {
			it = it->h_next;
			depth++;
		}
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

	if (expanding &&
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
static void mc_assoc_expand(void)
{
	old_hashtable = primary_hashtable;

	primary_hashtable = kzalloc(hashsize(hashpower + 1) * sizeof(void *),
				    GFP_KERNEL);
	if (primary_hashtable) {
		if (settings.verbose > 1)
			PRINTK("hash table expansion starting");
		hashpower++;
		expanding = 1;
		expand_bucket = 0;
		spin_lock(&stats_lock);
		stats.hash_power_level = hashpower;
		stats.hash_bytes += hashsize(hashpower) * sizeof(void *);
		stats.hash_is_expanding = 1;
		spin_unlock(&stats_lock);
	} else {
		/* bad news, but we can keep running */
		PRINTK("hash table expansion error");
		primary_hashtable = old_hashtable;
	}
}

static void mc_assoc_start_expand(void)
{
	if (started_expanding)
		return;
	started_expanding = 1;
	wake_up(&assoc_wait_queue);
}

/*
 * Note: this isn't an assoc_update. The key must not already exist
 * to call this.
 */
int mc_assoc_insert(item *it, u32 hv)
{
	unsigned int oldbucket;

	/* shouldn't have duplicately named things defined */
	//BUG_ON(mc_assoc_find(ITEM_key(it), it->nkey));	
	
	if (expanding &&
	    (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket) {
		it->h_next = old_hashtable[oldbucket];
		old_hashtable[oldbucket] = it;
	} else {
		it->h_next = primary_hashtable[hv & hashmask(hashpower)];
		primary_hashtable[hv & hashmask(hashpower)] = it;
	}

	hash_items++;
	if (!expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
		mc_assoc_start_expand();
	}

	return 0;
}

void mc_assoc_delete(const char *key, size_t nkey, u32 hv)
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

static atomic_t do_run_thread = ATOMIC_INIT(1);

static int mc_assoc_thread(void *ignore)
{
	set_freezable();
	while (atomic_read(&do_run_thread)) {
		int ii = 0;

		/* 
		 * Lock the cache, and bulk move multiple buckets to
		 * the new hash table.
		 */
		mc_item_lock_global();
		mutex_lock(&cache_lock);

		for (ii = 0; ii < settings.hash_bulk_move && expanding; ii++) {
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
				expanding = 0;
				started_expanding = 0;
				kfree(old_hashtable);

				spin_lock(&stats_lock);
				stats.hash_bytes -= hashsize(hashpower - 1) *
						    sizeof(void *);
				stats.hash_is_expanding = 0;
				spin_unlock(&stats_lock);
				if (settings.verbose > 1) {
					PRINTK("hash table expansion done");
				}
			}
		}

		mutex_unlock(&cache_lock);
		mc_item_unlock_global();

		if (!expanding) {
			/* 
			 * finished expanding. tell all threads to use
			 * fine-grained locks.
			 */
			mc_switch_item_lock_type(ITEM_LOCK_GRANULAR);
			mc_slabs_rebalancer_resume();

			/*
			 * We are done expanding.. just wait for next invocation
			 */
			wait_event_freezable(assoc_wait_queue,
					     started_expanding ||
					     kthread_should_stop());
			if (!atomic_read(&do_run_thread)) {
				goto out;
			}
			/* before doing anything, tell threads to use a global lock */
			mc_slabs_rebalancer_pause();
			mc_switch_item_lock_type(ITEM_LOCK_GLOBAL);
			mutex_lock(&cache_lock);
			mc_assoc_expand();
			mutex_unlock(&cache_lock);
		}
	}

out:
	return 0;
}

int INIT start_assoc_thread(void)
{
	int ret = 0;

	assoc_kthread = kthread_run(mc_assoc_thread,
				    NULL, "mc_assoc");
	if (IS_ERR(assoc_kthread)) {
		ret = PTR_ERR(assoc_kthread);
		PRINTK("create assoc_kthread error");
		goto out;
	}

out:
	return ret;
}

void stop_assoc_thread(void)
{
	atomic_set(&do_run_thread, 0);
	kthread_stop(assoc_kthread);
}

