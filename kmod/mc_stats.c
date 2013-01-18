/*
 * Detailed statistics management. For simple stats like total number of
 * "get" requests, we use inline code in memcached.c, but when
 * stats detail mode is activated, the code here records more information.
 */

#include <linux/string.h>
#include "mc.h"

struct stats stats;

#define PREFIX_HASH_SIZE	256

struct kmem_cache *prefix_cachep;

/* lock for global stats */
DEFINE_SPINLOCK(stats_lock);

/* lock for prefix_stats */
static DEFINE_MUTEX(prefix_stats_lock);

static prefix_stats_t *prefix_stats[PREFIX_HASH_SIZE];
static int num_prefixes = 0;
static int total_prefix_size = 0;

/**
 * cleans up all our previously collected stats.
 *
 * NOTE: caller must hold the stats lock.
 */
static void mc_stats_prefix_clear(void)
{
	int i;

	for (i = 0; i < PREFIX_HASH_SIZE; i++) {
		prefix_stats_t *cur, *next;
		for (cur = prefix_stats[i]; cur; cur = next) {
			next = cur->next;
			kfree(cur->prefix);
			kmem_cache_free(prefix_cachep, cur);
		}
		prefix_stats[i] = NULL;
	}
	num_prefixes = 0;
	total_prefix_size = 0;
}

/**
 * returns the stats structure for a prefix, creating it if it's
 * not already in the list.
 *
 * NOTE: caller must hold the stats lock.
 */
static prefix_stats_t* mc_stats_prefix_find(const char *key, size_t nkey)
{
	prefix_stats_t *pfs;
	u32 hashval;
	size_t len;
	int bailout = 1;

	BUG_ON(!key);

	for (len = 0; len < nkey && key[len] != '\0'; len++) {
		if (key[len] == settings.prefix_delimiter) {
			bailout = 0;
			break;
		}
	}

	if (bailout)
		return NULL;
	hashval = hash(key, len, 0) % PREFIX_HASH_SIZE;

	for (pfs = prefix_stats[hashval]; pfs; pfs = pfs->next) {
		if (strncmp(pfs->prefix, key, len) == 0) {
			return pfs;
		}
	}

	pfs = kmem_cache_alloc(prefix_cachep, GFP_KERNEL);
	if (!pfs) {
		PRINTK("allocate space for stats structure error");
		return NULL;
	}
	pfs->prefix = kmalloc(len + 1, GFP_KERNEL);
	if (!pfs->prefix) {
		PRINTK("allocate space for prefix of prefix_stats structure error");
		kfree(pfs);
		return NULL;
	}

	strncpy(pfs->prefix, key, len);
	pfs->prefix[len] = '\0';
	pfs->prefix_len = len;
	pfs->next = prefix_stats[hashval];
	prefix_stats[hashval] = pfs;

	num_prefixes++;
	total_prefix_size += len;

	return pfs;
}

/**
 * records a "get" of a key
 */
void mc_stats_prefix_record_get(const char *key, size_t nkey, int is_hit)
{
	prefix_stats_t *pfs;

	mutex_lock(&prefix_stats_lock);
	pfs = mc_stats_prefix_find(key, nkey);
	if (pfs) {
		pfs->num_gets++;
		if (is_hit)
			pfs->num_hits++;
	}
	mutex_unlock(&prefix_stats_lock);
}

/** 
 * records a "delete" of a key
 */
void mc_stats_prefix_record_delete(const char *key, size_t nkey)
{
	prefix_stats_t *pfs;

	mutex_lock(&prefix_stats_lock);
	pfs = mc_stats_prefix_find(key, nkey);
	if (pfs) {
		pfs->num_deletes++;
	}
	mutex_unlock(&prefix_stats_lock);
}

/**
 * records a "set" of a key
 */
void mc_stats_prefix_record_set(const char *key, size_t nkey)
{
	prefix_stats_t *pfs;

	mutex_lock(&prefix_stats_lock);
	pfs = mc_stats_prefix_find(key, nkey);
	if (pfs) {
		pfs->num_sets++;
	}
	mutex_unlock(&prefix_stats_lock);

}

/**
 * returns stats in textual form suitable for writing to client.
 *
 */
int mc_stats_prefix_dump(struct buffer *buf)
{
	const char *format = "PREFIX %s get %llu hit %llu set %llu del %llu\r\n";
	char *dumpstr;
	prefix_stats_t *pfs;
	int i, pos, res = 0;
	size_t size = 0, written = 0, total_written = 0;

	/*
	 * Figure out how big the buffer needs to be. This is the sum of the
	 * lengths of the prefixes themselves, plus the size of one copy of
	 * the per-prefix output with 20-digit values for all the counts,
	 * plus space for the "END" at the end.
	 */
	mutex_lock(&prefix_stats_lock);
	size = strlen(format) + total_prefix_size +
	       num_prefixes * (strlen(format) - 2 /* %s */
	       + 4 * (20 - 4)) /* %llu replaced by 20-digit num */
	       + sizeof("END\r\n");
	res = alloc_buffer(buf, size);
	if (res) {
		mutex_unlock(&prefix_stats_lock);
		PRINTK("can't allocate stats response");
		goto out;
	}
	BUFFER_PTR(buf, dumpstr);

	pos = 0;
	for (i = 0; i < PREFIX_HASH_SIZE; i++) {
		for (pfs = prefix_stats[i]; NULL != pfs; pfs = pfs->next) {
			written = snprintf(dumpstr + pos, size-pos, format,
					   pfs->prefix, pfs->num_gets, pfs->num_hits,
					   pfs->num_sets, pfs->num_deletes);
			pos += written;
			total_written += written;
			BUG_ON(total_written >= size);
		}
	}

	mutex_unlock(&prefix_stats_lock);
	memcpy(dumpstr + pos, "END\r\n", 6);

	buf->len = pos + 5;
out:
	return res;
}

int INIT stats_init(void)
{
	/* assuming we start in this state. */
	stats.accepting_conns = 1;

	return 0;
}

void stats_exit(void)
{
	mutex_lock(&prefix_stats_lock);
	mc_stats_prefix_clear();
	mutex_unlock(&prefix_stats_lock);
}

void mc_stats_reset(void)
{
	spin_lock(&stats_lock);
	stats.total_items = 0;
	stats.total_conns = 0;
	stats.rejected_conns = 0;
	stats.evictions = 0;
	stats.reclaimed = 0;
	stats.listen_disabled_num = 0;
	spin_unlock(&stats_lock);

	mutex_lock(&prefix_stats_lock);
	mc_stats_prefix_clear();
	mutex_unlock(&prefix_stats_lock);

	mc_threadlocal_stats_reset();
	mc_item_stats_reset();
}
