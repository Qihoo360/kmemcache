#ifndef __MC_H
#define __MC_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#include "config.h"
#include "mc_msg.h"
#include "memcache.h"
#include "sasl.h"
#include "connector.h"
#include "mc_buffer.h"
#include "mc_uparam.h"
#include "mc_oom.h"

/* Maximum length of a key */
#define KEY_MAX_LEN		250

/* size of an incr buf */
#define INCR_MAX_STORAGE_LEN	24

#define DATA_BUF_SIZE		2048
#define UDP_READ_BUF_SIZE	65536
#define UDP_MAX_PAYLOAD_SIZE	1400
#define UDP_HEADER_SIZE		8
#define MAX_SENDBUF_SIZE	(256 * 1024 * 1024)
/* I'm told the max length of a 64-bit num converted to string is 20 bytes.
 * Plus a few for spaces, \r\n, \0 */
#define SUFFIX_SIZE		24

/* initial size of list of items being returned by 'get' */
#define ITEM_LIST_INIT		200

/* Initial size of list of CAS suffixes appended to "gets" lines. */
#define SUFFIX_LIST_INIT	20

/* initial size of the sendmsg() scatter/gather array */
#define IOV_LIST_INIT		400

/* initial number of sendmsg() argument structures to allocate */
#define MSG_LIST_INIT		10

/* high water marks for buffer shrinking */
#define READ_BUF_HIGHWAT	8192
#define ITEM_LIST_HIGHWAT	400
#define IOV_LIST_HIGHWAT	600
#define MSG_LIST_HIGHWAT	100

/* binary protocol stuff */
#define MIN_BIN_PKT_LEN		16
#define BIN_PKT_HDR_WORDS	(MIN_BIN_PKT_LEN / sizeof(uint32_t))

/* initial power multiplier for the hash table */
#define HASHPOWER_DEFAULT	16

#define DEFAULT_HASH_BULK_MOVE	1

#define DEFAULT_SLAB_BULK_CHECK	1

/* slab sizing defiinitions */
#define POWER_SMALLEST		1
#define POWER_LARGEST		200
#define CHUNK_ALIGN_BYTES	8
#define MAX_SLAB_CLASSES	(POWER_LARGEST + 1)

/* How long an object can reasonably be assumed to be locked before
   harvesting it on a low memory condition. */
#define TAIL_REPAIR_TIME	(3 * 3600)
#define REALTIME_MAXDELTA	60*60*24*30

/* warning: don't use these macros with a function, as it evals its arg twice */
#define ITEM_get_cas(i) (((i)->it_flags & ITEM_CAS) ? \
        (i)->data->cas : (u64)0)

#define ITEM_set_cas(i,v) { \
    if ((i)->it_flags & ITEM_CAS) { \
        (i)->data->cas = v; \
    } \
}

#define ITEM_key(item) (((char*)&((item)->data)) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(u64) : 0))

#define ITEM_suffix(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(u64) : 0))

#define ITEM_data(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (item)->nsuffix \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(u64) : 0))

#define ITEM_ntotal(item) (sizeof(*item) + (item)->nkey + 1 \
         + (item)->nsuffix + (item)->nbytes \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(u64) : 0))

#define STAT_KEY_LEN 128
#define STAT_VAL_LEN 128

/** Append a simple stat with a stat name, value format and value */
#define APPEND_STAT(name, fmt, val) \
	mc_append_stat(name, f, c, fmt, val);

/** Append an indexed stat with a stat name (with format), value format
    and value */
#define APPEND_NUM_FMT_STAT(name_fmt, num, name, fmt, val)          \
    klen = snprintf(key_str, STAT_KEY_LEN, name_fmt, num, name);    \
    vlen = snprintf(val_str, STAT_VAL_LEN, fmt, val);               \
    f(key_str, klen, val_str, vlen, c);

/** Common APPEND_NUM_FMT_STAT format. */
#define APPEND_NUM_STAT(num, name, fmt, val) \
    APPEND_NUM_FMT_STAT("%d:%s", num, name, fmt, val)

/**
 * Callback for any function producing stats
 *
 * @param key the stat's key
 * @param klen length of the key
 * @param val the stat's value in an ascii form (e.g. text form of a number)
 * @param vlen length of the value
 * @parm cookie magic callback cookie
 */
typedef void (*add_stat_fn)(const char *key, u16 klen,
			    const char *val, u32 vlen,
			    const void *cookie);

typedef enum {
	conn_listening,	/* the socket which listens for connections */
	conn_new_cmd,	/* prepare connection for next command */
	conn_waiting,	/* waiting for a readable socket */
	conn_read,	/* reading in a command line */
	conn_parse_cmd,	/* try to parse a command from the input buffer */
	conn_write,	/* writing out a simple response */
	conn_nread,	/* reading in a fixed number of bytes */
	conn_swallow,	/* swallowing unnecessary bytes w/o storing */
	conn_closing,	/* closing this connection */
	conn_mwrite,	/* writing out many items sequentially */
	conn_max_state	/* Max state value (used for assertion) */
} conn_state_t;

typedef enum {
	bin_no_state,
	bin_reading_set_header,
	bin_reading_cas_header,
	bin_read_set_value,
	bin_reading_get_key,
	bin_reading_stat,
	bin_reading_del_header,
	bin_reading_incr_header,
	bin_read_flush_exptime,
	bin_reading_sasl_auth,
	bin_reading_sasl_auth_data,
	bin_reading_touch_key,
} bin_substate_t;

#define NREAD_ADD	1
#define NREAD_SET	2
#define NREAD_REPLACE	3
#define NREAD_APPEND	4
#define NREAD_PREPEND	5
#define NREAD_CAS	6

typedef enum {
	NOT_STORED = 0,
	STORED,
	EXISTS,
	NOT_FOUND
} store_item_t;

typedef enum {
	ITEM_LOCK_GRANULAR,
	ITEM_LOCK_GLOBAL
} item_lock_t;

typedef enum {
	OK,
	NON_NUMERIC,
	EOM,
	DELTA_ITEM_NOT_FOUND,
	DELTA_ITEM_CAS_MISMATCH
} delta_result_t;

/* global ststs */
struct stats {
	u64 curr_bytes;
	u64 rejected_conns;
	u64 get_cmds;
	u64 set_cmds;
	u64 touch_cmds;
	u64 get_hits;
	u64 get_misses;
	u64 touch_hits;
	u64 touch_misses;
	u64 evictions;
	u64 reclaimed;
	u64 listen_disabled_num;
	u64 hash_bytes;		/* size used for hash tables */
	u64 expired_unfetched;	/* items reclaimed but never touched */
	u64 evicted_unfetched;	/* items evicted but never touched */
	u64 slabs_moved;	/* times slabs were moved around */

#define STATS_ACCEPT	1	/* whether we are currently accepting */
#define STATS_HASH_EXP	2	/* If the hash table is being expanded */
#define	STATS_SLAB_RES	3	/* slab reassign in progress */
	unsigned long flags;

	rel_time_t started;	/* when the process was started */
	u32 curr_items;
	u32 total_items;
	u32 curr_conns;
	u32 total_conns;
	u32 conn_structs;
	u32 hash_power_level;	/* Better hope it's not over 9000 */
};

typedef struct prefix_stats prefix_stats_t;

struct prefix_stats {
	char	*prefix;
	size_t	len;

	u64	num_gets;
	u64	num_sets;
	u64	num_deletes;
	u64	num_hits;

	prefix_stats_t *next;
};

#define ITEM_LINKED 1
#define ITEM_CAS 2

/* temp */
#define ITEM_SLABBED 4

#define ITEM_FETCHED 8

/* item sotred in slab chunk */
typedef struct _stritem item;
struct _stritem {
	item *next;
	item *prev;
	item *h_next;    /* hash chain next */

	rel_time_t      time;       /* least recent access */
	rel_time_t      exptime;    /* expire time */
	int             nbytes;     /* size of data */
	atomic_t	refcount;
	u8		nsuffix;    /* length of flags-and-length string */
	u8		it_flags;   /* ITEM_* above */
	u8		slabs_clsid;/* which slab class we're in */
	u8		nkey;       /* key length, w/terminating null and padding */
	/* this odd type prevents type-punning issues when we do
	* the little shuffle to save space when not using CAS. */
	union {
	u64 cas;
	char end;
	} data[];
	/* if it_flags & ITEM_CAS we have 8 bytes CAS */
	/* then null-terminated key */
	/* then " flags length\r\n" (no terminating null) */
	/* then data with terminating \r\n (no terminating null; it's binary!) */
};

typedef struct conn conn;
#include "mc_slabs.h"
#include "mc_proto.h"
#include "mc_messenger.h"
#include "mc_worker.h"
#include "mc_dispatcher.h"

extern volatile rel_time_t current_time;
extern struct stats stats;
extern time_t process_started;
extern unsigned int hashpower;
extern struct dispatcher_thread dispatcher;

extern struct mutex cache_lock;

extern struct kmem_cache *prefix_cachep;

void do_accept_new_conns(u8 do_accept);

/* mc_thread.c */
void accept_new_conns(u8 do_accept);

/* mc_stats.c */
int	stats_init(void);
void	stats_exit(void);
void	mc_stats_reset(void);
void	mc_stats_prefix_record_get(const char *key, size_t nkey, int is_hit);
void	mc_stats_prefix_record_delete(const char *key, size_t nkey);
void	mc_stats_prefix_record_set(const char *key, size_t nkey);
int	mc_stats_prefix_dump(struct buffer *buf);

/* mc_items.c */
u64	mc_get_cas_id(void);
item*	mc_do_item_alloc(char *key, size_t nkey, int flags,
			 rel_time_t exptime, int nbytes,
			 u32 cur_hv);
void	mc_item_free(item *it);
int	mc_item_size_ok(size_t nkey, int flags, int nbytes);
int	mc_do_item_link(item *it, u32 hv);
void	mc_do_item_unlink(item *it, u32 hv);
void	mc_do_item_unlink_nolock(item *it, u32 hv);
void	mc_do_item_remove(item *it);
void	mc_do_item_update(item *it);
int	mc_do_item_replace(item *it, item *new_it, u32 hv);
int	mc_do_item_cachedump(unsigned int slabs_clsid, unsigned int limit,
			     struct buffer *buf);
void	mc_do_item_stats(add_stat_fn add_stats, void *c);
void	mc_do_item_stats_totals(add_stat_fn add_stats, void *c);
void	mc_do_item_stats_sizes(add_stat_fn add_stats, void *c);
void	mc_do_item_flush_expired(void);
item*	mc_do_item_get(const char *key, size_t nkey, u32 hv);
item*	mc_do_item_touch(const char *key, size_t nkey, u32 exptime, u32 hv);
void	mc_item_stats_reset(void);
void	mc_item_stats_evictions(u64 *evicted);

/* mc_hashtable.c */
int	hash_init(int power);
void	hash_exit(void);
item*	mc_hash_find(const char *key, u32 nkey, u32 hv);
int	mc_hash_insert(item *item, u32 hv);
void	mc_hash_delete(const char *key, size_t nkey, u32 hv);
void	mc_do_hash_move_next_bucket(void);
int	start_hash_thread(void);
void	stop_hash_thread(void);

/* misc */
u32 hash(const void *key, u32 length, u32 initval);

rel_time_t realtime(rel_time_t exptime);

int safe_strtoull(const char *str, u64 *out);
int safe_strtoll(const char *str, s64 *out);
int safe_strtoul(const char *str, u32 *out);
int safe_strtol(const char *str, s32 *out);

#define htonll(x)	cpu_to_be64(x)
#define ntohll(x)	be64_to_cpu(x)

#ifdef CONFIG_DEBUG
#define PRINTK(fmt, ...) \
	printk(KERN_ERR LOG_PREFIX "%s:%d: " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define PRINFO(fmt, ...) PRINTK(fmt, ##__VA_ARGS__)
#else
#define PRINFO(fmt, ...)
#define PRINTK(fmt, ...) \
	printk(KERN_ERR LOG_PREFIX fmt, ##__VA_ARGS__)
#endif

#ifdef CONFIG_VERBOSE
#define PVERBOSE(level, fmt, ...)		\
	do {					\
		if (settings.verbose > level) {	\
			printk(KERN_ERR		\
			       LOG_PREFIX	\
			       fmt,		\
			       ##__VA_ARGS__);	\
		}				\
	} while (0)
#else
#define PVERBOSE(level, fmt, ...)
#endif

#endif /* __MC_H */
