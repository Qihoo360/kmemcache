/*
 * transport helper for user space and kernel space.
 *
 * Parts derived from drivers/connector, copyright of
 * their respective owners.
 *
 * usages:
 *
 * kernel space
 *   connector_init
 *     mc_get_unique_val
 *     mc_add_callback(xx, xx, 1)
 *     mc_send_msg_*
 *     mc_del_callback(xx, 1)
 *     mc_put_unique_val
 *          ...
 *     mc_get_unique_val
 *     mc_add_callback(xx, xx, 0)
 *     mc_del_callback(xx, 0)
 *     mc_put_unique_val
 *   connector_exit
 *
 * user space 
 *   socket
 *   bind
 *   select
 *    ...
 *   close
 */

#ifndef __MC_CONNECTOR_H
#define __MC_CONNECTOR_H

#include <linux/types.h>

#define NETLINK_MEMCACHE	20
#define NETLINK_MEMCACHE_GRP	2
#define NETLINK_PAYLOAD		1024

#define CN_IDX_CACHE_BH		0x01
#define CN_IDX_INIT_SET		0x02
#define CN_IDX_SASL_DIS		0x10
#define CN_IDX_SASL_SER_NEW	0x11
#define CN_IDX_SASL_LIST_MECH	0x12
#define CN_IDX_SASL_SER_START	0x13
#define CN_IDX_SASL_SER_STEP	0x14
#define CN_IDX_SASL_GET_PROP	0x15
#define CN_IDX_SHUTDOWN		0x50

#define CN_VAL_INIT		0x1
#define CN_VAL_CACHE_BH		CN_VAL_INIT

struct cn_id {
	__u32	idx;
	__u32	val;
};

struct cn_msg {
	struct cn_id id;

	__u16	len;
	__u8	data[0];
};

#ifdef __KERNEL__
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <asm/atomic.h>

typedef void* (cn_callback_fn)(struct cn_msg *, struct netlink_skb_parms *);

struct cn_callback {
	struct sk_buff *skb;

	cn_callback_fn *f;

	void *out;
};

struct cn_entry {
#define ENTRY_NEW	(0x1 << 0)
#define ENTRY_RUNNING	(0x1 << 1)
#define ENTRY_FINISHED	(0x1 << 2)
	u32 flags:4;
	u32 unused:28;
	struct cn_id id;
	struct list_head list_entry;

	struct cn_callback callback;
	struct work_struct work;
	struct completion comp;
};

extern int connector_init(void);
extern void connector_exit(void);

extern u32 mc_get_unique_val(void);
extern void mc_put_unique_val(u32 val);
extern int mc_add_callback(struct cn_id *id, cn_callback_fn *f, int sync);
extern void mc_del_callback(struct cn_id *id, int sync);
extern void* mc_send_msg_sync(struct cn_msg *msg);
extern void* mc_send_msg_timeout(struct cn_msg *msg, unsigned long timeout);

#endif /* __KERNEL__ */
#endif /* __MC_CONNECTOR_H */
