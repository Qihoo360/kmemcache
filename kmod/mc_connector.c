#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <net/sock.h>

#include "mc.h"

static void mc_cn_work(struct work_struct *work);
static void mc_cn_work_del(struct work_struct *work);

#ifdef CONFIG_CN_CACHE
static struct kmem_cache *cn_cachep;
#endif

struct cn_queue {
	struct workqueue_struct *workqueue;

	struct list_head list;
	spinlock_t lock;
};

static struct cn {
	struct sock *sock;
	struct cn_queue *queue;
} cn;

static u32 unique_val = CN_VAL_INIT;
static DEFINE_SPINLOCK(unique_val_lock);

u32 mc_get_unique_val(void)
{
	u32 val;

	spin_lock_bh(&unique_val_lock);
	val = ++unique_val;
	unique_val &= val;
	spin_unlock_bh(&unique_val_lock);

	return val;
}
EXPORT_SYMBOL(mc_get_unique_val);

void mc_put_unique_val(u32 val)
{
	spin_lock_bh(&unique_val_lock);
	unique_val &= ~val;
	spin_unlock_bh(&unique_val_lock);
}
EXPORT_SYMBOL(mc_put_unique_val);

static void __mc_del_callback(struct cn_id *id)
{
	struct cn_entry *pos, *n;
	struct cn_queue *queue = cn.queue;

	spin_lock_bh(&queue->lock);
	list_for_each_entry_safe(pos, n, &queue->list, list_entry) {
		if (pos->id.idx == id->idx && pos->id.val == id->val) {
			list_del(&pos->list_entry);
			break;
		}
	}
	spin_unlock_bh(&queue->lock);

	if (&pos->list_entry != &queue->list) {
#ifdef CONFIG_CN_CACHE
		kmem_cache_free(cn_cachep, pos);
#else
		kfree(pos);
#endif
	}
}

void mc_del_callback(struct cn_id *id, int sync)
{
	if (likely(sync))
		__mc_del_callback(id);
}
EXPORT_SYMBOL(mc_del_callback);

int mc_add_callback(struct cn_id *id, cn_callback_fn *f, int sync)
{
	int ret = 0;
	struct cn_entry *entry, *pos;
	struct cn_queue *queue = cn.queue;

#ifdef CONFIG_CN_CACHE
	entry = kmem_cache_zalloc(cn_cachep, GFP_KERNEL);
#else
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
#endif
	if (!entry) {
		ret = -ENOMEM;
		goto out;
	}
	entry->flags = ENTRY_NEW;
	entry->id.idx = id->idx;
	entry->id.val = id->val;
	entry->callback.skb = NULL;
	entry->callback.out = NULL;
	entry->callback.f = f;
	if (likely(sync)) {
		INIT_WORK(&entry->work, mc_cn_work);
		init_completion(&entry->comp);
	} else {
		INIT_WORK(&entry->work, mc_cn_work_del);
	}

	spin_lock_bh(&queue->lock);
	list_for_each_entry(pos, &queue->list, list_entry) {
		if (pos->id.idx == id->idx && pos->id.val == id->val) {
			break;
		}
	}
	if (&pos->list_entry == &queue->list) {
		list_add_tail(&entry->list_entry, &queue->list);
		spin_unlock_bh(&queue->lock);
	} else {
		spin_unlock_bh(&queue->lock);
		ret = -EFAULT;
		goto free_entry;
	}

	return 0;

free_entry:
#ifdef CONFIG_CN_CACHE
	kmem_cache_free(cn_cachep, entry);
#else
	kfree(entry);
#endif
out:
	return ret;
}
EXPORT_SYMBOL(mc_add_callback);

static void mc_cn_work(struct work_struct *work)
{
	struct cn_entry *entry;
	struct cn_callback *callback;
	struct cn_msg *msg;
	struct netlink_skb_parms *parms;
       
	entry = container_of(work, struct cn_entry, work);
	callback = &entry->callback;
	msg = NLMSG_DATA(nlmsg_hdr(callback->skb));
	parms = &NETLINK_CB(callback->skb);

	callback->out = callback->f(msg, parms);
	kfree_skb(callback->skb);
	complete(&entry->comp);
}

static void mc_cn_work_del(struct work_struct *work)
{
	struct cn_entry *entry;
	struct cn_callback *callback;
	struct cn_msg *msg;
	struct netlink_skb_parms *parms;
       
	entry = container_of(work, struct cn_entry, work);
	callback = &entry->callback;
	msg = NLMSG_DATA(nlmsg_hdr(callback->skb));
	parms = &NETLINK_CB(callback->skb);

	callback->out = callback->f(msg, parms);
	kfree_skb(callback->skb);

	__mc_del_callback(&entry->id);
}

static void* __send_msg_sync(struct cn_msg *msg, unsigned long timeout)
{
	int ret = 0;
	size_t size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct cn_msg *data;
	struct cn_entry *entry;
	struct cn_queue *queue = cn.queue;

	spin_lock_bh(&queue->lock);
	list_for_each_entry(entry, &queue->list, list_entry) {
		if (entry->id.idx == msg->id.idx &&
		    entry->id.val == msg->id.val) {
			entry->flags = ENTRY_RUNNING;
			break;
		}
	}
	spin_unlock_bh(&queue->lock);

	if (unlikely(&entry->list_entry == &queue->list))
		return NULL;

	if (!netlink_has_listeners(cn.sock, NETLINK_MEMCACHE_GRP)) {
		PRINTK("netlink hasn't got a listener\n");
		ret = -ESRCH;
		goto out;
	}

	size = NLMSG_SPACE(sizeof(*msg) + msg->len);
	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb) {
		PRINTK("alloc skb error\n");
		ret = -ENOMEM;
		goto out;
	}

	nlh = NLMSG_PUT(skb, 0, 0, NLMSG_DONE, size - sizeof(*nlh));

	data = NLMSG_DATA(nlh);
	memcpy(data, msg, sizeof(*data) + msg->len);

	NETLINK_CB(skb).dst_group = 0;

	if ((ret = netlink_broadcast(cn.sock, skb, 0,
				     NETLINK_MEMCACHE_GRP,
				     GFP_KERNEL))) {
		PRINTK("netlink broadcast error\n");
		goto out;
	}

	ret = wait_for_completion_timeout(&entry->comp, timeout);
	if (!ret) {
		PRINTK("__send_msg_sync timeout\n");
		ret = -EFAULT;
		goto out;
	}
	entry->flags = ENTRY_FINISHED;
	return entry->callback.out;

nlmsg_failure:
	kfree_skb(skb);
	ret = -EFAULT;
out:
	return ERR_PTR(ret);
}

void* mc_send_msg_sync(struct cn_msg *msg)
{
	return __send_msg_sync(msg, MAX_SCHEDULE_TIMEOUT);
}
EXPORT_SYMBOL(mc_send_msg_sync);

void* mc_send_msg_timeout(struct cn_msg *msg, unsigned long timeout)
{
	return __send_msg_sync(msg, timeout);
}
EXPORT_SYMBOL(mc_send_msg_timeout);

static void mc_nl_callback(struct sk_buff *_skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct cn_msg *msg;
	struct cn_entry *entry;
	struct cn_queue *queue = cn.queue;

	skb = skb_get(_skb);
	if (skb->len < NLMSG_SPACE(0))
		goto out;

	nlh = nlmsg_hdr(skb);
	if (nlh->nlmsg_len < sizeof(struct cn_msg) ||
	    skb->len < nlh->nlmsg_len ||
	    nlh->nlmsg_len > NETLINK_PAYLOAD) {
		kfree_skb(skb);
		goto out;
	}

	msg = NLMSG_DATA(nlh);
	spin_lock_bh(&queue->lock);
	list_for_each_entry(entry, &queue->list, list_entry) {
		if (entry->id.idx == msg->id.idx &&
		    entry->id.val == msg->id.val) {
			entry->callback.skb = skb;
			if (!queue_work(queue->workqueue,
					&entry->work)) {
				spin_unlock_bh(&queue->lock);
				entry->callback.skb = NULL;
				PRINTK("may be dead lock, check callback\n");
				goto free_skb;
			}
			break;
		}
	}
	spin_unlock_bh(&queue->lock);

	return;

free_skb:
	kfree_skb(skb);
out:
	return;
}

int connector_init(void)
{
	int ret = 0;

#ifdef CONFIG_CN_CACHE
	cn_cachep = kmem_cache_create("mc_cn_cache",
				      sizeof(struct cn_entry),
				      0,
				      SLAB_HWCACHE_ALIGN,
				      NULL);
	if (!cn_cachep) {
		PRINTK("create connector cache error\n");
		ret = -ENOMEM;
		goto out;
	}
#endif

	cn.sock = netlink_kernel_create(&init_net,
				        NETLINK_MEMCACHE,
				        NETLINK_MEMCACHE_GRP,
				        mc_nl_callback,
				        NULL,
				        THIS_MODULE);
	if (!cn.sock) {
		PRINTK("create netlink error\n");
		ret = -EIO;
		goto free_cache;
	}

	cn.queue = kzalloc(sizeof(struct cn_queue), GFP_KERNEL);
	if (!cn.queue) {
		PRINTK("alloc connetctor queue error\n");
		ret = -ENOMEM;
		goto free_netlink;
	}
	cn.queue->workqueue = create_singlethread_workqueue("kmccn");
	if (!cn.queue->workqueue) {
		PRINTK("create connetctor queue error\n");
		ret = -ENOMEM;
		goto free_queue;
	}
	INIT_LIST_HEAD(&cn.queue->list);
	spin_lock_init(&cn.queue->lock);

	return 0;

free_queue:
	kfree(cn.queue);
	cn.queue = NULL;
free_netlink:
	netlink_kernel_release(cn.sock);
	cn.sock = NULL;
free_cache:
#ifdef CONFIG_CN_CACHE
	kmem_cache_destroy(cn_cachep);
out:
#endif
	return ret;
}

void connector_exit(void)
{
	struct cn_entry *pos, *n;
	struct cn_queue *queue = cn.queue;

	spin_lock_bh(&queue->lock);
	list_for_each_entry_safe(pos, n, &queue->list, list_entry) {
		if (pos->flags != ENTRY_RUNNING) {
			list_del(&pos->list_entry);
#ifdef CONFIG_CN_CACHE
			kmem_cache_free(cn_cachep, pos);
#else
			kfree(pos);
#endif
		}
	}
	spin_unlock_bh(&queue->lock);

	while (!list_empty(&queue->list)) {
		flush_workqueue(queue->workqueue);
		msleep(1000);
	}

	destroy_workqueue(queue->workqueue);
	kfree(queue);
	netlink_kernel_release(cn.sock);
#ifdef CONFIG_CN_CACHE
	kmem_cache_destroy(cn_cachep);
#endif
}
