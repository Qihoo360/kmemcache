#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include "kmodhelper.h"

static int delay = 2;
module_param(delay, int, 0);

#define ZOMBILE 1
static int flags;
static struct workqueue_struct *wq;
static LIST_HEAD(delay_list);
static DEFINE_SPINLOCK(list_lock);

struct callback_req {
	struct list_head list;
	struct delayed_work work;

	kmod_callback_t fun;
	void *arg;
};

static void callback_work(struct work_struct *work)
{
	struct callback_req *rq =
		container_of(work, struct callback_req, work.work);

	rq->fun(rq->arg);
	if (delay) {
		spin_lock_bh(&list_lock);
		list_del(&rq->list);
		spin_unlock_bh(&list_lock);
	}
	kfree(rq);
}

int register_callback(kmod_callback_t fun, void *arg)
{
	struct callback_req *rq;

	rq = kzalloc(sizeof(*rq), GFP_KERNEL);
	if (!rq) {
		return -ENOMEM;
	}
	rq->fun = fun;
	rq->arg = arg;
	INIT_LIST_HEAD(&rq->list);
	INIT_DELAYED_WORK(&rq->work, callback_work);
	if (delay) {
		spin_lock_bh(&list_lock);
		list_add(&rq->list, &delay_list);
		spin_unlock_bh(&list_lock);
	} else {
		schedule_work(&rq->work.work);
	}

	return 0;
}
EXPORT_SYMBOL(register_callback);

static int delay_read(char *page, char **start, off_t off,
		      int count, int *eof, void *data)
{
	unsigned int size = 0;
	int len;

	if (delay) {
		struct callback_req *req;

		spin_lock_bh(&list_lock);
		list_for_each_entry(req, &delay_list, list) {
			size++;
		}
		spin_unlock_bh(&list_lock);
	}

	len = sprintf(page, "delay: %u\n", size);

	return len;
}

static int delay_write(struct file *file, const char __user *buf,
		       unsigned long count, void *data)
{
	if (delay) {
		struct callback_req *rq;

		spin_lock_bh(&list_lock);
		list_for_each_entry(rq, &delay_list, list) {
			queue_delayed_work(wq, &rq->work, delay * HZ);
		}
		spin_unlock_bh(&list_lock);
	}

	return count;
}

static struct proc_dir_entry *delay_dir;

static int __init kmod_init(void)
{
	int ret = 0;
	struct proc_dir_entry *entry;

	delay_dir = proc_mkdir("kmodhelper", NULL);
	if (!delay_dir) {
		printk(KERN_ERR "create proc node error");
		ret = -ENOMEM;
		goto out;
	}
	entry = create_proc_entry("delay", S_IRUGO | S_IWUGO, delay_dir);
	if (!entry) {
		printk(KERN_ERR "create proc sub-node error");
		ret = -ENOMEM;
		goto del_proc;
	}
	entry->read_proc = delay_read;
	entry->write_proc = delay_write;

	if (delay) {
		wq = create_singlethread_workqueue("kmodhelper");
		if (!wq) {
			printk(KERN_ERR "create kernel workqueue error");
			ret = -ENOMEM;
			goto del_entry;
		}
	}

	return 0;

del_entry:
	remove_proc_entry("delay", delay_dir);
del_proc:
	remove_proc_entry("kmodhelper", NULL);
out:
	return ret;
}

static void __exit kmod_exit(void)
{
	if (delay) {
		struct callback_req *req;

		flags = ZOMBILE;

		spin_lock_bh(&list_lock);
		list_for_each_entry(req, &delay_list, list) {
			queue_delayed_work(wq, &req->work, 0);
		}
		spin_unlock_bh(&list_lock);

		flush_workqueue(wq);
		destroy_workqueue(wq);
	}

	remove_proc_entry("delay", delay_dir);
	remove_proc_entry("kmodhelper", NULL);
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_AUTHOR("Li Jianguo <byjgli@gmail.com>");
MODULE_DESCRIPTION("kmod helper");
MODULE_LICENSE("GPL v2");
