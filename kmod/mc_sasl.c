#include <linux/kernel.h>

#include "mc.h"

static void* mc_sasl_dispose_callback(struct cn_msg *msg,
				      struct netlink_skb_parms *pm)
{
	return msg;
}

void mc_sasl_dispose(sasl_conn_t **pconn)
{
	size_t size;
	struct cn_msg *msg;
	sasl_dispose_t *data;
	void *out;

	size = sizeof(struct cn_msg) + sizeof(sasl_dispose_t);

	msg = kmalloc(size, GFP_KERNEL);
	if (!msg) {
		PRINTK("alloc sasl dispose msg error");
		goto out;
	}
	msg->id.idx = CN_IDX_SASL_DIS;
	msg->id.val = mc_get_unique_val();

	data = (sasl_dispose_t *)msg->data;
	data->pconn = pconn;

	if (mc_add_callback(&msg->id, mc_sasl_dispose_callback)) {
		PRINTK("add sasl dispose callback error");
		goto free_id;
	}
	if (IS_ERR((out = mc_send_msg_sync(msg)))) {
		PRINTK("send sasl dispose error");
	}
	if (out) {
		mc_del_callback(&msg->id);
	}

free_id:
	mc_put_unique_val(msg->id.val);
	kfree(msg);
out:
	return;
}
