#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/workqueue.h>
#include <asm/atomic.h>

#include "mc.h"

static void set_sock_callbacks(struct socket *sock, conn *c);

struct kmem_cache *conn_cachep;

static inline conn* _conn_new(void)
{
	return kmem_cache_zalloc(conn_cachep, GFP_KERNEL);
}

static inline void _conn_free(void *objp)
{
	kmem_cache_free(conn_cachep, objp);
}

#define _free_buf(ptr, type, mem)			\
	do {						\
		struct buffer *buf;			\
		buf = &container_of(ptr, type, mem)->_buf;\
		free_buffer(buf);			\
	} while (0)

static void mc_conn_free(conn *c)
{
	if (c->cn_rbuf)
		free_buffer(&c->_rbuf._buf);
	if (c->cn_wbuf)
		free_buffer(&c->_wbuf._buf);
	if (c->cn_ilist)
		free_buffer(&c->_ilistbuf._buf);
	if (c->cn_suffixlist)
		free_buffer(&c->_slistbuf._buf);
	if (c->cn_iov)
		free_buffer(&c->_kvecbuf._buf);
	if (c->cn_msglist)
		free_buffer(&c->_msghdrbuf._buf);
	if (c->hdrbuf)
		kfree(c->hdrbuf);
	_conn_free(c);
}

#define MALLOC_OOM(_val, _type, _mem, _size)			\
	do {							\
		int ret = 0, size;				\
		struct buffer *buf;				\
								\
		size = (_size) * sizeof(typeof(*(_val)));	\
		buf = &container_of(&(_val), _type, _mem)->_buf;\
		ret = alloc_buffer(buf, size, 0);		\
		if (ret) {					\
			PRINTK("alloc buffer error\n");		\
			goto OOM;				\
		}						\
		BUFFER_PTR(buf, _val);				\
	} while (0)

conn* mc_conn_new(struct conn_req *rq)
{
	struct worker_storage *stor;
	conn *c = _conn_new();

	if (!c) {
		PRINTK("alloc new conn error\n");
		c = ERR_PTR(-ENOMEM);
		goto out;
	}

	c->cn_rsize	= rq->rsize;
	c->cn_wsize	= DATA_BUF_SIZE;
	c->cn_iovsize	= IOV_LIST_INIT;
	c->cn_msgsize	= MSG_LIST_INIT;
	c->cn_isize	= ITEM_LIST_INIT;
	c->cn_suffixsize= SUFFIX_LIST_INIT;

	MALLOC_OOM(c->cn_rbuf, struct simpbuf, buf, c->cn_rsize);
	MALLOC_OOM(c->cn_wbuf, struct simpbuf, buf, c->cn_wsize);
	MALLOC_OOM(c->cn_iov, struct kvecbuf, iov, c->cn_iovsize);
	MALLOC_OOM(c->cn_msglist, struct msghdrbuf, msglist, c->cn_msgsize);
	MALLOC_OOM(c->cn_ilist, struct ilistbuf, ilist, c->cn_isize);
	MALLOC_OOM(c->cn_suffixlist, struct slistbuf, suffixlist, c->cn_suffixsize);

	if (settings.binding_protocol == ascii_prot)
		c->proto_ops = &txt_proto_ops;
	else if (settings.binding_protocol == binary_prot)
		c->proto_ops = &bin_proto_ops;
	else
		c->proto_ops = &def_proto_ops;

	if (settings.flags & UNIX_SOCK) {
		c->request_addr_size = 0;
	} else {
		c->request_addr_size = sizeof(c->request_addr);
	}

	c->cmd		= 1;
	c->cn_wcurr	= c->cn_wbuf;
	c->cn_rcurr	= c->cn_rbuf;
	c->cn_icurr	= c->cn_ilist;
	c->cn_suffixcurr= c->cn_suffixlist;

	c->write_and_go	= rq->state;
	c->write_and_free.flags = BUF_NEGATIVE;
	c->stats.flags = BUF_NEGATIVE;

	c->sock = rq->sock;
	c->state = rq->state;
	c->transport = rq->transport;
	INIT_WORK(&c->work, mc_conn_work);
	atomic_set(&c->nref, 1);
	set_bit(EV_RDWR, &c->event);
	set_sock_callbacks(c->sock, c);

	c->cpu = rq->cpu;
	stor = rq->who;
	c->who = stor;
	spin_lock(&stor->lock);
	list_add(&c->list, &stor->list);
	spin_unlock(&stor->lock);

	spin_lock(&stats_lock);
        stats.conn_structs++;
	stats.curr_conns++;
	stats.total_conns++;
	spin_unlock(&stats_lock);

	return c;

OOM:
	mc_conn_free(c);
	c = ERR_PTR(-ENOMEM);
out:
	return c;
}

void mc_conn_close(conn *c)
{
	PVERBOSE(1, "<%p connection closed\n", c);

	if (!IS_UDP(c->transport)) {
		set_bit(EV_DEAD, &c->event);
		c->sock->ops->shutdown(c->sock, SHUT_RDWR);
		sock_release(c->sock);
		c->sock = NULL;
	}

	mc_accept_new_conns(1);

	spin_lock(&stats_lock);
	stats.curr_conns--;
	spin_unlock(&stats_lock);
}

void mc_conn_cleanup(conn *c)
{
	if (c->item) {
		mc_item_remove(c->who, c->item);
		c->item = NULL;
	}
	if (c->cn_ileft) {
		for (; c->cn_ileft > 0;) {
			mc_item_remove(c->who, *c->cn_icurr);

			c->cn_ileft--;
			c->cn_icurr++;
		}
	}
	if (c->cn_suffixleft) {
		for (; c->cn_suffixleft > 0;) {
			_suffix_free(*c->cn_suffixcurr);

			c->cn_suffixleft--;
			c->cn_suffixcurr++;
		}
	}
	if (c->write_and_free.flags != BUF_NEGATIVE) {
		free_buffer(&c->write_and_free);
		c->write_and_free.flags = BUF_NEGATIVE;
	}
	if (c->sasl_conn) {
		mc_sasl_dispose(&c->sasl_conn);
		c->sasl_conn = NULL;
	}
	if (IS_UDP(c->transport)) {
		conn_set_state(c, conn_read);
	}
}

conn* mc_conn_get(conn *c)
{
	if (atomic_inc_not_zero(&c->nref))
		return c;
	return NULL;
}

void mc_conn_put(conn *c)
{
	if (atomic_dec_and_test(&c->nref)) {
		spin_lock(&c->who->lock);
		list_del(&c->list);
		spin_unlock(&c->who->lock);
		mc_conn_cleanup(c);
		mc_conn_free(c);
	}
}

int update_event(conn *c, int flag)
{
	int ret = 0;

	switch (flag) {
	case EV_READ:
		set_bit(EV_RDWR, &c->event);
		break;
	case EV_WRITE:
		clear_bit(EV_RDWR, &c->event);
		break;
	case EV_DEAD:
		set_bit(EV_DEAD, &c->event);
		break;
	default:
		BUG();
		break;
	}

	return ret;
}

int mc_send(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = {buf, len};
	struct msghdr msg = {
		.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
	};

	return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

int mc_s2clog(struct socket *sock, int type)
{
	return mc_send(sock, s2c_msg[type], s2c_len[type]);
}

int mc_sendmsg(struct socket *sock, struct msghdr *msg)
{
	int i, total = 0;

	msg->msg_flags |= MSG_DONTWAIT | MSG_NOSIGNAL;

	for (i = 0; i < msg->msg_iovlen; i++)
		total += msg->msg_iov[i].iov_len;

	return kernel_sendmsg(sock, msg, (struct kvec *)msg->msg_iov,
			      msg->msg_iovlen, total);
}

int mc_recv(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = {buf, len};
	struct msghdr msg = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};

	return kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
}

int mc_recvfrom(struct socket *sock, void *buf, size_t len, int flags,
	        struct sockaddr *addr, size_t *addrlen)
{
	int ret;
	struct kvec iov = {buf, len};
	struct msghdr msg = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};
	struct sockaddr_storage address;

	if (flags)
		msg.msg_flags  |= flags;
	if (addr) {
		msg.msg_name	= (struct sockaddr *)&address;
		msg.msg_namelen = sizeof(address);
	}

	ret = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
	if (ret >= 0 && addr != NULL) {
		if (*addrlen > msg.msg_namelen)
			*addrlen = msg.msg_namelen;
		if (*addrlen < 0 || *addrlen > sizeof(struct sockaddr_storage))
			return -EINVAL;
		if (*addrlen) {
			memcpy(addr, &address, *addrlen);
		}
	}

	return ret;
}

/*
 * sock callback functions
 */

/* data available on socket, or listen socket received a connect */
static void mc_worker_data_ready(struct sock *sk, int unused)
{
	conn *c = sk->sk_user_data;

	PRINFO("data_ready %p state=%d", c, sk->sk_state);

	if (sk->sk_state != TCP_CLOSE_WAIT) {
		mc_queue_conn(c);
	}
}

/* socket has buffer space for writing */
static void mc_worker_write_space(struct sock *sk)
{
	conn *c = sk->sk_user_data;

	PRINFO("mc_worker_write_space on %p state=%d", c, sk->sk_state);

	if (sk->sk_state != TCP_CLOSE_WAIT) {
		mc_queue_conn(c);
	}

	/* since we have our own write_space, clear the SOCK_NOSPACE flag */
	clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
}

/* socket's state has changed */
static void mc_worker_state_change(struct sock *sk)
{
	conn *c = sk->sk_user_data;

	PRINFO("mc_worker_state_change on %p state=%d", c, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		mc_queue_conn(c);
		break;
	case TCP_ESTABLISHED:
		mc_queue_conn(c);
		break;
	}
}

/*
 * set up socket callbacks
 */
static void set_sock_callbacks(struct socket *sock, conn *c)
{
	struct sock *sk = sock->sk;

	sk->sk_user_data    = (void *)c;
	sk->sk_data_ready   = mc_worker_data_ready;
	sk->sk_write_space  = mc_worker_write_space;
	sk->sk_state_change = mc_worker_state_change;
}

static inline void __queue_conn(conn *c)
{
	/* release in mc_conn_work */
	if (!mc_conn_get(c)) {
		PRINTK("mc_queue_conn %p ref count 0\n", c);
		return;
	}

	if (!queue_work_on(c->cpu, slaved, &c->work)) {
		PRINFO("mc_queue_conn %p already on queue", c);
		mc_conn_put(c);
	} else {
		PRINFO("mc_queue_conn %p", c);
	}
}

void mc_queue_conn(conn *c)
{
	if (test_bit(EV_DEAD, &c->event)) {
		PRINFO("mc_queue_conn %p ignore EV_DEAD", c);
		return;
	}

	__queue_conn(c);
}

void mc_requeue_conn(conn *c)
{
	int poll;

	if (test_bit(EV_DEAD, &c->event)) {
		PRINFO("mc_requeue_conn %p ignore EV_DEAD", c);
		return;
	}

	poll = c->sock->ops->poll(c->sock->file, c->sock, NULL);
	if (test_bit(EV_RDWR, &c->event)) {
		if (poll & CONN_READ) {
			goto queue_conn;
		} else {
			PRINFO("mc_queue_conn %p ignore EV_READ", c);
		}
	} else {
		if (poll & CONN_WRITE) {
			goto queue_conn;
		} else {
			PRINTK("mc_queue_conn %p ignore EV_WRITE\n", c);
		}
	}

	return;

queue_conn:
	__queue_conn(c);

}
