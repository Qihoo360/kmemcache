#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/workqueue.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <asm/system.h>

#include "mc.h"

/* dispatcher master */
struct dispatcher_master {
#define ACCEPT_NEW	1
#define SOCK_CLOSE	2
	unsigned long flags;

	struct list_head list;		/* tcp/unix socket list */
	spinlock_t lock;

	struct workqueue_struct *wq;
};

static struct dispatcher_master dsper;

/* dispatcher listen socket */
struct serve_sock {
	net_transport_t transport;
	unsigned long state;		/* conn state */
	struct socket *sock;		/* listen socket */
	struct list_head list;		/* link to master's listen list */
	struct work_struct work;
};

static void mc_listen_work(struct work_struct *work);

static inline struct serve_sock* __alloc_serve_sock(net_transport_t trans)
{
	struct serve_sock *ss;

	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss) {
		PRINTK("alloc serve sock error\n");
		goto out;
	}
	ss->transport = trans;
	INIT_LIST_HEAD(&ss->list);
	INIT_WORK(&ss->work, mc_listen_work);

out:
	return ss;
}

static inline void __free_serve_sock(struct serve_sock *ss)
{
	kfree(ss);
}

void mc_accept_new_conns(int enable)
{
	struct serve_sock *ss;

	if (enable && test_bit(ACCEPT_NEW, &dsper.flags))
		return;
	if (enable) {
		set_bit(ACCEPT_NEW, &dsper.flags);
		spin_lock(&stats_lock);
		stats.accepting_conns = 1;
		spin_unlock(&stats_lock);
	} else {
		clear_bit(ACCEPT_NEW, &dsper.flags);

		spin_lock(&stats_lock);
		stats.accepting_conns = 0;
		stats.listen_disabled_num++;
		spin_unlock(&stats_lock);
	}

	spin_lock(&dsper.lock);
	list_for_each_entry(ss, &dsper.list, list) {
		int backlog = enable ? settings.backlog : 0;
		if (kernel_listen(ss->sock, backlog)) {
			PRINTK("mc_accept_new_conns listen error\n");
		}
	}
	spin_unlock(&dsper.lock);
}

/*
 * sock callback functions for accepted socket
 */

/* data available on socket, or listen socket received a connect */
static void mc_anon_data_ready(struct sock *sk, int unused)
{
	PRINFO("mc_anon_data_ready state=%d", sk->sk_state);
}

/* socket has buffer space for writing */
static void mc_anon_write_space(struct sock *sk)
{
	PRINFO("mc_anon_write_space state=%d", sk->sk_state);
}

/* socket's state has changed */
static void mc_anon_state_change(struct sock *sk)
{
	PRINFO("mc_anon_state_change state=%d", sk->sk_state);
}

static inline void set_anon_sock_callbacks(struct socket *sock)
{
	struct sock *sk = sock->sk;

	sk->sk_user_data    = NULL;
	sk->sk_data_ready   = mc_anon_data_ready;
	sk->sk_write_space  = mc_anon_write_space;
	sk->sk_state_change = mc_anon_state_change;
}

static inline int set_sock_nodelay(struct socket *sock)
{
	int ret, val = 1;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ret = sock->ops->setsockopt(sock, SOL_TCP, TCP_NODELAY,
				    (char __user *)&val, sizeof(val));

	set_fs(old_fs);

	return ret;
}

static int mc_accept_one(struct serve_sock *ss)
{
	int ret = 0;
	struct socket *nsock;
	struct socket *sock = ss->sock;

	ret = sock_create_lite(sock->sk->sk_family, sock->sk->sk_type,
			       sock->sk->sk_protocol, &nsock);
	if (ret < 0)
		goto out;

	nsock->type = sock->type;
	nsock->ops = sock->ops;
	ret = sock->ops->accept(sock, nsock, O_NONBLOCK);
	if (ret < 0)
		goto sock_release;

	nsock->sk->sk_allocation = GFP_ATOMIC;
	set_anon_sock_callbacks(nsock);
	if (likely(ss->transport == tcp_transport)) {
		ret = set_sock_nodelay(nsock);
		if (ret < 0)
			goto sock_release;
	}

	if (settings.maxconns_fast &&
	    stats.curr_conns >= settings.maxconns - 1) {
		if (mc_s2clog(nsock, MSG_SYS_CONNS)) {
			PRINTK("serve sends connection msg error\n");
		}
		spin_lock(&stats_lock);
		stats.rejected_conns++;
		spin_unlock(&stats_lock);
		goto err_out;
	} else {
		ret = mc_dispatch_conn_new(nsock, conn_new_cmd,
					   DATA_BUF_SIZE, ss->transport);
		if (unlikely(ret))
			goto err_out;
	}

out:
	return ret;
err_out:
	nsock->ops->shutdown(nsock, SHUT_RDWR);
sock_release:
	sock_release(nsock);

	goto out;
}

static void mc_listen_work(struct work_struct *work)
{
	struct serve_sock *ss =
		container_of(work, struct serve_sock, work);

	/* accept many */;
	for (; !test_bit(SOCK_CLOSE, &dsper.flags);) {
		if (mc_accept_one(ss))
			break;
	}
}

static void inline _queue(struct serve_sock *ss)
{
	if (!test_bit(ACCEPT_NEW, &dsper.flags)) {
		PRINFO("server don't accept new socket");
		return;
	}

	queue_work(dsper.wq, &ss->work);
}

/*
 * sock callback functions
 */

/* data available on socket, or listen socket received a connect */
static void mc_disp_data_ready(struct sock *sk, int unused)
{
	struct serve_sock *ss =
		(struct serve_sock *)sk->sk_user_data;

	PRINFO("mc_disp_data_ready state=%d", sk->sk_state);

	if (sk->sk_state == TCP_LISTEN)
		_queue(ss);
}

/* socket has buffer space for writing */
static void mc_disp_write_space(struct sock *sk)
{
	PRINFO("mc_disp_write_space state=%d", sk->sk_state);
}

/* socket's state has changed */
static void mc_disp_state_change(struct sock *sk)
{
	PRINFO("mc_disp_state_change state=%d", sk->sk_state);
}

static void set_sock_callbacks(struct socket *sock, struct serve_sock *ss)
{
	struct sock *sk = sock->sk;

	write_lock_bh(&sk->sk_callback_lock);

	sk->sk_user_data    = ss;
	sk->sk_data_ready   = mc_disp_data_ready;
	sk->sk_write_space  = mc_disp_write_space;
	sk->sk_state_change = mc_disp_state_change;

	write_unlock_bh(&sk->sk_callback_lock);
}

static int _log_socket_port(struct file *filp, const char *buf, size_t count)
{
	int ret = 0;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_write(filp, buf, count, &filp->f_pos);
	set_fs(old_fs);

	return (ret >= 0 ? 0 : ret);
}

static int log_socket_port(struct socket *sock, net_transport_t trans, struct file *filp)
{
	int ret = 0;
	char log[50];
	union {
		struct sockaddr_in  in;
		struct sockaddr_in6 in6;
	} addr;
	int addrlen = sizeof(addr);

	if (!filp)
		return 0;

	ret = kernel_getsockname(sock, (struct sockaddr *)&addr, &addrlen);
	if (ret) {
		PRINTK("kernel_getsockname error\n");
		goto out;
	}

	memset(log, 0, sizeof(log));
	if (sock->sk->sk_family == AF_INET) {
		snprintf(log, 50, "%s INET: %u\n",
			 IS_UDP(trans) ? "UDP" : "TCP",
			 ntohs(addr.in.sin_port));
	} else {
		snprintf(log, 50, "%s INET6: %u\n",
			 IS_UDP(trans) ? "UDP" : "TCP",
			 ntohs(addr.in6.sin6_port));
	}

	ret = _log_socket_port(filp, log, strlen(log));
out:
	return ret;
}

/**
 * Sets a socket's send buffer size to the maximum allowed by the system.
 */
static int maximize_sendbuf(struct socket *sock)
{
	int ret = 0;
	int old_size;
	int intsize = sizeof(old_size);
	int min, max, avg, last_good = 0;

	if ((ret = kernel_getsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				    (char *)&old_size, &intsize))) {
		PRINTK("kernel_getsockopt(SO_SNDBUF) error\n");
		goto out;
	}

	min = old_size;
	max = MAX_SENDBUF_SIZE;

	while (min <= max) {
		avg = ((unsigned int)(min + max)) / 2;
		if (!kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				       (char *)&avg, intsize)) {
			last_good = avg;
			min = avg + 1;
		} else {
			max = avg -1;
		}
	}

	PVERBOSE(1, "server socket send buffer : %d/%d\n", old_size, last_good);
out:
	return ret;
}

static int server_socket_inet(sock_entry_t *se, struct file *filp)
{
	int ret = 0;
	int flags = 1, level, name;
	struct serve_sock *ss;
	struct linger ling = {0, 0};

	ss = __alloc_serve_sock(se->trans);
	if (!ss) {
		PRINTK("alloc server socket error\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = sock_create_kern(se->family, se->type, se->protocol, &ss->sock);
	if (ret < 0) {
		PRINTK("create server socket error(%d), "
		       "family=%d, type=%d, protocol=%d\n",
		       ret, se->family, se->type, se->protocol);
		goto free_sock;
	}

	if (!IS_UDP(se->trans)) {
		ss->sock->sk->sk_allocation = GFP_ATOMIC;
		set_sock_callbacks(ss->sock, ss);
	}

	if (se->family == AF_INET6) {
		ret = kernel_setsockopt(ss->sock, IPPROTO_IPV6, IPV6_V6ONLY,
				(char *)&flags, sizeof(flags));
		if (ret < 0) {
			level = IPPROTO_IPV6;
			name = IPV6_V6ONLY;
			goto set_opt_err;
		}
	}
	ret = kernel_setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&flags, sizeof(flags));
	if (ret < 0) {
		level = SOL_SOCKET;
		name = SO_REUSEADDR;
		goto set_opt_err;
	}

	if (IS_UDP(se->trans)) {
		ret = maximize_sendbuf(ss->sock);
		if (ret < 0) {
			level = SOL_SOCKET;
			name = SO_SNDBUF;
			goto set_opt_err;
		}
	} else {
		ret = kernel_setsockopt(ss->sock, SOL_SOCKET, SO_KEEPALIVE,
				(char *)&flags, sizeof(flags));
		if (ret < 0) {
			level = SOL_SOCKET;
			name = SO_KEEPALIVE;
			goto set_opt_err;
		}

		ret = kernel_setsockopt(ss->sock, SOL_SOCKET, SO_LINGER,
				(char *)&ling, sizeof(ling));
		if (ret < 0) {
			level = SOL_SOCKET;
			name = SO_LINGER;
			goto set_opt_err;
		}

		ret = kernel_setsockopt(ss->sock, IPPROTO_TCP, TCP_NODELAY,
				(char *)&flags, sizeof(flags));
		if (ret < 0) {
			level = IPPROTO_TCP;
			name = TCP_NODELAY;
			goto set_opt_err;
		}

	}

	ret = kernel_bind(ss->sock, (struct sockaddr *)se->addr, se->addrlen);
	if (ret < 0) {
		PRINTK("bind server socket error\n");
		goto release_sock;
	}

	if (!IS_UDP(se->trans)) {
		ret = kernel_listen(ss->sock, settings.backlog);
		if (ret < 0) {
			PRINTK("listen server socket error\n");
			goto release_sock;
		}
	}

	if (se->family == AF_INET || se->family == AF_INET6) {
		ret = log_socket_port(ss->sock, ss->transport, filp);
		if (ret < 0) {
			PRINTK("log server socket port error\n");
			goto release_sock;
		}
	}

	if (IS_UDP(se->trans)) {
		static int last_cpu = -1;
		int cpu, res = 0;

		if (settings.num_threads_per_udp == 1) {
			last_cpu = (last_cpu + 1) % num_online_cpus();
			ret = mc_dispatch_conn_udp(ss->sock, conn_read,
						   UDP_READ_BUF_SIZE, last_cpu);
			if (!ret) res++;
		} else {
			for_each_online_cpu(cpu) {
				ret = mc_dispatch_conn_udp(ss->sock, conn_read,
							   UDP_READ_BUF_SIZE,
							   cpu);
				if (!ret) res++;
			}
		}

		if (res) {
			ret = 0;
			goto free_sock;
		} else {
			ret = -EFAULT;
			PRINTK("dispatch udp socket error\n");
			goto release_sock;
		}
	} else {
		spin_lock(&dsper.lock);
		list_add_tail(&ss->list, &dsper.list);
		spin_unlock(&dsper.lock);
	}

out:
	return ret;

set_opt_err:
	PRINTK("set server socket option (level=%d, name=%d) error\n", level, name);
release_sock:
	sock_release(ss->sock);
free_sock:
	__free_serve_sock(ss);

	goto out;
}

#define VALID_TRANS(x) ((x) == tcp_transport || (x) == udp_transport)

static char* parse_port_file(char *data, int len)
{
	char *end = data + len;
	int selen = sizeof(sock_entry_t);
	sock_entry_t *se = (sock_entry_t *)data;

	if (*(end - 1) != '\0')
		return NULL;

	do {
		if (VALID_TRANS(se->trans)) {
			data += selen + se->addrlen;
			se = (sock_entry_t *)data;
		}
		if (!VALID_TRANS(se->trans)) {
			break;
		}
	} while (data + selen + se->addrlen <= end);

	if (data >= end || VALID_TRANS(se->trans))
		return NULL;

	return data;
}

static int server_inet_init(void)
{
	int success = 0;
	char *path, *data = sock_info->data;
	int selen = sizeof(sock_entry_t);
	sock_entry_t *se = (sock_entry_t *)data;
	struct file *filp = NULL;

	if (sock_info->flags & PORT_FILE) {
		path = parse_port_file(sock_info->data, sock_info->len);
		if (!path) {
			PRINTK("parse socket port file error\n");
			goto out;
		}
		filp = filp_open(path, O_RDWR | O_APPEND | O_CREAT,
				 S_IRUGO | S_IWUGO);
		if (IS_ERR(filp)) {
			PRINTK("open socket port file error\n");
			goto out;
		}
	} else {
		path = data + sock_info->len;
	}

	for (; data + selen + se->addrlen <= path;) {
		if (VALID_TRANS(se->trans) &&
		    !server_socket_inet(se, filp)) {
			success++;
		}
		data += selen + se->addrlen;
		se = (sock_entry_t *)data;
	}

	if (filp) {
		filp_close(filp, NULL);
	}

out:
	return (success ? 0 : -EFAULT);
}

static int unlink_socket_file(const char *name)
{
	int ret = 0;

	struct path path;

	if (!name) {
		PRINTK("unix socket path arg error\n");
		ret = -EINVAL;
		goto out;
	}
	if (strlen(name) + 1 > UNIX_PATH_MAX) {
		PRINTK("unix socket path too long\n");
		ret = -EINVAL;
		goto out;
	}
	if (kern_path(name, LOOKUP_FOLLOW, &path)) {
		PRINTK("parse unix socket path error\n");
		ret = -EINVAL;
		goto out;
	}
	if (path.dentry->d_inode && S_ISSOCK(path.dentry->d_inode->i_mode)) {
		if ((ret = mnt_want_write(path.mnt))) {
			PRINTK("access permission error\n");
			goto put;
		}
		if ((ret = vfs_unlink(path.dentry->d_parent->d_inode, path.dentry))) {
			PRINTK("delete unix socket file error\n");
		}
		mnt_drop_write(path.mnt);
	}

put:
	path_put(&path);
out:
	return ret;
}

static int server_socket_unix(const char *path, int mask)
{
	int ret = 0;
	int flags = 1;
	struct linger ling = {0, 0};
	struct sockaddr_un addr;
	struct serve_sock *ss;

	if ((ret = unlink_socket_file(path))) {
		PRINTK("unlink unix socket file error\n");
		goto out;
	}

	ss = __alloc_serve_sock(local_transport);
	if (!ss) {
		PRINTK("alloc unix socket error\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = sock_create_kern(AF_UNIX, SOCK_STREAM, 0, &ss->sock);
	if (ret < 0) {
		PRINTK("create unix socket error\n");
		goto free_sock;
	}

	ss->sock->sk->sk_allocation = GFP_ATOMIC;
	set_sock_callbacks(ss->sock, ss);

	ret += kernel_setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&flags, sizeof(flags));
	ret += kernel_setsockopt(ss->sock, SOL_SOCKET, SO_KEEPALIVE,
			(char *)&flags, sizeof(flags));
	ret += kernel_setsockopt(ss->sock, SOL_SOCKET, SO_LINGER,
			(char *)&ling, sizeof(ling));
	if (ret < 0) {
		PRINTK("set unix socket option error\n");
		goto release_sock;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	mask = xchg(&current->fs->umask, ~(mask & S_IRWXUGO));
	ret = kernel_bind(ss->sock, (struct sockaddr *)&addr, sizeof(addr) - 1);
	if (ret < 0) {
		PRINTK("bind unix socket error\n");
		(void)xchg(&current->fs->umask, mask);
		goto release_sock;
	}
	(void)xchg(&current->fs->umask, mask);

	ret = kernel_listen(ss->sock, settings.backlog);
	if (ret < 0) {
		PRINTK("listen unix socket error\n");
		goto release_sock;
	}

	spin_lock(&dsper.lock);
	list_add_tail(&ss->list, &dsper.list);
	spin_unlock(&dsper.lock);

out:
	return ret;

release_sock:
	sock_release(ss->sock);
free_sock:
	__free_serve_sock(ss);

	goto out;
}

static int server_init(void)
{
	int ret = 0;

	BUG_ON(!sock_info);

	if (sock_info->flags & UNIX_SOCK) {
		ret = server_socket_unix((char *)sock_info->data,
					 settings.access);
	} else {
		ret = server_inet_init();
	}

	kfree(sock_info);
	sock_info = NULL;
	return ret;
}

static void server_exit(void)
{
	struct serve_sock *ss, *n;

	mc_accept_new_conns(0);

	spin_lock(&dsper.lock);
	list_for_each_entry_safe(ss, n, &dsper.list, list) {
		set_bit(SOCK_CLOSE, &ss->state);
		flush_work(&ss->work);
		ss->sock->ops->shutdown(ss->sock, SHUT_RDWR);
		sock_release(ss->sock);
		ss->sock = NULL;
		list_del(&ss->list);
		__free_serve_sock(ss);
	}
	spin_unlock(&dsper.lock);
}

/**
 * init dispatcher.
 * create the shared dispatcher kthread and start listen socket
 *
 * Returns 0 on success, error code other wise.
 */
int dispatcher_init(void)
{
	int ret = 0;

	INIT_LIST_HEAD(&dsper.list);
	spin_lock_init(&dsper.lock);

	dsper.wq = create_singlethread_workqueue("kmcmasterd");
	if (!dsper.wq) {
		PRINTK("create dispatcher kthread error\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = server_init();
	if (ret) {
		destroy_workqueue(dsper.wq);
	} else {
		set_bit(ACCEPT_NEW, &dsper.flags);
	}

out:
	return ret;
}

void dispatcher_exit(void)
{
	BUG_ON(list_empty(&dsper.list));
	server_exit();
	BUG_ON(!list_empty(&dsper.list));
	destroy_workqueue(dsper.wq);
}
