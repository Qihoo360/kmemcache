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

#include "mc.h"

struct dispatcher_thread dispatcher;
struct kmem_cache *listen_cachep;

void mc_accept_new_conns(int enable)
{
	struct serve_sock *ss;

	if (enable && test_bit(ACCEPT_NEW, &dispatcher.flags))
		return;

	spin_lock(&dispatcher.lock);
	list_for_each_entry(ss, &dispatcher.list, list) {
		int backlog = enable ? settings.backlog : 0;
		if (kernel_listen(ss->sock, backlog)) {
			PRINTK("mc_accept_new_conns listen error");
		}
	}
	spin_unlock(&dispatcher.lock);

	if (enable) {
		set_bit(ACCEPT_NEW, &dispatcher.flags);
		spin_lock(&stats_lock);
		stats.accepting_conns = 1;
		spin_unlock(&stats_lock);
	} else {
		clear_bit(ACCEPT_NEW, &dispatcher.flags);

		spin_lock(&stats_lock);
		stats.accepting_conns = 0;
		stats.listen_disabled_num++;
		spin_unlock(&stats_lock);
	}
}

static void mc_sock_work(struct work_struct *work)
{
	int ret = 0;
	struct socket *nsock;
	struct serve_sock *ss =
		(container_of(work, struct server_work, work))->ss;

	ret = kernel_accept(ss->sock, &nsock, O_NONBLOCK);
	if (ret) {
		if (ret == -EMFILE) {
			if (settings.verbose > 0) {
				PRINTK("too many open connections");
			}
			mc_accept_new_conns(0);
			cancel_work_sync(work);
		}
		PRINTK("accept new socket error");
		return;
	}

	if (settings.maxconns_fast &&
	    stats.curr_conns >= settings.maxconns - 1) {
		static char *str = "ERROR Too many open connections\r\n";

		if (mc_send(nsock, str, strlen(str))) {
			PRINTK("serve sends connection msg error");
		}
		goto err_out;
	} else {
		static char *str = "ERROR System heavy overload\r\n";

		ret = mc_dispatch_conn_new(nsock, conn_new_cmd,
					   DATA_BUF_SIZE, ss->transport);
		if (unlikely(ret)) {
			if (mc_send(nsock, str, strlen(str))) {
				PRINTK("serve sends connection msg error");
			}
			goto err_out;
		}
	}

	return;
err_out:
	nsock->ops->shutdown(nsock, SHUT_RDWR);
	sock_release(nsock);

	spin_lock(&stats_lock);
	stats.rejected_conns++;
	spin_unlock(&stats_lock);
	return;
}

static void inline _queue(struct serve_sock *ss)
{
	if (!test_bit(ACCEPT_NEW, &dispatcher.flags)) {
		PRINFO("server don't accept new socket");
		return;
	}
	if (test_bit(conn_closing, &ss->state)) {
		PRINTK("server socket closing");
		return;
	}
#ifdef CONFIG_LISTEN_CACHE
	{
		struct server_work *sw =
			kmem_cache_alloc(listen_cachep, GFP_ATOMIC);
		if (!sw) {
			PRINTK(" alloc new work_struct error");
			return;
		}
		sw->ss = ss;
		INIT_WORK(&sw->work, mc_sock_work);
		queue_work(dispatcher.wq, &sw->work);
	}
#else
	{
		if (!queue_work(dispatcher.wq, &ss->work)) {
			PRINTK(" a new socket already queued");
		}
	}
#endif
}

/*
 * sock callback functions
 */

/* data available on socket, or listen socket received a connect */
static void mc_disp_data_ready(struct sock *sk, int unused)
{
	struct serve_sock *ss = 
		(struct serve_sock *)sk->sk_user_data;
	if (sk->sk_state == TCP_LISTEN)
		_queue(ss);
	PRINFO("mc_disp_data_ready");
}

/* socket has buffer space for writing */
static void mc_disp_write_space(struct sock *sk)
{
	PRINFO("mc_disp_write_space");
}

/* socket's state has changed */
static void mc_disp_state_change(struct sock *sk)
{
	PRINFO("mc_disp_state_change");
}

static void set_sock_callbacks(struct socket *sock,
			       struct serve_sock *ss)
{
	struct sock *sk = sock->sk;

	sk->sk_user_data    = ss;
	sk->sk_data_ready   = mc_disp_data_ready;
	//sk->sk_write_space  = mc_disp_write_space;
	//sk->sk_state_change = mc_disp_state_change;
}

static int INIT _log_socket_port(struct file *filp, const char *buf, size_t count)
{
	int ret = 0;
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_write(filp, buf, count, &filp->f_pos);
	set_fs(old_fs);

	return (ret >= 0 ? 0 : ret);
}

static int INIT log_socket_port(struct socket *sock, net_transport_t trans,
				struct file *filp)
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
		PRINTK("kernel_getsockname error");
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
static int INIT maximize_sendbuf(struct socket *sock)
{
	return 0;
/*
	int ret = 0;
	int old_size;
	int intsize = sizeof(old_size);
	int min, max, avg, last_good = 0;

	if ((ret = kernel_getsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				    (char *)&old_size, &intsize))) {
		PRINTK("kernel_getsockopt(SO_SNDBUF) error");
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

	if (settings.verbose > 1)
		PRINTK("server socket send buffer : %d/%d", old_size, last_good);
out:
	return ret;
*/
}

static int INIT server_socket_inet(sock_entry_t *se, struct file *filp)
{
	int ret = 0;
	int flags = 1;
	struct serve_sock *ss;
	struct linger ling = {0, 0};

	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss) {
		PRINTK("alloc server socket error");
		ret = -ENOMEM;
		goto out;
	}
	ss->transport = se->trans;
	INIT_LIST_HEAD(&ss->list);
	INIT_WORK(&ss->work, mc_sock_work);

	if ((ret = sock_create_kern(se->family, se->type,
				    se->protocol, &ss->sock))) {
		PRINTK("create server socket error");
		goto free_sock;
	}
	if (!IS_UDP(se->trans)) {
		set_sock_callbacks(ss->sock, ss);
	}

	if ((se->family == AF_INET6 &&
	    kernel_setsockopt(ss->sock, IPPROTO_IPV6, IPV6_V6ONLY,
		    	      (char *)&flags, sizeof(flags))) ||
	    kernel_setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR,
		    	      (char *)&flags, sizeof(flags))) {
		PRINTK("set server socket option error");
		ret = -EIO;
		goto release_sock;
	}
	if (IS_UDP(se->trans)) {
		ret = maximize_sendbuf(ss->sock);
		if (ret)
			goto release_sock;
	} else {
		if (kernel_setsockopt(ss->sock, SOL_SOCKET, SO_KEEPALIVE,
				      (char *)&flags, sizeof(flags)) ||
		    kernel_setsockopt(ss->sock, SOL_SOCKET, SO_LINGER,
			    	      (char *)&ling, sizeof(ling)) ||
		    kernel_setsockopt(ss->sock, IPPROTO_TCP, TCP_NODELAY,
			    	      (char *)&flags, sizeof(flags))) {
			PRINTK("set server socket option error");
			ret = -EIO;
			goto release_sock;
		}
	}

	if ((ret = kernel_bind(ss->sock, (struct sockaddr *)se->addr,
			       se->addrlen))) {
		PRINTK("bind server socket error");
		goto release_sock;
	}

	if (!IS_UDP(se->trans)) {
		ret = kernel_listen(ss->sock, settings.backlog);
		if (ret) {
			PRINTK("listen server socket error");
			goto release_sock;
		}
	}

	if (se->family == AF_INET || se->family == AF_INET6) {
		ret = log_socket_port(ss->sock, ss->transport, filp);
		if (ret) {
			PRINTK("log server socket port error");
			goto release_sock;
		}
	}

	if (IS_UDP(se->trans)) {
		int i, res = 0;

		for (i = 0; i < settings.num_threads_per_udp; i++) {
			res = mc_dispatch_conn_new(ss->sock, conn_read,
						   UDP_READ_BUF_SIZE,
						   ss->transport);
			if (res) {
				PRINTK("dispatch udp conn error");
			} else {
				ret++;
			}
		}

		if (ret) {
			ret = 0;
			list_add(&ss->list, &dispatcher.udp_list);
		} else {
			ret = -EFAULT;
			sock_release(ss->sock);
			kfree(ss);
		}
	} else {
		spin_lock(&dispatcher.lock);
		list_add_tail(&ss->list, &dispatcher.list);
		spin_unlock(&dispatcher.lock);
	}

	return ret;

release_sock:
	sock_release(ss->sock);
free_sock:
	kfree(ss);
out:
	return ret;
}

static int INIT unlink_socket_file(const char *path)
{
	int ret = 0;
	struct nameidata nd;
	struct dentry *dentry;

	if (!path) {
		PRINTK("unix socket path arg error");
		ret = -EINVAL;
		goto out;
	}
	if (strlen(path) + 1 > UNIX_PATH_MAX) {
		PRINTK("unix socket path too long");
		ret = -EINVAL;
		goto out;
	}
	if (path_lookup(path, LOOKUP_PARENT, &nd)) {
		PRINTK("parse unix socket path error");
		ret = -EINVAL;
		goto out;
	}
	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_one_len(nd.last.name, nd.path.dentry, nd.last.len);
	if (IS_ERR(dentry)) {
		PRINTK("open unix socket path error");
		ret = -EINVAL;
		goto out_unlock;
	}
	if (dentry->d_inode && S_ISSOCK(dentry->d_inode->i_mode)) {
		if ((ret = mnt_want_write(nd.path.mnt))) {
			PRINTK("access permission error");
			goto put_dentry;
		}
		if ((ret = vfs_unlink(nd.path.dentry->d_inode, dentry))) {
			PRINTK("delete unix socket file error");
		}
		mnt_drop_write(nd.path.mnt);
	}

put_dentry:
	dput(dentry);
out_unlock:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
out:
	return ret;
}

static int INIT server_socket_unix(const char *path, int access_mask)
{
	int ret = 0;
	int flags = 1;
	struct linger ling = {0, 0};
	struct sockaddr_un addr;
	struct serve_sock *ss;

	if ((ret = unlink_socket_file(path))) {
		PRINTK("unlink unix socket file error");
		goto out;
	}

	ss = kzalloc(sizeof(*ss), GFP_KERNEL);
	if (!ss) {
		PRINTK("alloc unix socket error");
		ret = -ENOMEM;
		goto out;
	}
	ss->transport = local_transport;
	INIT_LIST_HEAD(&ss->list);
	INIT_WORK(&ss->work, mc_sock_work);

	if ((ret = sock_create_kern(AF_UNIX, SOCK_STREAM, 0, &ss->sock))) {
		PRINTK("create unix socket error");
		goto free_sock;
	}
	set_sock_callbacks(ss->sock, ss);
	if (kernel_setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR,
			      (char *)&flags, sizeof(flags)) ||
	    kernel_setsockopt(ss->sock, SOL_SOCKET, SO_KEEPALIVE,
		    	      (char *)&flags, sizeof(flags)) ||
	    kernel_setsockopt(ss->sock, SOL_SOCKET, SO_LINGER,
		    	      (char *)&ling, sizeof(ling))) {
		PRINTK("set unix socket option error");
		ret = -EIO;
		goto release_sock;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	access_mask = xchg(&current->fs->umask, ~(access_mask & S_IRWXUGO));
	if ((ret = kernel_bind(ss->sock, (struct sockaddr *)&addr,
			       sizeof(addr) - 1))) {
		PRINTK("bind unix socket error");
		xchg(&current->fs->umask, access_mask);
		goto release_sock;
	}
	xchg(&current->fs->umask, access_mask);
	if ((ret = kernel_listen(ss->sock, settings.backlog))) {
		PRINTK("listen unix socket error");
		goto release_sock;
	}

	spin_lock(&dispatcher.lock);
	list_add_tail(&ss->list, &dispatcher.list);
	spin_unlock(&dispatcher.lock);

	return 0;

release_sock:
	sock_release(ss->sock);
free_sock:
	kfree(ss);
out:
	return ret;
}

#define VALID_TRANS(x) ((x) == tcp_transport || (x) == udp_transport)

static char* INIT parse_port_file(char *data, int len)
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
			if (VALID_TRANS(se->trans))
				continue;
		}
		break;
	} while (data + selen + se->addrlen <= end);

	if (data >= end || VALID_TRANS(se->trans))
		return NULL;

	return data;
}

int INIT server_init(void)
{
	int ret = 0;
	char *path = NULL;

	if (!sock_info) {
		PRINTK("invalid socket info");
		return -EFAULT;
	}

	if (sock_info->flags & UNIX_SOCK) {
		path = (char *)sock_info->data;
		ret = server_socket_unix(path, settings.access);
	} else {
		int success = 0;
		char *data = sock_info->data;
		int selen = sizeof(sock_entry_t);
		sock_entry_t *se = (sock_entry_t *)data;
		struct file *filp = NULL;

		if (sock_info->flags & PORT_FILE) {
			path = parse_port_file(sock_info->data, sock_info->len);
			if (!path) {
				PRINTK("parse socket port file error");
				goto out;
			}
			filp = filp_open(path, O_RDWR | O_APPEND | O_CREAT,
					 S_IRUGO | S_IWUGO);
			if (IS_ERR(filp)) {
				PRINTK("open socket port file error");
				goto out;
			}
		} else {
			path = data + sock_info->len;
		}

		for (; data + selen + se->addrlen <= path;) {
			if (VALID_TRANS(se->trans)) {
				ret = server_socket_inet(se, filp);
				if (!ret) success++;
			}
			data += selen + se->addrlen;
			se = (sock_entry_t *)data;
		}

		ret = (success ? 0 : -EFAULT);
		if (filp) {
			filp_close(filp, NULL);
		}
	}

out:
	kfree(sock_info);
	sock_info = NULL;
	return ret;
}

void server_exit(void)
{
	struct serve_sock *ss, *n;

	spin_lock(&dispatcher.lock);
	list_for_each_entry_safe(ss, n, &dispatcher.list, list) {
		set_bit(conn_closing, &ss->state);
		cancel_work_sync(&ss->work);
		ss->sock->ops->shutdown(ss->sock, SHUT_RDWR);
		sock_release(ss->sock);
		ss->sock = NULL;
		list_del(&ss->list);
		kfree(ss);
	}
	spin_unlock(&dispatcher.lock);
}

/**
 * create the dispatcher kthread.
 *
 * Returns 0 on success, error code other wise.
 */
int INIT dispatcher_init(void)
{
	int ret = 0;

	if (single_dispatch) {
		dispatcher.wq =
			create_singlethread_workqueue("mc_dispatcher");
	} else {
		dispatcher.wq =
			create_workqueue("mc_dispatcher");
	}
	if (!dispatcher.wq) {
		PRINTK("create dispatcher kthread error");
		ret = -ENOMEM;
		goto out;
	}
	set_bit(ACCEPT_NEW, &dispatcher.flags);
	INIT_LIST_HEAD(&dispatcher.list);
	INIT_LIST_HEAD(&dispatcher.udp_list);
	atomic_set(&dispatcher._workers, 0);
	init_completion(&dispatcher._comp);

out:
	return ret;
}

void dispatcher_exit(void)
{
	destroy_workqueue(dispatcher.wq);
}
