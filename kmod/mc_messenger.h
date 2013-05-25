#ifndef __MC_MESSENGER_H
#define __MC_MESSENGER_H

#include <linux/poll.h>

struct proto_operations;
struct conn_req;

struct simpbuf {
	struct buffer _buf;
	char *buf;
	char *cur;
	int len;
	int bytes;
};

struct kvecbuf {
	struct buffer _buf;
	struct kvec *iov;
	int iovsize;	/* number of elements allocated in iov[] */
	int iovused;	/* number of elements used in iov[] */
};

struct msghdrbuf {
	struct buffer _buf;
	struct msghdr *msglist;
	int msgsize;	/* number of elements allocated in msglist[] */
	int msgused;	/* number of elements used in msglist[] */
	int msgcurr;	/* element in msglist[] being transmitted now */
	int msgbytes;	/* number of bytes in current msg */
};

struct ilistbuf {
	struct buffer _buf;
	item **ilist;	/* list of items to write out */
	int isize;
	item **icurr;
	int ileft;
};

struct slistbuf {
	struct buffer _buf;
	char **suffixlist;
	int suffixsize;
	char **suffixcurr;
	int suffixleft;
};

/* socket event bit flags */
#define EV_READ		2	/* read event, not used */
#define EV_WRITE	3	/* write event, note used */
#define EV_RDWR		4	/* 1 for READ, 0 for WRITE */
#define EV_BUSY		5	/* in process */
#define EV_CLOSED	7	/* udp closed */
#define EV_DEAD		9	/* about to free */

#define CONN_READ	(POLLIN | POLLRDNORM | POLLRDBAND)
#define CONN_WRITE	(POLLOUT | POLLWRNORM | POLLWRBAND)

struct conn {
	unsigned long event;
	atomic_t nref;
	struct worker_storage *who;
	struct work_struct work;
	struct list_head list;

	struct socket *sock;
	sasl_conn_t *sasl_conn;
	bin_substate_t substate;
	conn_state_t state;
	net_transport_t transport;

	const struct proto_operations *proto_ops;
#define cn_protocol	proto_ops->proto

	struct simpbuf	_rbuf;
#define cn_rbuf		_rbuf.buf	/* read commands into */
#define cn_rcurr	_rbuf.cur	/* parse commands here */
#define cn_rsize	_rbuf.len	/* sizeof cn_rbuf */
#define cn_rbytes	_rbuf.bytes	/* sizeof of unparsed form cn_rcurr */

	struct simpbuf	_wbuf;
#define cn_wbuf		_wbuf.buf
#define cn_wcurr	_wbuf.cur
#define cn_wsize	_wbuf.len
#define cn_wbytes	_wbuf.bytes

	/* which state to go into after finishing current write */
	conn_state_t  write_and_go;
	/* free this memory after finishing writing */
	struct buffer write_and_free;

	/* when we read in an item's value, it goes here */
	char   *ritem;
	int    rlbytes;

	/* data for the nread state */

	/*
	 * item is used to hold an item structure created after reading the command
	 * line of set/add/replace commands, but before we finished reading the actual
	 * data. The data is read into ITEM_data(item) to avoid extra copying.
	 */

	/* for commands set/add/replace  */
	void   *item;

	/* data for the swallow state */
	int    sbytes; 

	/* data for the mwrite state */
	struct kvecbuf	_kvecbuf;
#define cn_iov		_kvecbuf.iov
#define cn_iovsize	_kvecbuf.iovsize
#define cn_iovused	_kvecbuf.iovused

	struct msghdrbuf _msghdrbuf;
#define cn_msglist	_msghdrbuf.msglist	
#define cn_msgsize	_msghdrbuf.msgsize
#define cn_msgused	_msghdrbuf.msgused
#define cn_msgcurr	_msghdrbuf.msgcurr
#define cn_msgbytes	_msghdrbuf.msgbytes

	struct ilistbuf _ilistbuf;
#define cn_ilist	_ilistbuf.ilist
#define cn_isize	_ilistbuf.isize
#define cn_icurr	_ilistbuf.icurr
#define cn_ileft	_ilistbuf.ileft

	struct slistbuf _slistbuf;
#define cn_suffixlist	_slistbuf.suffixlist
#define cn_suffixsize	_slistbuf.suffixsize
#define cn_suffixcurr	_slistbuf.suffixcurr
#define cn_suffixleft	_slistbuf.suffixleft

	/* for UDP clients */
	int    request_id;		/* incoming UDP request ID */
	struct sockaddr request_addr;	/* who sent the most recent request */
	size_t request_addr_size;
	unsigned char *hdrbuf;		/* udp packet headers */
	int    hdrsize;			/* number of headers' worth of space */

	u8   noreply;	/* the reply should be sent? */
	/* current stats command */
	struct buffer stats;
	size_t offset;
	size_t stats_len;

	/* binary protocol stuff */
	protocol_binary_request_header bin_header;
	u64 cas;	/* the cas to return */
	short cmd;	/* current command being processed */
	int opaque;
	int keylen;
};

extern struct kmem_cache *conn_cachep;

conn*	mc_conn_new(struct conn_req *rq);
void	mc_conn_close(conn *c);
void	mc_conn_cleanup(conn *c);
conn*	mc_conn_get(conn *c);
void	mc_conn_put(conn *c);
void	mc_queue_conn(conn *c);
void	mc_requeue_conn(conn *c);
int	update_event(conn *c, int flag);

void	worker_set_sock_callbacks(struct socket *sock, conn *c);
int	mc_recvfrom(struct socket *sock, void *buf, size_t len, int flags,
		    struct sockaddr *addr, size_t *addrlen);
int	mc_recv(struct socket *sock, void *buf, size_t len);
int	mc_send(struct socket *sock, void *buf, size_t len);
int	mc_sendmsg(struct socket *sock, struct msghdr *msg);
int	mc_s2clog(struct socket *sock, int type);

static inline int realloc_simpbuf(struct simpbuf *sbuf,
				  size_t len, size_t valid, int move)
{
	int res = 0;
	struct buffer *buf = &sbuf->_buf;

	if (move && sbuf->cur != sbuf->buf)
		memmove(sbuf->buf, sbuf->cur, sbuf->bytes);
	if (realloc_buffer(buf, len, valid, 0)) {
		res = -ENOMEM;
	} else {
		BUFFER_PTR(buf, sbuf->buf);
	}
	if (move) {
		sbuf->cur = sbuf->buf;
	}

	return res;
}

static inline int realloc_ilistbuf(struct ilistbuf *ibuf,
				   size_t len, size_t valid)
{
	int res = 0;
	struct buffer *buf = &ibuf->_buf;

	if (realloc_buffer(buf,
			   len * sizeof(item *),
			   valid * sizeof(item *),
			   0)) {
		res = -ENOMEM;
	} else {
		BUFFER_PTR(buf, ibuf->ilist);
		ibuf->isize = len;
	}

	return res;
}

static inline int realloc_slistbuf(struct slistbuf *sbuf,
				   size_t len, size_t valid)
{
	int res = 0;
	struct buffer *buf = &sbuf->_buf;

	if (realloc_buffer(buf,
			   len * sizeof(char *),
			   valid * sizeof(char *),
			   0)) {
		res = -ENOMEM;
	} else {
		BUFFER_PTR(buf, sbuf->suffixlist);
		sbuf->suffixsize = len;
	}

	return res;
}

static inline int realloc_msghdrbuf(struct msghdrbuf *mbuf,
				    size_t len, size_t valid)
{
	int res = 0;
	struct buffer *buf = &mbuf->_buf;

	if (realloc_buffer(buf,
			   len * sizeof(struct msghdr),
			   valid * sizeof(struct msghdr),
			   0)) {
		res = -ENOMEM;
	} else {
		BUFFER_PTR(buf, mbuf->msglist);
		mbuf->msgsize = len;
	}

	return res;
}

static inline int realloc_kvecbuf(struct kvecbuf *vbuf,
				  size_t len, size_t valid)
{
	int res = 0;
	struct buffer *buf = &vbuf->_buf;

	if (realloc_buffer(buf,
			   len * sizeof(struct kvec),
			   valid * sizeof(struct kvec),
			   0)) {
		res = -ENOMEM;
	} else {
		BUFFER_PTR(buf, vbuf->iov);
		vbuf->iovsize = len;
	}

	return res;
}

#endif /* __MC_MESSENGER_H */
