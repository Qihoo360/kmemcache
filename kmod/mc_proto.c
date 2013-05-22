#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "mc.h"

const struct proto_operations def_proto_ops = {
	.proto	= negotiating_prot,
};

typedef enum {
	TRANSMIT_COMPLETE,   /* all done writing */
	TRANSMIT_INCOMPLETE, /* more data remaining to write */
	TRANSMIT_SOFT_ERROR, /* can't write any more right now */
	TRANSMIT_HARD_ERROR  /* can't write (c->state is set to conn_closing) */
} transmit_result_t;

typedef enum  {
	READ_DATA_RECEIVED,
	READ_NO_DATA_RECEIVED,
	READ_ERROR,            /* an error occured (on the socket) (or client closed connection) */
	READ_MEMORY_ERROR      /* failed to allocate more memory */
} try_read_result_t;


static const char* state_text[] = {
	"conn_listening",
	"conn_new_cmd",
	"conn_waiting",
	"conn_read",
	"conn_parse_cmd",
	"conn_write",
	"conn_nread",
	"conn_swallow",
	"conn_closing",
	"conn_mwrite"
};

static const char* prot_text[] = {
	"ascii",
	"binary",
	"auto-negotiate"
};

/**
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
void conn_set_state(conn *c, conn_state_t state)
{
	if (state != c->state) {
		PVERBOSE(2, ">%p: going from %s to %s\n",
			 c, state_text[c->state],
			 state_text[state]);

		c->state = state;
	}
}

/**
 * Shrinks a connection's buffers if they're too big.  This prevents
 * periodic large "get" requests from permanently chewing lots of server
 * memory.
 *
 * This should only be called in between requests since it can wipe output
 * buffers!
 */
static void mc_conn_shrink(conn *c)
{
	if (IS_UDP(c->transport))
		return;

	if (c->cn_rsize > READ_BUF_HIGHWAT && c->cn_rbytes < DATA_BUF_SIZE) {
		realloc_simpbuf(&c->_rbuf, DATA_BUF_SIZE, DATA_BUF_SIZE, 1);
	}

	if (c->cn_isize > ITEM_LIST_HIGHWAT) {
		realloc_ilistbuf(&c->_ilistbuf, ITEM_LIST_INIT, 0);
	}

	if (c->cn_msgsize > MSG_LIST_HIGHWAT) {
		realloc_msghdrbuf(&c->_msghdrbuf, MSG_LIST_INIT, 0);
	}

	if (c->cn_iovsize > IOV_LIST_HIGHWAT) {
		realloc_kvecbuf(&c->_kvecbuf, IOV_LIST_INIT, 0);
	}
}

static inline void reset_cmd_handler(conn *c)
{
	c->cmd = -1;
	c->substate = bin_no_state;
	if(c->item != NULL) {
		mc_item_remove(c->who, c->item);
		c->item = NULL;
	}
	mc_conn_shrink(c);
	if (c->cn_rbytes > 0) {
		conn_set_state(c, conn_parse_cmd);
	} else {
		conn_set_state(c, conn_waiting);
	}
}

/*
 * adds a delta value to a numeric item.
 *
 * c     connection requesting the operation
 * it    item to adjust
 * incr  true to increment value, false to decrement
 * delta amount to adjust value by
 * buf   buffer for response string
 *
 * returns a response string to send back to the client.
 */
delta_result_t mc_do_add_delta(conn *c, const char *key,
                               size_t nkey, u8 incr,
                               s64 delta, char *buf,
                               u64 *cas, u32 hv)
{
	char *ptr;
	u64 value;
	int res;
	item *it;

	it = mc_do_item_get(key, nkey, hv);
	if (!it) {
		return DELTA_ITEM_NOT_FOUND;
	}

	if (cas != NULL && *cas != 0 && ITEM_get_cas(it) != *cas) {
		mc_do_item_remove(it);
		return DELTA_ITEM_CAS_MISMATCH;
	}

	ptr = ITEM_data(it);

	if (safe_strtoull(ptr, &value)) {
		mc_do_item_remove(it);
		return NON_NUMERIC;
	}

	if (incr) {
		value += delta;
	} else {
		if(delta > value) {
			value = 0;
		} else {
			value -= delta;
		}
	}

	spin_lock(&c->who->stats.lock);
	if (incr) {
		c->who->stats.slab_stats[it->slabs_clsid].incr_hits++;
	} else {
		c->who->stats.slab_stats[it->slabs_clsid].decr_hits++;
	}
	spin_unlock(&c->who->stats.lock);

	snprintf(buf, INCR_MAX_STORAGE_LEN, "%llu", (unsigned long long)value);
	res = strlen(buf);
	if (res + 2 > it->nbytes || atomic_read(&it->refcount) != 1) { /* need to realloc */
		item *new_it;
		new_it = mc_do_item_alloc(ITEM_key(it), it->nkey,
					  simple_strtol(ITEM_suffix(it) + 1, NULL, 10),
					  it->exptime, res + 2, hv);
		if (new_it == 0) {
			mc_do_item_remove(it);
			return EOM;
		}
		memcpy(ITEM_data(new_it), buf, res);
		memcpy(ITEM_data(new_it) + res, "\r\n", 2);
		mc_item_replace(it, new_it, hv);

		/* 
		 * Overwrite the older item's CAS with our new CAS since we're
		 * returning the CAS of the old item below.
		 */
		ITEM_set_cas(it, (settings.use_cas) ? ITEM_get_cas(new_it) : 0);
		mc_do_item_remove(new_it);       /* release our reference */
	} else { /* replace in-place */
		/* When changing the value without replacing the item, we
		 * need to update the CAS on the existing item. */
		mutex_lock(&cache_lock); /* FIXME */
		ITEM_set_cas(it, (settings.use_cas) ? mc_get_cas_id() : 0);
		mutex_unlock(&cache_lock);

		memcpy(ITEM_data(it), buf, res);
		memset(ITEM_data(it) + res, ' ', it->nbytes - res - 2);
		mc_do_item_update(it);
	}

	if (cas) {
		*cas = ITEM_get_cas(it);    /* swap the incoming CAS value */
	}
	mc_do_item_remove(it);         /* release our reference */
	return OK;
}

/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. In threaded mode, this is protected by the cache lock.
 *
 * Returns the state of storage.
 */
store_item_t mc_do_store_item(item *it, int comm, conn* c, u32 hv)
{
	int flags;
	char *key = ITEM_key(it);
	item *old_it, *new_it = NULL;
	store_item_t stored = NOT_STORED;

	old_it = mc_do_item_get(key, it->nkey, hv);
	if (old_it != NULL && comm == NREAD_ADD) {
		/* add only adds a nonexistent item, but promote to head of LRU */
		mc_do_item_update(old_it);
	} else if (!old_it && (comm == NREAD_REPLACE
			    || comm == NREAD_APPEND
			    || comm == NREAD_PREPEND)) {
		/* replace only replaces an existing value; don't store */
	} else if (comm == NREAD_CAS) {
		/* validate cas operation */
		if(old_it == NULL) {
			// LRU expired
			stored = NOT_FOUND;
			spin_lock(&c->who->stats.lock);
			c->who->stats.cas_misses++;
			spin_unlock(&c->who->stats.lock);
		} else if (ITEM_get_cas(it) == ITEM_get_cas(old_it)) {
			// cas validates
			// it and old_it may belong to different classes.
			// I'm updating the stats for the one that's getting pushed out
			spin_lock(&c->who->stats.lock);
			c->who->stats.slab_stats[old_it->slabs_clsid].cas_hits++;
			spin_unlock(&c->who->stats.lock);

			mc_item_replace(old_it, it, hv);
			stored = STORED;
		} else {
			spin_lock(&c->who->stats.lock);
			c->who->stats.slab_stats[old_it->slabs_clsid].cas_badval++;
			spin_unlock(&c->who->stats.lock);

			PVERBOSE(1, "CAS:  failure: expected %llu, got %llu\n",
				 (unsigned long long)ITEM_get_cas(old_it),
				 (unsigned long long)ITEM_get_cas(it));

			stored = EXISTS;
		}
	} else {
		/*
		 * Append - combine new and old record into single one. Here it's
		 * atomic and thread-safe.
		 */
		if (comm == NREAD_APPEND || comm == NREAD_PREPEND) {
			//Validate CAS
			if (ITEM_get_cas(it) != 0) {
				// CAS much be equal
				if (ITEM_get_cas(it) != ITEM_get_cas(old_it)) {
					stored = EXISTS;
				}
			}

			if (stored == NOT_STORED) {
				/* we have it and old_it here - alloc memory to hold both */
				/* flags was already lost - so recover them from ITEM_suffix(it) */

				flags = (int)simple_strtol(ITEM_suffix(old_it), (char **) NULL, 10);

				new_it = mc_do_item_alloc(key, it->nkey, flags,
							  old_it->exptime,
							  it->nbytes + old_it->nbytes - 2 /* CRLF */,
							  hv);
				if (new_it == NULL) {
					/* SERVER_ERROR out of memory */
					if (old_it != NULL)
						mc_do_item_remove(old_it);

					return NOT_STORED;
				}

				/* copy data from it and old_it to new_it */

				if (comm == NREAD_APPEND) {
					memcpy(ITEM_data(new_it), ITEM_data(old_it), old_it->nbytes);
					memcpy(ITEM_data(new_it) + old_it->nbytes - 2 /* CRLF */, ITEM_data(it), it->nbytes);
				} else {
					/* NREAD_PREPEND */
					memcpy(ITEM_data(new_it), ITEM_data(it), it->nbytes);
					memcpy(ITEM_data(new_it) + it->nbytes - 2 /* CRLF */, ITEM_data(old_it), old_it->nbytes);
				}

				it = new_it;
			}
		}

		if (stored == NOT_STORED) {
			if (old_it != NULL)
				mc_item_replace(old_it, it, hv);
			else
				mc_do_item_link(it, hv);

			c->cas = ITEM_get_cas(it);

			stored = STORED;
		}
	}

	if (old_it != NULL)
		mc_do_item_remove(old_it);         /* release our reference */
	if (new_it != NULL)
		mc_do_item_remove(new_it);

	if (stored == STORED) {
		c->cas = ITEM_get_cas(it);
	}

	return stored;
}

void mc_append_stat(const char *name, add_stat_fn f,
		    conn *c, const char *fmt, ...)
{
	char val_str[STAT_VAL_LEN];
	int vlen;
	va_list ap;

	va_start(ap, fmt);
	vlen = vsnprintf(val_str, sizeof(val_str) - 1, fmt, ap);
	va_end(ap);

	f(name, strlen(name), val_str, vlen, c);
}

static int grow_stats_buf(conn *c, size_t needed)
{
	int ret = 0;
	size_t nsize, available;

	/* No buffer -- need to allocate fresh */
	if (c->stats.flags == BUF_NEGATIVE) {
		nsize = 1024;
		available = c->offset = 0;
	} else {
		nsize = c->stats_len;
		available = nsize - c->offset;
	}

	while (needed > available) {
		nsize = nsize << 1;
		available = nsize - c->offset;
	}

	if (c->stats.flags == BUF_NEGATIVE) {
		ret = alloc_buffer(&c->stats, nsize, 0);
	} else if (nsize != c->stats_len) {
		ret = realloc_buffer(&c->stats, nsize, c->stats_len, 0);
	}
	if (!ret) {
		c->stats_len = nsize;
	}
	return ret;
}

void mc_append_stats(const char *key, const u16 klen, const char *val,
		     u32 vlen, const void *cookie)
{
	conn *c;

	/* value without a key is invalid */
	if (klen == 0 && vlen > 0) {
		return ;
	}

	c = (conn*)cookie;

	if (c->cn_protocol == binary_prot) {
		size_t needed = vlen + klen + sizeof(protocol_binary_response_header);
		if (grow_stats_buf(c, needed)) {
			return ;
		}
		c->proto_ops->append_stats(key, klen, val, vlen, c);
	} else {
		size_t needed = vlen + klen + 10; // 10 == "STAT = \r\n"
		if (grow_stats_buf(c, needed)) {
			return ;
		}
		c->proto_ops->append_stats(key, klen, val, vlen, c);
	}
}

void mc_stat_settings(add_stat_fn f, void *c)
{
	APPEND_STAT("maxbytes", "%llu", settings.maxbytes);
	APPEND_STAT("maxconns", "%d", settings.maxconns);
	APPEND_STAT("tcpport", "%d", settings.port);
	APPEND_STAT("udpport", "%d", settings.udpport);
	APPEND_STAT("verbosity", "%d", settings.verbose);
	APPEND_STAT("oldest", "%lu", (unsigned long)settings.oldest_live);
	APPEND_STAT("evictions", "%s", settings.evict_to_free ? "on" : "off");
	APPEND_STAT("umask", "%o", settings.access);
	APPEND_STAT("growth_factor_numerator", "%d", settings.factor_numerator);
	APPEND_STAT("growth_factor_denominator", "%d", settings.factor_denominator);
	APPEND_STAT("chunk_size", "%d", settings.chunk_size);
	APPEND_STAT("num_threads", "%d", settings.num_threads);
	APPEND_STAT("num_threads_per_udp", "%d", settings.num_threads_per_udp);
	APPEND_STAT("stat_key_prefix", "%c", settings.prefix_delimiter);
	APPEND_STAT("detail_enabled", "%s",
		settings.detail_enabled ? "yes" : "no");
	APPEND_STAT("reqs_per_event", "%d", settings.reqs_per_event);
	APPEND_STAT("cas_enabled", "%s", settings.use_cas ? "yes" : "no");
	APPEND_STAT("tcp_backlog", "%d", settings.backlog);
	APPEND_STAT("binding_protocol", "%s",
		prot_text[settings.binding_protocol]);
	APPEND_STAT("auth_enabled_sasl", "%s", settings.sasl ? "yes" : "no");
	APPEND_STAT("item_size_max", "%d", settings.item_size_max);
	APPEND_STAT("maxconns_fast", "%s", settings.maxconns_fast ? "yes" : "no");
	APPEND_STAT("hashpower_init", "%d", settings.hashpower_init);
	APPEND_STAT("slab_reassign", "%s", settings.slab_reassign ? "yes" : "no");
	APPEND_STAT("slab_automove", "%d", settings.slab_automove);
}

/* return server specific stats only */
void mc_server_stats(add_stat_fn f, conn *c)
{
	pid_t pid = current->pid;
	rel_time_t now = current_time;
	struct stats _stats;
	struct slab_stats slab_stats;
	struct thread_stats *thread_stats;

	thread_stats = kmalloc(sizeof(*thread_stats), GFP_KERNEL);
	if (!thread_stats) {
		PRINTK("alloc thread_stats temp error\n");
		return;
	}

	mc_threadlocal_stats_aggregate(thread_stats);
	mc_slab_stats_aggregate(thread_stats, &slab_stats);

	spin_lock(&stats_lock);
	memcpy(&_stats, &stats, sizeof(_stats));
	spin_unlock(&stats_lock);

	APPEND_STAT("pid", "%lu", (long)pid);
	APPEND_STAT("uptime", "%u", now);
	APPEND_STAT("time", "%ld", now + (long)process_started);
	APPEND_STAT("version", "%s", VERSION);
	APPEND_STAT("pointer_size", "%d", (int)(8 * sizeof(void *)));

	APPEND_STAT("curr_connections", "%u", _stats.curr_conns - 1);
	APPEND_STAT("total_connections", "%u", _stats.total_conns);
	if (settings.maxconns_fast) {
		APPEND_STAT("rejected_connections", "%llu",
			    (unsigned long long)_stats.rejected_conns);
	}
	APPEND_STAT("connection_structures", "%u", _stats.conn_structs);
	APPEND_STAT("cmd_get", "%llu", (unsigned long long)thread_stats->get_cmds);
	APPEND_STAT("cmd_set", "%llu", (unsigned long long)slab_stats.set_cmds);
	APPEND_STAT("cmd_flush", "%llu", (unsigned long long)thread_stats->flush_cmds);
	APPEND_STAT("cmd_touch", "%llu", (unsigned long long)thread_stats->touch_cmds);
	APPEND_STAT("get_hits", "%llu", (unsigned long long)slab_stats.get_hits);
	APPEND_STAT("get_misses", "%llu", (unsigned long long)thread_stats->get_misses);
	APPEND_STAT("delete_misses", "%llu", (unsigned long long)thread_stats->delete_misses);
	APPEND_STAT("delete_hits", "%llu", (unsigned long long)slab_stats.delete_hits);
	APPEND_STAT("incr_misses", "%llu", (unsigned long long)thread_stats->incr_misses);
	APPEND_STAT("incr_hits", "%llu", (unsigned long long)slab_stats.incr_hits);
	APPEND_STAT("decr_misses", "%llu", (unsigned long long)thread_stats->decr_misses);
	APPEND_STAT("decr_hits", "%llu", (unsigned long long)slab_stats.decr_hits);
	APPEND_STAT("cas_misses", "%llu", (unsigned long long)thread_stats->cas_misses);
	APPEND_STAT("cas_hits", "%llu", (unsigned long long)slab_stats.cas_hits);
	APPEND_STAT("cas_badval", "%llu", (unsigned long long)slab_stats.cas_badval);
	APPEND_STAT("touch_hits", "%llu", (unsigned long long)slab_stats.touch_hits);
	APPEND_STAT("touch_misses", "%llu", (unsigned long long)thread_stats->touch_misses);
	APPEND_STAT("auth_cmds", "%llu", (unsigned long long)thread_stats->auth_cmds);
	APPEND_STAT("auth_errors", "%llu", (unsigned long long)thread_stats->auth_errors);
	APPEND_STAT("bytes_read", "%llu", (unsigned long long)thread_stats->bytes_read);
	APPEND_STAT("bytes_written", "%llu", (unsigned long long)thread_stats->bytes_written);
	APPEND_STAT("limit_maxbytes", "%llu", (unsigned long long)settings.maxbytes);
	APPEND_STAT("accepting_conns", "%u", _stats.accepting_conns);
	APPEND_STAT("listen_disabled_num", "%llu", (unsigned long long)_stats.listen_disabled_num);
	APPEND_STAT("threads", "%d", settings.num_threads);
	APPEND_STAT("conn_yields", "%llu", (unsigned long long)thread_stats->conn_yields);
	APPEND_STAT("hash_power_level", "%u", _stats.hash_power_level);
	APPEND_STAT("hash_bytes", "%llu", (unsigned long long)_stats.hash_bytes);
	APPEND_STAT("hash_is_expanding", "%u", _stats.hash_is_expanding);
	if (settings.slab_reassign) {
		APPEND_STAT("slab_reassign_running", "%u", _stats.slab_reassign_running);
		APPEND_STAT("slabs_moved", "%llu", _stats.slabs_moved);
	}

	kfree(thread_stats);
}

void mc_out_string(conn *c, const char *str, size_t len)
{
	if (c->noreply) {
		PVERBOSE(1, ">%p NOREPLY %s\n", c, str);
		c->noreply = 0;
		conn_set_state(c, conn_new_cmd);
		return;
	}

	PVERBOSE(1, ">%p %s\n", c, str);

	/* Nuke a partial output... */
	c->cn_msgcurr = 0;
	c->cn_msgused = 0;
	c->cn_iovused = 0;
	mc_add_msghdr(c);

	if (len + 2 > c->cn_wsize) {
		/* ought to be always enough. just fail for simplicity */
		str = s2c_msg[MSG_SER_LNGOUT];
		len = s2c_len[MSG_SER_LNGOUT];
	}

	memcpy(c->cn_wbuf, str, len);
	memcpy(c->cn_wbuf + len, "\r\n", 2);
	c->cn_wbytes = len + 2;
	c->cn_wcurr = c->cn_wbuf;

	conn_set_state(c, conn_write);
	c->write_and_go = conn_new_cmd;
}

/* set up a conn to write a buffer then free it, used for stats */
void write_and_free(conn *c, struct buffer *buf, int bytes)
{
	if (bytes > 0 && buf && buf->flags != BUF_NEGATIVE) {
		memcpy(&c->write_and_free, buf, sizeof(*buf));
		c->cn_wcurr = (char *)BUFFER(buf);
		c->cn_wbytes = bytes;
		conn_set_state(c, conn_write);
		c->write_and_go = conn_new_cmd;
	} else {
		OSTRING(c, MSG_SER_OOM_STAT);
	}
}

/**
 * Ensures that there is room for another struct iovec in a connection's
 * iov list.
 *
 * Returns 0 on success, -ENOMEM on out-of-memory.
 */
static int ensure_iov_space(conn *c)
{
	if (c->cn_iovused >= c->cn_iovsize) {
		int i, iovnum;

		if (realloc_kvecbuf(&c->_kvecbuf,
				    c->cn_iovsize * 2,
				    c->cn_iovsize)) {
			return -ENOMEM;
		}

		/* Point all the msghdr structures at the new list. */
		for (i = 0, iovnum = 0; i < c->cn_msgused; i++) {
			c->cn_msglist[i].msg_iov = (struct iovec *)&c->cn_iov[iovnum];
			iovnum += c->cn_msglist[i].msg_iovlen;
		}
	}

	return 0;
}

/*
 * Constructs a set of UDP headers and attaches them to the outgoing messages.
 */
int mc_build_udp_headers(conn *c)
{
	int i;
	unsigned char *hdr;

	if (c->cn_msgused > c->hdrsize) {
		void *new_hdrbuf;
		if (c->hdrbuf) {
			new_hdrbuf = krealloc(c->hdrbuf,
					      c->cn_msgused * 2 * UDP_HEADER_SIZE,
					      GFP_KERNEL);
		} else {
			new_hdrbuf = kmalloc(c->cn_msgused * 2 * UDP_HEADER_SIZE,
					     GFP_KERNEL);
		}
		if (! new_hdrbuf)
			return -ENOMEM;
		c->hdrbuf = (unsigned char *)new_hdrbuf;
		c->hdrsize = c->cn_msgused * 2;
	    }

	hdr = c->hdrbuf;
	for (i = 0; i < c->cn_msgused; i++) {
		c->cn_msglist[i].msg_iov[0].iov_base = (void*)hdr;
		c->cn_msglist[i].msg_iov[0].iov_len = UDP_HEADER_SIZE;
		*hdr++ = c->request_id / 256;
		*hdr++ = c->request_id % 256;
		*hdr++ = i / 256;
		*hdr++ = i % 256;
		*hdr++ = c->cn_msgused / 256;
		*hdr++ = c->cn_msgused % 256;
		*hdr++ = 0;
		*hdr++ = 0;
	}

    return 0;
}

/*
 * Adds a message header to a connection.
 *
 * Returns 0 on success, -ENOMEM on out-of-memory.
 */
int mc_add_msghdr(conn *c)
{
	struct msghdr *msg;

	if (c->cn_msgsize == c->cn_msgused) {
		if (realloc_msghdrbuf(&c->_msghdrbuf,
				      c->cn_msgsize * 2,
				      c->cn_msgsize)) {
			return -ENOMEM;
		}
	}

	msg = c->cn_msglist + c->cn_msgused;

	/* this wipes msg_iovlen, msg_control, msg_controllen, and msg_flags */
	memset(msg, 0, sizeof(struct msghdr));

	msg->msg_iov = (struct iovec *)&c->cn_iov[c->cn_iovused];

	if (c->request_addr_size > 0) {
		msg->msg_name = &c->request_addr;
		msg->msg_namelen = c->request_addr_size;
	}

	c->cn_msgbytes = 0;
	c->cn_msgused++;

	if (IS_UDP(c->transport)) {
		/* Leave room for the UDP header, which we'll fill in later. */
		return mc_add_iov(c, NULL, UDP_HEADER_SIZE);
	}

	return 0;
}

/**
 * Adds data to the list of pending data that will be written out to a
 * connection.
 *
 * Returns 0 on success, -ENOMEM on out-of-memory.
 */
int mc_add_iov(conn *c, const void *buf, int len)
{
	struct msghdr *m;
	int leftover;
	int limit_to_mtu;

	do {
		m = &c->cn_msglist[c->cn_msgused - 1];

		/*
		 * Limit UDP packets, and the first payloads of TCP replies, to
		 * UDP_MAX_PAYLOAD_SIZE bytes.
		 */
		limit_to_mtu = IS_UDP(c->transport) || (1 == c->cn_msgused);

		/* We may need to start a new msghdr if this one is full. */
		if (m->msg_iovlen == UIO_MAXIOV ||
		    (limit_to_mtu && c->cn_msgbytes >= UDP_MAX_PAYLOAD_SIZE)) {
			mc_add_msghdr(c);
			m = &c->cn_msglist[c->cn_msgused - 1];
		}

		if (ensure_iov_space(c))
			return -ENOMEM;

		/* If the fragment is too big to fit in the datagram, split it up */
		if (limit_to_mtu && len + c->cn_msgbytes > UDP_MAX_PAYLOAD_SIZE) {
			leftover = len + c->cn_msgbytes - UDP_MAX_PAYLOAD_SIZE;
			len -= leftover;
		} else {
			leftover = 0;
		}

		m = &c->cn_msglist[c->cn_msgused - 1];
		m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;
		m->msg_iov[m->msg_iovlen].iov_len = len;

		c->cn_msgbytes += len;
		c->cn_iovused++;
		m->msg_iovlen++;

		buf = ((char *)buf) + len;
		len = leftover;
	} while (leftover > 0);

	return 0;
}

/*
 * if we have a complete line in the buffer, process it.
 */
static int try_read_command(conn *c)
{
	if (c->cn_protocol == negotiating_prot || c->transport == udp_transport)  {
		if ((unsigned char)c->cn_rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ) {
			c->proto_ops = &bin_proto_ops;
		} else {
			c->proto_ops = &txt_proto_ops;
		}

		PVERBOSE(1, ">%p: client using the %s protocol\n",
			 c, prot_text[c->cn_protocol]);
	}

	if (c->cn_protocol == binary_prot) {
		protocol_binary_request_header* req;

		/* Do we have the complete packet header? */
		if (c->cn_rbytes < sizeof(c->bin_header)) {
			/* need more data! */
			return 0;
		} else {
#ifdef NEED_ALIGN
			if (((long)(c->cn_rcurr)) % 8 != 0) {
				/* must realign input buffer */
				memmove(c->cn_rbuf, c->cn_rcurr, c->cn_rbytes);
				c->cn_rcurr = c->cn_rbuf;
				PVERBOSE(1, ">%p: realign input buffer\n", c);

			}
#endif
			req = (protocol_binary_request_header*)c->cn_rcurr;

#ifdef CONFIG_VERBOSE
			if (settings.verbose > 1) {
				/* Dump the packet before we convert it to host order */
				int i;
				PRINTK("<%p read binary protocol data:\n", c);
				for (i = 0; i < sizeof(req->bytes); ++i) {
					if (i % 4 == 0) {
						printk("<%p   ", c);
					}
					printk(" 0x%02x", req->bytes[i]);
				}
				printk("\n");
			}
#endif

			c->bin_header = *req;
			c->bin_header.request.keylen = ntohs(req->request.keylen);
			c->bin_header.request.bodylen = ntohl(req->request.bodylen);
			c->bin_header.request.cas = ntohll(req->request.cas);

			if (c->bin_header.request.magic != PROTOCOL_BINARY_REQ) {
				PVERBOSE(0, "invalid magic:  %x\n", c->bin_header.request.magic);
				conn_set_state(c, conn_closing);
				return -EFAULT;
			}

			c->cn_msgcurr = 0;
			c->cn_msgused = 0;
			c->cn_iovused = 0;
			if (mc_add_msghdr(c)) {
				OSTRING(c, MSG_SER_OOM);
				return -EFAULT;
			}

			c->cmd = c->bin_header.request.opcode;
			c->keylen = c->bin_header.request.keylen;
			c->opaque = c->bin_header.request.opaque;
			/* clear the returned cas value */
			c->cas = 0;

			c->proto_ops->dispatch(c, NULL);

			c->cn_rbytes -= sizeof(c->bin_header);
			c->cn_rcurr += sizeof(c->bin_header);
		}
	} else {
		char *el, *cont;

		if (c->cn_rbytes == 0)
			return 0;

		el = memchr(c->cn_rcurr, '\n', c->cn_rbytes);
		if (!el) {
			if (c->cn_rbytes > 1024) {
				/*
				 * We didn't have a '\n' in the first k. This _has_ to be a
				 * large multiget, if not we should just nuke the connection.
				 */
				char *ptr = c->cn_rcurr;
				while (*ptr == ' ') { /* ignore leading whitespaces */
					++ptr;
				}

				if (ptr - c->cn_rcurr > 100 ||
				    (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {

					conn_set_state(c, conn_closing);
					return 1;
				}
			}

			return 0;
		}

		cont = el + 1;
		if ((el - c->cn_rcurr) > 1 && *(el - 1) == '\r') {
			el--;
		}
		*el = '\0';

		c->proto_ops->dispatch(c, c->cn_rcurr);

		c->cn_rbytes -= (cont - c->cn_rcurr);
		c->cn_rcurr = cont;
	}

	return 1;
}

/*
 * read a UDP request.
 */
static try_read_result_t try_read_udp(conn *c)
{
	int res;

	c->request_addr_size = sizeof(c->request_addr);
	res = mc_recvfrom(c->sock, c->cn_rbuf, c->cn_rsize,
			  0, &c->request_addr, &c->request_addr_size);
	if (res > 8) {
		unsigned char *buf = (unsigned char *)c->cn_rbuf;
		spin_lock(&c->who->stats.lock);
		c->who->stats.bytes_read += res;
		spin_unlock(&c->who->stats.lock);

		/* Beginning of UDP packet is the request ID; save it. */
		c->request_id = buf[0] * 256 + buf[1];

		/* If this is a multi-packet request, drop it. */
		if (buf[4] != 0 || buf[5] != 1) {
			OSTRING(c, MSG_SER_MUL_PACK);
			return READ_NO_DATA_RECEIVED;
		}

		/* Don't care about any of the rest of the header. */
		res -= 8;
		memmove(c->cn_rbuf, c->cn_rbuf + 8, res);

		c->cn_rbytes = res;
		c->cn_rcurr = c->cn_rbuf;
		return READ_DATA_RECEIVED;
	}

	return READ_NO_DATA_RECEIVED;
}

/**
 * read from network as much as we can, handle buffer overflow and
 * connection close.
 * before reading, move the remaining incomplete fragment of a command
 * (if any) to the beginning of the buffer.
 *
 * To protect us from someone flooding a connection with bogus data causing
 * the connection to eat up all available memory, break out and start looking
 * at the data I've got after a number of reallocs...
 *
 * Return try_read_result_t
 */
static try_read_result_t try_read_network(conn *c)
{
	try_read_result_t gotdata = READ_NO_DATA_RECEIVED;
	int res, avail;
	int num_allocs = 0;

	if (c->cn_rcurr != c->cn_rbuf) {
		if (c->cn_rbytes != 0) /* otherwise there's nothing to copy */
			memmove(c->cn_rbuf, c->cn_rcurr, c->cn_rbytes);
		c->cn_rcurr = c->cn_rbuf;
	}

	while (1) {
		if (c->cn_rbytes >= c->cn_rsize) {
			if (num_allocs == 4) {
				return gotdata;
			}
			++num_allocs;
			res = realloc_simpbuf(&c->_rbuf, c->cn_rsize * 2, c->cn_rsize, 0);
			if (res) {
				PVERBOSE(0, "couldn't realloc input buffer\n");
				c->cn_rbytes = 0; /* ignore what we read */
				OSTRING(c, MSG_SER_OOM_RREQ);
				c->write_and_go = conn_closing;
				return READ_MEMORY_ERROR;
			}
			c->cn_rcurr = c->cn_rbuf;
		}

		avail = c->cn_rsize - c->cn_rbytes;
		res = mc_recv(c->sock, c->cn_rbuf + c->cn_rbytes, avail);
		if (res > 0) {
			spin_lock(&c->who->stats.lock);
			c->who->stats.bytes_read += res;
			spin_unlock(&c->who->stats.lock);
			gotdata = READ_DATA_RECEIVED;
			c->cn_rbytes += res;
			if (res == avail) {
				continue;
			} else {
				break;
			}
		}
		if (res == 0) {
			return READ_ERROR;
		}
		if (res < 0) {
			if (res == -EAGAIN || res == -EWOULDBLOCK) {
				break;
			}
			return READ_ERROR;
		}
	}

	return gotdata;
}

/**
 * Transmit the next chunk of data from our list of msgbuf structures.
 *
 * Returns:
 *   TRANSMIT_COMPLETE   All done writing.
 *   TRANSMIT_INCOMPLETE More data remaining to write.
 *   TRANSMIT_SOFT_ERROR Can't write any more right now.
 *   TRANSMIT_HARD_ERROR Can't write (c->state is set to conn_closing)
 */
static transmit_result_t transmit(conn *c)
{
	if (c->cn_msgcurr < c->cn_msgused &&
	    c->cn_msglist[c->cn_msgcurr].msg_iovlen == 0) {
		/* Finished writing the current msg; advance to the next. */
		c->cn_msgcurr++;
	}

	if (c->cn_msgcurr < c->cn_msgused) {
		ssize_t res;
		struct msghdr *m = &c->cn_msglist[c->cn_msgcurr];

		res = mc_sendmsg(c->sock, m);
		if (res > 0) {
			spin_lock(&c->who->stats.lock);
			c->who->stats.bytes_written += res;
			spin_unlock(&c->who->stats.lock);

			/* 
			 * We've written some of the data. Remove the completed
			 * iovec entries from the list of pending writes.
			 */
			while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) {
				res -= m->msg_iov->iov_len;
				m->msg_iovlen--;
				m->msg_iov++;
			}

			/* 
			 * Might have written just part of the last iovec entry;
			 * adjust it so the next write will do the rest.
			 */
			if (res > 0) {
				m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
				m->msg_iov->iov_len -= res;
			}
			return TRANSMIT_INCOMPLETE;
		}
		if (res < 0 && (res == -EAGAIN || res == -EWOULDBLOCK)) {
			if (update_event(c, EV_WRITE)) {
				PVERBOSE(0, "couldn't update event\n");
				conn_set_state(c, conn_closing);
				return TRANSMIT_HARD_ERROR;
			}
			return TRANSMIT_SOFT_ERROR;
		}

		/*
		 * if res == 0 or res <0(not EAGAIN or EWOULDBLOCK),
		 * we have a real error, on which we close the connection
		 */
		PVERBOSE(0, "failed to write, and not due to blocking\n");

		if (IS_UDP(c->transport))
			conn_set_state(c, conn_read);
		else
			conn_set_state(c, conn_closing);
		return TRANSMIT_HARD_ERROR;
	} else {
		return TRANSMIT_COMPLETE;
	}
}

void mc_worker_machine(conn *c)
{
	int stop = 0;
	int nreqs = settings.reqs_per_event;
	int res = 0;

more:
	switch(c->state) {
	case conn_listening:
		stop = 1;
		break;
	case conn_waiting:
		if (update_event(c, EV_READ)) {
			PVERBOSE(0, "couldn't update event\n");
			conn_set_state(c, conn_closing);
			break;
		}

		conn_set_state(c, conn_read);
		stop = true;
		break;

	case conn_read:
		res = IS_UDP(c->transport) ?
		      try_read_udp(c) :
		      try_read_network(c);

		switch (res) {
		case READ_NO_DATA_RECEIVED:
			conn_set_state(c, conn_waiting);
			break;
		case READ_DATA_RECEIVED:
			conn_set_state(c, conn_parse_cmd);
			break;
		case READ_ERROR:
			conn_set_state(c, conn_closing);
			break;
		case READ_MEMORY_ERROR:
			/* 
			 * failed to allocate more memory,
			 * state already set by try_read_network
			 */
			break;
		default:
			break;
		}
		break;

	case conn_parse_cmd :
		if (try_read_command(c) == 0) {
			/* need more data! */
			conn_set_state(c, conn_waiting);
		}

		break;

	case conn_new_cmd:
		/* only process nreqs at a time to avoid starving other connections */
		--nreqs;
		if (nreqs >= 0) {
			reset_cmd_handler(c);
		} else {
			spin_lock(&c->who->stats.lock);
			c->who->stats.conn_yields++;
			spin_unlock(&c->who->stats.lock);

			if (c->cn_rbytes > 0) {
				if (update_event(c, EV_WRITE)) {
					PVERBOSE(0, "couldn't update event\n");
					conn_set_state(c, conn_closing);
				}
			}
			stop = true;
		}
		break;

	case conn_nread:
		if (c->rlbytes == 0) {
			c->proto_ops->complete_nread(c);
			break;
		}
		/* first check if we have leftovers in the conn_read buffer */
		if (c->cn_rbytes > 0) {
			int tocopy = c->cn_rbytes > c->rlbytes
				   ? c->rlbytes : c->cn_rbytes;
			if (c->ritem != c->cn_rcurr) {
				memmove(c->ritem, c->cn_rcurr, tocopy);
			}
			c->ritem += tocopy;
			c->rlbytes -= tocopy;
			c->cn_rcurr += tocopy;
			c->cn_rbytes -= tocopy;
			if (c->rlbytes == 0)
				break;
		}

		/*  now try reading from the socket */
		res = mc_recv(c->sock, c->ritem, c->rlbytes);
		if (res > 0) {
			spin_lock(&c->who->stats.lock);
			c->who->stats.bytes_read += res;
			spin_unlock(&c->who->stats.lock);

			if (c->cn_rcurr == c->ritem) {
				c->cn_rcurr += res;
			}
			c->ritem += res;
			c->rlbytes -= res;
			break;
		}
		if (res == 0) {
			/* end of stream */
			conn_set_state(c, conn_closing);
			break;
		}
		if (res <0 && (res == -EAGAIN || res == -EWOULDBLOCK)) {
			if (update_event(c, EV_READ)) {
				PVERBOSE(0, "Couldn't update event\n");
				conn_set_state(c, conn_closing);
				break;
			}
			stop = true;
			break;
		}
		/* otherwise we have a real error, on which we close the connection */
		PVERBOSE(0,"failed to read, and not due to blocking:"
			 "errno: %d cn_rcurr=%lx ritem=%lx rbuf=%lx rlbytes=%d cn_rsize=%d\n",
			 -res, (long)c->cn_rcurr, (long)c->ritem, (long)c->cn_rbuf,
			 (int)c->rlbytes, (int)c->cn_rsize);

		conn_set_state(c, conn_closing);
		break;

	case conn_swallow:
		/* we are reading sbytes and throwing them away */
		if (c->sbytes == 0) {
			conn_set_state(c, conn_new_cmd);
			break;
		}

		/* first check if we have leftovers in the conn_read buffer */
		if (c->cn_rbytes > 0) {
			int tocopy = c->cn_rbytes > c->sbytes ? c->sbytes : c->cn_rbytes;
			c->sbytes -= tocopy;
			c->cn_rcurr += tocopy;
			c->cn_rbytes -= tocopy;
			break;
		}

		/*  now try reading from the socket */
		res = mc_recv(c->sock, c->cn_rbuf,
			      c->cn_rsize > c->sbytes ? c->sbytes : c->cn_rsize);
		if (res > 0) {
			spin_lock(&c->who->stats.lock);
			c->who->stats.bytes_read += res;
			spin_unlock(&c->who->stats.lock);
			c->sbytes -= res;
			break;
		}
		if (res == 0) {
			/* end of stream */
			conn_set_state(c, conn_closing);
			break;
		}
		if (res < 0 && (res == -EAGAIN || res == -EWOULDBLOCK)) {
			if (update_event(c, EV_READ )) {
				PVERBOSE(0, "Couldn't update event\n");
				conn_set_state(c, conn_closing);
				break;
			}
			stop = true;
			break;
		}
		/* otherwise we have a real error, on which we close the connection */
		PVERBOSE(0, "failed to read, and not due to blocking\n");
		conn_set_state(c, conn_closing);
		break;

	case conn_write:
		/*
		 * We want to write out a simple response. If we haven't already,
		 * assemble it into a msgbuf list (this will be a single-entry
		 * list for TCP or a two-entry list for UDP).
		 */
		if (c->cn_iovused == 0 || (IS_UDP(c->transport) && c->cn_iovused == 1)) {
			if (mc_add_iov(c, c->cn_wcurr, c->cn_wbytes) != 0) {
				PVERBOSE(0, "couldn't build response\n");
				conn_set_state(c, conn_closing);
				break;
			}
		}

		/* fall through... */

	case conn_mwrite:
		if (IS_UDP(c->transport) &&
		    c->cn_msgcurr == 0 &&
		    mc_build_udp_headers(c) != 0) {
			PVERBOSE(0, "failed to build UDP headers\n");
			conn_set_state(c, conn_closing);
			break;
		}
		switch (transmit(c)) {
		case TRANSMIT_COMPLETE:
			if (c->state == conn_mwrite) {
				while (c->cn_ileft > 0) {
					item *it = *(c->cn_icurr);
					mc_item_remove(c->who, it);
					c->cn_icurr++;
					c->cn_ileft--;
				}
				while (c->cn_suffixleft > 0) {
					char *suffix = *(c->cn_suffixcurr);
					_suffix_free(suffix);
					c->cn_suffixcurr++;
					c->cn_suffixleft--;
				}
				/* XXX:  I don't know why this wasn't the general case */
				if(c->cn_protocol == binary_prot) {
					conn_set_state(c, c->write_and_go);
				} else {
					conn_set_state(c, conn_new_cmd);
				}
			} else if (c->state == conn_write) {
				if (c->write_and_free.flags != BUF_NEGATIVE) {
					free_buffer(&c->write_and_free);
					c->write_and_free.flags = BUF_NEGATIVE;
				}
				conn_set_state(c, c->write_and_go);
			} else {
				PVERBOSE(0, "unexpected state %d\n", c->state);
				conn_set_state(c, conn_closing);
			}
			break;

		case TRANSMIT_INCOMPLETE:
		case TRANSMIT_HARD_ERROR:
			break;                   /* Continue in state machine. */

		case TRANSMIT_SOFT_ERROR:
			stop = true;
			break;
		}
		break;

	case conn_closing:
		if (IS_UDP(c->transport))
			mc_conn_cleanup(c);
		else {
			mc_conn_close(c);
			mc_conn_put(c);
		}
		stop = true;
		break;

	case conn_max_state:
		break;
	}

	if (!stop) goto more;
}
