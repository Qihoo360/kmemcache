#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>

#include "mc.h"

static void bin_add_header(conn *c, u16 err, u8 hdr_len,
			   u16 key_len, u32 body_len)
{
	protocol_binary_response_header* header;

	c->cn_msgcurr = 0;
	c->cn_msgused = 0;
	c->cn_iovused = 0;
	if (mc_add_msghdr(c)) {
		/* XXX:  out_string is inappropriate here */
		OSTRING(c, MSG_SER_OOM);
		return;
	}

	header = (protocol_binary_response_header *)c->cn_wbuf;

	header->response.magic	= (u8)PROTOCOL_BINARY_RES;
	header->response.opcode = c->bin_header.request.opcode;
	header->response.keylen = (u16)htons(key_len);
	header->response.extlen = (u8)hdr_len;
	header->response.datatype = (u8)PROTOCOL_BINARY_RAW_BYTES;
	header->response.status	= (u16)htons(err);
	header->response.bodylen= htonl(body_len);
	header->response.opaque = c->opaque;
	header->response.cas	= htonll(c->cas);

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;
		PRINTK(">%s Writing bin response:", current->comm);
		for (i = 0; i < sizeof(header->bytes); ++i) {
		    if (i % 4 == 0) {
			PRINTK(">%s  ", current->comm);
		    }
		    PRINTK(" 0x%02x", header->bytes[i]);
		}
		PRINTK("\n");
	}
#endif

	mc_add_iov(c, c->cn_wbuf, sizeof(header->response));
}

static void bin_write_error(conn *c, protocol_binary_response_status err, int swallow)
{
	const char *errstr = s2c_msg[MSG_BIN_UKNW];
	size_t len = s2c_len[MSG_BIN_UKNW];

	switch (err) {
	case PROTOCOL_BINARY_RESPONSE_ENOMEM:
		errstr = s2c_msg[MSG_BIN_OOM];
		len = s2c_len[MSG_BIN_OOM];
		break;
	case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
		errstr = s2c_msg[MSG_BIN_NCMD];
		len = s2c_len[MSG_BIN_NCMD];
		break;
	case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
		errstr = s2c_msg[MSG_BIN_NFD];
		len = s2c_len[MSG_BIN_NFD];
		break;
	case PROTOCOL_BINARY_RESPONSE_EINVAL:
		errstr = s2c_msg[MSG_BIN_NARG];
		len = s2c_len[MSG_BIN_NARG];
		break;
	case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
		errstr = s2c_msg[MSG_BIN_XKEY];
		len = s2c_len[MSG_BIN_XKEY];
		break;
	case PROTOCOL_BINARY_RESPONSE_E2BIG:
		errstr = s2c_msg[MSG_BIN_LARG];
		len = s2c_len[MSG_BIN_LARG];
		break;
	case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
		errstr = s2c_msg[MSG_BIN_NNUM];
		len = s2c_len[MSG_BIN_NNUM];
		break;
	case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
		errstr = s2c_msg[MSG_BIN_NSTO];
		len = s2c_len[MSG_BIN_NSTO];
		break;
	case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
		errstr = s2c_msg[MSG_BIN_AUTH];
		len = s2c_len[MSG_BIN_AUTH];
		break;
	default:
		errstr = s2c_msg[MSG_BIN_UHND];
		len = s2c_len[MSG_BIN_UHND];
		PRINTK(">%s UNHANDLED ERROR: %d\n", current->comm, err);
		break;
	}

	PVERBOSE(1, ">%s Writing an error: %s\n", current->comm, errstr);

	bin_add_header(c, err, 0, 0, len);
	if (len > 0) {
		mc_add_iov(c, errstr, len);
	}
	conn_set_state(c, conn_mwrite);
	if(swallow > 0) {
		c->sbytes = swallow;
		c->write_and_go = conn_swallow;
	} else {
		c->write_and_go = conn_new_cmd;
	}
}

/**
 * Form and send a response to a command over the binary protocol
 */
static void bin_write_response(conn *c, void *d, int hlen, int keylen, int dlen)
{
	if (!c->noreply ||
	    c->cmd == PROTOCOL_BINARY_CMD_GET ||
	    c->cmd == PROTOCOL_BINARY_CMD_GETK) {
		bin_add_header(c, 0, hlen, keylen, dlen);
		if(dlen > 0) {
			mc_add_iov(c, d, dlen);
		}
		conn_set_state(c, conn_mwrite);
		c->write_and_go = conn_new_cmd;
	} else {
		conn_set_state(c, conn_new_cmd);
	}
}

/**
 * Get a pointer to the start of the request
 * struct for the current command.
 */
static inline void* bin_get_request(conn *c)
{
	char *ret = c->cn_rcurr;
	
	ret -= sizeof(c->bin_header)
	     + c->bin_header.request.keylen
	     + c->bin_header.request.extlen;
	
	return ret;
}

/**
 * Get a pointer to the key in this request.
 */
static inline char* bin_get_key(conn *c)
{
	return c->cn_rcurr - (c->bin_header.request.keylen);
}

static void bin_touch(conn *c)
{
	char *key;
	size_t nkey;
	rel_time_t exptime;
	item *it;
	protocol_binary_response_get* rsp;
	protocol_binary_request_touch *t;

	rsp = (protocol_binary_response_get*)c->cn_wbuf;
	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;
	t   = bin_get_request(c);
	exptime = ntohl(t->message.body.expiration);

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;
		/* May be GAT/GATQ/etc */
		PRINTK("<%s TOUCH ", current->comm);
		for (i = 0; i < nkey; ++i) {
			PRINTK("%c", key[i]);
		}
		PRINTK("\n");
	}
#endif

	it = mc_item_touch(c->who, key, nkey, realtime(exptime));
	if (it) {
		/* the length has two unnecessary bytes ("\r\n") */
		u16 keylen = 0;
		u32 bodylen = sizeof(rsp->message.body) + (it->nbytes - 2);

		mc_item_update(c->who, it);
		spin_lock(&c->who->stats.lock);
		c->who->stats.touch_cmds++;
		c->who->stats.slab_stats[it->slabs_clsid].touch_hits++;
		spin_unlock(&c->who->stats.lock);

		if (c->cmd == PROTOCOL_BINARY_CMD_TOUCH) {
			bodylen -= it->nbytes - 2;
		} else if (c->cmd == PROTOCOL_BINARY_CMD_GATK) {
			bodylen += nkey;
			keylen = nkey;
		}

		bin_add_header(c, 0, sizeof(rsp->message.body), keylen, bodylen);
		rsp->message.header.response.cas = htonll(ITEM_get_cas(it));

		// add the flags
		rsp->message.body.flags = htonl(simple_strtoul(ITEM_suffix(it),
							       NULL, 10));
		mc_add_iov(c, &rsp->message.body, sizeof(rsp->message.body));

		if (c->cmd == PROTOCOL_BINARY_CMD_GATK) {
			mc_add_iov(c, ITEM_key(it), nkey);
		}

		/* Add the data minus the CRLF */
		if (c->cmd != PROTOCOL_BINARY_CMD_TOUCH) {
			mc_add_iov(c, ITEM_data(it), it->nbytes - 2);
		}

		conn_set_state(c, conn_mwrite);
		c->write_and_go = conn_new_cmd;
		/* Remember this command so we can garbage collect it later */
		c->item = it;
	} else {
		spin_lock(&c->who->stats.lock);
		c->who->stats.touch_cmds++;
		c->who->stats.touch_misses++;
		spin_unlock(&c->who->stats.lock);

		if (c->noreply) {
			conn_set_state(c, conn_new_cmd);
		} else {
			if (c->cmd == PROTOCOL_BINARY_CMD_GATK) {
				char *ofs;
				
				ofs = c->cn_wbuf + sizeof(protocol_binary_response_header);
				bin_add_header(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,
					       0, nkey, nkey);
				memcpy(ofs, key, nkey);
				mc_add_iov(c, ofs, nkey);
				conn_set_state(c, conn_mwrite);
				c->write_and_go = conn_new_cmd;
			} else {
				bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
			}
		}
	}

	if (settings.detail_enabled) {
		mc_stats_prefix_record_get(key, nkey, NULL != it);
	}
}

static void bin_get(conn *c)
{
	char *key;
	size_t nkey;
	item *it;
	protocol_binary_response_get* rsp;
       
	rsp = (protocol_binary_response_get*)c->cn_wbuf;
	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;
		PRINTK("<%s GET ", current->comm);
		for (i = 0; i < nkey; ++i) {
			printk(" %c", key[i]);
		}
		printk("\n");
	}
#endif

	it = mc_item_get(c->who, key, nkey);
	if (it) {
		/* the length has two unnecessary bytes ("\r\n") */
		u16 keylen = 0;
		u32 bodylen = sizeof(rsp->message.body) + (it->nbytes - 2);

		mc_item_update(c->who, it);
		spin_lock(&c->who->stats.lock);
		c->who->stats.get_cmds++;
		c->who->stats.slab_stats[it->slabs_clsid].get_hits++;
		spin_unlock(&c->who->stats.lock);

		if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
			bodylen += nkey;
			keylen = nkey;
		}
		bin_add_header(c, 0, sizeof(rsp->message.body), keylen, bodylen);
		rsp->message.header.response.cas = htonll(ITEM_get_cas(it));

		// add the flags
		rsp->message.body.flags = htonl(simple_strtoul(ITEM_suffix(it),
							       NULL, 10));
		mc_add_iov(c, &rsp->message.body, sizeof(rsp->message.body));

		if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
			mc_add_iov(c, ITEM_key(it), nkey);
		}

		/* Add the data minus the CRLF */
		mc_add_iov(c, ITEM_data(it), it->nbytes - 2);
		conn_set_state(c, conn_mwrite);
		c->write_and_go = conn_new_cmd;
		/* Remember this command so we can garbage collect it later */
		c->item = it;
	} else {
		spin_lock(&c->who->stats.lock);
		c->who->stats.get_cmds++;
		c->who->stats.get_misses++;
		spin_unlock(&c->who->stats.lock);

		if (c->noreply) {
			conn_set_state(c, conn_new_cmd);
		} else {
			if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
				char *ofs;

			       	ofs = c->cn_wbuf + sizeof(protocol_binary_response_header);
				bin_add_header(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,
					       0, nkey, nkey);
				memcpy(ofs, key, nkey);
				mc_add_iov(c, ofs, nkey);
				conn_set_state(c, conn_mwrite);
				c->write_and_go = conn_new_cmd;
			} else {
				bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
			}
		}
	}

	if (settings.detail_enabled) {
		mc_stats_prefix_record_get(key, nkey, NULL != it);
	}
}

static void bin_stat(conn *c)
{
	char *subcommand;
	size_t nkey;

	subcommand = bin_get_key(c);
	nkey = c->bin_header.request.keylen;

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;
		PRINTK("<%s STATS ", current->comm);
		for (i = 0; i < nkey; ++i) {
			printk(" %c", subcommand[i]);
		}
		printk("\n");
	}
#endif

	if (nkey == 0) {
		/* request all statistics */
		mc_server_stats(&mc_append_stats, c);
		(void)mc_get_stats(NULL, 0, &mc_append_stats, c);
	} else if (!strncmp(subcommand, "reset", 5)) {
		mc_stats_reset();
	} else if (!strncmp(subcommand, "settings", 8)) {
		mc_stat_settings(&mc_append_stats, c);
	} else if (!strncmp(subcommand, "detail", 6)) {
		char *subcmd_pos;
		char *dump_buf;

		subcmd_pos = subcommand + 6;
		if (!strncmp(subcmd_pos, " dump", 5)) {
			int ret;
			DECLEARE_BUFFER(buf);

			ret = mc_stats_prefix_dump(&buf);
			if (ret < 0) {
				bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
				return ;
			} else {
				BUFFER_PTR(&buf, dump_buf);
				mc_append_stats("detailed", 8,
					        dump_buf, ret, c);
				free_buffer(&buf);
			}
		} else if (!strncmp(subcmd_pos, " on", 3)) {
			settings.detail_enabled = 1;
		} else if (!strncmp(subcmd_pos, " off", 4)) {
			settings.detail_enabled = 0;
		} else {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
			return;
		}
	} else {
		if (!mc_get_stats(subcommand, nkey, &mc_append_stats, c)) {
			if (c->stats.flags == BUF_NEGATIVE) {
				bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
			} else {
				write_and_free(c, &c->stats, c->offset);
				c->stats.flags = BUF_NEGATIVE;
			}
		} else {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
		}

		return;
	}

	/* Append termination package and start the transfer */
	mc_append_stats(NULL, 0, NULL, 0, c);
	if (c->stats.flags == BUF_NEGATIVE) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
	} else {
		write_and_free(c, &c->stats, c->offset);
		c->stats.flags = BUF_NEGATIVE;
	}
}

static void mc_init_sasl_conn(conn *c)
{
	int result;

	/* should something else be returned? */
	if (!settings.sasl)
		return;

	if (!c->sasl_conn) {
		result = mc_sasl_server_new("memcached",
					    NULL,
					    my_sasl_hostname[0] ? my_sasl_hostname : NULL,
					    NULL,
					    NULL,
					    NULL,
					    0,
					    &c->sasl_conn);
		if (result != SASL_OK) {
			PVERBOSE(0, "failed to initialize SASL conn.\n");

			c->sasl_conn = NULL;
		}
	}
}

static void bin_sasl_auth(conn *c)
{
	int nkey, vlen;
	char *key;
	item *it;

	// Guard for handling disabled SASL on the server.
	if (!settings.sasl) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,
				c->bin_header.request.bodylen
				- c->bin_header.request.keylen);
		return;
	}

	nkey = c->bin_header.request.keylen;
	vlen = c->bin_header.request.bodylen - nkey;
	if (nkey > MAX_SASL_MECH_LEN) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_EINVAL, vlen);
		c->write_and_go = conn_swallow;
		return;
	}

	key = bin_get_key(c);

	it = mc_item_alloc(key, nkey, 0, 0, vlen);
	if (!it) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
		c->write_and_go = conn_swallow;
		return;
	}

	c->item = it;
	c->ritem = ITEM_data(it);
	c->rlbytes = vlen;
	conn_set_state(c, conn_nread);
	c->substate = bin_reading_sasl_auth_data;
}

static void bin_complete_sasl_auth(conn *c)
{
	int nkey, vlen, result = 1;
	const char *challenge;
	const char *out = NULL;
	unsigned int outlen = 0;
	char *mech;

	nkey = c->bin_header.request.keylen;
	vlen = c->bin_header.request.bodylen - nkey;

	mech = (char *)kmalloc(nkey + 1, GFP_KERNEL);
	if (!mech) {
		PRINTK("bin_complete_sasl_auth error\n");
		return;
	}
	memcpy(mech, ITEM_key((item*)c->item), nkey);
	mech[nkey] = 0x00;

	PVERBOSE(0, "mech:  ``%s'' with %d bytes of data\n", mech, vlen);

	challenge = vlen == 0 ? NULL : ITEM_data((item*) c->item);

	mc_init_sasl_conn(c);

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_SASL_AUTH:
		result = mc_sasl_server_start(c->sasl_conn, mech,
					      challenge, vlen,
			   		      &out, &outlen);
		break;
	case PROTOCOL_BINARY_CMD_SASL_STEP:
		result = mc_sasl_server_step(c->sasl_conn,
					     challenge, vlen,
					     &out, &outlen);
		break;
	default:
		/* CMD should be one of the above */
		/* This code is pretty much impossible, but makes the compiler
		   happier */
		PVERBOSE(0, "unhandled command %d with challenge %s\n", c->cmd, challenge);

		break;
	}

	mc_item_unlink(c->who, c->item);

	PVERBOSE(0, "sasl result code:  %d\n", result);

	switch(result) {
	case SASL_OK:
		bin_write_response(c, "Authenticated", 0, 0, 13);
		spin_lock(&c->who->stats.lock);
		c->who->stats.auth_cmds++;
		spin_unlock(&c->who->stats.lock);
		break;
	case SASL_CONTINUE:
		bin_add_header(c, PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE, 0, 0, outlen);
		if(outlen > 0) {
			mc_add_iov(c, out, outlen);
		}
		conn_set_state(c, conn_mwrite);
		c->write_and_go = conn_new_cmd;
		break;
	default:
		PVERBOSE(0, "unknown sasl response:  %d\n", result);
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
		spin_lock(&c->who->stats.lock);
		c->who->stats.auth_cmds++;
		c->who->stats.auth_errors++;
		spin_unlock(&c->who->stats.lock);
	}

	kfree(mech);
}

static void bin_update(conn *c)
{
	char *key;
	int nkey;
	int vlen;
	item *it;
	protocol_binary_request_set* req;

	req = bin_get_request(c);
	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;

	/* fix byteorder in the request */
	req->message.body.flags = ntohl(req->message.body.flags);
	req->message.body.expiration = ntohl(req->message.body.expiration);

	vlen = c->bin_header.request.bodylen
	     - (nkey + c->bin_header.request.extlen);

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;

		if (c->cmd == PROTOCOL_BINARY_CMD_ADD) {
			printk("<%s ADD\n", current->comm);
		} else if (c->cmd == PROTOCOL_BINARY_CMD_SET) {
			printk("<%s SET\n", current->comm);
		} else {
			printk("<%s REPLACE\n", current->comm);
		}
		for (i = 0; i < nkey; i++) {
			printk("%c", key[i]);
		}

		PRINTK("value len is %d\n", vlen);
	}
#endif

	if (settings.detail_enabled) {
		mc_stats_prefix_record_set(key, nkey);
	}

	it = mc_item_alloc(key, nkey, req->message.body.flags,
			   realtime(req->message.body.expiration), vlen + 2);
	if (!it) {
		if (!mc_item_size_ok(nkey, req->message.body.flags, vlen + 2)) {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_E2BIG, vlen);
		} else {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
		}

		/* Avoid stale data persisting in cache because we failed alloc.
		 * Unacceptable for SET. Anywhere else too? */
		if (c->cmd == PROTOCOL_BINARY_CMD_SET) {
			it = mc_item_get(c->who, key, nkey);
			if (it) {
				mc_item_unlink(c->who, it);
				mc_item_remove(c->who, it);
			}
		}

		/* swallow the data line */
		c->write_and_go = conn_swallow;
		return;
	}

	ITEM_set_cas(it, c->bin_header.request.cas);

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_ADD:
		c->cmd = NREAD_ADD;
		break;
	case PROTOCOL_BINARY_CMD_SET:
		c->cmd = NREAD_SET;
		break;
	case PROTOCOL_BINARY_CMD_REPLACE:
		c->cmd = NREAD_REPLACE;
		break;
	default:
		BUG();
		break;
	}

	if (ITEM_get_cas(it) != 0) {
		c->cmd = NREAD_CAS;
	}

	c->item = it;
	c->ritem = ITEM_data(it);
	c->rlbytes = vlen;
	conn_set_state(c, conn_nread);
	c->substate = bin_read_set_value;
}

static void bin_append_prepend(conn *c)
{
	char *key;
	int nkey;
	int vlen;
	item *it;

	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;
	vlen= c->bin_header.request.bodylen - nkey;

	PVERBOSE(1, "value len is %d\n", vlen);

	if (settings.detail_enabled) {
		mc_stats_prefix_record_set(key, nkey);
	}

	it = mc_item_alloc(key, nkey, 0, 0, vlen + 2);
	if (!it) {
		if (!mc_item_size_ok(nkey, 0, vlen + 2)) {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_E2BIG, vlen);
		} else {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
		}
		/* swallow the data line */
		c->write_and_go = conn_swallow;
		return;
	}

	ITEM_set_cas(it, c->bin_header.request.cas);

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_APPEND:
		c->cmd = NREAD_APPEND;
		break;
	case PROTOCOL_BINARY_CMD_PREPEND:
		c->cmd = NREAD_PREPEND;
		break;
	default:
		BUG_ON(1);
		break;
	}

	c->item = it;
	c->ritem = ITEM_data(it);
	c->rlbytes = vlen;
	conn_set_state(c, conn_nread);
	c->substate = bin_read_set_value;
}

static void bin_flush(conn *c)
{
	rel_time_t exptime = 0;
	protocol_binary_request_flush *req;

	req = bin_get_request(c);

	if (c->bin_header.request.extlen == sizeof(req->message.body)) {
		exptime = ntohl(req->message.body.expiration);
	}

	if (exptime > 0) {
		settings.oldest_live = realtime(exptime) - 1;
	} else {
		settings.oldest_live = current_time - 1;
	}
	mc_item_flush_expired();

	spin_lock(&c->who->stats.lock);
	c->who->stats.flush_cmds++;
	spin_unlock(&c->who->stats.lock);

	bin_write_response(c, NULL, 0, 0, 0);
}

static void bin_delete(conn *c)
{
	char *key;
	size_t nkey;
	item *it;
	protocol_binary_request_delete *req;

	req = bin_get_request(c);
	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;

	PVERBOSE(1, "deleting %s\n", key);

	if (settings.detail_enabled) {
		mc_stats_prefix_record_delete(key, nkey);
	}

	it = mc_item_get(c->who, key, nkey);
	if (it) {
		u64 cas = ntohll(req->message.header.request.cas);
		if (cas == 0 || cas == ITEM_get_cas(it)) {
			spin_lock(&c->who->stats.lock);
			c->who->stats.slab_stats[it->slabs_clsid].delete_hits++;
			spin_unlock(&c->who->stats.lock);

			mc_item_unlink(c->who, it);
			bin_write_response(c, NULL, 0, 0, 0);
		} else {
			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
		}
		mc_item_remove(c->who, it);	/* release our reference */
	} else {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);

		spin_lock(&c->who->stats.lock);
		c->who->stats.delete_misses++;
		spin_unlock(&c->who->stats.lock);
	}
}

static void bin_complete_incr(conn *c)
{
	item *it;
	char *key;
	size_t nkey;
	/* Weird magic in add_delta forces me to pad here */
	char tmpbuf[INCR_MAX_STORAGE_LEN];
	u64 cas = 0;
	protocol_binary_response_incr* rsp;
	protocol_binary_request_incr* req;

	rsp = (protocol_binary_response_incr*)c->cn_wbuf;
	req = bin_get_request(c);
	/* fix byteorder in the request */
	req->message.body.delta = ntohll(req->message.body.delta);
	req->message.body.initial = ntohll(req->message.body.initial);
	req->message.body.expiration = ntohl(req->message.body.expiration);
	key = bin_get_key(c);
	nkey= c->bin_header.request.keylen;

#ifdef CONFIG_VERBOSE
	if (settings.verbose > 1) {
		int i;
		PRINTK("incr ");

		for (i = 0; i < nkey; i++) {
			printk("%c", key[i]);
		}
		PRINTK(" %lld, %llu, %d\n",
		       (long long)req->message.body.delta,
		       (long long)req->message.body.initial,
		       req->message.body.expiration);
	}
#endif

	if (c->bin_header.request.cas != 0) {
		cas = c->bin_header.request.cas;
	}

	switch(mc_add_delta(c->who, c, key, nkey,
			    c->cmd == PROTOCOL_BINARY_CMD_INCREMENT,
			    req->message.body.delta, tmpbuf, &cas)) {
	case OK:
		rsp->message.body.value = htonll(simple_strtoull(tmpbuf, NULL, 10));
		if (cas) {
			c->cas = cas;
		}
		bin_write_response(c, &rsp->message.body, 0, 0,
				   sizeof(rsp->message.body.value));
		break;
	case NON_NUMERIC:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL, 0);
		break;
	case EOM:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
		break;
	case DELTA_ITEM_NOT_FOUND:
		if (req->message.body.expiration != 0xffffffff) {
			/* Save some room for the response */
			rsp->message.body.value = htonll(req->message.body.initial);
			it = mc_item_alloc(key, nkey, 0,
					   realtime(req->message.body.expiration),
					   INCR_MAX_STORAGE_LEN);
			if (it != NULL) {
				snprintf(ITEM_data(it), INCR_MAX_STORAGE_LEN, "%llu",
					 (unsigned long long)req->message.body.initial);

				if (mc_store_item(c->who, it, NREAD_ADD, c)) {
					c->cas = ITEM_get_cas(it);
					bin_write_response(c, &rsp->message.body, 0, 0,
							   sizeof(rsp->message.body.value));
				} else {
					bin_write_error(c, PROTOCOL_BINARY_RESPONSE_NOT_STORED, 0);
				}
				mc_item_remove(c->who, it);         /* release our reference */
			} else {
				bin_write_error(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
			}
		} else {
			spin_lock(&c->who->stats.lock);
			if (c->cmd == PROTOCOL_BINARY_CMD_INCREMENT) {
				c->who->stats.incr_misses++;
			} else {
				c->who->stats.decr_misses++;
			}
			spin_unlock(&c->who->stats.lock);

			bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
		}
		break;
	case DELTA_ITEM_CAS_MISMATCH:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
		break;
	}
}

static void bin_complete_update(conn *c)
{
	protocol_binary_response_status eno =
	       	PROTOCOL_BINARY_RESPONSE_EINVAL;
	store_item_t ret = NOT_STORED;
	item *it = c->item;

	spin_lock(&c->who->stats.lock);
	c->who->stats.slab_stats[it->slabs_clsid].set_cmds++;
	spin_unlock(&c->who->stats.lock);

	/* We don't actually receive the trailing two characters in the bin
	 * protocol, so we're going to just set them here */
	*(ITEM_data(it) + it->nbytes - 2) = '\r';
	*(ITEM_data(it) + it->nbytes - 1) = '\n';

	ret = mc_store_item(c->who, it, c->cmd, c);

	switch (ret) {
	case STORED:
		/* Stored */
		bin_write_response(c, NULL, 0, 0, 0);
		break;
	case EXISTS:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
		break;
	case NOT_FOUND:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
		break;
	case NOT_STORED:
		if (c->cmd == NREAD_ADD) {
			eno = PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
		} else if(c->cmd == NREAD_REPLACE) {
			eno = PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
		} else {
			eno = PROTOCOL_BINARY_RESPONSE_NOT_STORED;
		}
		bin_write_error(c, eno, 0);
		break;
	}

	/* release the c->item reference */
	mc_item_remove(c->who, c->item);
	c->item = 0;
}

static void bin_complete_nread(conn *c)
{
	switch (c->substate) {
	case bin_reading_set_header:
		if (c->cmd == PROTOCOL_BINARY_CMD_APPEND ||
		    c->cmd == PROTOCOL_BINARY_CMD_PREPEND) {
			bin_append_prepend(c);
		} else {
			bin_update(c);
		}
		break;
	case bin_read_set_value:
		bin_complete_update(c);
		break;
	case bin_reading_get_key:
		bin_get(c);
		break;
	case bin_reading_touch_key:
		bin_touch(c);
		break;
	case bin_reading_stat:
		bin_stat(c);
		break;
	case bin_reading_del_header:
		bin_delete(c);
		break;
	case bin_reading_incr_header:
		bin_complete_incr(c);
		break;
	case bin_read_flush_exptime:
		bin_flush(c);
		break;
	case bin_reading_sasl_auth:
		bin_sasl_auth(c);
		break;
	case bin_reading_sasl_auth_data:
		bin_complete_sasl_auth(c);
		break;
	default:
		PRINTK("not handling substate %d\n", c->substate);
		BUG();
		break;
	}
}

/* Just write an error message and disconnect the client */
static void handle_bin_protocol_error(conn *c)
{
	bin_write_error(c, PROTOCOL_BINARY_RESPONSE_EINVAL, 0);
	PVERBOSE(0, "Protocol error (opcode %02x), close connection\n",
		 c->bin_header.request.opcode);
	c->write_and_go = conn_closing;
}

static void bin_list_sasl_mechs(conn *c)
{
	const char *result_string = NULL;
	unsigned int string_length = 0;
	int result;

	// Guard against a disabled SASL.
	if (!settings.sasl) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,
				c->bin_header.request.bodylen -
				c->bin_header.request.keylen);
		return;
	}

	mc_init_sasl_conn(c);
	result = mc_sasl_listmech(c->sasl_conn,
				  NULL,
				  "",   /* What to prepend the string with */
				  " ",  /* What to separate mechanisms with */
				  "",   /* What to append to the string */
				  &result_string,
				  &string_length,
				  NULL);
	if (result != SASL_OK) {
		/* Perhaps there's a better error for this... */
		PVERBOSE(0, "Failed to list SASL mechanisms.\n");
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
		return;
	}
	bin_write_response(c, (char*)result_string, 0, 0, string_length);
}

static void bin_read_key(conn *c, bin_substate_t next_substate, int extra)
{
	ptrdiff_t offset;

	c->substate = next_substate;
	c->rlbytes = c->keylen + extra;

	/* Ok... do we have room for the extras and the key in the input buffer? */
	offset = c->cn_rcurr + sizeof(protocol_binary_request_header) - c->cn_rbuf;

	if (c->rlbytes > c->cn_rsize - offset) {
		size_t nsize = c->cn_rsize;
		size_t size = c->rlbytes + sizeof(protocol_binary_request_header);

		while (size > nsize) {
			nsize *= 2;
		}

		if (nsize != c->cn_rsize) {
			PVERBOSE(1, "%p: Need to grow buffer from %lu to %lu\n",
				 c, (unsigned long)c->cn_rsize, (unsigned long)nsize);

			if (realloc_simpbuf(&c->_rbuf, nsize, c->cn_rsize, 0)) {
				PVERBOSE(0, ">%p: failed to grow buffer.. closing connection\n", c);
				conn_set_state(c, conn_closing);
				return;
			}

			/* cn_rcurr should point to the same offset in the packet */
			c->cn_rcurr = c->cn_rbuf + offset - sizeof(protocol_binary_request_header);
		}
		if (c->cn_rbuf != c->cn_rcurr) {
			memmove(c->cn_rbuf, c->cn_rcurr, c->cn_rbytes);
			c->cn_rcurr = c->cn_rbuf;
			PVERBOSE(1, ">%p: repack input buffer\n", c);
		}
	}

	/* preserve the header in the buffer.. */
	c->ritem = c->cn_rcurr + sizeof(protocol_binary_request_header);
	conn_set_state(c, conn_nread);
}

static int authenticated(conn *c)
{
	int ret = 0;

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_SASL_AUTH:       /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_SASL_STEP:       /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_VERSION:         /* FALLTHROUGH */
		ret = 1;
		break;
	default:
		if (c->sasl_conn) {
			const void *uname = NULL;
			mc_sasl_getprop(c->sasl_conn, SASL_USERNAME, &uname);
			ret = uname != NULL;
		}
	}

	PVERBOSE(1, "authenticated() in cmd 0x%02x is %s\n",
		 c->cmd, ret ? "true" : "false");

	return ret;
}

static void bin_dispatch_command(conn *c, char *noused)
{
	int protocol_error = 0;
	int extlen = c->bin_header.request.extlen;
	int keylen = c->bin_header.request.keylen;
	u32 bodylen = c->bin_header.request.bodylen;

	if (settings.sasl && !authenticated(c)) {
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
		c->write_and_go = conn_closing;
		return;
	}

	c->noreply = 1;

	/* binprot supports 16bit keys, but internals are still 8bit */
	if (keylen > KEY_MAX_LEN) {
		handle_bin_protocol_error(c);
		return;
	}

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_SETQ:
		c->cmd = PROTOCOL_BINARY_CMD_SET;
		break;
	case PROTOCOL_BINARY_CMD_ADDQ:
		c->cmd = PROTOCOL_BINARY_CMD_ADD;
		break;
	case PROTOCOL_BINARY_CMD_REPLACEQ:
		c->cmd = PROTOCOL_BINARY_CMD_REPLACE;
		break;
	case PROTOCOL_BINARY_CMD_DELETEQ:
		c->cmd = PROTOCOL_BINARY_CMD_DELETE;
		break;
	case PROTOCOL_BINARY_CMD_INCREMENTQ:
		c->cmd = PROTOCOL_BINARY_CMD_INCREMENT;
		break;
	case PROTOCOL_BINARY_CMD_DECREMENTQ:
		c->cmd = PROTOCOL_BINARY_CMD_DECREMENT;
		break;
	case PROTOCOL_BINARY_CMD_QUITQ:
		c->cmd = PROTOCOL_BINARY_CMD_QUIT;
		break;
	case PROTOCOL_BINARY_CMD_FLUSHQ:
		c->cmd = PROTOCOL_BINARY_CMD_FLUSH;
		break;
	case PROTOCOL_BINARY_CMD_APPENDQ:
		c->cmd = PROTOCOL_BINARY_CMD_APPEND;
		break;
	case PROTOCOL_BINARY_CMD_PREPENDQ:
		c->cmd = PROTOCOL_BINARY_CMD_PREPEND;
		break;
	case PROTOCOL_BINARY_CMD_GETQ:
		c->cmd = PROTOCOL_BINARY_CMD_GET;
		break;
	case PROTOCOL_BINARY_CMD_GETKQ:
		c->cmd = PROTOCOL_BINARY_CMD_GETK;
		break;
	case PROTOCOL_BINARY_CMD_GATQ:
		c->cmd = PROTOCOL_BINARY_CMD_GAT;
		break;
	case PROTOCOL_BINARY_CMD_GATKQ:
		c->cmd = PROTOCOL_BINARY_CMD_GAT;
		break;
	default:
		c->noreply = 0;
		break;
	}

	switch (c->cmd) {
	case PROTOCOL_BINARY_CMD_VERSION:
		if (extlen == 0 && keylen == 0 && bodylen == 0) {
			bin_write_response(c, VERSION, 0, 0,
					   strlen(VERSION));
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_FLUSH:
		if (keylen == 0 && bodylen == extlen &&
		    (extlen == 0 || extlen == 4)) {
			bin_read_key(c, bin_read_flush_exptime, extlen);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_NOOP:
		if (extlen == 0 && keylen == 0 && bodylen == 0) {
			bin_write_response(c, NULL, 0, 0, 0);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_SET: /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_ADD: /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_REPLACE:
		if (extlen == 8 && keylen != 0 && bodylen >= (keylen + 8)) {
			bin_read_key(c, bin_reading_set_header, 8);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_GETQ:  /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_GET:   /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_GETKQ: /* FALLTHROUGH */
	case PROTOCOL_BINARY_CMD_GETK:
		if (extlen == 0 && bodylen == keylen && keylen > 0) {
			bin_read_key(c, bin_reading_get_key, 0);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_DELETE:
		if (keylen > 0 && extlen == 0 && bodylen == keylen) {
			bin_read_key(c, bin_reading_del_header, extlen);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_INCREMENT:
	case PROTOCOL_BINARY_CMD_DECREMENT:
		if (keylen > 0 && extlen == 20 && bodylen == (keylen + extlen)) {
			bin_read_key(c, bin_reading_incr_header, 20);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_APPEND:
	case PROTOCOL_BINARY_CMD_PREPEND:
		if (keylen > 0 && extlen == 0) {
			bin_read_key(c, bin_reading_set_header, 0);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_STAT:
		if (extlen == 0) {
			bin_read_key(c, bin_reading_stat, 0);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_QUIT:
		if (keylen == 0 && extlen == 0 && bodylen == 0) {
			bin_write_response(c, NULL, 0, 0, 0);
			c->write_and_go = conn_closing;
			if (c->noreply) {
				conn_set_state(c, conn_closing);
			}
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
		if (extlen == 0 && keylen == 0 && bodylen == 0) {
			bin_list_sasl_mechs(c);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_SASL_AUTH:
	case PROTOCOL_BINARY_CMD_SASL_STEP:
		if (extlen == 0 && keylen != 0) {
			bin_read_key(c, bin_reading_sasl_auth, 0);
		} else {
			protocol_error = 1;
		}
		break;
	case PROTOCOL_BINARY_CMD_TOUCH:
	case PROTOCOL_BINARY_CMD_GAT:
	case PROTOCOL_BINARY_CMD_GATQ:
	case PROTOCOL_BINARY_CMD_GATK:
	case PROTOCOL_BINARY_CMD_GATKQ:
		if (extlen == 4 && keylen != 0) {
			bin_read_key(c, bin_reading_touch_key, 4);
		} else {
			protocol_error = 1;
		}
		break;
	default:
		bin_write_error(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, bodylen);
		break;
	}

	if (protocol_error)
		handle_bin_protocol_error(c);
}

static void bin_append_stats(const char *key, u16 klen,
			     const char *val, u32 vlen, conn *c)
{
	char *buf;
	u32 bodylen = klen + vlen;

	protocol_binary_response_header header = {
		.response.magic   = (u8)PROTOCOL_BINARY_RES,
		.response.opcode  = PROTOCOL_BINARY_CMD_STAT,
		.response.keylen  = (u16)htons(klen),
		.response.datatype= (u8)PROTOCOL_BINARY_RAW_BYTES,
		.response.bodylen = htonl(bodylen),
		.response.opaque  = c->opaque
	};

	buf = (char *)BUFFER(&c->stats) + c->offset;

	memcpy(buf, header.bytes, sizeof(header.response));
	buf += sizeof(header.response);

	if (klen > 0) {
		memcpy(buf, key, klen);
		buf += klen;

		if (vlen > 0) {
			memcpy(buf, val, vlen);
		}
	}

	c->offset += sizeof(header.response) + bodylen;
}

const struct proto_operations bin_proto_ops = {
	.proto		= binary_prot,
	.dispatch	= bin_dispatch_command,
	.complete_nread	= bin_complete_nread,
	.append_stats	= bin_append_stats
};
