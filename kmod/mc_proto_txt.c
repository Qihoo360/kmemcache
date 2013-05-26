#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "mc.h"

struct kmem_cache *suffix_cachep;

typedef struct token_s {
	char *value;
	size_t length;
} token_t;

#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1

#define MAX_TOKENS 8

static inline bool set_noreply_maybe(conn *c, token_t *tokens, size_t ntokens)
{
	int noreply_index = ntokens - 2;

	/*
	 * NOTE: this function is not the first place where we are going to
	 * send the reply.  We could send it instead from process_command()
	 * if the request line has wrong number of tokens.  However parsing
	 * malformed line for "noreply" option is not reliable anyway, so
	 * it can't be helped.
	 */
	if (tokens[noreply_index].value &&
	    strcmp(tokens[noreply_index].value, "noreply") == 0) {
		c->noreply = 1;
	}
	return c->noreply;
}

/*
 * Tokenize the command string by replacing whitespace with '\0' and update
 * the token array tokens with pointer to start of each token and length.
 * Returns total number of tokens.  The last valid token is the terminal
 * token (value points to the first unprocessed character of the string and
 * length zero).
 *
 * Usage example:
 *
 *  while(tokenize_command(command, ncommand, tokens, max_tokens) > 0) {
 *      for(int ix = 0; tokens[ix].length != 0; ix++) {
 *          ...
 *      }
 *      ncommand = tokens[ix].value - command;
 *      command  = tokens[ix].value;
 *   }
 */
static size_t tokenize_command(char *command, token_t *tokens, size_t max_tokens)
{
	char *s, *e;
	size_t len, ntokens = 0;
	unsigned int i = 0;

	s = e = command;
	len = strlen(command);

	for (i = 0; i < len; i++) {
		if (*e == ' ') {
			if (s != e) {
				tokens[ntokens].value = s;
				tokens[ntokens].length = e - s;
				ntokens++;
				*e = '\0';
				if (ntokens == max_tokens - 1) {
					e++;
					s = e; /* so we don't add an extra token */
					break;
				}
			}
			s = e + 1;
		}
		e++;
	}

	if (s != e) {
		tokens[ntokens].value = s;
		tokens[ntokens].length = e - s;
		ntokens++;
	}

	/*
	 * If we scanned the whole string, the terminal value pointer is null,
	 * otherwise it is the first unprocessed character.
	 */
	tokens[ntokens].value =  *e == '\0' ? NULL : e;
	tokens[ntokens].length = 0;
	ntokens++;

	return ntokens;
}

static void txt_stats_detail(conn *c, const char *command)
{
	if (!strcmp(command, "on")) {
		settings.detail_enabled = 1;
		OSTRING(c, MSG_TXT_OK);
	} else if (!strcmp(command, "off")) {
		settings.detail_enabled = 0;
		OSTRING(c, MSG_TXT_OK);
	} else if (!strcmp(command, "dump")) {
		int ret;
		DECLEARE_BUFFER(buf);

		ret = mc_stats_prefix_dump(&buf);
		write_and_free(c, &buf, ret);
	} else {
		OSTRING(c, MSG_TXT_USG_STAT);
	}
}

static void txt_stat(conn *c, token_t *tokens, size_t ntokens)
{
	const char *subcommand = tokens[SUBCOMMAND_TOKEN].value;

	if (ntokens < 2) {
		OSTRING(c, MSG_TXT_BAD_CMDLIN);
		return;
	}

	if (ntokens == 2) {
		mc_server_stats(&mc_append_stats, c);
		(void)mc_get_stats(NULL, 0, &mc_append_stats, c);
	} else if (!strcmp(subcommand, "reset")) {
		mc_stats_reset();
		OSTRING(c, MSG_TXT_RESET);
		return ;
	} else if (!strcmp(subcommand, "detail")) {
		/* NOTE: how to tackle detail with binary? */
		if (ntokens < 4)
			txt_stats_detail(c, "");  /* outputs the error message */
		else
			txt_stats_detail(c, tokens[2].value);
		/* Output already generated */
		return ;
	} else if (!strcmp(subcommand, "settings")) {
		mc_stat_settings(&mc_append_stats, c);
	} else if (!strcmp(subcommand, "cachedump")) {
		unsigned int id, limit = 0, ret;
		DECLEARE_BUFFER(buf);

		if (ntokens < 5) {
			OSTRING(c, MSG_TXT_BAD_CMDLIN);
			return;
		}

		if (safe_strtoul(tokens[2].value, &id) ||
		    safe_strtoul(tokens[3].value, &limit)) {
			OSTRING(c, MSG_TXT_BAD_CMDFMT);
			return;
		}

		if (id >= POWER_LARGEST) {
			OSTRING(c, MSG_TXT_ILL_SLAB);
			return;
		}

		ret =  mc_item_cachedump(id, limit, &buf);
		write_and_free(c, &buf, ret);
		return ;
	} else {
		/* getting here means that the subcommand is either engine specific or
		 * is invalid. query the engine and see. */
		if (!mc_get_stats(subcommand, strlen(subcommand), &mc_append_stats, c)) {
			if (c->stats.flags == BUF_NEGATIVE) {
				OSTRING(c, MSG_SER_OOM_STAT);
			} else {
				write_and_free(c, &c->stats, c->offset);
				c->stats.flags = BUF_NEGATIVE;
			}
		} else {
			OSTRING(c, MSG_TXT_ERROR);
		}
		return ;
	}

	/* append terminator and start the transfer */
	mc_append_stats(NULL, 0, NULL, 0, c);

	if (c->stats.flags == BUF_NEGATIVE) {
		OSTRING(c, MSG_SER_OOM_STAT);
	} else {
		write_and_free(c, &c->stats, c->offset);
		c->stats.flags = BUF_NEGATIVE;
	}
}

/* ntokens is overwritten here... shrug.. */
static void txt_get(conn *c, token_t *tokens, size_t ntokens, int return_cas)
{
	char *key;
	size_t nkey;
	int i = 0, ret;
	item *it;
	token_t *key_token = &tokens[KEY_TOKEN];
	char *suffix;

	do {
		while(key_token->length != 0) {
			key = key_token->value;
			nkey = key_token->length;

			if(nkey > KEY_MAX_LEN) {
				OSTRING(c, MSG_TXT_BAD_CMDFMT);
				return;
			}

			it = mc_item_get(c->who, key, nkey);
			if (settings.detail_enabled) {
				mc_stats_prefix_record_get(key, nkey, NULL != it);
			}
			if (it) {
				if (i >= c->cn_isize) {
					ret = realloc_ilistbuf(&c->_ilistbuf,
							c->cn_isize * 2, c->cn_isize);
					if (ret) {
						mc_item_remove(c->who, it);
						break;
					}
				}

				/*
				 * Construct the response. Each hit adds three elements to the
				 * outgoing data list:
				 *   "VALUE "
				 *   key
				 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
				 */
				if (return_cas) {
					int suffix_len;
					/* Goofy mid-flight realloc. */
					if (i >= c->cn_suffixsize) {
						ret = realloc_slistbuf(&c->_slistbuf,
								c->cn_suffixsize * 2, c->cn_suffixsize);
						if (ret) {
							mc_item_remove(c->who, it);
							break;
						}
					}

					suffix = _suffix_new();
					if (suffix == NULL) {
						OSTRING(c, MSG_SER_OOM_CAS);
						mc_item_remove(c->who, it);
						return;
					}
					*(c->cn_suffixlist + i) = suffix;
					suffix_len = snprintf(suffix, SUFFIX_SIZE, " %llu\r\n",
							      (unsigned long long)ITEM_get_cas(it));
					if (mc_add_iov(c, "VALUE ", 6) ||
					    mc_add_iov(c, ITEM_key(it), it->nkey) ||
					    mc_add_iov(c, ITEM_suffix(it), it->nsuffix - 2) ||
					    mc_add_iov(c, suffix, suffix_len) ||
					    mc_add_iov(c, ITEM_data(it), it->nbytes)) {
						mc_item_remove(c->who, it);
						break;
					}
				} else {
					if (mc_add_iov(c, "VALUE ", 6) ||
					    mc_add_iov(c, ITEM_key(it), it->nkey) ||
					    mc_add_iov(c, ITEM_suffix(it), it->nsuffix + it->nbytes)) {
						mc_item_remove(c->who, it);
						break;
					}
				}

				PVERBOSE(1, ">%s sending key %s\n", current->comm, ITEM_key(it));

				/* item_get() has incremented it->refcount for us */
#ifdef CONFIG_SLOCK
				spin_lock(&c->who->slock);
				c->who->stats.slab_stats[it->slabs_clsid].get_hits++;
				c->who->stats.get_cmds++;
				spin_unlock(&c->who->slock);
#else
				ATOMIC64_INC(c->who->stats.slab_stats[it->slabs_clsid].get_hits);
				ATOMIC64_INC(c->who->stats.get_cmds);
#endif
				mc_item_update(c->who, it);
				*(c->cn_ilist + i) = it;
				i++;

			} else {
#ifdef CONFIG_SLOCK
				spin_lock(&c->who->slock);
				c->who->stats.get_misses++;
				c->who->stats.get_cmds++;
				spin_unlock(&c->who->slock);
#else
				ATOMIC64_INC(c->who->stats.get_misses);
				ATOMIC64_INC(c->who->stats.get_cmds);
#endif
			}

			key_token++;
		}

		/*
		 * If the command string hasn't been fully processed, get the next set
		 * of tokens.
		 */
		if(key_token->value != NULL) {
			ntokens = tokenize_command(key_token->value, tokens, MAX_TOKENS);
			key_token = tokens;
		}

	} while(key_token->value != NULL);

	c->cn_icurr = c->cn_ilist;
	c->cn_ileft = i;
	if (return_cas) {
		c->cn_suffixcurr = c->cn_suffixlist;
		c->cn_suffixleft = i;
	}

	PVERBOSE(1, ">%s END\n", current->comm);

	/*
	 * If the loop was terminated because of out-of-memory, it is not
	 * reliable to add END\r\n to the buffer, because it might not end
	 * in \r\n. So we send SERVER_ERROR instead.
	 */
	if (key_token->value != NULL ||
	    mc_add_iov(c, "END\r\n", 5) ||
	    (IS_UDP(c->transport) && mc_build_udp_headers(c))) {
		OSTRING(c, MSG_SER_OOM_WRES);
	} else {
		conn_set_state(c, conn_mwrite);
		c->cn_msgcurr = 0;
	}

	return;
}

static void txt_update(conn *c, token_t *tokens, size_t ntokens, int comm, int handle_cas) 
{
	char *key;
	size_t nkey;
	unsigned int flags;
	u32 exptime_int = 0;
	rel_time_t exptime;
	int vlen;
	u64 req_cas_id=0;
	item *it;


	set_noreply_maybe(c, tokens, ntokens);

	if (tokens[KEY_TOKEN].length > KEY_MAX_LEN) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	key = tokens[KEY_TOKEN].value;
	nkey = tokens[KEY_TOKEN].length;

	if (safe_strtoul(tokens[2].value, (u32 *)&flags) ||
	    safe_strtol(tokens[3].value, &exptime_int) ||
	    safe_strtol(tokens[4].value, (s32 *)&vlen)) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	/* Ubuntu 8.04 breaks when I pass exptime to safe_strtol */
	exptime = exptime_int;

	/* 
	 * Negative exptimes can underflow and end up immortal. realtime() will
	 * immediately expire values that are greater than REALTIME_MAXDELTA, but less
	 * than process_started, so lets aim for that.
	 */
	if (exptime < 0)
		exptime = REALTIME_MAXDELTA + 1;

	// does cas value exist?
	if (handle_cas) {
		if (safe_strtoull(tokens[5].value, &req_cas_id)) {
			OSTRING(c, MSG_TXT_BAD_CMDFMT);
			return;
		}
	}

	vlen += 2;
	if (vlen < 0 || vlen - 2 < 0) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	if (settings.detail_enabled) {
		mc_stats_prefix_record_set(key, nkey);
	}

	it = mc_item_alloc(key, nkey, flags, realtime(exptime), vlen);

	if (it == 0) {
		if (!mc_item_size_ok(nkey, flags, vlen)) {
			OSTRING(c, MSG_SER_LAROBJ);
		} else {
			OSTRING(c, MSG_SER_OOM_SOBJ);
		}
		/* swallow the data line */
		c->write_and_go = conn_swallow;
		c->sbytes = vlen;

		/* Avoid stale data persisting in cache because we failed alloc.
		* Unacceptable for SET. Anywhere else too? */
		if (comm == NREAD_SET) {
			it = mc_item_get(c->who, key, nkey);
			if (it) {
				mc_item_unlink(c->who, it);
				mc_item_remove(c->who, it);
			}
		}

		return;
	}
	ITEM_set_cas(it, req_cas_id);

	c->item = it;
	c->ritem = ITEM_data(it);
	c->rlbytes = it->nbytes;
	c->cmd = comm;
	conn_set_state(c, conn_nread);
}

static void txt_touch(conn *c, token_t *tokens, size_t ntokens)
{
	char *key;
	size_t nkey;
	s32 exptime_int = 0;
	item *it;

	set_noreply_maybe(c, tokens, ntokens);

	if (tokens[KEY_TOKEN].length > KEY_MAX_LEN) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	key = tokens[KEY_TOKEN].value;
	nkey = tokens[KEY_TOKEN].length;

	if (safe_strtol(tokens[2].value, &exptime_int)) {
		OSTRING(c, MSG_TXT_ILL_TIME);
		return;
	}

	it = mc_item_touch(c->who, key, nkey, realtime(exptime_int));
	if (it) {
		mc_item_update(c->who, it);
#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		c->who->stats.touch_cmds++;
		c->who->stats.slab_stats[it->slabs_clsid].touch_hits++;
		spin_unlock(&c->who->slock);
#else
		ATOMIC64_INC(c->who->stats.touch_cmds);
		ATOMIC64_INC(c->who->stats.slab_stats[it->slabs_clsid].touch_hits);
#endif

		OSTRING(c, MSG_TXT_TOUCHED);
		mc_item_remove(c->who, it);
	} else {
#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		c->who->stats.touch_cmds++;
		c->who->stats.touch_misses++;
		spin_unlock(&c->who->slock);
#else
		ATOMIC64_INC(c->who->stats.touch_cmds);
		ATOMIC64_INC(c->who->stats.touch_misses);
#endif
		OSTRING(c, MSG_TXT_NFOUND);
	}
}

static void txt_arithmetic(conn *c, token_t *tokens, size_t ntokens, int incr)
{
	char temp[INCR_MAX_STORAGE_LEN];
	u64 delta;
	char *key;
	size_t nkey;

	set_noreply_maybe(c, tokens, ntokens);

	if (tokens[KEY_TOKEN].length > KEY_MAX_LEN) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	key = tokens[KEY_TOKEN].value;
	nkey = tokens[KEY_TOKEN].length;

	if (safe_strtoull(tokens[2].value, &delta)) {
		OSTRING(c, MSG_TXT_ILL_NUM);
		return;
	}

	switch(mc_add_delta(c->who, c, key, nkey, incr, delta, temp, NULL)) {
	case OK:
		mc_out_string(c, temp, strlen(temp));
		break;
	case NON_NUMERIC:
		OSTRING(c, MSG_TXT_CRE_VAL);
		break;
	case EOM:
		OSTRING(c, MSG_SER_OOM);
		break;
	case DELTA_ITEM_NOT_FOUND:
#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		if (incr) {
			c->who->stats.incr_misses++;
		} else {
			c->who->stats.decr_misses++;
		}
		spin_unlock(&c->who->slock);
#else
		if (incr) {
			ATOMIC64_INC(c->who->stats.incr_misses);
		} else {
			ATOMIC64_INC(c->who->stats.decr_misses);
		}
#endif

		OSTRING(c, MSG_TXT_NFOUND);
		break;
	case DELTA_ITEM_CAS_MISMATCH:
		/* Should never get here */
		break;
	}
}

static void txt_delete(conn *c, token_t *tokens, size_t ntokens)
{
	char *key;
	size_t nkey;
	item *it;

	if (ntokens > 3) {
		int hold_is_zero = strcmp(tokens[KEY_TOKEN+1].value, "0") == 0;
		int sets_noreply = set_noreply_maybe(c, tokens, ntokens);
		int valid = (ntokens == 4 && (hold_is_zero || sets_noreply))
			 || (ntokens == 5 && hold_is_zero && sets_noreply);
		if (!valid) {
			OSTRING(c, MSG_TXT_BAD_CMDUSG);
			return;
		}
	}

	key = tokens[KEY_TOKEN].value;
	nkey = tokens[KEY_TOKEN].length;

	if(nkey > KEY_MAX_LEN) {
		OSTRING(c, MSG_TXT_BAD_CMDFMT);
		return;
	}

	if (settings.detail_enabled) {
		mc_stats_prefix_record_delete(key, nkey);
	}

	it = mc_item_get(c->who, key, nkey);
	if (it) {
#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		c->who->stats.slab_stats[it->slabs_clsid].delete_hits++;
		spin_unlock(&c->who->slock);
#else
		ATOMIC64_INC(c->who->stats.slab_stats[it->slabs_clsid].delete_hits);
#endif

		mc_item_unlink(c->who,it);
		mc_item_remove(c->who, it);      /* release our reference */
		OSTRING(c, MSG_TXT_DELETED);
	} else {
#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		c->who->stats.delete_misses++;
		spin_unlock(&c->who->slock);
#else
		ATOMIC64_INC(c->who->stats.delete_misses);
#endif

		OSTRING(c, MSG_TXT_NFOUND);
	}
}

static void txt_verbosity(conn *c, token_t *tokens, size_t ntokens)
{
	unsigned int level;

	set_noreply_maybe(c, tokens, ntokens);

	level = simple_strtoul(tokens[1].value, NULL, 10);
	settings.verbose = level > MAX_VERBOSITY_LEVEL ? MAX_VERBOSITY_LEVEL : level;
	OSTRING(c, MSG_TXT_OK);
	return;
}

static void txt_slabs_automove(conn *c, token_t *tokens, size_t ntokens)
{
	unsigned int level;

	set_noreply_maybe(c, tokens, ntokens);

	level = simple_strtoul(tokens[2].value, NULL, 10);
	if (level == 0) {
		settings.slab_automove = 0;
	} else if (level == 1 || level == 2) {
		settings.slab_automove = level;
	} else {
		OSTRING(c, MSG_TXT_ERROR);
		return;
	}
	OSTRING(c, MSG_TXT_OK);
	return;
}

static void txt_dispatch_command(conn *c, char *command)
{
	token_t tokens[MAX_TOKENS];
	size_t ntokens;
	int comm;

	PVERBOSE(1, "<%s %s\n", current->comm, command);

	/*
	 * for commands set/add/replace, we build an item and read the data
	 * directly into it, then continue in nread_complete().
	 */
	c->cn_msgcurr = 0;
	c->cn_msgused = 0;
	c->cn_iovused = 0;
	if (mc_add_msghdr(c)) {
		OSTRING(c, MSG_SER_OOM_PRES);
		return;
	}

	ntokens = tokenize_command(command, tokens, MAX_TOKENS);
	if (ntokens >= 3 &&
	    (!strcmp(tokens[COMMAND_TOKEN].value, "get") ||
	    (!strcmp(tokens[COMMAND_TOKEN].value, "bget")))) {

		txt_get(c, tokens, ntokens, false);

	} else if ((ntokens == 6 || ntokens == 7) &&
		   ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) ||
		    (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) ||
		    (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)) ||
		    (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = NREAD_PREPEND)) ||
		    (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = NREAD_APPEND)) )) {

		txt_update(c, tokens, ntokens, comm, false);

	} else if ((ntokens == 7 || ntokens == 8) && (strcmp(tokens[COMMAND_TOKEN].value, "cas") == 0 && (comm = NREAD_CAS))) {

		txt_update(c, tokens, ntokens, comm, true);

	} else if ((ntokens == 4 || ntokens == 5) && (strcmp(tokens[COMMAND_TOKEN].value, "incr") == 0)) {

		txt_arithmetic(c, tokens, ntokens, 1);

	} else if (ntokens >= 3 && (strcmp(tokens[COMMAND_TOKEN].value, "gets") == 0)) {

		txt_get(c, tokens, ntokens, true);

	} else if ((ntokens == 4 || ntokens == 5) && (strcmp(tokens[COMMAND_TOKEN].value, "decr") == 0)) {

		txt_arithmetic(c, tokens, ntokens, 0);

	} else if (ntokens >= 3 && ntokens <= 5 && (strcmp(tokens[COMMAND_TOKEN].value, "delete") == 0)) {

		txt_delete(c, tokens, ntokens);

	} else if ((ntokens == 4 || ntokens == 5) && (strcmp(tokens[COMMAND_TOKEN].value, "touch") == 0)) {

		txt_touch(c, tokens, ntokens);

	} else if (ntokens >= 2 && (strcmp(tokens[COMMAND_TOKEN].value, "stats") == 0)) {

		txt_stat(c, tokens, ntokens);

	} else if (ntokens >= 2 && ntokens <= 4 && (strcmp(tokens[COMMAND_TOKEN].value, "flush_all") == 0)) {
		rel_time_t exptime = 0;

		set_noreply_maybe(c, tokens, ntokens);

#ifdef CONFIG_SLOCK
		spin_lock(&c->who->slock);
		c->who->stats.flush_cmds++;
		spin_unlock(&c->who->slock);
#else
		ATOMIC64_INC(c->who->stats.flush_cmds);
#endif

		if(ntokens == (c->noreply ? 3 : 2)) {
		    settings.oldest_live = current_time - 1;
		    mc_item_flush_expired();
		    OSTRING(c, MSG_TXT_OK);
		    return;
		}

		if (safe_strtoul(tokens[1].value, (u32 *)&exptime)) {
			OSTRING(c, MSG_TXT_BAD_CMDFMT);
			return;
		}

		/*
		  If exptime is zero realtime() would return zero too, and
		  realtime(exptime) - 1 would overflow to the max unsigned
		  value.  So we process exptime == 0 the same way we do when
		  no delay is given at all.
		*/
		if (exptime > 0)
			settings.oldest_live = realtime(exptime) - 1;
		else /* exptime == 0 */
			settings.oldest_live = current_time - 1;
		mc_item_flush_expired();
		OSTRING(c, MSG_TXT_OK);
		return;

	} else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "version") == 0)) {

		OSTRING(c, MSG_SYS_VERSION);

	} else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "quit") == 0)) {

		conn_set_state(c, conn_closing);

	} else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "shutdown") == 0)) {

		if (settings.shutdown_command) {
			conn_set_state(c, conn_closing);
		} else {
			OSTRING(c, MSG_SYS_SHUT);
		}

	} else if (ntokens > 1 && strcmp(tokens[COMMAND_TOKEN].value, "slabs") == 0) {
		if (ntokens == 5 && strcmp(tokens[COMMAND_TOKEN + 1].value, "reassign") == 0) {
			int src, dst, rv;

			if (settings.slab_reassign == false) {
				OSTRING(c, MSG_TXT_SLAB_DIS);
				return;
			}

			if (safe_strtol(tokens[2].value, &src) ||
			    safe_strtol(tokens[3].value, &dst)) {
				OSTRING(c, MSG_TXT_BAD_CMDFMT);
				return;
			}

			rv = mc_slabs_reassign(src, dst);
			switch (rv) {
			case REASSIGN_OK:
				OSTRING(c, MSG_TXT_OK);
				break;
			case REASSIGN_RUNNING:
				OSTRING(c, MSG_SYS_BUSY);
				break;
			case REASSIGN_BADCLASS:
				OSTRING(c, MSG_SYS_BADCLS);
				break;
			case REASSIGN_NOSPACE:
				OSTRING(c, MSG_SYS_NOSPACE);
				break;
			case REASSIGN_SRC_DST_SAME:
				OSTRING(c, MSG_SYS_SAMECLS);
				break;
			}
			return;
		} else if (ntokens == 4 && !strcmp(tokens[COMMAND_TOKEN + 1].value, "automove")) {
			txt_slabs_automove(c, tokens, ntokens);
		} else {
			OSTRING(c, MSG_TXT_ERROR);
		}
	} else if ((ntokens == 3 || ntokens == 4) && (strcmp(tokens[COMMAND_TOKEN].value, "verbosity") == 0)) {
		txt_verbosity(c, tokens, ntokens);
	} else {
		OSTRING(c, MSG_TXT_ERROR);
	}
	return;
}

/**
 * We get here after reading the value in set/add/replace
 * commands. The command has been stored in c->cmd, and
 * the item is ready in c->item.
 */
static void txt_complete_nread(conn *c)
{
	item *it = c->item;
	int comm = c->cmd;
	store_item_t ret;

#ifdef CONFIG_SLOCK
	spin_lock(&c->who->slock);
	c->who->stats.slab_stats[it->slabs_clsid].set_cmds++;
	spin_unlock(&c->who->slock);
#else
	ATOMIC64_INC(c->who->stats.slab_stats[it->slabs_clsid].set_cmds);
#endif

	if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2)) {
		OSTRING(c, MSG_TXT_BAD_CHUNK);
	} else {
		ret = mc_store_item(c->who, it, comm, c);

		switch (ret) {
		case STORED:
			OSTRING(c, MSG_TXT_STORED);
			break;
		case EXISTS:
			OSTRING(c, MSG_TXT_EXISTS);
			break;
		case NOT_FOUND:
			OSTRING(c, MSG_TXT_NFOUND);
			break;
		case NOT_STORED:
			OSTRING(c, MSG_TXT_NSTORED);
			break;
		default:
			OSTRING(c, MSG_SER_STYPE);
			break;
		}
	}

	/* release the c->item reference */
	mc_item_remove(c->who, c->item);
	c->item = 0;
}

static void txt_append_stats(const char *key, u16 klen,
			     const char *val, u32 vlen, conn *c)
{
	char *pos;
	int remaining, room;
	u32 nbytes = 0;

	pos = (char *)BUFFER(&c->stats) + c->offset;
	remaining = c->stats_len - c->offset;
	room = remaining - 1;

	if (klen == 0 && vlen == 0) {
		nbytes = snprintf(pos, room, "END\r\n");
	} else if (vlen == 0) {
		nbytes = snprintf(pos, room, "STAT %s\r\n", key);
	} else {
		nbytes = snprintf(pos, room, "STAT %s %s\r\n", key, val);
	}

	c->offset += nbytes;
}

const struct proto_operations txt_proto_ops = {
	.proto		= ascii_prot,
	.dispatch	= txt_dispatch_command,
	.complete_nread	= txt_complete_nread,
	.append_stats	= txt_append_stats
};
