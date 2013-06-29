#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include "umemcached.h"

int netlink_send_env(int sock, struct cn_msg *rcv)
{
	ask_env_t *ask;
	ack_env_t *ack;
	struct cn_msg *snd;
	char *env;
	char buf[KMC_V_ACK_ENV + PATH_MAX];

	union {
		str_t		*_str;
		int		*_int; 
		unsigned long 	*_ul;
	} data;

	ask = (ask_env_t *)rcv->data;

	snd = (struct cn_msg *)buf;
	ack = (ack_env_t *)snd->data;
	snd->id.idx = rcv->id.idx;
	snd->id.val = rcv->id.val;
	ack->env    = *ask;

	switch (*ask) {
	case T_MEMD_INITIAL_MALLOC:
		data._ul = (unsigned long *)ack->data;
		env = getenv("T_MEMD_INITIAL_MALLOC");
		if (env) {
			*data._ul = atol(env);
		} else {
			*data._ul = 0;
		}
		snd->len = sizeof(ack_env_t) + sizeof(unsigned long);
		break;
	case T_MEMD_SLABS_LIMIT:
		data._int = (int *)ack->data;
		env = getenv("T_MEMD_SLABS_LIMIT");
		if (env && atoi(env)) {
			*data._int = 1;
		} else {
			*data._int = 0;
		}
		snd->len = sizeof(ack_env_t) + sizeof(int);
		break;
	case MEMCACHED_PORT_FILENAME:
		data._str = (str_t *)ack->data;
		env = getenv("MEMCACHED_PORT_FILENAME");
		if (env) {
			data._str->len = strlen(env);
			memcpy(data._str->buf, env, data._str->len);
		} else {
			data._str->len = 0;
		}
		snd->len = sizeof(ack_env_t) + data._str->len;
		break;
	default:
		printf("kernel env error\n");
		return -1;
	}

	return netlink_send(sock, snd);
}

