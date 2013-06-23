#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "umemcached.h"

int netlink_send_env(int sock, struct cn_msg *rcv)
{
	ask_env_t *ask;
	ack_env_t *ack;
	struct cn_msg *snd;
	char *env;
	char buf[KMC_V_ACK_ENV + PATH_MAX];

	union {
		char		*_str;
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
		if (env) {
			*data._int = atoi(env);
		} else {
			*data._int = 0;
		}
		snd->len = sizeof(ack_env_t) + sizeof(int);
		break;
	default:
		printf("kernel env error\n");
		return -1;
	}

	return netlink_send(sock, snd);
}

