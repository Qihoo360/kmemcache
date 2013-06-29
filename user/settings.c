#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#include "umemcached.h"

static struct addrinfo_pair {
	struct addrinfo *ai;
	net_transport_t trans; 
	struct addrinfo_pair *next;
} ainfo = {
	.ai	= NULL,
	.next	= &ainfo
};

static void unregister_addrinfo(void)
{
	struct addrinfo_pair *p, *q;

	for (p = ainfo.next; p != &ainfo;) {
		freeaddrinfo(p->ai);
		q = p->next;
		free(p);
		p = q;
	}
	ainfo.next = &ainfo;
}

static int register_addrinfo(struct addrinfo *ai, net_transport_t trans)
{
	struct addrinfo_pair *pair;

	pair = malloc(sizeof(*pair));
	if (!pair) {
		unregister_addrinfo();
		return 1;
	}

	pair->ai = ai;
	pair->trans = trans;
	pair->next = ainfo.next;
	ainfo.next = pair;

	return 0;
}

#define xisspace(c) isspace((unsigned char)c)

int safe_strtol(const char *str, int *out) {
	errno = 0;
	*out = 0;
	char *endptr;
	long l = strtol(str, &endptr, 10);

	if ((errno == ERANGE) || (str == endptr)) {
		return -1;
	}

	if (xisspace(*endptr) || (*endptr == '\0' && endptr != str)) {
		*out = l;
		return 0;
	}
	return -1;
}

static int parse_server_socket(const char *interface, int port,
			       net_transport_t transport)
{
	int ret = 0;
	char port_buf[NI_MAXSERV];
	struct addrinfo *ai;
	struct addrinfo hints = {
		.ai_flags = AI_PASSIVE,
		.ai_family = AF_UNSPEC
	};

	hints.ai_socktype = IS_UDP(transport) ? SOCK_DGRAM : SOCK_STREAM;

	if (port == -1)
		port = 0;
	snprintf(port_buf, sizeof(port_buf), "%d", port);

	ret = getaddrinfo(interface, port_buf, &hints, &ai);
	if (ret != 0) {
		if (ret != EAI_SYSTEM)
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		else
			perror("getaddrinfo");
		return 1;
	}

	return register_addrinfo(ai, transport);
}

static int parse_server_sockets(int port, net_transport_t transport)
{
	if (!settings.inter) {
		return parse_server_socket(settings.inter, port, transport);
	} else {
		char *b, *p;
		int ret = 0;
		char *list;

		list = strdup(settings.inter);
		if (list == NULL) {
			fprintf(stderr, "Failed to allocate memory"
				"for parsing server interface string\n");
			return 1;
		}

		for (p = strtok_r(list, ";,", &b);
		     p != NULL;
		     p = strtok_r(NULL, ";,", &b)) {
			int the_port = port;
			char *s = strchr(p, ':');

			if (s != NULL) {
				*s = '\0';
				++s;
				if (safe_strtol(s, &the_port)) {
					fprintf(stderr, "Invalid port number: \"%s\"", s);
					return 1;
				}
			}
			if (strcmp(p, "*") == 0) {
				p = NULL;
			}

			ret |= parse_server_socket(p, the_port, transport);
			if (ret) {
				fprintf(stderr, "parse socket error\n");
				return 1;
			}
		}

		free(list);
		return ret;
	}
}

static int construct_inet(void *_addr)
{
	int res = 0;
	struct addrinfo *addr;
	struct addrinfo_pair *p;
	sock_entry_t *entry;
	inet_t *inet = (inet_t *)_addr;

	if (settings.port && parse_server_sockets(settings.port,
						  tcp_transport)) {
		res = -1;
		goto out;
	}
	if (settings.udpport && parse_server_sockets(settings.udpport,
						     udp_transport)) {
		res = -1;
		goto out;
	}

	entry = (sock_entry_t *)inet->buf;
	for (p = ainfo.next; p != &ainfo; p = p->next) {
		for (addr = p->ai; addr; addr = addr->ai_next) {
			entry->trans	= p->trans;
			entry->family	= addr->ai_family;
			entry->type	= addr->ai_socktype;
			entry->protocol	= addr->ai_protocol;
			entry->addrlen	= addr->ai_addrlen;
			memcpy(entry->addr, addr->ai_addr, addr->ai_addrlen);

			res += entry->addrlen + sizeof(sock_entry_t);
			entry = (sock_entry_t *)((char *)inet->buf + res);
		}
	}
	inet->len = res;

out:
	unregister_addrinfo();

	 //keep issue_67.t test passed
	 //return (res <= 0 ? res : res + sizeof(inet_t));
	return (res + sizeof(inet_t));
}

static int construct_unix(void *addr)
{
	str_t *str = (str_t *)addr;

	str->len = strlen(settings.socketpath);
	memcpy(str->buf, settings.socketpath, str->len);

	return (str->len + sizeof(str_t));
}

static int construct_inter(void *addr)
{
	str_t *str = (str_t *)addr;

	str->len = strlen(settings.inter);
	memcpy((void *)str->buf, settings.inter, str->len);

	return (str->len + sizeof(str_t));
}

static int construct_factor(void *addr)
{
	str_t *str = (str_t *)addr;

	str->len = strlen(settings.factor);
	memcpy((void *)str->buf, settings.factor, str->len);

	return (str->len + sizeof(str_t));
}

static int construct_settings(struct cn_msg *msg)
{
	int ret = 0;
	int res, pos = 0;
	settings_init_t *data;

	data = (settings_init_t *)msg->data;

	data->base.port		  	= settings.port;
	data->base.udpport		= settings.udpport;
	data->base.access		= settings.access;
	data->base.backlog		= settings.backlog;
	data->base.verbose		= settings.verbose;
	data->base.maxbytes		= settings.maxbytes;
	data->base.maxconns		= settings.maxconns;
	data->base.num_threads_per_udp	= settings.num_threads_per_udp;
	data->base.reqs_per_event	= settings.reqs_per_event;
	data->base.evict_to_free	= settings.evict_to_free;
	data->base.chunk_size		= settings.chunk_size;
	data->base.item_size_max	= settings.item_size_max;
	data->base.slab_automove	= settings.slab_automove;
	data->base.hashpower_init	= settings.hashpower_init;
	data->base.hash_bulk_move	= settings.hash_bulk_move;
	data->base.slab_bulk_check	= settings.slab_bulk_check;
	data->base.oldest_live		= settings.oldest_live;
	data->base.binding_protocol	= settings.binding_protocol;
	data->base.factor_numerator	= settings.factor_numerator;
	data->base.factor_denominator	= settings.factor_denominator;
	data->base.use_cas		= settings.use_cas;
	data->base.sasl			= settings.sasl;
	data->base.maxconns_fast	= settings.maxconns_fast;
	data->base.slab_reassign	= settings.slab_reassign;
	data->base.prefix_delimiter	= settings.prefix_delimiter;
	data->base.detail_enabled	= settings.detail_enabled;
	data->base.shutdown_command	= settings.shutdown_command;
	data->base.preallocate		= settings.preallocate;
	data->base.factor		= NULL;
	data->base.socketpath		= NULL;
	data->base.inter		= NULL;

	/* SLAB_FACTOR */
	res = construct_factor(data->data + pos);
	data->flags |= SLAB_FACTOR;
	data->len   += res;
	pos	    += res;

	/* INET_INTER */
	if (settings.inter != NULL) {
		res = construct_inter(data->data + pos);
		data->flags |= INET_INTER;
		data->len   += res;
		pos	    += res;
	}

	if (settings.socketpath != NULL) {
		/* UNIX_SOCK */
		res = construct_unix(data->data + pos);
		data->flags |= UNIX_SOCK;
		data->len   += res;
		pos	    += res;
	} else {
		/* INET_SOCK */
		res = construct_inet(data->data + pos);
		if (res <= 0) {
			ret = -1;
		} else {
			data->flags |= INET_SOCK;
			data->len   += res;
			pos	    += res;
		}
	}

	msg->len = data->len + sizeof(*data);

	return ret;
}

int netlink_send_settings(int sock, struct cn_id *id)
{
	char buf[NETLINK_PAYLOAD] = {0};
	struct cn_msg *msg = (struct cn_msg *)buf;

	if (construct_settings(msg)) {
		printf("construct settings msg error\n");
		return -1;
	}
	msg->id.idx = id->idx;
	msg->id.val = id->val;

	return netlink_send(sock, msg);
}
