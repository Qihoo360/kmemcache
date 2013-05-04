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
				fprintf(stderr, "parse socket error");
				return 1;
			}
		}

		free(list);
		return ret;
	}
}

static int construct_server_socket(settings_init_t *data)
{
	int ret = 0;
	char *port_file;
	struct addrinfo *addr;
	struct addrinfo_pair *p;
	sock_entry_t *entry;

	if (settings.port && parse_server_sockets(settings.port,
						  tcp_transport)) {
		ret = -1;
		goto out;
	}
	if (settings.udpport && parse_server_sockets(settings.udpport,
						     udp_transport)) {
		ret = -1;
		goto out;
	}

	entry = (sock_entry_t *)data->data;
	for (p = ainfo.next; p != &ainfo; p = p->next) {
		for (addr = p->ai; addr; addr = addr->ai_next) {
			entry->trans	= p->trans;
			entry->family	= addr->ai_family;
			entry->type	= addr->ai_socktype;
			entry->protocol	= addr->ai_protocol;
			entry->addrlen	= addr->ai_addrlen;
			memcpy(entry->addr, addr->ai_addr, addr->ai_addrlen);

			data->len += entry->addrlen + sizeof(sock_entry_t);
			entry = (sock_entry_t *)(data->data + data->len);
		}
	}

	port_file = getenv("MEMCACHED_PORT_FILENAME");
	if (port_file) {
		data->flags &= PORT_FILE;
		memcpy(entry, port_file, strlen(port_file) + 1);
		data->len += strlen(port_file) + 1;
	}

out:
	unregister_addrinfo();
	return ret;
}

static int construct_settings(struct cn_msg *msg)
{
	int ret = 0;
	settings_init_t *data;	

	data = (settings_init_t *)msg->data;

	data->port		  = settings.port;
	data->udpport		  = settings.udpport;
	data->access		  = settings.access;
	data->backlog		  = settings.backlog;
	data->verbose		  = settings.verbose;
	data->maxbytes		  = settings.maxbytes;
	data->maxconns		  = settings.maxconns;
	data->num_threads 	  = settings.num_threads;
	data->num_threads_per_udp = settings.num_threads_per_udp;
	data->reqs_per_event	  = settings.reqs_per_event;
	data->evict_to_free	  = settings.evict_to_free;
	data->chunk_size	  = settings.chunk_size;
	data->item_size_max	  = settings.item_size_max;
	data->slab_automove	  = settings.slab_automove;
	data->hashpower_init	  = settings.hashpower_init;
	data->hash_bulk_move	  = settings.hash_bulk_move;
	data->slab_bulk_check	  = settings.slab_bulk_check;
	data->oldest_live	  = settings.oldest_live;
	data->binding_protocol	  = settings.binding_protocol;
	data->factor_numerator    = settings.factor_numerator;
	data->factor_denominator  = settings.factor_denominator;
	data->use_cas		  = settings.use_cas;
	data->sasl		  = settings.sasl;
	data->maxconns_fast	  = settings.maxconns_fast;
	data->slab_reassign	  = settings.slab_reassign;
	data->prefix_delimiter	  = settings.prefix_delimiter;
	data->detail_enabled	  = settings.detail_enabled;
	data->shutdown_command	  = settings.shutdown_command;
	data->preallocate	  = settings.preallocate;

	if (settings.socketpath != NULL) {
		data->flags = UNIX_SOCK;
		data->len = strlen(settings.socketpath) + 1;
		memcpy(data->data, settings.socketpath, data->len);
	} else {
		ret = construct_server_socket(data);
	}

	msg->len = data->len + sizeof(*data);

	return ret;
}

int netlink_send_settings(int sock, struct cn_id *id)
{
	static int init = 0;
	static char buf[NETLINK_PAYLOAD];
	struct cn_msg *msg = (struct cn_msg *)buf;

	if (init == 0) {
		memset(buf, 0, sizeof(buf));
		if (construct_settings(msg)) {
			printf("construct settings msg error");
			return -1;
		}
		init = 1;
	}
	msg->id.idx = id->idx;
	msg->id.val = id->val;

	return netlink_send(sock, msg);
}
