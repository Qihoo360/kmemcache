#define _XOPEN_SOURCE	500

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <linux/netlink.h>

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <sysexits.h>
#include <errno.h>
#include <assert.h>
#include <pwd.h>
#include <math.h>

#include "umemcached.h"

//#define enable_daemon	1

struct settings settings;

static void usage(void)
{
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      TCP port number to listen on (default: 11211)\n"
           "-U <num>      UDP port number to listen on (default: 11211, 0 is off)\n"
           "-s <file>     UNIX socket path to listen on (disables network support)\n"
           "              XXX: must be absolute path\n"
           "-A            enable ascii \"shutdown\" command\n"
           "-a <mask>     access mask for UNIX socket, in octal (default: 0700)\n"
           "-l <addr>     interface to listen on (default: INADDR_ANY, all addresses)\n"
           "              <addr> may be specified as host:port. If you don't specify\n"
           "              a port number, the value you specified with -p or -U is\n"
           "              used. You may specify multiple addresses separated by comma\n"
           "              or by using -l multiple times\n"

#ifdef enable_daemon
           "-d            run as a daemon\n"
#endif
           "-r            maximize core file limit\n"
           "-m <num>      max memory to use for items in megabytes (default: 64 MB)\n"
           "-M            return error on memory exhausted (rather than removing items)\n"
           "-c <num>      max simultaneous connections (default: 1024)\n"
           "-v            verbose (print errors/warnings while in event loop)\n"
           "-vv           very verbose (also print client commands/reponses)\n"
           "-vvv          extremely verbose (also print internal state transitions)\n"
           "-h            print this help and exit\n"
           "-i            print memcached and libevent license\n"
           "-f <factor>   chunk size growth factor (default: 1.25)\n"
           "-n <bytes>    minimum space allocated for key+value+flags (default: 48)\n");
    printf("-L            Try to use large memory pages (if available). Increasing\n"
           "              the memory page size could reduce the number of TLB misses\n"
           "              and improve the performance. In order to get large pages\n"
           "              from the OS, memcached will allocate the total item-cache\n"
           "              in one large chunk.\n");
    printf("-D <char>     Use <char> as the delimiter between key prefixes and IDs.\n"
           "              This is used for per-prefix stats reporting. The default is\n"
           "              \":\" (colon). If this option is specified, stats collection\n"
           "              is turned on automatically; if not, then it may be turned on\n"
           "              by sending the \"stats detail on\" command to the server.\n");
    printf("-R            Maximum number of requests per event, limits the number of\n"
           "              requests process for a given connection to prevent \n"
           "              starvation (default: 20)\n");
    printf("-C            Disable use of CAS\n");
    printf("-b            Set the backlog queue limit (default: 1024)\n");
    printf("-B            Binding protocol - one of ascii, binary, or auto (default)\n");
    printf("-I            Override the size of each slab page. Adjusts max item size\n"
           "              (default: 1mb, min: 1k, max: 128m)\n");
#ifdef ENABLE_SASL
    printf("-S            Turn on Sasl authentication(not implemented yet)\n");
#endif
    printf("-o            Comma separated list of extended or experimental options\n"
           "              - (EXPERIMENTAL) maxconns_fast: immediately close new\n"
           "                connections if over maxconns limit\n"
           "              - hashpower: An integer multiplier for how large the hash\n"
           "                table should be. Can be grown at runtime if not big enough.\n"
           "                Set this based on \"STAT hash_power_level\" before a \n"
           "                restart.\n"
           );
    return;
}

static void usage_license(void)
{
    printf(PACKAGE " " VERSION "\n\n");
    printf(
    "Copyright (C) 2012, Li Jianguo <byjgli@gmail.com>\n"
    "\n"
    "kmemcache is derived from memcached-v1.4.15, exactly it is a\n"
    "linux kernel memcached, and aims at quicker response and higher performance.\n"
    "\n"
    "kmemcache is free software; you can redistribute it and/or modify it\n"
    "under the terms of the GNU General Public License as published by\n"
    "the Free Software Foundation; either version 2, or (at your option)\n"
    "any later version.\n"
    "\n"
    "kmemcache is distributed in the hope that it will be useful, but WITHOUT\n"
    "ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or\n"
    "FITNESS FOR A PARTICULAR PURPOSE.\n"
    "\n"
    "You should have received a copy of the GNU General Public License\n"
    "along with kmemcache; see the file COPYING.\n"
    "\n"
    "Copyright (c) 2003, Danga Interactive, Inc. <http://www.danga.com/>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions are\n"
    "met:\n"
    "\n"
    "    * Redistributions of source code must retain the above copyright\n"
    "notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "    * Redistributions in binary form must reproduce the above\n"
    "copyright notice, this list of conditions and the following disclaimer\n"
    "in the documentation and/or other materials provided with the\n"
    "distribution.\n"
    "\n"
    "    * Neither the name of the Danga Interactive nor the names of its\n"
    "contributors may be used to endorse or promote products derived from\n"
    "this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
    "\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
    "LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
    "A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
    "OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
    "SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
    "LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
    "OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    "\n"
    "\n"
    "This product includes software developed by Niels Provos.\n"
    "\n"
    "[ libevent ]\n"
    "\n"
    "Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions\n"
    "are met:\n"
    "1. Redistributions of source code must retain the above copyright\n"
    "   notice, this list of conditions and the following disclaimer.\n"
    "2. Redistributions in binary form must reproduce the above copyright\n"
    "   notice, this list of conditions and the following disclaimer in the\n"
    "   documentation and/or other materials provided with the distribution.\n"
    "3. All advertising materials mentioning features or use of this software\n"
    "   must display the following acknowledgement:\n"
    "      This product includes software developed by Niels Provos.\n"
    "4. The name of the author may not be used to endorse or promote products\n"
    "   derived from this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
    "IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
    "OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
    "IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
    "INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
    "NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
    "THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    );

    return;
}

/*
#ifndef HAVE_SIGIGNORE
static int sigignore(int sig)
{
	struct sigaction sa = {
		.sa_handler = SIG_IGN,
		.sa_flags   = 0
	};

	if (sigemptyset(&sa.sa_mask) == -1 ||
	    sigaction(sig, &sa, 0) == -1) {
		return -1;
	}
	return 0;
}
#endif
*/

/*
 * On systems that supports multiple page sizes we may reduce the
 * number of TLB-misses by using the biggest available page size
 */
static int enable_large_pages(void)
{
#if defined(HAVE_GETPAGESIZES) && defined(HAVE_MEMCNTL)
    int ret = -1;
    size_t sizes[32];
    int avail = getpagesizes(sizes, 32);
    if (avail != -1) {
        size_t max = sizes[0];
        struct memcntl_mha arg = {0};
        int ii;

        for (ii = 1; ii < avail; ++ii) {
            if (max < sizes[ii]) {
                max = sizes[ii];
            }
        }

        arg.mha_flags   = 0;
        arg.mha_pagesize = max;
        arg.mha_cmd = MHA_MAPSIZE_BSSBRK;

        if (memcntl(0, 0, MC_HAT_ADVISE, (caddr_t)&arg, 0, 0) == -1) {
            fprintf(stderr, "Failed to set large pages: %s\n",
                    strerror(errno));
            fprintf(stderr, "Will use default page size\n");
        } else {
            ret = 0;
        }
    } else {
        fprintf(stderr, "Failed to get supported pagesizes: %s\n",
                strerror(errno));
        fprintf(stderr, "Will use default page size\n");
    }

    return ret;
#else
    return -1;
#endif
}

static void settings_init(void)
{
	char *env;
	int val;

	settings.use_cas	= 1;
	settings.access		= 0700;
	settings.port		= 11211;
	settings.udpport	= 11211;
	/* By default this string should be NULL for getaddrinfo() */
	settings.inter		= NULL;
	settings.maxbytes	= 64 * 1024 * 1024; /* default is 64MB */
	settings.maxconns	= 1024;         /* to limit connections-related memory to about 5MB */
	settings.verbose	= 0;
	settings.oldest_live	= 0;
	settings.evict_to_free	= 1;       /* push old items out of cache when memory runs out */
	settings.socketpath	= NULL;       /* by default, not using a unix socket */
	settings.factor		= "1.25";
	settings.factor_numerator	= 125;
	settings.factor_denominator	= 100;
	settings.chunk_size	= 48;         /* space for a modest key and value */
	settings.num_threads_per_udp	= 0;
	settings.prefix_delimiter	= ':';
	settings.detail_enabled	= 0;
	settings.reqs_per_event	= 20;
	settings.backlog	= 1024;
	settings.binding_protocol	= negotiating_prot;
	settings.item_size_max	= 1024 * 1024; /* The famous 1MB upper limit. */
	settings.maxconns_fast	= 0;
	settings.hashpower_init	= 0;
	settings.slab_reassign	= 0;
	settings.slab_automove	= 0;
	settings.shutdown_command	= 0;
	settings.slab_bulk_check= DEFAULT_SLAB_BULK_CHECK;
	settings.hash_bulk_move	= DEFAULT_HASH_BULK_MOVE;
	settings.preallocate	= 0;

	env = getenv("MEMCACHED_HASH_BULK_MOVE");
	if (env != NULL) {
		val = atoi(env);
		if (val != 0) {
			settings.hash_bulk_move = val;
		}
	}

	env = getenv("MEMCACHED_SLAB_BULK_CHECK");
	if (env != NULL) {
		val = atoi(env);
		if (val != 0) {
			settings.slab_bulk_check = val;
		}
	}
}

static void double_int(char *fstr, int *nume, int *deno)
{
	int power, t = 1;
	double factor;
	char *pos = fstr;

	while (*pos++ != '.');
	power = strlen(pos);
	while (power-- > 0) t *= 10;

	factor = atof(fstr);
	*nume = t * factor;
	*deno = t;
}

static int wait_threads = 0;
static pthread_cond_t  wait_cond  = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;

void wait_for_thread_exit(int nthreads)
{
	while (wait_threads < nthreads) {
		pthread_cond_wait(&wait_cond, &wait_mutex);	
	}
}

void notify_thread_exit(void)
{
	pthread_mutex_lock(&wait_mutex);
	wait_threads++;
	pthread_mutex_unlock(&wait_mutex);
	pthread_cond_signal(&wait_cond);
}

int netlink_send(int sock, struct cn_msg *msg)
{
	int ret = 0;
	unsigned int size;
	struct nlmsghdr *nlh;
	struct cn_msg *m;
	char buf[NETLINK_PAYLOAD + sizeof(struct nlmsghdr)];

	size = NLMSG_SPACE(sizeof(struct cn_msg) + msg->len);

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_seq  = 0;
	nlh->nlmsg_pid  = getpid();
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_len  = NLMSG_LENGTH(size - sizeof(*nlh));
	nlh->nlmsg_flags= 0;

	m = NLMSG_DATA(nlh);
	memcpy(m, msg, sizeof(*m) + msg->len);

	ret = send(sock, nlh, size, 0);
	if (ret == -1) {
		perror("send msg error");
	}

	return ret;
}

static void process_cache_bh_status(struct cn_msg *msg)
{
	__s32 *status;

	status = (__s32 *)msg->data;
	if (*status) {
		printf("start kmemcache server success\n");
	} else {
		printf("start kmemcache server failed\n");
	}
}

#define MAX_EVENTS	1
static void main_loop(void)
{
	int ret, flags;
	int sock, epoll, nfds, i;
	struct sockaddr_nl local;
	struct epoll_event ev, events[MAX_EVENTS];

	sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_MEMCACHE);
	if (sock == -1) {
		perror("socket");
		return;
	}

	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl, F_GETFL");
		goto close_sock;
	}
	ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		perror("fcntl, F_SETFL");
		goto close_sock;
	}

	local.nl_family = AF_NETLINK;
	local.nl_groups = NETLINK_MEMCACHE_GRP;
	local.nl_pid	= 0;

	ret = bind(sock, (struct sockaddr *)&local, sizeof(local));
	if (ret == -1) {
		perror("bind");
		goto close_sock;
	}

	epoll = epoll_create(MAX_EVENTS);
	if (epoll == -1) {
		perror("epoll_create");
		goto close_sock;
	}

	ev.events  = EPOLLIN;
	ev.data.fd = sock;
	ret = epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &ev);
	if (ret == -1) {
		perror("epoll_ctl: add sock error");
		goto close_epoll;
	}

	netlink_send_cache_bh(sock);

	for (; ;) {
		nfds = epoll_wait(epoll, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			perror("epoll_wait error");
			break;
		}

		for (i = 0; i < nfds; i++) {
			if (events[i].data.fd == sock) {
				size_t len;
				struct nlmsghdr *nlh;
				char buf[NETLINK_PAYLOAD];
				struct cn_msg *msg;

				len = recv(sock, buf, sizeof(buf), 0);
				if (len == -1) {
					perror("recv sock error");
					continue;
				}

				nlh = (struct nlmsghdr *)buf;

				switch (nlh->nlmsg_type) {
				case NLMSG_ERROR:
					perror("netlink recv error");
					break;
				case NLMSG_DONE:
					msg = (struct cn_msg *)NLMSG_DATA(nlh);	

					switch (msg->id.idx) {
					case CN_IDX_INIT_SET:
						netlink_send_settings(sock, &msg->id);
						break;
					case CN_IDX_ENV:
						netlink_send_env(sock, msg);
						break;
					case CN_IDX_CACHE_BH_STATUS:
						process_cache_bh_status(msg);
						goto close_epoll;
					case CN_IDX_SHUTDOWN:
						netlink_send_shutdown(sock, &msg->id);
						goto close_epoll;
					default:
						break;
					}
				default:
					break;
				}
			}
		}
	}

close_epoll:
	close(epoll);
close_sock:
	close(sock);
}

int main(int argc, char *argv[])
{
	int c;
#ifdef enable_daemon
	int do_daemonize= 0;
#endif
	int maxcore	= 0;
	struct rlimit rlim;
	char unit	= '\0';
	int size_max	= 0;

	int protocol_specified	= 0;
	int tcp_specified	= 0;
	int udp_specified	= 0;

	char *subopts;
	char *subopts_value;

	enum {
		MAXCONNS_FAST = 0,
		HASHPOWER_INIT,
		SLAB_REASSIGN,
		SLAB_AUTOMOVE
	};
	char *const subopts_tokens[] = {
		[MAXCONNS_FAST]	= "maxconns_fast",
		[HASHPOWER_INIT]= "hashpower",
		[SLAB_REASSIGN] = "slab_reassign",
		[SLAB_AUTOMOVE] = "slab_automove",
		NULL
	};

	/* init settings */
	settings_init();
	
	/* set stderr non-buffering (for running under, say, daemontools) */
	setbuf(stderr, NULL);

	/* process arguments */
	while (-1 != (c = getopt(argc, argv,
		"a:"	/* access mask for unix socket */
		"A"	/* enable admin shutdown commannd */
		"p:"	/* TCP port number to listen on */
		"s:"	/* unix socket path to listen on */
		"U:"	/* UDP port number to listen on */
		"m:"	/* max memory to use for items in megabytes */
		"M"	/* return error on memory exhausted */
		"c:"	/* max simultaneous connections */
		"hi"	/* help, licence info */
		"r"	/* maximize core file limit */
		"v"	/* verbose */
#ifdef enable_daemon
		"d"	/* daemon mode */
#endif
		"l:"	/* interface to listen on */
		"f:"	/* factor? */
		"n:"	/* minimum space allocated for key+value+flags */
		"D:"	/* prefix delimiter? */
		"L"	/* Large memory pages */
		"R:"	/* max requests per event */
		"C"	/* Disable use of CAS */
		"b:"	/* backlog queue limit */
		"B:"	/* Binding protocol */
		"I:"	/* Max item size */
		"S"	/* Sasl ON */
		"o:"	/* Extended generic options */
	))) {
		switch (c) {
		case 'A':
			/* enables "shutdown" command */
			settings.shutdown_command = 1;
			break;

		case 'a':
			/* access for unix domain socket, as octal mask (like chmod)*/
			settings.access= strtol(optarg,NULL,8);
			break;

		case 'U':
			settings.udpport = atoi(optarg);
			udp_specified = 1;
			break;
		case 'p':
			settings.port = atoi(optarg);
			tcp_specified = 1;
			break;
		case 's':
			settings.socketpath = optarg;
			break;
		case 'm':
			settings.maxbytes = ((size_t)atoi(optarg)) * 1024 * 1024;
			break;
		case 'M':
			settings.evict_to_free = 0;
			break;
		case 'c':
			settings.maxconns = atoi(optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'i':
			usage_license();
			exit(EXIT_SUCCESS);
		case 'v':
			settings.verbose++;
			break;
		case 'l':
			if (settings.inter != NULL) {
				size_t len = strlen(settings.inter) + strlen(optarg) + 2;
				char *p = malloc(len);
				if (p == NULL) {
				fprintf(stderr, "Failed to allocate memory\n");
				return 1;
				}
				snprintf(p, len, "%s,%s", settings.inter, optarg);
				free(settings.inter);
				settings.inter = p;
			} else {
				settings.inter= strdup(optarg);
			}
			break;
#ifdef enable_daemon
		case 'd':
			do_daemonize = 1;
			break;
#endif
		case 'r':
			maxcore = 1;
			break;
		case 'R':
			settings.reqs_per_event = atoi(optarg);
			if (settings.reqs_per_event == 0) {
				fprintf(stderr, "Number of requests per event must be greater than 0\n");
				return 1;
			}
			break;
		case 'f':
			if (atof(optarg) <= 1.0) {
				fprintf(stderr, "Factor must be greater than 1\n");
				return 1;
			}
			settings.factor = strdup(optarg);
			double_int(optarg, &settings.factor_numerator, &settings.factor_denominator);
			break;
		case 'n':
			settings.chunk_size = atoi(optarg);
			if (settings.chunk_size == 0) {
				fprintf(stderr, "Chunk size must be greater than 0\n");
				return 1;
			}
			break;
		case 'D':
			if (! optarg || ! optarg[0]) {
				fprintf(stderr, "No delimiter specified\n");
				return 1;
			}
			settings.prefix_delimiter = optarg[0];
			settings.detail_enabled = 1;
			break;
		case 'L' :
			if (enable_large_pages() == 0) {
				settings.preallocate = 1;
			} else {
				fprintf(stderr, "Cannot enable large pages on this system\n"
				"(There is no Linux support as of this version)\n");
				return 1;
			}
			break;
		case 'C' :
			settings.use_cas = 0;
			break;
		case 'b' :
			settings.backlog = atoi(optarg);
			break;
		case 'B':
			protocol_specified = 1;
			if (strcmp(optarg, "auto") == 0) {
				settings.binding_protocol = negotiating_prot;
			} else if (strcmp(optarg, "binary") == 0) {
				settings.binding_protocol = binary_prot;
			} else if (strcmp(optarg, "ascii") == 0) {
				settings.binding_protocol = ascii_prot;
			} else {
				fprintf(stderr, "Invalid value for binding protocol: %s\n"
					" -- should be one of auto, binary, or ascii\n", optarg);
				exit(EX_USAGE);
			}
			break;
		case 'I':
			unit = optarg[strlen(optarg)-1];
			if (unit == 'k' || unit == 'm' ||
				unit == 'K' || unit == 'M') {
				optarg[strlen(optarg)-1] = '\0';
				size_max = atoi(optarg);
				if (unit == 'k' || unit == 'K')
				size_max *= 1024;
				if (unit == 'm' || unit == 'M')
				size_max *= 1024 * 1024;
				settings.item_size_max = size_max;
			} else {
				settings.item_size_max = atoi(optarg);
			}
			if (settings.item_size_max < 1024) {
				fprintf(stderr, "Item max size cannot be less than 1024 bytes.\n");
				return 1;
			}
			if (settings.item_size_max > 1024 * 1024 * 128) {
				fprintf(stderr, "Cannot set item size limit higher than 128 mb.\n");
				return 1;
			}
			if (settings.item_size_max > 1024 * 1024) {
				fprintf(stderr, "WARNING: Setting item max size above 1MB is not"
				" recommended!\n"
				" Raising this limit increases the minimum memory requirements\n"
				" and will decrease your memory efficiency.\n"
				);
			}
			break;
		case 'S': /* set Sasl authentication to 1. Default is 0 */
#ifndef ENABLE_SASL
			fprintf(stderr, "This server is not built with SASL support.\n");
			exit(EX_USAGE);
#endif
			settings.sasl = 1;
			break;
		case 'o': /* It's sub-opts time! */
			subopts = optarg;

			while (*subopts != '\0') {

				switch (getsubopt(&subopts, subopts_tokens, &subopts_value)) {
				case MAXCONNS_FAST:
					settings.maxconns_fast = 1;
					break;
				case HASHPOWER_INIT:
					if (subopts_value == NULL) {
						fprintf(stderr, "Missing numeric argument for hashpower\n");
						return 1;
					}
					settings.hashpower_init = atoi(subopts_value);
					if (settings.hashpower_init < 12) {
						fprintf(stderr, "Initial hashtable multiplier of %d is too low\n",
							settings.hashpower_init);
						return 1;
					} else if (settings.hashpower_init > 64) {
						fprintf(stderr, "Initial hashtable multiplier of %d is too high\n"
							"Choose a value based on \"STAT hash_power_level\" from a running instance\n",
							settings.hashpower_init);
						return 1;
					}
					break;
				case SLAB_REASSIGN:
					settings.slab_reassign = 1;
					break;
				case SLAB_AUTOMOVE:
					if (subopts_value == NULL) {
						settings.slab_automove = 1;
						break;
					}
					settings.slab_automove = atoi(subopts_value);
					if (settings.slab_automove < 0 || settings.slab_automove > 2) {
						fprintf(stderr, "slab_automove must be between 0 and 2\n");
						return 1;
					}
					break;
				default:
					printf("Illegal suboption \"%s\"\n", subopts_value);
					return 1;
				}

			}
			break;
		default:
			fprintf(stderr, "Illegal argument \"%c\"\n", c);
			return 1;
		}
	}

	/*
	 * Use one workerthread to serve each UDP port if the user specified
	 * multiple ports
	 */
	if (settings.inter != NULL && strchr(settings.inter, ',')) {
		settings.num_threads_per_udp = 1;
	} else {
		settings.num_threads_per_udp = 0x7fffffff;
	}

	if (settings.sasl) {
		if (!protocol_specified) {
			settings.binding_protocol = binary_prot;
		} else {
			if (settings.binding_protocol != binary_prot) {
				fprintf(stderr, "ERROR: You cannot allow the ASCII protocol while using SASL.\n");
				exit(EX_USAGE);
			}
		}
	}

	if (tcp_specified && !udp_specified) {
		settings.udpport = settings.port;
	} else if (udp_specified && !tcp_specified) {
		settings.port = settings.udpport;
	}

	if (maxcore != 0) {
		struct rlimit rlim_new;

		/*
		* First try raising to infinity; if that fails, try bringing
		* the soft limit to the hard.
		*/
		if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
			rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
			if (setrlimit(RLIMIT_CORE, &rlim_new)!= 0) {
				/* failed. try raising just to the old max */
				rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
				(void)setrlimit(RLIMIT_CORE, &rlim_new);
			}
		}

		/*
		* getrlimit again to see what we ended up with. Only fail if
		* the soft limit ends up 0, because then no core files will be
		* created at all.
		*/
		if ((getrlimit(RLIMIT_CORE, &rlim) != 0) || rlim.rlim_cur == 0) {
			fprintf(stderr, "failed to ensure corefile creation\n");
			exit(EX_OSERR);
		}
	}

	/*
	* If needed, increase rlimits to allow as many connections
	* as needed.
	*/
	if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
		fprintf(stderr, "failed to getrlimit number of files\n");
		exit(EX_OSERR);
	} else {
		rlim.rlim_cur = settings.maxconns;
		rlim.rlim_max = settings.maxconns;
		if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
			fprintf(stderr, "failed to set rlimit for open files. Try starting as root or requesting smaller maxconns value.\n");
			exit(EX_OSERR);
		}
	}

	/* lose root privileges if we have them */
	if (getuid() != 0 || geteuid() != 0) {
		fprintf(stderr, "run as root\n");
		exit(EX_USAGE);
	}

	/* Initialize Sasl if -S was specified */
	if (settings.sasl) {
	//	init_sasl();
	}

#ifdef enable_daemon
	/* daemonize if requested */
	/* if we want to ensure our ability to dump core, don't chdir to / */
	if (do_daemonize) {
		if (sigignore(SIGHUP) == -1) {
			perror("Failed to ignore SIGHUP");
		}
		if (daemonize(maxcore, settings.verbose) == -1) {
			fprintf(stderr, "failed to daemon() in order to daemonize\n");
			exit(EXIT_FAILURE);
		}
	}
#endif

	main_loop();

	return 0;
}
