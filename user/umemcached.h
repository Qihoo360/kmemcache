#ifndef __UMEMCACHED_H
#define __UMEMCACHED_H

#include <stdbool.h>

#include "config.h"
#include "memcache.h"
#include "connector.h"
#include "sasl.h"

//typedef int bool;

struct settings {
    size_t maxbytes;
    int maxconns;
    int port;
    int udpport;
    char *inter;
    int verbose;
    rel_time_t oldest_live; /* ignore existing items older than this */
    int evict_to_free;
    char *socketpath;   /* path to unix socket if using local socket */
    int access;  /* access mask (a la chmod) for unix domain socket */
    char *factor;		   /* chunk size growth factor */
    int factor_numerator;          /* chunk size growth factor */
    int factor_denominator;        /* chunk size growth factor */
    int chunk_size;
    int num_threads_per_udp; /* number of worker threads serving each udp socket */
    char prefix_delimiter;  /* character that marks a key prefix (for stats) */
    int detail_enabled;     /* nonzero if we're collecting detailed stats */
    int reqs_per_event;     /* Maximum number of io to process on each
                               io-event. */
    bool use_cas;
    protocol_t binding_protocol;
    int backlog;
    int item_size_max;        /* Maximum item size, and upper end for slabs */
    bool sasl;              /* SASL on/off */
    bool maxconns_fast;     /* Whether or not to early close connections */
    bool slab_reassign;     /* Whether or not slab reassignment is allowed */
    int slab_automove;     /* Whether or not to automatically move slabs */
    int hashpower_init;     /* Starting hash power level */
    bool shutdown_command; /* allow shutdown command */
    int slab_bulk_check;
    int hash_bulk_move;
    bool preallocate;
};

extern struct settings settings;

extern void wait_for_thread_exit(int nthreads);
extern void notify_thread_exit(void);

extern int daemonize(int nochdir, int noclose);

extern int netlink_send(int sock, struct cn_msg *msg);
extern int netlink_send_env(int sock, struct cn_msg *rcv);
extern int netlink_send_settings(int sock, struct cn_id *id);
extern int netlink_send_cache_bh(int sock);
extern int netlink_send_shutdown(int sock, struct cn_id *id);

#endif /* __UMEMCACHED_H */
