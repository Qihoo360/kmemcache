#ifndef __MC_PROTO_H
#define __MC_PROTO_H

#include "mc_proto_bin.h"

struct proto_operations {
	protocol_t proto;

	void (*dispatch)(conn *c, char *cmd);
	void (*complete_nread)(conn *c);
	void (*append_stats)(const char *key, u16 klen,
			     const char *val, u32 vlen, conn *c);
};

extern const struct proto_operations bin_proto_ops;
extern const struct proto_operations txt_proto_ops;
extern const struct proto_operations def_proto_ops;

extern struct kmem_cache *suffix_cachep;

static inline void* _suffix_new(void)
{
	return kmem_cache_alloc(suffix_cachep, GFP_KERNEL);
}

static inline void _suffix_free(void *objp)
{
	kmem_cache_free(suffix_cachep, objp);
}

void	mc_out_string(conn *c, const char *str);
delta_result_t mc_do_add_delta(conn *c, const char *key, size_t nkey, u8 incr,
			       s64 delta, char *buf, u64 *cas, u32 hv);
store_item_t mc_do_store_item(item *item, int comm, conn* c, u32 hv);
void	mc_append_stat(const char *name, add_stat_callback add_stats,
		       conn *c, const char *fmt, ...);
void	mc_append_stats(const char *key, const u16 klen, const char *val,
		        u32 vlen, const void *cookie);
void	mc_server_stats(add_stat_callback add_stats, conn *c);
void	conn_set_state(conn *c, conn_state_t state);
void	mc_stat_settings(add_stat_callback add_stats, void *c);
void	write_and_free(conn *c, struct buffer *buf, int bytes);
int	mc_add_msghdr(conn *c);
int	mc_build_udp_headers(conn *c);
int	mc_add_iov(conn *c, const void *buf, int len);
void	mc_worker_machine(conn *c);

#endif /* __MC_PROTO_H */
