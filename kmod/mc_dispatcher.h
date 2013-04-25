#ifndef __MC_DISPATCHER_H
#define __MC_DISPATCHER_H

/* dispatcher thread */
struct dispatcher_thread {
#define ACCEPT_NEW	1
	unsigned long flags;

	struct workqueue_struct *wq;
	struct list_head list;		/* tcp/unix socket */
	spinlock_t lock;

	struct list_head udp_list;	/* init/exit, no lock */

	/* init */
	atomic_t _workers;
	struct completion _comp;
};

extern int single_dispatch;
extern struct dispatcher_thread dispatcher;

#define BEGIN_WAIT_FOR_THREAD_REGISTRATION()	\
	do {					\
		atomic_set(&dispatcher._workers,\
			   0);			\
	} while (0)

#define WAIT_FOR_THREAD_REGISTRATION()		\
	do {					\
		wait_for_completion(            \
			&dispatcher._comp);	\
	} while (0)

#define REGISTER_THREAD_INITIALIZED()			\
	do {						\
		int finish = atomic_inc_return(         \
				&dispatcher._workers);	\
		if (finish == settings.num_threads)	\
			complete(&dispatcher._comp);	\
	} while (0)

struct serve_sock {
	net_transport_t transport;
	unsigned long state;	/* conn state */
	struct socket *sock;
	struct work_struct work;
	struct list_head list;
};

/* init settings callback return */
typedef struct {
	s8  flags;
	u16 len;
	s8  data[0];
} parser_sock_t;
extern parser_sock_t *sock_info;

#ifdef CONFIG_LISTEN_CACHE
struct server_work {
	struct work_struct work;
	struct serve_sock *ss;
};

extern struct kmem_cache *listen_cachep;
#endif

void	mc_accept_new_conns(int enable);
int	dispatcher_init(void);
void	dispatcher_exit(void);
int	server_init(void);
void	server_exit(void);

#endif /* __MC_DISPATCHER_H */
