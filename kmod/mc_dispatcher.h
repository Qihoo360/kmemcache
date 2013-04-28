#ifndef __MC_DISPATCHER_H
#define __MC_DISPATCHER_H

#include <linux/kthread.h>
#include <asm/atomic.h>

/* dispatcher master */
struct dispatcher_master {
#define ACCEPT_NEW	1
	unsigned long flags;

	struct list_head listen_list;	/* tcp/unix socket list */
	struct list_head udp_list;	/* udp socket list */
	spinlock_t sock_lock;

#ifdef CONFIG_SINGLE_DISPATCHER
	atomic_long_t req;		/* all client requests num */
	struct task_struct *dsp_tsk;	/* master dispatcher kthread */
	struct list_head dsp_list;	/* dispatch job list */
	spinlock_t dsp_lock;
#endif
};

extern struct dispatcher_master dsper;

/* dispatcher listen socket */
struct serve_sock {
	atomic_long_t req;		/* client requests num */

	net_transport_t transport;
	unsigned long state;		/* conn state */
	struct socket *sock;		/* listen socket */

	struct list_head list;		/* link to master's listen list */
#ifdef CONFIG_SINGLE_DISPATCHER
	struct list_head dsp_list;	/* link to master's job list */
#endif
	struct task_struct *dsp_tsk;	/* tcp/unix gets a dispatcher kthread */
};

extern void	mc_accept_new_conns(int enable);
extern int	dispatcher_init(void);
extern void	dispatcher_exit(void);
extern int	server_init(void);
extern void	server_exit(void);

#endif /* __MC_DISPATCHER_H */
