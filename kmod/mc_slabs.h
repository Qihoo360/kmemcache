#ifndef __MC_SLAB_H
#define __MC_SLAB_H

/* percent of totalram that slabs could use */
extern unsigned long slabsize;

/* init the subsystem */
extern int slabs_init(size_t limit, int factor_nume, int factor_deno, bool prealloc);

/* clear up the subsystem */
extern void slabs_exit(void);

/* figures out which slab class (chunk size) is required */
extern unsigned int mc_slabs_clsid(size_t size);

/* allocate object of given length */
extern void* mc_slabs_alloc(size_t size, unsigned int id);

/* free previously allocated object */
extern void mc_slabs_free(void *ptr, size_t size, unsigned int id);

/* adjust the stats for memory requested */
extern void mc_slabs_adjust_mem_requested(unsigned int id, size_t old, size_t ntotal);

/* return a datum for stats in binary protocol */
extern int mc_get_stats(const char *stat_type, int nkey, add_stat_fn f, void *c);

/* fill buffer with stats */
extern void mc_slabs_stats(add_stat_fn f, void *c);

#define REASSIGN_OK		0x0
#define	REASSIGN_RUNNING	0x1
#define	REASSIGN_BADCLASS	0x2
#define	REASSIGN_NOSPACE	0x3
#define	REASSIGN_SRC_DST_SAME	0x4

struct slab_rebal {
	unsigned long flag;
	struct task_struct *tsk;
	wait_queue_head_t wq;

	struct mutex lock;
	void *slab_start;
	void *slab_end;
	void *slab_pos;
	int s_clsid;
	int d_clsid;
	int busy_items;
	u8 done;
	u8 signal;
};

extern struct slab_rebal slab_rebal;

extern int start_slab_thread(void);
extern void stop_slab_thread(void);

extern int mc_slabs_reassign(int src, int dst);

extern void mc_wakeup_slabs_mten(void);

extern void mc_slabs_rebalancer_pause(void);
extern void mc_slabs_rebalancer_resume(void);

#endif /* __MC_SLAB_H */
