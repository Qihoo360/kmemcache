#ifndef __MC_OOM_H
#define __MC_OOM_H

#ifdef CONFIG_OOM
extern int oom_init(void);
extern void oom_exit(void);
#else
static inline int oom_init(void) { return 0; }
static inline void oom_exit(void) { }
#endif

#endif /* __MC_OOM_H */
