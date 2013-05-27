#ifndef __UPARAM_H
#define __UPARAM_H

/* msg timeout from umemcached in seconds */
extern int timeout;

/* init settings callback return */
typedef struct {
	s8  flags;
	u16 len;
	s8  data[0];
} parser_sock_t;

/* used only once, then free */
extern parser_sock_t *sock_info;

extern int settings_init(void);
extern void settings_exit(void);

extern void shutdown_cmd(void);

#endif /* __UPARAM_H */
