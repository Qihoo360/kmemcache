#ifndef __MC_SASL_H
#define __MC_SASL_H

typedef struct {
	void ** pconn;
} sasl_dispose_t;

#ifdef __KERNEL__

// Longest one I could find was ``9798-U-RSA-SHA1-ENC''
#define MAX_SASL_MECH_LEN 32

#define SASL_OK		0
#define SASL_CONTINUE	1
#define SASL_USERNAME	0

typedef void sasl_conn_t;
typedef struct sasl_callback {
	unsigned long id;
	int (*proc)(void);
	void *context;
} sasl_callback_t;

#ifdef CONFIG_SASL
void	mc_sasl_dispose(sasl_conn_t **pconn);
int	mc_sasl_server_new(const char *service,
			   const char *serverFQDN,
			   const char *user_realm,
			   const char *iplocalport,
			   const char *ipremoteport,
			   const sasl_callback_t *callbacks,
			   unsigned flags,
			   sasl_conn_t **pconn);
int	mc_sasl_listmech(sasl_conn_t *conn,
			 const char *user,
			 const char *prefix,
			 const char *sep,
			 const char *suffix,
			 const char **result,
			 unsigned *plen,
			 int *pcount);
int	mc_sasl_server_start(sasl_conn_t *conn,
			     const char *mech,
			     const char *clientin,
			     unsigned clientinlen,
			     const char **serverout,
			     unsigned *serveroutlen);
int	mc_sasl_server_step(sasl_conn_t *conn,
			    const char *clientin,
			    unsigned clientinlen,
			    const char **serverout,
			    unsigned *serveroutlen);
int	mc_sasl_getprop(sasl_conn_t *conn,
			int propnum,
			const void **pvalue);

extern char my_sasl_hostname[1025];
#else
#define mc_init_sasl() {}
#define mc_sasl_dispose(x) {}
#define mc_sasl_server_new(a, b, c, d, e, f, g, h) 1
#define mc_sasl_listmech(a, b, c, d, e, f, g, h) 1
#define mc_sasl_server_start(a, b, c, d, e, f) 1
#define mc_sasl_server_step(a, b, c, d, e) 1
#define mc_sasl_getprop(a, b, c) {}
#endif

#endif /* __KERNEL__ */
#endif /* __MC_SASL_H */
