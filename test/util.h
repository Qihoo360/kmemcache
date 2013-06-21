#ifndef __TEST_UTIL_H
#define __TEST_UTIL_H

extern void close_terminal(void);

extern void insert_kmod(const char *mod);
extern int  check_kmod(const char *mod);
extern void remove_kmod(const char *mod);

extern void __start_kmc_server(char *argv[]);
extern void __stop_kmc_server(char *argv[]);

extern void start_kmc_server(char *argv[]);
extern void stop_kmc_server(char *argv[]);

#endif /* __TEST_UTIL_H */
