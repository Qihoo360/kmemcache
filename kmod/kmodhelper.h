#ifndef _KMOD_HELPER
#define _KMOD_HELPER

typedef void (*kmod_callback_t)(void *);

extern int register_callback(kmod_callback_t fun, void *arg);

#endif /* _KMOD_HELPER */
