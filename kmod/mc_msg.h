#ifndef __MC_MSG_H
#define __MC_MSG_H

#define MSG_SYS_CONNS	0
#define MSG_MAX		108

extern char* s2c_msg[MSG_MAX];
extern u8    s2c_len[MSG_MAX];

extern void msg_init(void);

#endif
