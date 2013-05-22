#include <linux/kernel.h>
#include <linux/string.h>
#include "mc_msg.h"

char* s2c_msg[MSG_MAX] = {
	"ERROR Too many open connections\r\n",
};

u8 s2c_len[MSG_MAX];

void msg_init(void)
{
	int i;

	for (i = 0; i < MSG_MAX; i++) {
		s2c_len[i] = strlen(s2c_msg[i]);
	}
}
