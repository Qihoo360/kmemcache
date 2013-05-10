#include <linux/oom.h>
#include <linux/notifier.h>
#include "mc.h"

/* must run in process context */
static int mc_oom_notify(struct notifier_block *nb, unsigned long dummy, void *v)
{
	unsigned long *freed = v;

	/* simple treatment now */
	*freed += 1;

	return NOTIFY_OK;
}

static struct notifier_block mc_oom_nb = {
	.notifier_call	= mc_oom_notify,
};

int oom_init(void)
{
	return register_oom_notifier(&mc_oom_nb);
}

void oom_exit(void)
{
	unregister_oom_notifier(&mc_oom_nb);
}
