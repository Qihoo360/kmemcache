#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/string.h>

#include "mc.h"
#include "kmodtest.h"

#define COPY_FROM_USER(type)							\
	do {									\
		if (unlikely(!access_ok(VERIFY_WRITE, user, sizeof(type))))	\
			return -EFAULT;						\
		if (copy_from_user(&kern, user, sizeof(type)))			\
			return -EFAULT;						\
		if (unlikely(!access_ok(VERIFY_READ, kern.str.p, kern.str.len)))\
			return -EFAULT;						\
		str = strndup_user(kern.str.p, kern.str.len);			\
		if (IS_ERR(str))						\
			return -EFAULT;						\
	} while (0)

static int str_ull_helper(unsigned long __user arg)
{
	int ret;
	char *str;
	struct str_ull kern, *user;

	user = (struct str_ull *)arg;
	COPY_FROM_USER(struct str_ull);

	ret = safe_strtoull(str, &kern.out);
	if (!ret && __copy_to_user(&user->out, &kern.out, sizeof(__u64))) {
		ret = -EFAULT;
	}

	kfree(str);
	return ret;
}

static int str_ll_helper(unsigned long __user arg)
{
	int ret;
	char *str;
	struct str_ll kern, *user;

	user = (struct str_ll *)arg;
	COPY_FROM_USER(struct str_ll);

	ret = safe_strtoll(str, &kern.out);
	if (!ret && __copy_to_user(&user->out, &kern.out, sizeof(__s64))) {
		ret = -EFAULT;
	}

	kfree(str);
	return ret;
}

static int str_ul_helper(unsigned long __user arg)
{
	int ret;
	char *str;
	struct str_ul kern, *user;

	user = (struct str_ul *)arg;
	COPY_FROM_USER(struct str_ul);

	ret = safe_strtoul(str, &kern.out);
	if (!ret && __copy_to_user(&user->out, &kern.out, sizeof(__u32))) {
		ret = -EFAULT;
	}

	kfree(str);
	return ret;
}

static int str_l_helper(unsigned long __user arg)
{
	int ret;
	char *str;
	struct str_l kern, *user;

	user = (struct str_l *)arg;
	COPY_FROM_USER(struct str_l);

	ret = safe_strtol(str, &kern.out);
	if (!ret && __copy_to_user(&user->out, &kern.out, sizeof(__s32))) {
		ret = -EFAULT;
	}

	kfree(str);
	return ret;
}

static long kmc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case KMC_STR_ULL:
		ret = str_ull_helper(arg);
		break;
	case KMC_STR_LL:
		ret = str_ll_helper(arg);
		break;
	case KMC_STR_UL:
		ret = str_ul_helper(arg);
		break;
	case KMC_STR_L:
		ret = str_l_helper(arg);
		break;
	default:
		BUG();
		break;
	}

	return ret;
}

static int kmc_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int kmc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations kmc_miscdev_fops = {
	.owner		= THIS_MODULE,
	.open		= kmc_open,
	.unlocked_ioctl	= kmc_ioctl,
	.release	= kmc_release,
};

static struct miscdevice kmc_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "kmemcache",
	.fops	= &kmc_miscdev_fops,
};

static int __init kmc_test_init(void)
{
	int ret = 0;

	ret = misc_register(&kmc_miscdev);
	if (ret) {
		PRINTK("register kmc_miscdev error\n");
	}

	return ret;
}

static void __exit kmc_test_exit(void)
{
	misc_deregister(&kmc_miscdev);
}

module_init(kmc_test_init);
module_exit(kmc_test_exit);

MODULE_AUTHOR("Li Jianguo <byjgli@gmail.com>");
MODULE_DESCRIPTION("kmemcache test");
MODULE_LICENSE("GPL v2");
