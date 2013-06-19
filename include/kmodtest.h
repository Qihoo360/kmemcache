#ifndef __KMOD_TEST_H
#define __KMOD_TEST_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct __str {
	size_t	     len;
	const char   *p;
};

struct str_ull {
	struct __str str;
	__u64	     out;	
};

struct str_ll {
	struct __str str;
	__s64	     out;	
};

struct str_ul {
	struct __str str;
	__u32	     out;	
};

struct str_l {
	struct __str str;
	__s32	     out;	
};

#define KMC_MAGIC	0xff

#define KMC_STR_ULL	_IOWR(KMC_MAGIC, 0, struct str_ull)
#define KMC_STR_LL	_IOWR(KMC_MAGIC, 1, struct str_ll)
#define KMC_STR_UL	_IOWR(KMC_MAGIC, 2, struct str_ul)
#define KMC_STR_L	_IOWR(KMC_MAGIC, 3, struct str_l)

#endif /* __KMOD_TEST_H */
