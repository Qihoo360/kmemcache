#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/errno.h>

/* POSIX isspace */
static unsigned char __read_mostly type[] = {'\0', '\r', '\n', '\t', '\f', '\v'};
#define ISSPACE(c)				\
({						\
 	int i, res = 0;				\
 	for (i = 0; i < sizeof(type); i++) { 	\
 		if (type[i] == c) {		\
 			res = 1;		\
 			break;			\
 		}				\
 	}					\
 	res;					\
})

int safe_strtoull(const char *str, u64 *out)
{
	char *endptr = NULL;
	unsigned long long ull;

	ull = simple_strtoull(str, &endptr, 10);
	if (endptr == str)
		return -EINVAL;
	if (ISSPACE(*endptr)) {
		if ((long long)ull < 0 && strchr(str, '-')) {
			return -EINVAL;
		}
		*out = ull;
		return 0;
	}
	return -EINVAL;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
static long long __simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoull(cp + 1, endp, base);
	return simple_strtoull(cp, endp, base);
}

#define simple_strtoll __simple_strtoll
#endif

int safe_strtoll(const char *str, s64 *out)
{
	char *endptr = NULL;
	long long ll;

	ll = simple_strtoll(str, &endptr, 10);
	if (endptr == str)
		return -EINVAL;
	if (ISSPACE(*endptr) || *endptr == '\0') {
		*out = ll;
		return 0;
	}
	return -EINVAL;
}

int safe_strtoul(const char *str, u32 *out)
{
	char *endptr = NULL;
	unsigned long ul;

	ul = simple_strtoul(str, &endptr, 10);
	if (endptr == str)
		return -EINVAL;
	if (ISSPACE(*endptr) || *endptr == '\0') {
		if ((long)ul < 0 && strchr(str, '-')) {
			return -EINVAL;
		}
		*out = ul;
		return 0;
	}
	return -EINVAL;
}

int safe_strtol(const char *str, s32 *out)
{
	char *endptr = NULL;
	long l;

	l = simple_strtol(str, &endptr, 10);
	if (endptr == str)
		return -EINVAL;
	if (ISSPACE(*endptr) || *endptr == '\0') {
		*out = l;
		return 0;
	}
	return -EINVAL;
}

