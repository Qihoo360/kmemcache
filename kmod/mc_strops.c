#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/errno.h>

/* POSIX isspace */
static unsigned char __read_mostly type[] = {'\0', '\r', '\n', ' ', '\t', '\f', '\v'};
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
	char temp[65] = {'\0'};
	unsigned long long ull;

	while (*str == ' ')
		str++;
	if (unlikely(*str == '+'))
		str++;
	ull = simple_strtoull(str, &endptr, 10);
	if (endptr != str && ISSPACE(*endptr)) {
		if ((long long)ull < 0 && strchr(str, '-')) {
			return -EINVAL;
		}
		snprintf(temp, 64, "%llu", (u64)ull);
		if (!memcmp(temp, str, strlen(temp))) {
			*out = ull;
			return 0;
		}
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
	char temp[65] = {'\0'};
	long long ll;

	while (*str == ' ')
		str++;
	if (unlikely(*str == '+'))
		str++;
	ll = simple_strtoll(str, &endptr, 10);
	if (endptr != str && ISSPACE(*endptr)) {
		snprintf(temp, 64, "%lld", (s64)ll);
		if (!memcmp(temp, str, strlen(temp))) {
			*out = ll;
			return 0;
		}
	}
	return -EINVAL;
}

int safe_strtoul(const char *str, u32 *out)
{
	char *endptr = NULL;
	char temp[33] = {'\0'};
	unsigned long ul;

	while (*str == ' ')
		str++;
	if (unlikely(*str == '+'))
		str++;
	ul = simple_strtoul(str, &endptr, 10);
	if (endptr != str && ISSPACE(*endptr)) {
		if ((long)ul < 0 && strchr(str, '-')) {
			return -EINVAL;
		}
		snprintf(temp, 32, "%u", (u32)ul);
		if (!memcmp(temp, str, strlen(temp))) {
			*out = ul;
			return 0;
		}
	}
	return -EINVAL;
}

int safe_strtol(const char *str, s32 *out)
{
	char *endptr = NULL;
	char temp[33] = {'\0'};
	long l;

	while (*str == ' ')
		str++;
	if (unlikely(*str == '+'))
		str++;
	l = simple_strtol(str, &endptr, 10);
	if (endptr != str && ISSPACE(*endptr)) {
		snprintf(temp, 32, "%d", (s32)l);
		if (!memcmp(temp, str, strlen(temp))) {
			*out = l;
			return 0;
		}
	}
	return -EINVAL;
}

