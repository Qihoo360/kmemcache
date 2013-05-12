#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "mc.h"

#define alloc_policy(len)		\
({					\
 	unsigned int flags = 0;		\
 	if ((len) <= BUF_KMALLOC_MAX)	\
 		flags = BUF_KMALLOC;	\
 	else if ( len > BUF_PAGES_MAX)	\
 		flags = BUF_VMALLOC;	\
 	else				\
 		flags = BUF_PAGES;	\
 	flags;				\
})

static inline int _alloc_buffer(struct buffer *buf, size_t len, gfp_t mask)
{
	int ret = 0;
	unsigned int order;

	order = get_order(len);
	if (unlikely(order >= MAX_ORDER)) {
		ret = -EFBIG;
		goto out;
	}

#ifdef CONFIG_X86_32
	buf->_page = alloc_pages(mask | GFP_PAGES, order);
	if (!buf->_page) {
		ret = -ENOMEM;
		goto out;
	}
	buf->buf = kmap(buf->_page);
#else
	buf->buf = (void *)__get_free_pages(mask | GFP_PAGES, order);
	if (!buf->buf) {
		ret = -ENOMEM;
		goto out;
	}
#endif
	buf->room = (_AC(1,UL) << (order + PAGE_SHIFT));

out:
	return ret;
}

int alloc_buffer(struct buffer *buf, size_t len, gfp_t mask)
{
	int ret = 0;
	unsigned int which;

	which = alloc_policy(len);
xchg:
	switch (which) {
	case BUF_KMALLOC:
		buf->buf = kmalloc(len, mask | GFP_KERNEL);
		if (!buf->buf) {
			PRINFO("kmalloc - alloc buffer error");
			ret = -ENOMEM;
			goto out;
		}
		buf->room = ksize(buf->buf);
		break;
	case BUF_VMALLOC:
		buf->buf = __vmalloc(len, mask | GFP_PAGES, PAGE_KERNEL);
		if (!buf->buf) {
			PRINFO("vmalloc - alloc buffer error");
			ret = -ENOMEM;
			goto out;
		}
		buf->room = len;
		break;
	case BUF_PAGES:
		ret = _alloc_buffer(buf, len, mask);
		if (ret) {
			PRINFO("alloc_pages - alloc buffer error");
			ret = 0;
			which = BUF_VMALLOC;
			goto xchg;
		}
		break;
	default:
		BUG();
		break;
	}

	if (ret == 0) {
		buf->flags = which;
	}
out:
	return ret;
}

static inline void _memcpy(void *dst, struct buffer *buf, size_t valid)
{
	void *src;

	src = buf->buf;
	memcpy(dst, src, valid);
}

static inline void _memmove(struct buffer *dst, struct buffer *src, size_t valid)
{
	void *_dst;

	_dst = dst->buf;
	_memcpy(_dst, src, valid);
}

static inline int _realloc_buffer(struct buffer *buf, size_t len, size_t valid, gfp_t mask)
{
	struct buffer new_buf;

	if (alloc_buffer(&new_buf, len, mask))
		return -ENOMEM;

	_memmove(&new_buf, buf, valid);
	free_buffer(buf);
	memcpy(buf, &new_buf, sizeof(*buf));
	
	return 0;
}

static inline int _realloc_buffer_more(struct buffer *buf, size_t more, size_t valid, gfp_t mask)
{
	return _realloc_buffer(buf, more, valid, mask);
}

static inline int _realloc_buffer_less(struct buffer *buf, size_t less, size_t valid, gfp_t mask)
{
	if (buf->flags == BUF_KMALLOC)
		return 0;

	if (buf->flags == BUF_PAGES && alloc_policy(less) == BUF_PAGES) {
		unsigned int neworder, oldorder; 
		neworder = get_order(less);
		oldorder = get_order(buf->room);
		if (neworder == oldorder)
			return 0;
	}

	return _realloc_buffer(buf, less, valid, mask);
}

int realloc_buffer(struct buffer *buf, size_t len, size_t valid, gfp_t mask)
{
	BUG_ON(buf->flags >= BUF_FLAGS_MAX);
	if (buf->flags == BUF_NEGATIVE)
		return alloc_buffer(buf, len, mask);
	if (len > buf->room) {
		return _realloc_buffer_more(buf, len, valid, mask);
	}
	if (len < buf->room) {
		return _realloc_buffer_less(buf, len, valid, mask);
	}
	return 0;
}

static inline void __free_buffer(struct buffer *buf)
{
	unsigned int order;

	order = get_order(buf->room);

#ifdef CONFIG_X86_32
	kunmap(buf->_page);
	__free_pages(buf->_page, order);
#else
	free_pages((unsigned long)buf->buf, order);
#endif
}

static inline void _free_buffer(struct buffer *buf)
{
	switch (buf->flags) {
	case BUF_KMALLOC:
		kfree(buf->buf);
		break;
	case BUF_VMALLOC:
		vfree(buf->buf);
		break;
	case BUF_PAGES:
		__free_buffer(buf);
		break;
	case BUF_NEGATIVE:
		break;
	default:
		BUG();
		break;
	}
}

void free_buffer(struct buffer *buf)
{
	_free_buffer(buf);
}

void free_buffer_init(struct buffer *buf)
{
	_free_buffer(buf);
	init_buffer(buf);
}
