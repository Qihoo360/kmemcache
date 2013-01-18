#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "mc.h"

#ifdef CONFIG_PAGES_CACHE

#define MAX_RETRY	2

static unsigned long totalpages;
static LIST_HEAD(pages_cache);
static DEFINE_SPINLOCK(pages_cache_lock);

static inline int free_max_order(void)
{
	struct pages *pages, *max = NULL;

	spin_lock_bh(&pages_cache_lock);
	list_for_each_entry(pages, &pages_cache, list) {
		if (!max) {
			max = pages;
		} else if (pages->order > max->order) {
			max = pages;
		}
	}
	if (max) {
		list_del(&max->list);
		totalpages -= (1 << max->order);
		spin_unlock_bh(&pages_cache_lock);
		goto free_pages;
	}
	spin_unlock_bh(&pages_cache_lock);

	return -EFAULT;

free_pages:
	__free_pages(max->page, max->order);
	kfree(max);
	return 0;
}

static inline int free_next_order(unsigned int order)
{
	struct pages *pages, *nxt = NULL;

	spin_lock_bh(&pages_cache_lock);
retry_nxt:
	list_for_each_entry(pages, &pages_cache, list) {
		if (pages->order == order + 1) {
			nxt = pages;
			break;
		}
	}
	if (!nxt && !list_empty(&pages_cache)) {
		order++;
		goto retry_nxt;
	}
	if (nxt) {
		list_del(&nxt->list);
		totalpages -= (1 << nxt->order);
		spin_unlock_bh(&pages_cache_lock);
		goto free_pages;
	}
	spin_unlock_bh(&pages_cache_lock);

	return -EFAULT;

free_pages:
	__free_pages(nxt->page, nxt->order);
	kfree(nxt);
	return 0;
}

static int _alloc_buffer(struct buffer *buf, size_t len)
{
	int order, ret = 0, retry = 0;
	struct pages *pages, *n;

	order = get_order(len);
	if ((1 << order) * PAGE_SIZE < len)
		order += 1;

	spin_lock_bh(&pages_cache_lock);
	list_for_each_entry_safe(pages, n, &pages_cache, list) {
		if (pages->order == order) {
			list_del(&pages->list);
			totalpages -= (1 << pages->order);
			break;
		}
	}
	spin_unlock_bh(&pages_cache_lock);

	if (&pages->list == &pages_cache) {
retry_kmalloc:
		pages = (struct pages *)kmalloc(sizeof(*pages), GFP_KERNEL);
		if (!pages) {
			if (retry > MAX_RETRY) {
				ret = -ENOMEM;
				goto out;
			}
			if (!free_max_order()) {
				retry++;
				goto retry_kmalloc;
			} else {
				ret = -ENOMEM;
				goto out;
			}
		}

retry_page:
		pages->page = alloc_pages(GFP_PAGES, order);
		if (!pages->page) {
			if (retry > MAX_RETRY) {
				kfree(pages);
				ret = -ENOMEM;
				goto out;
			}
			if (!free_next_order(order)) {
				retry++;
				goto retry_page;
			} else {
				kfree(pages);
				ret = -ENOMEM;
				goto out;
			}
		}
		pages->order = order;
	}

	pages->buf = kmap(pages->page);
	buf->_pages = pages;
	buf->room  = (1 << (order + PAGE_SHIFT));

out:
	return ret;
}

static void _free_buffer(struct buffer *buf)
{
	unsigned int add;
	struct pages *pages = buf->_pages;

	add = (1 << pages->order);
	kunmap(pages->page);

	spin_lock_bh(&pages_cache_lock);
	if (totalpages + add < totalram_pages / 4) {
		list_add(&pages->list, &pages_cache);
		totalpages += add;
	} else {
		spin_unlock_bh(&pages_cache_lock);
		goto free_pages;
	}
	spin_unlock_bh(&pages_cache_lock);

	return;

free_pages:
	__free_pages(pages->page, pages->order);
	kfree(pages);
}

void pages_cache_exit(void)
{
	struct pages *pages, *n;

	spin_lock_bh(&pages_cache_lock);
	list_for_each_entry_safe(pages, n, &pages_cache, list) {
		__free_pages(pages->page, pages->order);
		list_del(&pages->list);
		kfree(pages);
	}
	spin_unlock_bh(&pages_cache_lock);
}

#else
static inline int _alloc_buffer(struct buffer *buf, size_t len)
{
	int ret = 0;

	buf->buf_order = get_order(len);
	if ((1 << buf->buf_order) * PAGE_SIZE < len)
		buf->buf_order++;

	buf->buf_page = alloc_pages(GFP_PAGES, buf->buf_order);
	if (!buf->buf_page) {
		ret = -ENOMEM;
		goto out;
	}
	buf->room = (1 << (buf->buf_order + PAGE_SHIFT));
	buf->buf_addr = kmap(buf->buf_page);

out:
	return ret;
}

static inline void _free_buffer(struct buffer *buf)
{
	kunmap(buf->buf_page);
	__free_pages(buf->buf_page, buf->buf_order);
}
#endif

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

int alloc_buffer(struct buffer *buf, size_t len)
{
	int ret = 0;
	unsigned int flags;

	flags = alloc_policy(len);
xchg:
	switch (flags) {
	case BUF_KMALLOC:
		buf->buf = kmalloc(len, GFP_KERNEL);
		if (!buf->buf) {
			PRINTK("kmalloc: alloc buffer error");
			ret = -ENOMEM;
			goto out;
		}
		buf->room = ksize(buf->buf);
		break;
	case BUF_VMALLOC:
		buf->buf = vmalloc(len);
		if (!buf->buf) {
			PRINTK("vmalloc: alloc buffer error");
			ret = -ENOMEM;
			goto out;
		}
		break;
	case BUF_PAGES:
		ret = _alloc_buffer(buf, len);
		if (ret) {
			PRINTK("alloc_pages: alloc buffer error");
			ret = 0;
			flags = BUF_VMALLOC;
			goto xchg;
		}
		break;
	default:
		BUG();
		break;
	}

	if (ret == 0) {
		buf->flags = flags;
		buf->len = len;
	}
out:
	return ret;
}

static inline void _memcpy(void *dst, struct buffer *buf, size_t valid)
{
	void *src;

	switch (buf->flags) {
	case BUF_KMALLOC:
	case BUF_VMALLOC:
		src = buf->buf;
		break;
	case BUF_PAGES:
		src = buf->buf_addr;
		break;
	default:
		BUG();
		break;
	}

	memcpy(dst, src, valid);
}

static inline void _memmove(struct buffer *dst, struct buffer *src, size_t valid)
{
	void *_dst;

	switch (dst->flags) {
	case BUF_KMALLOC:
	case BUF_VMALLOC:
		_dst = dst->buf;
		break;
	case BUF_PAGES:
		_dst = dst->buf_addr;
		break;
	default:
		BUG();
		break;
	}

	return _memcpy(_dst, src, valid);
}

static inline int _realloc_buffer(struct buffer *buf, size_t len, size_t valid)
{
	struct buffer new_buf;

	if (alloc_buffer(&new_buf, len)) {
		return -ENOMEM;
	}

	_memmove(&new_buf, buf, valid);
	free_buffer(buf);
	memcpy(buf, &new_buf, sizeof(*buf));
	
	return 0;
}

static inline int _realloc_buffer_more(struct buffer *buf, size_t more, size_t valid)
{
	if (buf->flags == BUF_PAGES &&
	    buf->room >= more) {
		return 0;
	}
	if (buf->flags == BUF_KMALLOC &&
	    buf->room >= more) {
		return 0;
	}

	return _realloc_buffer(buf, more, valid);
}

static inline int _realloc_buffer_less(struct buffer *buf, size_t less, size_t valid)
{
	if (valid > less) {
		PRINTK("_realloc_buffer_less error");
		return -EINVAL;
	}

	return _realloc_buffer(buf, less, valid);
}

int realloc_buffer(struct buffer *buf, size_t len, size_t valid)
{
	if (!len || valid > buf->len) {
		BUG();
		return -EINVAL;
	}

	if (len > buf->len) {
		return _realloc_buffer_more(buf, len, valid);
	}
	else if (len < buf->len) {
		return _realloc_buffer_less(buf, len, valid);
	} else {
		return 0;
	}
}

void free_buffer(struct buffer *buf)
{
	switch (buf->flags) {
	case BUF_KMALLOC:
		kfree(buf->buf);
		break;
	case BUF_VMALLOC:
		vfree(buf->buf);
		break;
	case BUF_PAGES:
		_free_buffer(buf);
		break;
	case BUF_NEGATIVE:
	default:
		break;
	}
}
