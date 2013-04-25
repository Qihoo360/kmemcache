#ifndef __MC_BUFFER_H
#define __MC_BUFFER_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#ifdef CONFIG_X86_32
#define GFP_PAGES GFP_KERNEL
#else
#define GFP_PAGES GFP_KERNEL
#endif

#define BUF_NEGATIVE	0
#define BUF_KMALLOC	1
#define BUF_VMALLOC	2
#define BUF_PAGES	3

#define BUF_KMALLOC_MAX	PAGE_SIZE / 2
#define BUF_PAGES_MAX	16 * PAGE_SIZE

#ifdef  CONFIG_PAGES_CACHE
#include <linux/list.h>

struct pages {
	unsigned int order;
	struct page *page;
	void *buf;

	struct list_head list;
};
#endif

struct buffer {
	/*
	 * BUF_NEGATIVE: not alloced
	 * BUF_KMALLOC : kmalloc
	 * BUF_VMALLOC : vmalloc
	 * BUF_PAGES   : alloc_pages
	 */
	unsigned int flags: 3;

	/*
	 * for kmalloc, ksize(p)
	 * for alloc_pages, bytes size
	 */
	unsigned int room: 29;

	/* request len */
	size_t len;

	union {
		void *buf;
#ifdef CONFIG_PAGES_CACHE
		struct pages *_pages;
#define buf_page _pages->page
#define buf_addr _pages->buf
#define buf_order _pages->order
#else
		struct {
			unsigned int _order;
			struct page *_page;
			void *_buf;
		};
#define buf_page _page
#define buf_addr _buf
#define buf_order _order
#endif
	};
};

#define BUFFER(b)			\
({					\
 	void *_buf;			\
 	switch ((b)->flags) {		\
 	case BUF_KMALLOC:		\
 	case BUF_VMALLOC:		\
 		_buf = (b)->buf;	\
 		break;			\
 	case BUF_PAGES:			\
 		_buf = (b)->buf_addr;	\
 		break;			\
 	default:			\
 		BUG_ON(1);		\
 		break;			\
 	}				\
 	_buf;				\
})

#define BUFFER_PTR(buf, ptr)			\
	do {					\
		void *_buf;			\
		_buf = BUFFER(buf);		\
		(ptr) = (typeof(*(ptr)) *)_buf;	\
	} while (0)

#ifdef CONFIG_BUFFER_CACHE
extern struct kmem_cache *buffer_cachep;
#endif

extern int alloc_buffer(struct buffer *buf, size_t len);
extern int realloc_buffer(struct buffer *buf, size_t len, size_t valid);
extern void free_buffer(struct buffer *buf);

#ifdef CONFIG_PAGES_CACHE
extern void pages_cache_exit(void);
#else
static inline void pages_cache_exit(void) {}
#endif

#endif /* __MC_BUFFER_H */
